"""Independent Stage 4 generations measured with a fixed coverage campaign.

Each trial starts from the same catalog in a new artifact root.  Rollback
attempts inside one trial are never counted as independent generations.  The
coverage statistic has two axes: trial means and seeds within each trial.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import shutil
import statistics
import sys
from typing import Any, Callable, Mapping, Sequence

from .artifacts import ArtifactStore
from .coverage_arms import (
    ArmSpec, ArmsManifest, CoverageArmsConfig, CoverageArmsError, GATE_METRICS,
    ROLE_CONTRACTED, TARGET_LAYER, digest, load_manifest,
    measure_target_arm, _recipe_problems, _INCLUDE_TARGET,
)
from .generation_cli import main as generation_main
from .llm import LLMClient
from .llm_config import resolve_llm
from .records import write_json
from .triplet import load_triplets_json


SCHEMA_VERSION = 1
CATALOGS = (
    "functions.json", "annotations.json", "flows.json", "sfg.json",
    "triplets.json", "protocol_candidates.json", "protocol_conventions.json",
    "protocol_ir.json",
)


def _tree_digests(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): digest(path)
        for path in sorted(root.rglob("*")) if path.is_file()
    }


def _input_digests(template: Path, manifest: ArmsManifest, project_root: Path) -> dict:
    catalogs = {
        name: digest(template / name)
        for name in CATALOGS if (template / name).is_file()
    }
    for required in ("functions.json", "triplets.json", "protocol_ir.json"):
        if required not in catalogs:
            raise ValueError(f"generation template requires {required}")
    target = manifest.root / str(manifest.target_source.get("path", ""))
    if not target.is_file() or not (project_root / target.name).is_file():
        raise ValueError("project root must contain the manifest target source")
    if digest(target) != digest(project_root / target.name):
        raise ValueError("project target source differs from the coverage manifest")
    if digest(target) != manifest.target_source.get("sha256"):
        raise ValueError("coverage target source differs from the manifest digest")
    corpus = manifest.root / str(manifest.corpus.get("path", ""))
    if not corpus.is_dir():
        raise ValueError("coverage corpus is missing")
    corpus_digests = _tree_digests(corpus)
    if corpus_digests != manifest.corpus.get("digests"):
        raise ValueError("coverage corpus differs from the manifest digests")
    return {
        "catalogs": catalogs,
        "target_source_sha256": digest(target),
        "corpus": corpus_digests,
        "reference_sha256": manifest.arm("reference").sha256,
    }


def _copy_catalogs(template: Path, destination: Path, digests: Mapping[str, str]) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    for name, expected in digests.items():
        source = template / name
        if digest(source) != expected:
            raise ValueError(f"generation input changed during campaign: {name}")
        shutil.copyfile(source, destination / name)


def _trial_coverage(
    trial: int, harness: Path, manifest: ArmsManifest,
    config: CoverageArmsConfig, output: Path,
) -> list[dict[str, Any]]:
    raw = harness.read_bytes()
    recipe = "single_tu" if _INCLUDE_TARGET.search(raw.decode("utf-8")) else "two_tu"
    spec = ArmSpec(
        name=f"generation_{trial:03d}", path=str(harness),
        sha256=digest(harness), size=harness.stat().st_size,
        recipe=recipe, role=ROLE_CONTRACTED,
        provenance="fresh Stage 4 publish in an isolated trial root",
    )
    problems = _recipe_problems(spec, raw)
    if problems:
        raise ValueError("; ".join(problems))
    target = manifest.root / str(manifest.target_source["path"])
    corpus = manifest.root / str(manifest.corpus["path"])
    return [measure_target_arm(
        spec, harness, target, config,
        root=output / "coverage", corpus=corpus, seed=seed,
    ) for seed in config.seeds]


def _stage4_provenance(layout: Any) -> dict[str, Any]:
    attempts = sorted((layout.generation / "stage4").glob("attempt_*/metadata.json"))
    response_ids = []
    for path in attempts:
        try:
            metadata = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        plan = metadata.get("plan_generation_metadata", {})
        response_id = plan.get("response_id") if isinstance(plan, Mapping) else None
        if isinstance(response_id, str) and response_id:
            response_ids.append(response_id)
    return {
        "stage4_attempts": len(attempts),
        "plan_response_ids": response_ids,
    }


def run_campaign(
    *, template: Path, ft_id: str, project_root: Path,
    manifest: ArmsManifest, output: Path, trials: int = 3,
    config: CoverageArmsConfig | None = None,
    llm_factory: Callable[[int], LLMClient] | None = None,
) -> dict[str, Any]:
    """Run N fresh generations; keep unsuccessful trials in the denominator."""

    if type(trials) is not int or trials < 3:
        raise ValueError("at least three independent generations are required")
    config = config or CoverageArmsConfig()
    if len(config.seeds) < 2:
        raise ValueError("at least two distinct seeds are required within each trial")
    template = Path(template).resolve()
    project_root = Path(project_root).resolve()
    output = Path(output).resolve()
    inputs = _input_digests(template, manifest, project_root)
    if ft_id not in {triplet.id for triplet in load_triplets_json(template / "triplets.json")}:
        raise ValueError(f"FunctionTriplet {ft_id} is absent from the template")
    first_client = None
    if llm_factory is None:
        # Fail before the reference coverage campaign if real-provider settings
        # are absent. Use this client for trial one and make a new one for each
        # later trial.
        first_client = resolve_llm(
            None, provider=None, model=None, mock_responses=None,
            recorded_responses=None,
        )
        inputs["llm_config"] = first_client.config.to_dict()
    else:
        inputs["llm_config"] = {"provider": "injected"}
    output.mkdir(parents=True, exist_ok=False)

    reference = manifest.arm("reference")
    target = manifest.root / str(manifest.target_source["path"])
    corpus = manifest.root / str(manifest.corpus["path"])
    reference_runs = [measure_target_arm(
        reference, manifest.resolve(reference), target, config,
        root=output / "coverage", corpus=corpus, seed=seed,
    ) for seed in config.seeds]

    generations: list[dict[str, Any]] = []
    clients: list[LLMClient] = []
    for number in range(1, trials + 1):
        if {key: value for key, value in inputs.items() if key != "llm_config"} != _input_digests(template, manifest, project_root):
            raise ValueError("generation or measurement inputs changed during campaign")
        trial_root = output / f"generation_{number:03d}"
        _copy_catalogs(template, trial_root, inputs["catalogs"])
        client = (
            llm_factory(number) if llm_factory is not None else
            first_client if number == 1 else resolve_llm(
                None, provider=None, model=None, mock_responses=None,
                recorded_responses=None,
            )
        )
        if llm_factory is None and client.config.to_dict() != inputs["llm_config"]:
            raise ValueError("LLM configuration changed during campaign")
        if client is not None:
            if any(client is previous for previous in clients):
                raise ValueError("each generation requires a fresh LLM client")
            clients.append(client)
        exit_code = generation_main([
            "--artifacts", str(trial_root), "--ft", ft_id,
            "--project-root", str(project_root), "--validate",
        ], llm=client, run_command=True)
        layout = ArtifactStore(trial_root).for_triplet(ft_id)
        result_path = layout.pipeline_result
        result = (
            json.loads(result_path.read_text(encoding="utf-8"))
            if result_path.is_file() else {}
        )
        published = exit_code == 0 and result.get("success") is True
        harness = layout.harness
        entry: dict[str, Any] = {
            "trial": number,
            "root": trial_root.relative_to(output).as_posix(),
            "generation_status": "published" if published and harness.is_file()
                                 else "failed",
            "exit_code": exit_code,
            "failure_reason": (
                result.get("failure_reason")
                if result.get("failure_reason") else
                "pipeline reported success without a published harness"
                if published and not harness.is_file() else
                f"generation command exited {exit_code} without a pipeline result"
                if exit_code else None
            ),
            "rollback_count": result.get("rollback_count"),
            **_stage4_provenance(layout),
            "harness_sha256": digest(harness) if published and harness.is_file() else None,
            "coverage_runs": [],
        }
        if entry["generation_status"] == "published":
            try:
                entry["coverage_runs"] = _trial_coverage(
                    number, harness, manifest, config, output
                )
            except (OSError, ValueError) as error:
                entry["coverage_error"] = f"{type(error).__name__}: {error}"
        generations.append(entry)
        # A long or interrupted real-provider campaign still has a record of
        # every completed trial, without making a partial set look complete.
        document = _document(ft_id, trials, config, inputs, reference_runs, generations)
        write_json(output / "measurements.json", document, sort_keys=True,
                   allow_nan=False)

    if {key: value for key, value in inputs.items() if key != "llm_config"} != _input_digests(template, manifest, project_root):
        raise ValueError("generation or measurement inputs changed during campaign")
    (output / "report.md").write_text(render_report(document), encoding="utf-8")
    return document


def _measured(run: Mapping[str, Any], metric: str, runs: int, seed: int) -> float | None:
    if (run.get("scope") != TARGET_LAYER or run.get("status") != "passed"
            or run.get("runs") != runs or run.get("seed") != seed
            or run.get("seed_recorded") != seed):
        return None
    value = (run.get("totals") or {}).get(metric, {}).get("percent")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if math.isfinite(value) and 0 <= value <= 100 else None


def summarize(document: Mapping[str, Any]) -> dict[str, Any]:
    """Separate spread of trial means from spread of runs within a trial."""

    seeds = document["config"]["seeds"]
    budget = document["config"]["runs"]
    generations = document["generations"]
    summary: dict[str, Any] = {}
    for metric in GATE_METRICS:
        per_generation = []
        for entry in generations:
            runs = entry.get("coverage_runs", ())
            values = []
            for seed in seeds:
                matching = [run for run in runs if run.get("seed") == seed]
                values.append(
                    _measured(matching[0], metric, budget, seed)
                    if len(matching) == 1 else None
                )
            complete = (
                entry.get("generation_status") == "published"
                and all(value is not None for value in values)
            )
            per_generation.append({
                "trial": entry["trial"], "complete": complete,
                "mean_percent": statistics.mean(values) if complete else None,
                "within_sample_variance": statistics.variance(values) if complete else None,
            })
        complete = [item for item in per_generation if item["complete"]]
        means = [item["mean_percent"] for item in complete]
        between = statistics.variance(means) if len(means) >= 2 else None
        within = (
            statistics.mean(item["within_sample_variance"] for item in complete)
            if complete else None
        )
        grand_mean = statistics.mean(means) if means else None
        summary[metric] = {
            "requested_generations": len(generations),
            "measured_generations": len(complete),
            "mean_percent": grand_mean,
            "between_generation_sample_variance": between,
            "within_generation_sample_variance": within,
            "between_generation_cv": (
                math.sqrt(between) / grand_mean
                if between is not None and grand_mean else None
            ),
            "within_generation_cv": (
                math.sqrt(within) / grand_mean
                if within is not None and grand_mean else None
            ),
            "per_generation": per_generation,
        }
    return summary


def _document(ft_id, trials, config, inputs, reference_runs, generations):
    document = {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "harness_generation.generation_variance",
        "ft_id": ft_id,
        "requested_generations": trials,
        "config": {"runs": config.runs, "seeds": list(config.seeds)},
        "inputs": inputs,
        "reference_runs": reference_runs,
        "generations": generations,
    }
    document["summary"] = summarize(document)
    reference_complete = all(
        sum(
            _measured(run, metric, config.runs, seed) is not None
            for run in reference_runs
        ) == 1
        for metric in GATE_METRICS for seed in config.seeds
    )
    document["reference_complete"] = reference_complete
    document["status"] = (
        "complete" if reference_complete and len(generations) == trials and all(
            item["measured_generations"] == trials
            for item in document["summary"].values()
        ) else "incomplete"
    )
    return document


def render_report(document: Mapping[str, Any]) -> str:
    llm = document.get("inputs", {}).get("llm_config", {})
    lines = [
        "# Independent generation variance",
        "",
        f"FT: `{document['ft_id']}`. Status: **{document['status']}**.",
        f"Requested independent generations: {document['requested_generations']}; "
        f"seeds per generation: {len(document['config']['seeds'])}; "
        f"fixed budget: {document['config']['runs']} executions.",
        f"LLM: {llm.get('model', 'injected')}; "
        f"temperature: {llm.get('temperature', 'unspecified')}.",
        "",
        "Each generation starts in a fresh artifact root from the same input catalogs. "
        "Rollback attempts within one generation are not separate samples. "
        "Coverage is LLVM target-source coverage with sanitizers off.",
        "The reference is a single translation unit; each generated harness's "
        "recipe is listed below. These measurements describe this benchmark "
        "and do not isolate a method effect from recipe differences.",
        "",
        f"Reference measurement: {'complete' if document['reference_complete'] else 'incomplete'}.",
        "",
        "| metric | measured generations | reference mean % | generated mean % | between generation sample variance | "
        "within generation sample variance | between CV | within CV |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    def show(value):
        return "unavailable" if value is None else f"{value:.6g}"
    for metric in GATE_METRICS:
        row = document["summary"][metric]
        reference_values = [
            _measured(run, metric, document["config"]["runs"], seed)
            for seed in document["config"]["seeds"]
            for run in document["reference_runs"] if run.get("seed") == seed
        ]
        reference_mean = (
            statistics.mean(reference_values)
            if len(reference_values) == len(document["config"]["seeds"])
            and all(value is not None for value in reference_values) else None
        )
        lines.append(
            f"| {metric} | {row['measured_generations']}/"
            f"{row['requested_generations']} | {show(reference_mean)} | "
            f"{show(row['mean_percent'])} | "
            f"{show(row['between_generation_sample_variance'])} | "
            f"{show(row['within_generation_sample_variance'])} | "
            f"{show(row['between_generation_cv'])} | "
            f"{show(row['within_generation_cv'])} |"
        )
    lines.extend([
        "", "Sample variances use n−1. Between generation variance is computed "
        "from each complete generation's mean across seeds; within generation "
        "variance is the mean of its seed level sample variances. These are "
        "descriptive spreads, not a confidence interval or a causal estimate.",
        "", "## Trial outcomes", "",
        "| trial | generation | Stage 4 attempts | recipe | measured seeds | harness SHA-256 | reason |",
        "|---:|---|---:|---|---:|---|---|",
    ])
    for entry in document["generations"]:
        measured = sum(
            run.get("status") == "passed"
            for run in entry.get("coverage_runs", ())
        )
        recipe = next((run.get("recipe") for run in entry.get("coverage_runs", ())
                       if isinstance(run.get("recipe"), str)), "—")
        lines.append(
            f"| {entry['trial']} | {entry['generation_status']} | "
            f"{entry.get('stage4_attempts', 0)} | {recipe} | {measured} | "
            f"{entry['harness_sha256'] or '—'} | "
            f"{str(entry.get('failure_reason') or entry.get('coverage_error') or '—').replace('|', '/')} |"
        )
    lines.extend([
        "", "A failed generation or missing coverage measurement stays in the "
        "requested denominator. It is never imputed as zero or silently "
        "replaced. Identical harness hashes are retained as separate requests "
        "and disclosed above; different requests do not guarantee different code.",
        "Three generations support only descriptive spreads for this target "
        "and budget. Seed level zero variance means no variation was observed "
        "at this budget; it is not three independent confirmations.",
        "",
    ])
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness-generation generation-variance")
    parser.add_argument("--template", required=True, type=Path,
                        help="Catalog root containing functions, triplets, and protocol IR")
    parser.add_argument("--ft", required=True, dest="ft_id")
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path,
                        help="New campaign directory")
    parser.add_argument("--manifest", type=Path, default=None,
                        help="coverage-arms manifest with target, corpus, reference")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--runs", type=int, default=20_000)
    parser.add_argument("--seeds", default="1,2,3")
    args = parser.parse_args(argv)
    try:
        from .coverage_arms import DEFAULT_MANIFEST
        seeds = tuple(int(value) for value in args.seeds.split(","))
        manifest = load_manifest(args.manifest or DEFAULT_MANIFEST)
        document = run_campaign(
            template=args.template, ft_id=args.ft_id,
            project_root=args.project_root, manifest=manifest,
            output=args.output, trials=args.trials,
            config=CoverageArmsConfig(runs=args.runs, seeds=seeds),
        )
    except (OSError, ValueError, CoverageArmsError) as error:
        print(f"Generation variance failed: {error}", file=sys.stderr)
        return 1
    print(args.output / "report.md")
    return 0 if document["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
