"""Measured HarnessPlan refinement over isolated Stage 4 candidates."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import statistics
import sys
from typing import Any, Callable, Mapping

from .artifacts import ArtifactStore
from .evaluation import (
    CandidateEvaluation, EvaluationOptimizer, OptimizationConfig,
)
from .evaluation.types import (
    EvaluationRecipe, EvaluationReport, Evidence, Measurement, MetricId,
    MetricResult, MetricStatus,
)
from .iteration import WeightedAggregationPolicy
from .llm import LLMClient
from .llm_config import resolve_llm
from .pipeline_validation import PipelineStageValidator, PipelineValidationConfig
from .promotion import promote_harness
from .records import write_json
from .stage4 import Stage4Generator, Stage4Result
from .target_build import TargetBuildConfig
from .target_contract import TargetContract
from .target_coverage import TargetCoverageCollector, TargetCoverageConfig
from .triplet import FunctionTriplet, load_triplets_json


Measure = Callable[[Path, TargetBuildConfig, Path, str, int, int, Path | None],
                   Mapping[str, Any]]


def _measure(
    harness: Path, target: TargetBuildConfig, artifacts: Path, ft_id: str,
    seed: int, budget: int, corpus: Path | None,
) -> Mapping[str, Any]:
    return TargetCoverageCollector(TargetCoverageConfig(
        runs=budget, seed=seed,
    )).measure(harness, target, artifacts=artifacts, ft_id=ft_id,
               corpus=corpus).summary


@dataclass(frozen=True)
class PlanOptimizationConfig:
    artifacts: Path
    output: Path
    ft_id: str
    target_build: TargetBuildConfig
    rounds: int = 1
    children_per_round: int = 3
    runs: int = 1000
    seeds: tuple[int, ...] = (1, 2, 3)
    holdout_seeds: tuple[int, ...] = (101, 102, 103)
    corpus: Path | None = None

    def __post_init__(self) -> None:
        if any(type(value) is not int or value < 1 for value in (
            self.rounds, self.children_per_round, self.runs,
        )):
            raise ValueError("rounds, children_per_round and runs must be positive")
        if (not self.seeds or any(type(seed) is not int or seed < 0 for seed in
                                  (*self.seeds, *self.holdout_seeds))
                or len(set(self.seeds)) != len(self.seeds)
                or len(set(self.holdout_seeds)) != len(self.holdout_seeds)):
            raise ValueError("seeds must be non-negative and distinct; train seeds cannot be empty")
        if set(self.seeds) & set(self.holdout_seeds):
            raise ValueError("holdout seeds must be disjoint from train seeds")
        if self.corpus is not None and not Path(self.corpus).is_dir():
            raise ValueError("corpus must be an existing directory")


def _source_sha256(target: TargetBuildConfig) -> str:
    digest = hashlib.sha256()
    for path in (*target.source_files, *target.header_files):
        digest.update(path.relative_to(target.project_root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _coverage_report(
    candidate_id: str, parent_id: str | None, round_index: int,
    source_sha256: str, harness: Path | None, target: TargetBuildConfig,
    root: Path, ft_id: str, seeds: tuple[int, ...], budget: int,
    corpus: Path | None, measure: Measure,
) -> EvaluationReport:
    measurements: list[Measurement] = []
    evidence: list[Evidence] = []
    values: list[float] = []
    for seed in seeds if harness is not None else ():
        if _source_sha256(target) != source_sha256:
            raise ValueError("target sources changed during optimization")
        try:
            summary = dict(measure(harness, target, root, ft_id, seed, budget, corpus))
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            summary = {"status": "unavailable", "error": type(error).__name__}
        evidence_path = root / f"coverage_seed_{seed}.json"
        write_json(evidence_path, summary, sort_keys=True, allow_nan=False)
        target_only = summary.get("target_only")
        totals = target_only.get("totals") if isinstance(target_only, Mapping) else None
        branch = totals.get("branches") if isinstance(totals, Mapping) else None
        percent = branch.get("percent") if isinstance(branch, Mapping) else None
        count = branch.get("count") if isinstance(branch, Mapping) else None
        if (summary.get("status") != "passed"
                or summary.get("scope") != "target_code"
                or summary.get("runs") != budget
                or summary.get("seed") != seed
                or summary.get("recipe_identity") != target.to_recipe().identity
                or type(count) is not int or count < 1
                or type(percent) not in (int, float) or not 0 <= percent <= 100):
            values.clear()
            break
        values.append(float(percent))
        measurements.append(Measurement(
            f"branches_percent_seed_{seed}", float(percent), "percent", "target_code",
        ))
        evidence.append(Evidence(evidence_path.name, "Target-only branch coverage"))
    measured = len(values) == len(seeds) and bool(seeds)
    if _source_sha256(target) != source_sha256:
        raise ValueError("target sources changed during optimization")
    metric = MetricResult(
        MetricId.COVERAGE,
        MetricStatus.MEASURED if measured else MetricStatus.UNAVAILABLE,
        "PlanOptimizationTargetCoverage", "1",
        "Equal-budget target-only branch coverage" if measured
        else "Target-only branch coverage is incomplete or incomparable",
        score=(sum(values) / len(values) / 100 if measured else None),
        measurements=tuple(measurements) if measured else (),
        evidence=tuple(evidence),
    )
    report = EvaluationReport(
        candidate_id, parent_id, round_index, source_sha256,
        hashlib.sha256(harness.read_bytes()).hexdigest() if harness else None,
        (metric,),
    )
    policy = WeightedAggregationPolicy(
        weights={MetricId.COVERAGE: 1.0}, require_dynamic_quality=False,
    )
    from dataclasses import replace
    return replace(report, aggregate=policy.aggregate(report))


def run_plan_optimization(
    config: PlanOptimizationConfig, llm: LLMClient, *,
    measure: Measure = _measure,
) -> Any:
    """Refine a validated parent Plan and compare candidates at one recipe."""
    source_root = Path(config.artifacts).resolve()
    output = Path(config.output).resolve()
    if output.exists():
        raise ValueError("optimization output must not already exist")
    target = config.target_build
    target.validate_inputs()
    triplets = {item.id: item for item in load_triplets_json(source_root / "triplets.json")}
    triplet = triplets.get(config.ft_id)
    if triplet is None:
        raise ValueError(f"unknown FunctionTriplet: {config.ft_id}")
    source_layout = ArtifactStore(source_root).for_triplet(config.ft_id)
    parent_plan_path = (
        source_layout.stable_harness_plan
        if source_layout.stable_harness_plan.is_file()
        else source_layout.stage4_harness_plan
    )
    for path in (source_layout.harness, source_layout.stage3_rough,
                 parent_plan_path, source_root / "functions.json"):
        if not path.is_file():
            raise ValueError(f"parent artifact is missing: {path.name}")
    template_plan = json.loads(parent_plan_path.read_text(encoding="utf-8"))
    if not isinstance(template_plan, dict):
        raise ValueError("parent HarnessPlan must be an object")
    contract = ArtifactStore(source_root).load_target_contract() or TargetContract.from_triplet(triplet)
    recipe = EvaluationRecipe(
        project_root=str(target.project_root),
        recipe_identity=target.to_recipe().identity,
        contract_identity=contract.id,
        target_sources=tuple(path.relative_to(target.project_root).as_posix()
                             for path in target.source_files),
        input_language=contract.input.mode if contract.input else "raw_bytes",
        budget=config.runs, seeds=config.seeds,
        holdout_seeds=config.holdout_seeds,
    )
    source_hash = _source_sha256(target)
    output.mkdir(parents=True)
    candidates: dict[str, tuple[Path, dict[str, Any], CandidateEvaluation]] = {}

    def candidate_root(candidate_id: str) -> Path:
        root = output / "candidates" / candidate_id
        store = ArtifactStore(root)
        store.ensure_catalogs()
        for path in (source_root / "functions.json", source_root / "triplets.json",
                     source_root / "protocol_ir.json", source_root / "target_contract.json"):
            if path.is_file():
                shutil.copyfile(path, root / path.name)
        layout = store.for_triplet(config.ft_id).ensure_generation()
        shutil.copyfile(source_layout.stage3_rough, layout.stage3_rough)
        return root

    def evaluate_one(
        candidate_id: str, parent_id: str | None, round_index: int,
        seeds: tuple[int, ...], budget: int, root: Path,
        plan: dict[str, Any], validation_status: str,
        *, phase: str = "train",
    ) -> CandidateEvaluation:
        layout = ArtifactStore(root).for_triplet(config.ft_id)
        harness = layout.harness if validation_status == "passed" else None
        report = _coverage_report(
            candidate_id, parent_id, round_index, source_hash, harness,
            target, root, config.ft_id, seeds, budget, config.corpus, measure,
        )
        filename = "holdout_evaluation.json" if phase == "holdout" else "evaluation.json"
        write_json(root / filename, report.to_dict(),
                   sort_keys=True, allow_nan=False)
        return CandidateEvaluation(
            candidate_id, parent_id, round_index, validation_status,
            recipe.identity, recipe.contract_identity, report, phase,
        )

    def run_candidate(
        parent_id: str | None, round_index: int, child_index: int,
        seeds: tuple[int, ...], budget: int,
    ) -> CandidateEvaluation:
        candidate_id = f"r{round_index:03d}_c{child_index:03d}"
        root = candidate_root(candidate_id)
        layout = ArtifactStore(root).for_triplet(config.ft_id)
        if parent_id is None:
            plan = template_plan
            shutil.copyfile(source_layout.harness, layout.stage4_harness)
            layout.write_json(layout.stage4_harness_plan, plan)
            harness_code = layout.stage4_harness.read_text(encoding="utf-8")
            attempt = layout.stage4_attempts / "attempt_001"
            attempt.mkdir(parents=True)
            result = Stage4Result(
                triplet_id=config.ft_id, harness_code=harness_code,
                harness_path=layout.stage4_harness, stable_path=None,
                generation_metadata={}, attempt_directory=attempt,
                harness_plan=plan,
            )
        else:
            parent_root, parent_plan, parent_evaluation = candidates[parent_id]
            parent_metric = parent_evaluation.report.metrics[0]
            feedback = {
                "parent_candidate": parent_id,
                "parent_plan_sha256": hashlib.sha256(json.dumps(
                    parent_plan, sort_keys=True,
                ).encode()).hexdigest(),
                "metric_status": parent_metric.status.value,
                "measured_score": parent_metric.score,
                "measurements": [item.__dict__ for item in parent_metric.measurements],
                "evidence_root": str(parent_root),
            }
            write_json(root / "plan_feedback.json", feedback,
                       sort_keys=True, allow_nan=False)
            try:
                result = Stage4Generator(llm).run(
                    triplet, rough_code=layout.stage3_rough,
                    functions_json=root / "functions.json", artifacts=root,
                    publish=False, parent_plan=parent_plan,
                    optimization_feedback=feedback,
                )
                plan = dict(result.harness_plan)
            except (OSError, RuntimeError, TypeError, ValueError) as error:
                plan = dict(parent_plan)
                write_json(root / "generation_error.json", {
                    "type": type(error).__name__, "message": str(error),
                })
                evaluation = evaluate_one(candidate_id, parent_id, round_index,
                                          seeds, budget, root, plan, "failed")
                candidates[candidate_id] = (root, plan, evaluation)
                return evaluation
        try:
            validator = PipelineStageValidator(
                triplet, artifacts=root, functions_json=root / "functions.json",
                project_root=target.project_root,
                config=PipelineValidationConfig(target_build=target, fuzz_smoke=None),
            )
            validation = validator.validate_stage4(result)
            summary_path = layout.validation_summary
            summary = json.loads(summary_path.read_text()) if summary_path.is_file() else {}
            promoted = promote_harness(
                layout, harness_code=result.harness_code, harness_plan=plan,
                validation_summary=summary,
                recipe_identity=recipe.identity,
                contract_identity=recipe.contract_identity,
                candidate_id=candidate_id,
            )
            status = "passed" if validation.status == "passed" and promoted else "failed"
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            write_json(root / "validation_error.json", {
                "type": type(error).__name__, "message": str(error),
            })
            status = "failed"
        evaluation = evaluate_one(candidate_id, parent_id, round_index,
                                  seeds, budget, root, plan, status)
        candidates[candidate_id] = (root, plan, evaluation)
        return evaluation

    def run_holdout(
        selected: CandidateEvaluation, seeds: tuple[int, ...], budget: int,
    ) -> CandidateEvaluation:
        root, plan, _ = candidates[selected.candidate_id]
        return evaluate_one(selected.candidate_id, selected.parent_id,
                            selected.round_index, seeds, budget, root, plan,
                            selected.validation_status, phase="holdout")

    optimizer = EvaluationOptimizer(
        OptimizationConfig(recipe, config.rounds, config.children_per_round),
        run_candidate, run_holdout=run_holdout,
        output=output / "evaluation",
    )
    result = optimizer.run()
    generation_means: dict[str, float] = {}
    run_variances: dict[str, float | None] = {}
    for candidate_id, (_root, _plan, candidate) in candidates.items():
        if candidate.round_index == 0:
            continue
        metric = candidate.report.metrics[0]
        if metric.status != MetricStatus.MEASURED:
            continue
        values = [float(item.value) for item in metric.measurements]
        generation_means[candidate_id] = statistics.mean(values)
        run_variances[candidate_id] = (
            statistics.pvariance(values) if len(values) > 1 else None
        )
    write_json(output / "plan_optimization.json", {
        **result.to_dict(),
        "source_sha256": source_hash,
        "candidate_roots": {key: str(value[0]) for key, value in candidates.items()},
        "variance": {
            "generation_means_percent": generation_means,
            "generation_variance_percent_squared": (
                statistics.pvariance(generation_means.values())
                if len(generation_means) > 1 else None
            ),
            "run_variance_percent_squared_by_generation": run_variances,
        },
    }, sort_keys=True, allow_nan=False)
    return result


def main(argv: list[str] | None = None, *, llm: LLMClient | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness-generation plan-optimize")
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--ft", required=True)
    parser.add_argument("--target-build", required=True, type=Path)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--rounds", type=int, default=1)
    parser.add_argument("--children-per-round", type=int, default=3)
    parser.add_argument("--runs", type=int, default=1000)
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    parser.add_argument("--holdout-seeds", type=int, nargs="+", default=[101, 102, 103])
    parser.add_argument("--corpus", type=Path)
    providers = parser.add_mutually_exclusive_group()
    providers.add_argument("--mock-responses", type=Path)
    providers.add_argument("--recorded-responses", type=Path)
    parser.add_argument("--model")
    args = parser.parse_args(argv)
    try:
        client = resolve_llm(
            llm, provider=None, model=args.model,
            mock_responses=args.mock_responses,
            recorded_responses=args.recorded_responses,
        )
        target = TargetBuildConfig.load(args.target_build, project_root=args.project_root)
        config = PlanOptimizationConfig(
            artifacts=args.artifacts, output=args.output, ft_id=args.ft,
            target_build=target, rounds=args.rounds,
            children_per_round=args.children_per_round, runs=args.runs,
            seeds=tuple(args.seeds), holdout_seeds=tuple(args.holdout_seeds),
            corpus=args.corpus,
        )
        result = run_plan_optimization(config, client)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        print(f"Plan optimization failed: {error}", file=sys.stderr)
        return 1
    print(f"plan-optimization={result.status} selected={result.selected_candidate or '-'}")
    return 0 if result.status == "completed" else 1
