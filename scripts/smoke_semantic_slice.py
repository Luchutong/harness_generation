#!/usr/bin/env python3
"""Explicit real-model smoke; never loaded by pytest and never writes legacy FTs."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evaluate_candidate_validation_real import credential_environment
from harness_generation.artifacts import ArtifactStore
from harness_generation.entry_candidates import discover_candidates
from harness_generation.records import write_json
from harness_generation.semantic_discovery import (CandidateValidationAgent, DeepSeekAgentModel, DeepSeekConfig,
    RepositoryTools, ValidationBudget)
from harness_generation.semantic_discovery.models import candidate_id
from harness_generation.semantic_discovery.persistence import (run_configuration as validation_config,
    save_run as save_validation, write_validated_catalog)
from harness_generation.semantic_discovery.tools import RepositoryIndex
from harness_generation.semantic_slicing import SemanticSliceAgent, SemanticSliceTools, build_frontier
from harness_generation.semantic_slicing.cli import main as slice_cli
from harness_generation.semantic_slicing.persistence import (load_accepted_candidates, load_compatible_slice,
    run_configuration, save_run)
from harness_generation.sfg_adapter import load_sfg_artifacts
from sfg_builder.parser import CProjectParser, write_functions_json

HUB_SOURCE = """typedef unsigned long size_t;
typedef struct Context { const unsigned char *data; size_t size; int logger; int calls; } Context;
Context *create(void) { return calloc(1, sizeof(Context)); }
void destroy(Context *ctx) { free(ctx); }
void set_logger(Context *ctx) { ctx->logger = 1; }
int stats(Context *ctx) { return ctx->calls; }
void feed(Context *ctx, const void *data, size_t size) { ctx->data = data; ctx->size = size; }
int parse(Context *ctx) { ctx->calls++; return ctx->size ? ctx->data[0] : 0; }
int encode(Context *ctx, unsigned char *out) { out[0] = (unsigned char)ctx->calls; return 1; }
"""


def prepare_fixture(output, model, budget, *, name="hub", source=HUB_SOURCE):
    project = output / f"{name}_project"
    project.mkdir()
    (project / "api.c").write_text(source, encoding="utf-8")
    store = ArtifactStore(output / f"{name}_phase1")
    write_functions_json(CProjectParser().parse(project), store.functions, project=project)
    # Parser-only Phase 1: no fake semantic annotations or ownership assertions.
    write_json(store.annotations, {"schema_version": 1, "annotations": []})
    write_json(store.flows, {"schema_version": 1, "flows": []})
    write_json(store.sfg, {"schema_version": 1, "nodes": [], "edges": [], "functions": []})
    artifacts = load_sfg_artifacts(store.root)
    catalog = discover_candidates(artifacts)
    store.write_candidate_catalog(catalog)
    candidate = next(c for c in catalog.candidates if c.function == "parse")
    index = RepositoryIndex(artifacts, catalog, functions_path=store.functions)
    run = CandidateValidationAgent(model, budget).validate(candidate, RepositoryTools(artifacts, catalog, budget, index=index))
    save_validation(store, run, validation_config(catalog, budget, model))
    write_validated_catalog(store, catalog, {candidate.function_id: run.result}, {})
    print(f"[LIVE VALIDATION] {name} parse: {run.result['verdict']} / {run.result['run_status']}", flush=True)
    return store, run.result


def copy_validated(source, destination):
    shutil.copytree(source, destination)
    store = ArtifactStore(destination)
    document = json.loads(store.functions.read_text(encoding="utf-8"))
    project = Path(document["project"])
    if not project.is_absolute():
        project = (source / project).resolve()
    document["project"] = os.path.relpath(project, destination)
    write_json(store.functions, document, sort_keys=True, allow_nan=False)
    # Preserve historical validation inputs and evidence, but never copy derived
    # slices into this independent smoke run.
    if store.semantic_slices_directory.exists():
        shutil.rmtree(store.semantic_slices_directory)
    return store


def evaluate(store, name, case, model, budget):
    artifacts = load_sfg_artifacts(store.root)
    catalog = store.load_candidate_catalog()
    catalog.validate_against(artifacts)
    index = RepositoryIndex(artifacts, catalog, functions_path=store.functions)
    accepted = load_accepted_candidates(store, catalog, index)
    candidate, validation = next((c, v) for c, v in accepted if c.function == name)
    frontier = build_frontier(store, artifacts, catalog, candidate, validation)
    tools = SemanticSliceTools(artifacts, catalog, frontier, budget, index=index)
    start = time.monotonic()
    run = SemanticSliceAgent(model, budget).slice(tools)
    config = run_configuration(catalog, frontier, budget, model, 32)
    save_run(store, run, config)
    names = {fid: f["name"] for fid, f in artifacts.functions_by_id.items()}
    row = {"case": case, "anchor": name, "run_status": run.result["run_status"],
        "termination": run.metadata["termination"], "fallback": run.metadata["canonical_is_fallback"],
        "groups": {key: [names[fid] for fid in run.result[key]] for key in
            ("core_functions", "support_functions", "excluded_functions", "unresolved_frontier")},
        "frontier_count": len(frontier.function_ids), "budget": run.result["budget"],
        "artifact_directory": str(store.semantic_slice_run(candidate_id(candidate.function_id)).relative_to(ROOT)),
        "resume_verified": load_compatible_slice(store, frontier, config, index, budget) == run.result,
        "elapsed_seconds": round(time.monotonic() - start, 3),
        "usage": {key: sum(event.get("metadata", {}).get("usage", {}).get(key, 0)
                           for event in run.trace["events"] if event["kind"] == "model_response")
                  for key in ("prompt_tokens", "completion_tokens", "total_tokens")}}
    # Expectations are explicit and conservative; a fallback is not a successful
    # semantic decision even when its anchor happens to match a group assertion.
    core = set(row["groups"]["core_functions"])
    row["meets_expectation"] = (row["run_status"] in {"completed", "completed_with_unresolved"} and not row["fallback"]
        and (core == {"parse", "feed"} and {"create", "destroy"} <= set(row["groups"]["support_functions"])
             and not {"set_logger", "stats", "encode"} & (core | set(row["groups"]["support_functions"]))
             if case == "shared_context_hub" else
             {"decoder_wrapper", "feed", "process_context"} <= core if case == "wrapper" else
             core == {"parse"} if case == "direct_parser" else {"json_parse", "json_parse_ex"} <= core))
    print(f"[LIVE SLICE] {case}: {row['run_status']} {row['groups']} expectation={row['meets_expectation']}", flush=True)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", type=Path, default=ROOT / ".env")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--validated-inputs", type=Path, default=ROOT / "artifacts/candidate_validation_real_20260928_03")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    # This is the only explicit dotenv-to-provider mapping. Never print it.
    environment = credential_environment(args.credentials)
    config = DeepSeekConfig.from_environment(environ=environment, thinking="disabled")
    model = DeepSeekAgentModel(config, environ=environment)
    budget = ValidationBudget()
    hub, validation = prepare_fixture(output, model, budget)
    direct, direct_validation = prepare_fixture(output, model, budget, name="direct", source="""typedef unsigned long size_t;
int parse(const unsigned char *data, size_t size) { return size ? data[0] : 0; }
""")
    fixture = copy_validated(args.validated_inputs.resolve() / "fixture_phase1", output / "fixture_phase1")
    json_store = copy_validated(args.validated_inputs.resolve() / "json_phase1", output / "json_phase1")
    rows = []
    summary = {"schema_version": 1, "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": config.to_dict(), "budget_limits": budget.to_dict(), "hub_validation": validation,
        "direct_validation": direct_validation, "cases": rows}
    cases = [(hub, "parse", "shared_context_hub"), (direct, "parse", "direct_parser"),
             (fixture, "decoder_wrapper", "wrapper"), (json_store, "json_parse", "json_parser")]
    for store, name, case in cases:
        if ((case == "shared_context_hub" and validation["verdict"] != "accepted")
                or (case == "direct_parser" and direct_validation["verdict"] != "accepted")):
            rows.append({"case": case, "meets_expectation": False, "not_run": "anchor_not_accepted"})
        else:
            rows.append(evaluate(store, name, case, model, budget))
        write_json(output / "summary.partial.json", summary, sort_keys=True, allow_nan=False)
    cli_store = copy_validated(direct.root, output / "cli_phase1")
    cli_run = subprocess.run([sys.executable, "-m", "harness_generation", "semantic-slice", "--artifacts", str(cli_store.root),
        "--candidate", next(c.function_id for c in cli_store.load_candidate_catalog().candidates if c.function == "parse")],
        cwd=ROOT, env={**os.environ, **environment}, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=480, check=False)
    (output / "cli_smoke.txt").write_text(cli_run.stdout, encoding="utf-8")
    summary["cli_live_exit"] = cli_run.returncode
    # Exercise the public CLI's compatible resume path with no provider key.
    os.environ.pop("DEEPSEEK_API_KEY", None)
    summary["cli_resume_exit"] = slice_cli(["--artifacts", str(direct.root), "--candidate",
        next(c.function_id for c in direct.load_candidate_catalog().candidates if c.function == "parse"), "--resume"])
    summary["cases_meeting_expectation"] = sum(row["meets_expectation"] for row in rows)
    write_json(output / "summary.json", summary, sort_keys=True, allow_nan=False)
    print(f"[LIVE SLICE] {summary['cases_meeting_expectation']}/{len(rows)} expectations; {output / 'summary.json'}", flush=True)
    return 0 if summary["cases_meeting_expectation"] == len(rows) and summary["cli_resume_exit"] == 0 and cli_run.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
