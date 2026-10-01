#!/usr/bin/env python3
"""Zero-model replay of recorded raw evidence under current framework rules.

The original failed/successful publication is preserved. No semantic fact is
rewritten; only the derived Context and current Gate are published in a copy.
"""
from copy import deepcopy
import argparse
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness_generation.artifacts import ArtifactStore
from harness_generation.cli import main
from harness_generation.harness_context.models import ContextBudget, ContextRun, MiningState
from harness_generation.harness_context.evidence import build_context
from harness_generation.harness_context.api_closure import build_api_closure
from harness_generation.harness_context.completeness import HarnessContextCompletenessValidator
from harness_generation.harness_context.persistence import save_context
from harness_generation.minimal_ft.models import ProjectSnapshot
from harness_generation.records import write_json
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.source_paths import SourcePathResolver


def replay():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--harness", type=Path)
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    for path in args.input.iterdir():
        if path.name in {"context_generations", "retry_summary.json", "reprojection_summary.json"}:
            continue
        if path.is_dir():
            shutil.copytree(path, args.output / path.name)
        else:
            shutil.copy2(path, args.output / path.name)
    functions = json.loads((args.output / "functions.json").read_text())
    functions["project"] = str(SourcePathResolver.from_functions_document(functions, args.input / "functions.json").project_root)
    write_json(args.output / "functions.json", functions)
    store = ArtifactStore(args.output)
    snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(store.root))
    roots = list(store.root.glob("harness_contexts/*"))
    if len(roots) != 1:
        raise ValueError("select one FT publication for replay")
    root = roots[0]
    load = lambda name: json.loads((root / (name + ".json")).read_text())
    marker, requirements, resolutions = load("metadata"), load("requirements"), load("resolutions")["resolutions"]
    ft = json.loads((store.minimal_ft_run(root.name) / "minimal_ft.json").read_text())
    facts = load("facts")["facts"]
    original_facts = deepcopy(facts)
    state = MiningState(ContextBudget(**marker["configuration"]["budget"]))
    state.evidence = {r["evidence_id"]: r for r in load("evidence")["records"]}
    state.discoveries = marker["discoveries"]
    rows = requirements["requirements"]
    closure = build_api_closure(ft, rows, resolutions, snapshot, state)
    context = build_context(ft, rows, facts, snapshot, state.evidence)
    context["dependencies"] = deepcopy(closure["unresolved_api_dependencies"])
    report = HarnessContextCompletenessValidator().validate(context, closure, ft, snapshot, rows, resolutions, state)
    context["frozen"] = report["generation_allowed"]
    assert facts == original_facts
    metadata = {"schema_version": 1, "policy_version": marker["policy_version"], "ft_id": ft["ft_id"],
        "execution_index": marker["execution_index"] + 1, "termination": "framework_evidence_replay",
        "framework_construction_version": context["construction_contract"]["version"],
        "historical_context_metrics": marker["metrics"], "metrics": {"model_calls": 0, "tool_calls": 0,
            "source_chars": 0, "tokens": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}},
        "harness_generated": False, "model_decides_completeness": False, "raw_facts_unchanged": True}
    save_context(store, ContextRun(requirements, context, closure, report, metadata), marker["configuration"], state, resolutions)
    summary = {"category": "recorded_model_evidence_framework_replay", "input": str(args.input.resolve()),
        "framework_construction_version": context["construction_contract"]["version"],
        "context_model_calls": 0, "raw_facts_unchanged": True, "completeness": report,
        "historical_context_metrics": marker["metrics"], "generation_exit": None}
    if args.harness or args.generate:
        options = ["--harness", str(args.harness.resolve())] if args.harness else ["--env-file", str(args.env_file)]
        summary["generation_exit"] = main(["context-generate", "--artifacts", str(store.root), "--build", "--runtime", *options])
        g = next((store.root / "context_generations").glob("*/*/*/metadata.json"), None)
        summary["generation"] = json.loads(g.read_text()) if g else {"status": "blocked", "model_calls": 0}
        if g:
            summary["compile"] = json.loads((g.parent / "build/build.json").read_text()) if (g.parent / "build/build.json").exists() else None
            summary["runtime"] = json.loads((g.parent / "build/runtime.json").read_text()) if (g.parent / "build/runtime.json").exists() else None
    write_json(store.root / "reprojection_summary.json", summary, sort_keys=True, allow_nan=False)
    print("[EVIDENCE REPLAY]", report["status"], "context_model_calls=0", "hard_missing=" + str(len(report["hard_missing"])), flush=True)
    return int(not report["generation_allowed"] or summary["generation_exit"] not in {0, None})


if __name__ == "__main__":
    raise SystemExit(replay())
