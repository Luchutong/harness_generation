#!/usr/bin/env python3
"""Explicit native Context retry on unchanged, real-model upstream artifacts."""
import argparse
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness_generation.cli import main
from harness_generation.records import write_json
from harness_generation.semantic_discovery.provider_config import agent_configuration, load_environment_file
from harness_generation.source_paths import SourcePathResolver
from smoke_context_pipeline import responses
from smoke_harness_context import input_hashes


def retry():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    for name in ("functions.json", "annotations.json", "flows.json", "sfg.json", "candidate_discovery", "semantic_slices", "minimal_fts"):
        path = args.upstream / name
        if path.is_dir():
            shutil.copytree(path, args.output / name)
        elif path.is_file():
            shutil.copy2(path, args.output / name)
    functions = json.loads((args.output / "functions.json").read_text())
    project = SourcePathResolver.from_functions_document(functions, args.upstream / "functions.json").project_root
    functions["project"] = str(project)
    write_json(args.output / "functions.json", functions)
    before = input_hashes(args.output)
    load_environment_file(args.env_file)
    cfg = agent_configuration("openai-compatible")
    base = ["--artifacts", str(args.output), "--provider", "openai-compatible", "--model", cfg.model, "--thinking", cfg.thinking]
    context_exit = main(["harness-context", *base, "--requirement-mode", "grouped"])
    generation_exit = main(["context-generate", *base, "--build", "--runtime"])
    context = next((args.output / "harness_contexts").glob("*/completeness.json"))
    marker = context.parent / "metadata.json"
    generation = next((args.output / "context_generations").glob("*/*/*/metadata.json"), None)
    events = responses(args.output)
    # Upstream calls are historical and not charged to this retry.
    context_events = {k: v for k, v in events.items() if any(k == e.get("metadata", {}).get("response_id")
        for f in (args.output / "harness_contexts").glob("*/agent_runs/*/trace.json") for e in json.loads(f.read_text())["events"])}
    row = {"category": "full_model_pipeline_upstream_reused", "upstream_origin": str(args.upstream.resolve()),
        "provider": cfg.to_dict(), "context_exit": context_exit, "generation_exit": generation_exit,
        "completeness": json.loads(context.read_text()), "context_metrics": json.loads(marker.read_text())["metrics"],
        "closure": json.loads((context.parent / "api_closure.json").read_text()),
        "upstream_unchanged": before == input_hashes(args.output), "served_models": sorted({e["served_model"] for e in context_events.values()}),
        "generation": json.loads(generation.read_text()) if generation else {"status": "blocked", "model_calls": 0}}
    if generation:
        build, runtime = generation.parent / "build/build.json", generation.parent / "build/runtime.json"
        row["compile_success"] = build.exists() and json.loads(build.read_text())["success"]
        row["runtime_success"] = runtime.exists() and json.loads(runtime.read_text())["status"] == "passed"
        response = generation.parent / "response.json"
        if response.exists():
            row["code_response"] = {k: v for k, v in json.loads(response.read_text()).items() if k != "content"}
    write_json(args.output / "retry_summary.json", row, sort_keys=True, allow_nan=False)
    return int(context_exit != 0 or generation_exit != 0)


if __name__ == "__main__":
    raise SystemExit(retry())
