#!/usr/bin/env python3
"""Development/regression: fresh native candidate → Slice → FT → Context → code.

Small synthetic API models are explicitly fixtures, not cross-project evidence.
No recorded, mock, fabricated semantic annotation or provider fallback is used.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness_generation.artifacts import ArtifactStore
from harness_generation.cli import main
from harness_generation.records import write_json
from harness_generation.semantic_discovery.provider_config import agent_configuration, load_environment_file
from harness_generation.sfg_adapter import load_sfg_artifacts
from sfg_builder.parser import CProjectParser, write_functions_json
from smoke_harness_context import OWNED, EXTERNAL, input_hashes

DATASET_ROLE = "development_regression"
CASES = {
    "direct": """#include <stddef.h>
int parse(const unsigned char *data, size_t size) { return size ? data[0] : 0; }
""",
    "external_context": EXTERNAL,
    "owned_return": OWNED,
    "callback": """#include <stddef.h>
typedef struct Context { int (*consume)(void *userdata, const unsigned char *data, size_t size); void *userdata; } Context;
int parse(Context *ctx, const unsigned char *data, size_t size) { return ctx->consume(ctx->userdata, data, size); }
""",
    "nul_string": """#include <string.h>
int parse(const char *text) { return text[0] ? (int)strlen(text) : 0; }
""",
    "shared_context": """#include <stdlib.h>
#include <stddef.h>
typedef struct Context { const unsigned char *data; size_t size; } Context;
Context *create(void) { return calloc(1,sizeof(Context)); }
void destroy(Context *ctx) { free(ctx); }
void feed(Context *ctx, const unsigned char *data, size_t size) { ctx->data=data; ctx->size=size; }
int parse(Context *ctx) { return ctx->size ? ctx->data[0] : 0; }
void example(const unsigned char *data, size_t size) { Context *a=create(); Context *b=a; feed(b,data,size); parse(a); destroy(b); }
""",
}


def responses(root):
    events = {}
    for trace in root.glob("**/attempt_*/trace.json"):
        for event in json.loads(trace.read_text())["events"]:
            if event["kind"] == "model_response":
                events[event["metadata"]["response_id"]] = event["metadata"]
    for trace in (root / "candidate_discovery/agent_runs").glob("*/trace.json"):
        for event in json.loads(trace.read_text())["events"]:
            if event["kind"] == "model_response":
                events[event["metadata"]["response_id"]] = event["metadata"]
    for trace in (root / "semantic_slices").glob("*/trace.json"):
        for event in json.loads(trace.read_text())["events"]:
            if event["kind"] == "model_response":
                events[event["metadata"]["response_id"]] = event["metadata"]
    for response in (root / 'context_generations').glob('**/response.json'):
        record = json.loads(response.read_text())
        metadata = {**record.get('metadata', {}), 'response_id': record.get('response_id'),
                    'usage': record.get('usage', {}), 'served_model': record.get('model')}
        if metadata.get('response_id'):
            events[metadata['response_id']] = metadata
    return events


def evaluate(output, name, source, args):
    project, root = output / f"{name}_project", output / f"{name}_phase1"
    project.mkdir()
    (project / "api.c").write_text(source, encoding="utf-8")
    store = ArtifactStore(root)
    write_functions_json(CProjectParser().parse(project), store.functions, project=project)
    for path, field in ((store.annotations, "annotations"), (store.flows, "flows")):
        write_json(path, {"schema_version": 1, field: []})
    write_json(store.sfg, {"schema_version": 1, "nodes": [], "edges": [], "functions": []})
    anchor = next(f["id"] for f in load_sfg_artifacts(root).functions if f["name"] == "parse")
    base = ["--artifacts", str(root)]
    provider = ["--provider", args.provider, "--model", args.model, "--thinking", args.thinking]
    validation_options = [item for key, value in getattr(args, "validation_budget", {}).items() for item in ("--" + key.replace("_", "-"), str(value))]
    context_options = [item for key, value in getattr(args, "context_budget", {}).items() for item in ("--" + key.replace("_", "-"), str(value))]
    row = {"case": name, "project": str(project), "artifacts": str(root), "anchor": anchor,
           "category": "full_model_pipeline", "dataset_role": DATASET_ROLE, "blind_generalization_evidence": False,
           "source_kind": "synthetic_api_fixture", "static_analysis": "parser_only", "stage_exits": {},
           "slice_status": "not_run", "ft_status": "not_run", "plan_status": "not_run", "compile_success": False, "runtime_success": False}
    for command, options in (("candidates", []), ("candidate-validate", provider + validation_options + ["--candidate", anchor]),
                             ("semantic-slice", provider + validation_options + ["--candidate", anchor]), ("minimal-ft", [])):
        result = main([command, *base, *options])
        row["stage_exits"][command] = result
        if command == "semantic-slice":
            path = next(store.semantic_slices_directory.glob("*/slice.json"), None)
            if path:
                row["slice_status"] = json.loads(path.read_text())["run_status"]
        if command == "minimal-ft":
            path = next(store.minimal_fts_directory.glob("ft_*/minimal_ft.json"), None)
            if path:
                row["ft_status"] = json.loads(path.read_text())["build_status"]
        if result:
            row["status"] = f"{command}_failed"
            events = responses(root)
            row["actual_provider_responses"] = len(events)
            row["served_models"] = sorted({m["served_model"] for m in events.values()})
            row["response_tokens"] = {key: sum(m.get("usage", {}).get(key, 0) for m in events.values())
                                      for key in ("prompt_tokens", "completion_tokens", "total_tokens")}
            return row
    before = input_hashes(root)
    context_exit = main(["harness-context", *base, *provider, *context_options, "--requirement-mode", "grouped"])
    row["stage_exits"]["harness-context"] = context_exit
    ft_dirs = list(store.minimal_fts_directory.glob("ft_*"))
    if len(ft_dirs) != 1:
        raise ValueError("smoke expects one selected anchor FT")
    ft = json.loads((ft_dirs[0] / "minimal_ft.json").read_text())
    row["minimal_ft_size"] = len(ft["core_functions"]) + len(ft["support_candidates"])
    row["minimal_ft_core"] = [r["function"] for r in ft["core_functions"]]
    context_dir = root / "harness_contexts" / ft["ft_id"]
    row["context"] = json.loads((context_dir / "completeness.json").read_text())
    row["context_metrics"] = json.loads((context_dir / "metadata.json").read_text())["metrics"]
    row["closure_apis"] = json.loads((context_dir / "api_closure.json").read_text())["required_support_apis"]
    # Always exercise generation's gate, including blocked contexts.
    row["stage_exits"]["context-generate"] = main(["context-generate", *base, *provider, "--build", "--runtime"])
    marker = next((root / "context_generations").glob("*/*/*/metadata.json"), None)
    row["generation"] = json.loads(marker.read_text()) if marker else {"status": "blocked", "model_calls": 0}
    if marker:
        directory = marker.parent
        row["plan_status"] = "built" if (directory / "harness_plan.json").is_file() or (directory / "plan.json").is_file() else "not_built"
        response = directory / "response.json"
        if response.is_file():
            row["code_generation_response"] = {k: v for k, v in json.loads(response.read_text()).items() if k != "content"}
        build = directory / "build/build.json"
        replay = directory / "build/runtime.json"
        row["compile_success"] = build.is_file() and json.loads(build.read_text())["success"]
        row["runtime_success"] = replay.is_file() and json.loads(replay.read_text())["status"] == "passed"
        if row["generation"]["status"] == "passed":
            saved = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.rglob("*") if p.is_file()}
            row["stage_exits"]["generation-resume"] = main(["context-generate", *base, *provider, "--build", "--runtime", "--resume"])
            row["generation_resume_unchanged"] = all(saved[p] == (p.read_bytes(), p.stat().st_mtime_ns) for p in saved)
    row["upstream_unchanged"] = before == input_hashes(root)
    events = responses(root)
    row["actual_provider_responses"] = len(events)
    row["served_models"] = sorted({m["served_model"] for m in events.values()})
    row["response_tokens"] = {key: sum(m.get("usage", {}).get(key, 0) for m in events.values())
                              for key in ("prompt_tokens", "completion_tokens", "total_tokens")}
    row["status"] = row["generation"]["status"]
    return row


def smoke(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    parser.add_argument("--provider", choices=("deepseek", "openai-compatible"), default="openai-compatible")
    parser.add_argument("--model")
    parser.add_argument("--case", action="append", choices=tuple(CASES))
    parser.add_argument("--budget-file", type=Path, help="Explicit fixed validation/context limits for repeated experiments")
    args = parser.parse_args(argv)
    if args.budget_file:
        from harness_generation.semantic_discovery.models import ValidationBudget
        from harness_generation.harness_context.models import ContextBudget
        profile = json.loads(args.budget_file.read_text())
        args.validation_budget = ValidationBudget(**profile["validation"]).to_dict()
        args.context_budget = ContextBudget(**profile["context"]).to_dict()
    load_environment_file(args.env_file)
    cfg = agent_configuration(args.provider, model=args.model)
    args.model, args.thinking = cfg.model, cfg.thinking
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for name, source in CASES.items():
        if args.case and name not in args.case:
            continue
        print(f"[REAL PIPELINE] starting {name}", flush=True)
        rows.append(evaluate(args.output, name, source, args))
        summary = {"schema_version": 1, "timestamp": datetime.now(timezone.utc).isoformat(), "provider": cfg.to_dict(),
            "mock_fallback": False, "cross_project_evaluation": False, "dataset_role": DATASET_ROLE,
            "blind_generalization_evidence": False, "cases": rows,
            "passed_cases": sum(r["status"] == "passed" for r in rows)}
        write_json(args.output / "summary.json", summary, sort_keys=True, allow_nan=False)
        print(f"[REAL PIPELINE] {name}: {rows[-1]['status']}", flush=True)
    return int(any(row["status"] != "passed" for row in rows))


if __name__ == "__main__":
    raise SystemExit(smoke())
