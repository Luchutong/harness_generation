#!/usr/bin/env python3
"""Real DeepSeek context smoke; no mock provider fallback and no generation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness_generation.artifacts import ArtifactStore
from harness_generation.entry_candidates import CandidateCatalog
from harness_generation.harness_context.cli import main as context_cli
from harness_generation.minimal_ft.cli import main as minimal_cli
from harness_generation.minimal_ft.models import ProjectSnapshot
from harness_generation.records import write_json
from harness_generation.semantic_discovery.models import candidate_id, digest
from harness_generation.semantic_discovery.tools import RepositoryTools, RepositoryIndex
from harness_generation.semantic_slicing.models import SLICE_POLICY_VERSION
from harness_generation.sfg_adapter import load_sfg_artifacts
from sfg_builder.parser import CProjectParser, write_functions_json

OWNED = """typedef unsigned long size_t;
typedef struct Node { int value; } Node;
Node *parse(const unsigned char *data, size_t size) { Node *node = malloc(sizeof(Node)); if (node) node->value = size ? data[0] : 0; return node; }
void node_release(Node *node) { free(node); }
"""
EXTERNAL = """typedef unsigned long size_t;
typedef struct Context { int ready; int calls; } Context;
static int initialized = 0;
Context *context_create(void) { Context *ctx = calloc(1, sizeof(Context)); if (ctx) { ctx->ready = 1; initialized = 1; } return ctx; }
void context_release(Context *ctx) { free(ctx); }
int parse(Context *ctx, const unsigned char *data, size_t size) { if (!initialized || !ctx->ready) return -1; ctx->calls++; return size ? data[0] : 0; }
"""


def load_environment(path):
    if path.exists():
        # Reuse the existing explicit LLM_* -> DeepSeek credential mapping;
        # values never enter logs, artifacts or configuration fingerprints.
        from evaluate_candidate_validation_real import credential_environment
        for name, value in credential_environment(path).items():
            os.environ.setdefault(name, value)


def prepare_fixture(output, name, source):
    """Explicit hand-selected upstream fixture, never presented as real Slice mining."""
    project, root = output / f"{name}_project", output / f"{name}_phase1"
    if root.exists():
        return root
    project.mkdir(parents=True)
    (project / "api.c").write_text(source, encoding="utf-8")
    root.mkdir(parents=True)
    store = ArtifactStore(root)
    write_functions_json(CProjectParser().parse(project), store.functions, project=project)
    for path, field in ((store.annotations, "annotations"), (store.flows, "flows")):
        write_json(path, {"schema_version": 1, field: []})
    write_json(store.sfg, {"schema_version": 1, "nodes": [], "edges": [], "functions": []})
    artifacts = load_sfg_artifacts(root)
    snapshot = ProjectSnapshot.from_artifacts(artifacts)
    function = next(f for f in artifacts.functions if f["name"] == "parse")
    catalog = CandidateCatalog((), snapshot.source_fingerprint)
    tools = RepositoryTools(artifacts, catalog, index=RepositoryIndex(artifacts, catalog, functions_path=store.functions))
    proof = tools.execute("get_function", {"function": function["id"]})
    cid = candidate_id(function["id"])
    doc = {"schema_version": 1, "artifact_kind": "semantic_slice", "policy_version": SLICE_POLICY_VERSION,
        "candidate_id": cid, "anchor_function_id": function["id"], "anchor_function": function["name"],
        "classification": [{"function_id": function["id"], "function": function["name"], "role": "core",
            "reason_codes": ["accepted_anchor"], "evidence_ids": proof["evidence_ids"], "open_questions": []}],
        "core_functions": [function["id"]], "support_functions": [], "excluded_functions": [], "unresolved_frontier": [],
        "budget": {"exhausted": False}, "model": {"provider": "hand-selected-fixture", "model": "no-upstream-model"}, "run_status": "completed"}
    evidence = {"schema_version": 1, "records": proof["evidence"]}
    trace = {"schema_version": 1, "events": [{"kind": "tool_call", "tool": "get_function", "result_evidence_ids": proof["evidence_ids"]}]}
    config = {"policy_version": SLICE_POLICY_VERSION, "source_fingerprint": snapshot.source_fingerprint,
              "fixture_preparation": "manual_single_core_anchor"}
    metadata = {"source_fingerprint": snapshot.source_fingerprint, "candidate_id": cid, "anchor_function_id": function["id"],
        "initial_frontier_ids": [function["id"]], "discovered_function_ids": [], "configuration": config,
        "configuration_fingerprint": digest(config), "document_digests": {"slice": digest(doc), "evidence": digest(evidence), "trace": digest(trace)}}
    directory = store.semantic_slice_run(cid)
    directory.mkdir(parents=True)
    for key, value in (("slice", doc), ("evidence", evidence), ("trace", trace), ("metadata", metadata)):
        write_json(directory / f"{key}.json", value, sort_keys=True, allow_nan=False)
    if minimal_cli(["--artifacts", str(root)]) != 0:
        raise ValueError("invalid explicit upstream fixture")
    return root


def input_hashes(root):
    result = {}
    for path in root.rglob("*.json"):
        relative = path.relative_to(root)
        if relative.parts[0] == "harness_contexts":
            continue
        result[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def evaluate(case, root, args):
    before = input_hashes(root)
    command = ["--artifacts", str(root), "--model", args.model, "--thinking", "disabled",
               "--max-total-model-calls", str(args.max_total_model_calls)]
    print(f"[REAL CONTEXT] starting {case}", flush=True)
    build_exit = context_cli(command + (["--resume"] if args.resume else []))
    directories = [p for p in (root / "harness_contexts").iterdir() if p.is_dir()]
    assert len(directories) == 1
    directory = directories[0]
    documents = {name: json.loads((directory / f"{name}.json").read_text(encoding="utf-8"))
                 for name in ("metadata", "harness_context", "api_closure", "completeness")}
    metadata, context, closure, completeness = (documents[name] for name in ("metadata", "harness_context", "api_closure", "completeness"))
    traces = []
    for path in directory.glob("agent_runs/*/attempt_*/trace.json"):
        attempt_metadata = json.loads((path.parent / "metadata.json").read_text(encoding="utf-8"))
        if attempt_metadata.get("execution_index") == metadata.get("execution_index"):
            traces.append(json.loads(path.read_text(encoding="utf-8")))
    actual_responses = [event for trace in traces for event in trace["events"] if event["kind"] == "model_response"]
    usage = {key: sum(event.get("metadata", {}).get("usage", {}).get(key, 0) for event in actual_responses)
             for key in ("prompt_tokens", "completion_tokens", "total_tokens")}
    row = {"case": case, "input_artifacts": str(root), "context_artifacts": str(directory), "build_exit": build_exit,
        "status": completeness["status"], "frozen": context["frozen"], "metrics": metadata["metrics"],
        "served_models": sorted({event["metadata"].get("served_model", "unknown") for event in actual_responses}),
        "actual_provider_responses": len(actual_responses), "actual_response_tokens": usage,
        "hard_missing": completeness["hard_missing"], "validation_errors": completeness["validation_errors"],
        "required_support": [r["function_id"] for r in closure["required_support_apis"]],
        "optional_support": [r["function_id"] for r in closure["optional_support_apis"]],
        "input_bindings": context["input_contract"]["bindings"], "upstream_unchanged": before == input_hashes(root),
        "model_configuration": metadata["configuration"]["model"], "termination": metadata["termination"]}
    if completeness["status"] == "complete":
        saved = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.rglob("*.json")}
        row["resume_exit"] = context_cli(command + ["--resume"])
        row["resume_unchanged"] = all(saved[p] == (p.read_bytes(), p.stat().st_mtime_ns) for p in saved)
    row["audit_passed"] = (row["upstream_unchanged"] and bool(actual_responses) and usage["total_tokens"] > 0
        and metadata["configuration"]["model"]["provider"] == "deepseek"
        and completeness["status"] in {"complete", "incomplete"})
    print(f"[REAL CONTEXT] {case}: {row['status']} hard_missing={len(row['hard_missing'])} "
          f"responses={len(actual_responses)} audit={row['audit_passed']}", flush=True)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slices", type=Path, default=ROOT / "artifacts/semantic_slice_real_20260928_03")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/harness_context_real_20260928_01")
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    parser.add_argument("--model", default="deepseek-flash")
    parser.add_argument("--max-total-model-calls", type=int, default=24)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--case", action="append", default=[])
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    try:
        load_environment(args.env_file)
    except (OSError, ValueError):
        write_json(args.output / "summary.json", {"real_smoke": "skipped", "reason": "credential_configuration_unavailable", "mock_fallback": False})
        print("Real DeepSeek smoke skipped: credential configuration unavailable. No mock fallback.")
        return 2
    if not os.environ.get("DEEPSEEK_API_KEY", "").strip():
        write_json(args.output / "summary.json", {"real_smoke": "skipped", "reason": "missing_deepseek_api_key", "mock_fallback": False})
        print("Real DeepSeek smoke skipped: missing API key. No mock fallback.")
        return 2
    cases = [("direct_parser", args.slices / "direct_phase1"), ("context_lifecycle", args.slices / "hub_phase1"),
             ("json_parser", args.slices / "json_phase1"), ("wrapper_fixture", args.slices / "fixture_phase1")]
    if not args.case or "owned_return_cleanup" in args.case:
        cases.append(("owned_return_cleanup", prepare_fixture(args.output, "owned", OWNED)))
    if not args.case or "ft_external_required_support" in args.case:
        cases.append(("ft_external_required_support", prepare_fixture(args.output, "external_required", EXTERNAL)))
    if args.case:
        cases = [(case, root) for case, root in cases if case in args.case]
    if not cases:
        parser.error("unknown --case")
    rows = []
    for case, root in cases:
        rows.append(evaluate(case, root, args))
        write_json(args.output / "summary.json", {"schema_version": 1, "provider": "deepseek", "mock_fallback": False,
            "cases": rows, "audit_passed": all(row["audit_passed"] for row in rows),
            "complete_cases": sum(row["status"] == "complete" for row in rows), "incomplete_cases": sum(row["status"] == "incomplete" for row in rows)},
            sort_keys=True, allow_nan=False)
    return 0 if all(row["audit_passed"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
