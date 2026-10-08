#!/usr/bin/env python3
"""Small development comparison of native proof acquisition, with fixed caps.

Only Context requirement investigation is measured. FT preparation is an
explicit offline fixture; this is neither blind nor an end-to-end model cohort.
Run each arm in its own source snapshot. No provider retry or mock fallback.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
CASES = {
    "owned_return_cleanup": {"kind": "ownership", "source": '''#include <stdlib.h>
#include <stddef.h>
typedef struct Item { unsigned value; } Item;
Item *parse(const unsigned char *data, size_t size) { Item *p=malloc(sizeof(Item)); if(p) p->value=size?data[0]:0; return p; }
void finish(Item *p) { free(p); }
''', "expected": "owned_return_release"},
    "shared_field_initializer": {"kind": "state", "source": '''#include <stdlib.h>
#include <stddef.h>
typedef struct Box { unsigned ready; unsigned bias; } Box;
Box *make(void) { return calloc(1,sizeof(Box)); }
void prime(Box *box) { box->ready=1; box->bias=0; }
void finish(Box *box) { free(box); }
int parse(Box *box,const unsigned char *data,size_t size) { if(box->ready!=1) __builtin_trap(); return size?data[0]^box->bias:0; }
''', "expected": "same_subject_initializer"},
    "callback_userdata_borrow": {"kind": "ownership", "source": '''#include <stddef.h>
typedef struct User { unsigned bias; } User;
typedef int (*Callback)(void *user,const unsigned char *data,size_t size);
int parse(void *user,const unsigned char *data,size_t size) { User *u=user; return size?data[0]^u->bias:u->bias; }
''', "expected": "borrowed_userdata_and_retained_buffer"},
    "wrong_field_initializer": {"kind": "state", "source": '''#include <stddef.h>
typedef struct Box { unsigned ready; unsigned other; } Box;
void prime(Box *box) { box->other=1; }
int parse(Box *box,const unsigned char *data,size_t size) { if(box->ready!=1) __builtin_trap(); return size?data[0]:0; }
''', "expected": "unresolved_missing_ready_writer"},
}


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    tmp.replace(path)


def source_hashes(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for name in ("harness_generation", "sfg_builder") for p in sorted((root / name).rglob("*.py"))}


def worker(args):
    implementation = args.implementation.resolve()
    sys.path[:0] = [str(implementation), str(implementation / "tests")]
    from harness_generation.harness_context import HarnessRequirementBuilder, ContextBudget
    from harness_generation.harness_context.agent import HarnessContextAgent
    from harness_generation.harness_context.models import fact_id
    from harness_generation.semantic_discovery.models import canonical, digest
    from harness_generation.semantic_discovery.persistence import save_run_documents
    from harness_generation.semantic_discovery.provider_config import load_environment_file, agent_configuration, native_agent_model
    from test_harness_context import setup, owner

    case = CASES[args.case]
    args.output.mkdir(parents=True, exist_ok=True)
    work = args.output / "fixture"
    work.mkdir()
    budget = ContextBudget(max_total_model_calls=4, max_tool_calls=12, max_source_chars=24000)
    prepared = setup(work, case["source"], budget=budget)
    ft, snapshot, state, tools = prepared[1], prepared[3], prepared[4], prepared[5]
    requirement = next(r for r in HarnessRequirementBuilder().build(ft, snapshot)["requirements"] if r["kind"] == case["kind"])
    tools.activate(requirement)
    subject_source = tools.bootstrap()
    facts = []
    if args.case == "callback_userdata_borrow":
        from harness_generation.harness_context.proposals import ownership_subject
        entry = owner("data")
        subject = ownership_subject(entry, requirement["subject_function_id"], snapshot)
        entry.update({k: subject[k] for k in ("subject_id", "subject_kind")})
        fact = {"requirement_id": requirement["requirement_id"], "function_id": requirement["subject_function_id"],
            "predicate": "ownership", "value": {"entries": [entry]}, "evidence_ids": subject_source["evidence_ids"]}
        fact["fact_id"] = fact_id(fact)
        facts = [fact]
    if args.case == "wrong_field_initializer":
        tools.execute("find_initializers", {"type": "Box"})
        tools.execute("get_function", {"function": prepared[0][-1]["prime"]})
    seeded_tools, seeded_chars = state.tool_calls, state.source_chars
    task = {"task_id": "development_" + args.case, "requirement_id": requirement["requirement_id"],
        "kind": case["kind"], "subject_function_id": requirement["subject_function_id"],
        "blocked_roots": ["development_root"], "graph_holes": [],
        "question": requirement["question"], "missing_proofs": [{"predicate": case["kind"],
            "subject_parameter": "user" if args.case == "callback_userdata_borrow" else "box" if case["kind"] == "state" else None,
            "diagnostics": []}]}
    load_environment_file(args.env_file)
    provider = "openai-compatible" if os.environ.get("LLM_API_KEY", "").strip() else "deepseek"
    config = agent_configuration(provider)
    model = native_agent_model(config)
    started = time.monotonic()
    run = HarnessContextAgent(model, state).investigate(requirement, tools, facts, [task])
    elapsed = time.monotonic() - started
    entries = [e for f in run.result["facts"] for e in f["value"].get("entries", [])]
    conditions = [c for f in run.result["facts"] for c in f["value"].get("preconditions", [])]
    returned = [e for e in entries if e["return_value"]]
    if args.case == "owned_return_cleanup":
        correct = run.result["status"] == "resolved" and any(e["ownership"] == "owned" and e["release_api"] == prepared[0][-1]["finish"] for e in returned)
    elif args.case == "shared_field_initializer":
        correct = run.result["status"] == "resolved" and any(c["parameter"] == "box" and c["kind"] == "initialized" and c["api"] == prepared[0][-1]["prime"] for c in conditions)
    elif args.case == "callback_userdata_borrow":
        correct = run.result["status"] == "resolved" and all(any(e["parameter"] == p and e["ownership"] == "borrowed" and e["release_api"] is None and e["lifetime"] == "during_call" for e in entries) for p in ("data", "user"))
    else:
        correct = run.result["status"] == "unresolved" and bool(run.result["open_questions"])
    responses = [e for e in run.trace["events"] if e["kind"] == "model_response"]
    model_errors = [e for e in run.trace["events"] if e["kind"] == "model_error"]
    configuration = {"purpose": "targeted_requirement_development", "native": True,
        "budget": budget.to_dict(), "model": config.to_dict(), "case": args.case}
    save_run_documents(args.output / "agent", run, configuration)
    row = {"arm": args.arm, "case": args.case, "expected": case["expected"], "status": run.result["status"],
        "correct_proof_outcome": correct and not model_errors and bool(responses) and run.metadata["termination"] == "final_decision",
        "termination": run.metadata["termination"], "minimal_ft_digest": digest(ft),
        "model_calls": state.model_calls, "tool_calls": state.tool_calls,
        "seed_tool_calls": seeded_tools, "seed_source_chars": seeded_chars,
        "source_chars": state.source_chars, "tokens": state.tokens, "elapsed_seconds": round(elapsed, 3),
        "native_responses": len(responses), "execution_errors": model_errors,
        "provider_errors": [e for e in model_errors if e.get("error_category") != "budget_exhausted"],
        "served_models": sorted({e.get("metadata", {}).get("served_model", "unknown") for e in responses}),
        "budget": budget.to_dict(), "registered_tools": sorted(s["function"]["name"] for s in tools.schemas),
        "source_sha256": hashlib.sha256(case["source"].encode()).hexdigest(),
        "open_questions": run.result["open_questions"], "schema_repair_attempted": run.metadata.get("schema_repair_attempted", False),
        "schema_repair_success": run.metadata.get("schema_repair_success", False),
        "proof_investigation": run.metadata.get("proof_investigation"),
        "compile_runtime_measured": False, "blind_experiment": False}
    write(args.output / "trial.json", row)
    print(json.dumps({k: row[k] for k in ("arm", "case", "status", "correct_proof_outcome", "model_calls", "tool_calls", "native_responses")}), flush=True)
    return 0


def coordinator(args):
    roots = {"baseline": args.baseline.resolve(), "revision": args.revision.resolve()}
    hashes = {arm: source_hashes(root) for arm, root in roots.items()}
    cases = args.cases or list(CASES)
    schedule = [{"case": case, "arm": arm} for i, case in enumerate(cases)
        for arm in (("baseline", "revision") if i % 2 == 0 else ("revision", "baseline"))]
    registration = {"purpose": "fixed_budget_targeted_agent_development", "blind_experiment": False,
        "upstream_model_measured": False, "compile_runtime_measured": False, "planned_trials": len(schedule),
        "schedule": schedule, "source_snapshots": {a: str(r) for a, r in roots.items()}, "source_hashes": hashes,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "case_sha256": {name: hashlib.sha256(CASES[name]["source"].encode()).hexdigest() for name in cases},
        "stopping_rules": ["no retry or mock fallback", "preserve every scheduled outcome", "stop on source mutation", "stop on authentication failure"]}
    args.output.mkdir(parents=True, exist_ok=True)
    write(args.output / "registration.json", registration)
    rows = []
    for number, trial in enumerate(schedule):
        if any(source_hashes(root) != hashes[arm] for arm, root in roots.items()):
            raise RuntimeError("source snapshot changed")
        target = args.output / (str(number + 1).zfill(2) + "_" + trial["case"] + "_" + trial["arm"])
        command = [sys.executable, str(Path(__file__).resolve()), "--worker", "--implementation", str(roots[trial["arm"]]),
            "--arm", trial["arm"], "--case", trial["case"], "--env-file", str(args.env_file.resolve()), "--output", str(target.resolve())]
        with (args.output / (target.name + ".log")).open("w") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        if (target / "trial.json").is_file():
            row = json.loads((target / "trial.json").read_text())
        else:
            row = {**trial, "correct_proof_outcome": False, "worker_exit": result.returncode, "worker_error": True}
        rows.append(row)
        print(json.dumps({k: row.get(k) for k in ("arm", "case", "status", "correct_proof_outcome", "model_calls", "native_responses")}), flush=True)
        write(args.output / "summary.json", {"registration": registration, "completed": len(rows) == len(schedule), "trials": rows})
        if any(e.get("http_status") in {401, 403} for e in row.get("provider_errors", [])):
            break
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--implementation", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--revision", type=Path)
    parser.add_argument("--arm")
    parser.add_argument("--case", choices=tuple(CASES))
    parser.add_argument("--cases", nargs="+", choices=tuple(CASES))
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    return worker(args) if args.worker else coordinator(args)


if __name__ == "__main__":
    raise SystemExit(main())
