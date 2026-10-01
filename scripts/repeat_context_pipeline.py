#!/usr/bin/env python3
"""Explicit independent, budget-matched native trials. Never imported by pytest."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness_generation.harness_context.models import ContextBudget
from harness_generation.semantic_discovery.models import ValidationBudget
from harness_generation.semantic_discovery.provider_config import agent_configuration, load_environment_file
from harness_generation.records import write_json
from smoke_context_pipeline import CASES, DATASET_ROLE

CASE_NAMES = ("direct", "nul_string", "shared_context", "owned_return", "callback")


def describe(values):
    return {"n": len(values), "mean": statistics.mean(values) if values else None,
            "median": statistics.median(values) if values else None,
            "min": min(values) if values else None, "max": max(values) if values else None}


def trial_metrics(root, case, trial, exit_code):
    summary_path = root / "summary.json"
    row = json.loads(summary_path.read_text())["cases"][0] if summary_path.is_file() else {"status": "process_failed"}
    metrics = {"case": case, "trial": trial, "category": "full_model_pipeline", "exit": exit_code,
        "artifacts": str(root), "status": row["status"], "slice_status": row.get("slice_status", "not_run"),
        "slice_success": row.get("slice_status") in {"completed", "completed_with_unresolved"},
        "ft_status": row.get("ft_status", "not_run"), "context_status": row.get("context", {}).get("status", "not_run"),
        "context_completion": row.get("context", {}).get("generation_allowed") is True,
        "hard_gaps": len(row["context"]["hard_missing"]) if "context" in row else None,
        "hard_gap_codes": sorted({g["code"] for g in row.get("context", {}).get("hard_missing", [])}),
        "compile_success": row.get("compile_success", False), "runtime_success": row.get("runtime_success", False),
        "context_metrics": row.get("context_metrics"), "served_models": row.get("served_models", []),
        "source_chars": row.get("context_metrics", {}).get("source_chars", 0), "stages": {}}
    phase = root / (case + "_phase1")
    for stage, pattern in (("candidate", "candidate_discovery/agent_runs/*/trace.json"), ("slice", "semantic_slices/*/trace.json")):
        files = list(phase.glob(pattern))
        events = json.loads(files[0].read_text())["events"] if files else []
        responses = [e for e in events if e["kind"] == "model_response"]
        metrics["stages"][stage] = {"model_calls": len(responses) + sum(e["kind"] == "model_error" for e in events),
            "tool_calls": sum(e["kind"] == "tool_call" for e in events),
            "tokens": sum(e["metadata"].get("usage", {}).get("total_tokens", 0) for e in responses)}
    ctx = row.get("context_metrics", {})
    metrics["stages"]["context"] = {"model_calls": ctx.get("model_calls", 0), "tool_calls": ctx.get("tool_calls", 0),
        "tokens": ctx.get("tokens", {}).get("total_tokens", 0)}
    code = row.get("code_generation_response", {}).get("usage", {})
    metrics["stages"]["code"] = {"model_calls": row.get("generation", {}).get("model_calls", 0), "tool_calls": 0,
        "tokens": code.get("total_tokens", 0)}
    for key in ("model_calls", "tool_calls", "tokens"):
        metrics[key] = sum(s[key] for s in metrics["stages"].values())
    metrics["provider_responses"] = row.get("actual_provider_responses", 0) + int(bool(code))
    return metrics


def summarize(rows):
    summaries = {}
    for name in CASE_NAMES:
        selected = [r for r in rows if r["case"] == name]
        summaries[name] = {"trials": len(selected), **{key: sum(r[key] for r in selected) for key in
            ("slice_success", "context_completion", "compile_success", "runtime_success")},
            **{key: describe([r[key] for r in selected if r[key] is not None]) for key in
               ("hard_gaps", "model_calls", "tool_calls", "tokens", "source_chars")},
            "context_calls": describe([r["stages"]["context"]["model_calls"] for r in selected]),
            "context_tokens": describe([r["stages"]["context"]["tokens"] for r in selected])}
    return summaries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    parser.add_argument("--repetitions", type=int, choices=range(5, 11), default=5)
    parser.add_argument("--workers", type=int, choices=(1, 2), default=2)
    args = parser.parse_args()
    load_environment_file(args.env_file)
    cfg = agent_configuration("openai-compatible")
    args.output = args.output.resolve();args.output.mkdir(parents=True, exist_ok=False)
    budget = {"validation": ValidationBudget().to_dict(), "context": ContextBudget().to_dict()}
    write_json(args.output / "budgets.json", budget)
    files = list((ROOT / "harness_generation").rglob("*.py")) + list((ROOT / "sfg_builder").rglob("*.py"))
    implementation = hashlib.sha256(b"".join(str(p.relative_to(ROOT)).encode() + p.read_bytes() for p in sorted(files))).hexdigest()
    metadata = {"schema_version": 1, "category": "full_model_pipeline", "source_kind": "synthetic_api_fixture",
        "dataset_role": DATASET_ROLE, "blind_generalization_evidence": False,
        "explicit_parse_anchor": True, "candidate_recall_evaluation": False, "cross_project_evaluation": False,
        "started_at": datetime.now(timezone.utc).isoformat(), "provider": cfg.to_dict(), "budgets": budget,
        "implementation_fingerprint": implementation, "requested_repetitions": args.repetitions,
        "workers": args.workers, "fresh_upstream_per_trial": True, "retry_failed_trials": False,
        "generation_max_tokens": 8192, "agent_temperature": "provider default (not specified)",
        "random_seed": "not supported/unspecified", "source_digests": {n: hashlib.sha256(CASES[n].encode()).hexdigest() for n in CASE_NAMES}}
    rows = []
    def execute(name, number):
        root = args.output / f"{name}_{number:02d}"
        log = args.output / f"{name}_{number:02d}.log"
        with log.open("w") as stream:
            run = subprocess.run([sys.executable, str(ROOT / "scripts/smoke_context_pipeline.py"), "--output", str(root),
                "--case", name, "--env-file", str(args.env_file.resolve()), "--budget-file", str(args.output / "budgets.json")],
                cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
        return trial_metrics(root, name, number, run.returncode)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        jobs = {pool.submit(execute, name, number): (name, number) for number in range(1, args.repetitions + 1) for name in CASE_NAMES}
        for future in as_completed(jobs):
            name, number = jobs[future]
            try:
                row = future.result()
            except Exception as error:
                row = {"case": name, "trial": number, "status": "runner_error", "error_type": type(error).__name__,
                       "slice_success": False, "context_completion": False, "compile_success": False, "runtime_success": False,
                       "hard_gaps": None, "model_calls": 0, "tool_calls": 0, "tokens": 0, "source_chars": 0,
                       "stages": {"context": {"model_calls": 0, "tokens": 0}}}
            rows.append(row);rows.sort(key=lambda r: (r["case"], r["trial"]))
            write_json(args.output / "summary.json", {**metadata, "completed_trials": len(rows), "trials": rows, "statistics": summarize(rows)})
            print(f"[REPEAT {len(rows)}/{len(jobs)}] {name}/{number} {row['status']} slice={row['slice_success']} context={row['context_completion']} gaps={row['hard_gaps']} calls={row['model_calls']} tokens={row['tokens']}", flush=True)
    current = hashlib.sha256(b"".join(str(p.relative_to(ROOT)).encode() + p.read_bytes() for p in sorted(files))).hexdigest()
    write_json(args.output / "summary.json", {**metadata, "completed_at": datetime.now(timezone.utc).isoformat(),
        "implementation_unchanged": current == implementation, "completed_trials": len(rows), "trials": rows, "statistics": summarize(rows)})
    return int(current != implementation or len(rows) != len(CASE_NAMES) * args.repetitions)


if __name__ == "__main__":
    raise SystemExit(main())
