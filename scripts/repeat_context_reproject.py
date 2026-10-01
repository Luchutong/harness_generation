#!/usr/bin/env python3
"""Paired framework replay of a completed native cohort; no upstream model calls.

Revalidate existing successful harnesses. Newly complete or previously failed
translations get one real code call, explicitly separate from the native cohort.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness_generation.records import write_json
from repeat_context_pipeline import CASE_NAMES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    args = parser.parse_args()
    baseline = json.loads((args.input / "summary.json").read_text())
    if baseline.get("completed_trials") != 5 * baseline["requested_repetitions"] or not baseline.get("implementation_unchanged"):
        raise ValueError("input must be a completed, unchanged native cohort")
    args.output = args.output.resolve();args.output.mkdir(parents=True, exist_ok=False)
    files = sorted(list((ROOT / "harness_generation").rglob("*.py")) + list((ROOT / "sfg_builder").rglob("*.py")))
    fingerprint = lambda: hashlib.sha256(b"".join(str(p.relative_to(ROOT)).encode() + p.read_bytes() for p in files)).hexdigest()
    metadata = {"category": "paired_recorded_evidence_framework_replay", "baseline": str(args.input.resolve()),
        "baseline_fingerprint": baseline["implementation_fingerprint"], "implementation_fingerprint": fingerprint(),
        "context_model_calls": 0, "upstream_model_calls": 0, "additional_code_calls_per_eligible_trial": 1,
        "raw_facts_unchanged": True, "native_repeated_current_implementation": False}
    def execute(old):
        name = f"{old['case']}_{old['trial']:02d}"
        phase = Path(old["artifacts"]) / (old["case"] + "_phase1")
        row = {"case": old["case"], "trial": old["trial"], "baseline_status": old["status"],
            "baseline_context_completion": old["context_completion"], "baseline_hard_gaps": old["hard_gaps"],
            "context_completion": False, "compile_success": False, "runtime_success": False,
            "context_model_calls": 0, "code_model_calls": 0, "code_tokens": 0}
        if not list(phase.glob("harness_contexts/*/metadata.json")):
            return {**row, "status": "upstream_failed_no_context", "hard_gaps": None}
        cmd = [sys.executable, str(ROOT / "scripts/smoke_context_reproject.py"), "--input", str(phase),
            "--output", str(args.output / name), "--env-file", str(args.env_file.resolve())]
        harnesses = list(phase.glob("context_generations/*/*/*/harness.cpp"))
        if old["runtime_success"] and len(harnesses) == 1:
            cmd += ["--harness", str(harnesses[0])]
            row["code_mode"] = "existing_harness_revalidation"
        else:
            cmd += ["--generate"]
            row["code_mode"] = "one_real_translation_if_complete"
        with (args.output / (name + ".log")).open("w") as stream:
            result = subprocess.run(cmd, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT)
        path = args.output / name / "reprojection_summary.json"
        if not path.is_file():
            return {**row, "status": "replay_process_failed", "exit": result.returncode, "hard_gaps": None}
        replay = json.loads(path.read_text());report = replay["completeness"]
        generation = replay.get("generation", {})
        markers = list((args.output / name).glob("context_generations/*/*/*/response.json"))
        usage = json.loads(markers[0].read_text()).get("usage", {}) if markers else {}
        return {**row, "status": generation.get("status", report["status"]), "exit": result.returncode,
            "context_completion": report["generation_allowed"], "hard_gaps": len(report["hard_missing"]),
            "hard_gap_codes": sorted({g["code"] for g in report["hard_missing"]}),
            "validation_errors": report["validation_errors"],
            "compile_success": (replay.get("compile") or {}).get("success", False),
            "runtime_success": (replay.get("runtime") or {}).get("status") == "passed",
            "code_model_calls": generation.get("model_calls", 0), "code_tokens": usage.get("total_tokens", 0)}
    rows = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(execute, old) for old in baseline["trials"]]
        for future in as_completed(jobs):
            rows.append(future.result());rows.sort(key=lambda r: (r["case"], r["trial"]))
            write_json(args.output / "summary.json", {**metadata, "trials": rows})
            row = future.result()
            print(f"[PAIRED {len(rows)}/{len(jobs)}] {row['case']}/{row['trial']} {row['status']} gaps={row['hard_gaps']}", flush=True)
    stats = {case: {key: sum(r[key] for r in rows if r["case"] == case) for key in
        ("context_completion", "compile_success", "runtime_success", "code_model_calls", "code_tokens")} for case in CASE_NAMES}
    write_json(args.output / "summary.json", {**metadata, "completed_trials": len(rows), "statistics": stats,
        "implementation_unchanged": fingerprint() == metadata["implementation_fingerprint"], "trials": rows})
    return int(fingerprint() != metadata["implementation_fingerprint"])


if __name__ == "__main__":
    raise SystemExit(main())
