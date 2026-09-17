"""Compile -> smoke -> short fuzz; collect raw metrics even after failure."""

from copy import deepcopy
import time

from .config import CandidateConfig
from .core import compile_harness
from .fuzz import run_fuzzer
from .records import write_json
from .smoke import run_smoke


def execute_pipeline(config: CandidateConfig, result: dict) -> int:
    stage = "compilation"
    try:
        started = time.monotonic()
        result["compilation"] = compile_harness(config.output)
        result["compile_elapsed_seconds"] = round(time.monotonic() - started, 3)
        write_json(config.output / "compile_result.json", {
            **result["compilation"], "elapsed_seconds": result["compile_elapsed_seconds"],
        })
        if result["compilation"]["status"] != "passed":
            result.update(failure_stage=stage, error="Compilation failed; see compile_stderr.txt")
            if config.smoke_test or config.fuzz_seconds:
                result["smoke"] = {"status": "blocked", "reason": "compilation_not_passed"}
            if config.fuzz_seconds:
                result["fuzzing"] = {"status": "blocked", "reason": "compilation_not_passed"}
            return 1
        if config.smoke_test or config.fuzz_seconds:
            stage = "smoke"
            result["smoke"] = run_smoke(config.output)
            if _stage_result_is_accepted_target_finding(result["smoke"]):
                result["smoke"]["accepted"] = True
                result["smoke"]["acceptance_reason"] = (
                    "sanitizer/libFuzzer finding is attributed to target code"
                )
                if config.fuzz_seconds:
                    result["fuzzing"] = {
                        "status": "blocked",
                        "reason": "target_finding_observed_during_smoke",
                    }
                return 0
            if result["smoke"]["status"] != "passed":
                result.update(failure_stage=stage, error="Smoke test did not pass; see smoke_result.json")
                if config.fuzz_seconds:
                    result["fuzzing"] = {"status": "blocked", "reason": "smoke_not_passed"}
                return 130 if result["smoke"]["status"] == "interrupted" else 1
        if config.fuzz_seconds:
            stage = "fuzzing"
            result["fuzzing"] = run_fuzzer(config.output, config.fuzz_seconds, config.corpus)
            if _fuzz_result_is_accepted_target_finding(result["fuzzing"]):
                result["fuzzing"]["accepted"] = True
                result["fuzzing"]["acceptance_reason"] = (
                    "sanitizer/libFuzzer finding is attributed to target code"
                )
            elif result["fuzzing"]["status"] != "completed":
                result.update(failure_stage=stage, error="Short fuzz run did not complete; see fuzz_result.json")
                return 130 if result["fuzzing"]["status"] == "interrupted" else 1
        return 0
    except KeyboardInterrupt:
        result[stage] = {"status": "interrupted"}
        result.update(failure_stage=stage, error="Execution interrupted")
        if stage != "fuzzing" and config.fuzz_seconds:
            result["fuzzing"] = {"status": "blocked", "reason": f"{stage}_interrupted"}
        return 130
    except OSError:
        result[stage] = {"status": "error"}
        result["failure_stage"] = stage
        if stage == "compilation" and (config.smoke_test or config.fuzz_seconds):
            result["smoke"] = {"status": "blocked", "reason": "compilation_error"}
        if stage != "fuzzing" and config.fuzz_seconds:
            result["fuzzing"] = {"status": "blocked", "reason": f"{stage}_error"}
        raise


def collect_metrics(result: dict) -> dict:
    """Keep engine-level measurements separate from target quality scores."""
    measurements = []

    def add(name, value, unit, scope, evidence):
        if value is not None:
            measurements.append({"name": name, "value": value, "unit": unit,
                                 "scope": scope, "evidence": evidence})

    add("compile_time", result.get("compile_elapsed_seconds"), "seconds", "build", "compile_result.json")
    smoke = result.get("smoke", {})
    for name in ("requested_cases", "attempted_cases", "completed_cases"):
        add(f"smoke_{name}", smoke.get(name), "cases", "fixed_input_replay", "smoke_result.json")
    add("smoke_time", smoke.get("elapsed_seconds"), "seconds", "processes_including_startup", "smoke_result.json")
    fuzz = result.get("fuzzing", {})
    stats = fuzz.get("statistics", {})
    for key, unit in (("number_of_executed_units", "executions"), ("average_exec_per_sec", "executions/second"),
                      ("coverage_edges_or_blocks", "edges_or_blocks"), ("features", "features"),
                      ("new_units_added", "corpus_units"),
                      ("peak_rss_mb", "MiB")):
        add(f"fuzzer_{key}", stats.get(key), unit, "instrumented_program", "fuzz_result.json")
    add("fuzz_wall_time", fuzz.get("elapsed_seconds"), "seconds", "process_including_startup", "fuzz_result.json")
    return {
        "schema_version": 1, "candidate_id": result["candidate_id"],
        "source_sha256": result["source_sha256"], "harness_sha256": result.get("harness_sha256"),
        "status": "collected" if measurements else "unavailable",
        "stages": {name: deepcopy(result.get(name, {"status": "not_started"}))
                   for name in ("compilation", "smoke", "fuzzing")},
        "measurements": measurements,
        "limitations": ["Smoke completion is not target API reachability.",
                        "Engine cov/ft includes harness and instrumentation; it is not target source coverage.",
                        "Engine execution rate is not isolated target-call latency.",
                        "Fresh-process smoke checks do not measure determinism or state reset.",
                        "Findings enter scoring only after target-versus-harness attribution; target findings are triage signals, not exploit classifications."],
    }


def _fuzz_result_is_accepted_target_finding(fuzzing: dict) -> bool:
    return _stage_result_is_accepted_target_finding(fuzzing)


def _stage_result_is_accepted_target_finding(stage_result: dict) -> bool:
    if stage_result.get("status") != "finding":
        return False
    classification = stage_result.get("crash_classification")
    if not isinstance(classification, dict):
        return False
    return classification.get("classification") == "potential_target_crash"
