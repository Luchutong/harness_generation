"""Sequential independent sampling, provenance and accounting; no search yet."""

from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import os
import sys
import time

from .candidate import run_candidate
from .config import CandidateConfig
from .records import write_json
from .evaluation import EvaluationEngine


def run_experiment(config: CandidateConfig, original: bytes, count: int,
                   existing_code: str | None = None, *,
                   evaluation_engine: EvaluationEngine | None = None) -> int:
    entries = [{"candidate_id": (f"{config.parent_id}.r{config.round_index}.candidate_{i:04d}"
                                 if config.revision else f"candidate_{i:04d}"), "parent_id": config.parent_id,
                "round_index": config.round_index,
                "directory": "." if count == 1 else f"candidates/candidate_{i:04d}",
                "status": "not_started"} for i in range(1, count + 1)]
    summary = {
        "schema_version": 2, "strategy": "feedback_revision" if config.revision else "independent_sampling",
        "parent_directory": str(config.revision.parent_directory) if config.revision else None,
        "round_index": config.round_index,
        "started_at": datetime.now(timezone.utc).isoformat(), "status": "running",
        "requested_candidates": count, "model": None if config.harness else config.model,
        "temperature": config.temperature, "generate_only": config.generate_only,
        "fuzz_seconds_per_candidate": config.fuzz_seconds,
        "smoke_test": bool(config.smoke_test or config.fuzz_seconds),
        "source_sha256": hashlib.sha256(original).hexdigest(), "function": config.function,
        "candidates": entries,
    }
    started = time.monotonic()
    seen = {}
    analysis_cache = {}
    usage = {key: 0 for key in ("prompt_tokens", "completion_tokens", "total_tokens")}
    exit_code = 1

    def save():
        summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
        summary["completed_candidates"] = sum(e["status"] in ("passed", "failed") for e in entries)
        summary["generated_candidates"] = sum(e.get("generation") == "passed" for e in entries)
        summary["unique_harnesses"] = len(seen)
        summary["api_attempts"] = sum(e.get("api_attempts", 0) for e in entries)
        summary["reported_usage_totals"] = usage
        summary["usage_missing_candidates"] = [e["candidate_id"] for e in entries
                                                  if e.get("api_attempted") and not e.get("usage_reported")]
        summary["usage_missing_isf_classification"] = [
            e["candidate_id"] for e in entries
            if e.get("isf_classification", {}).get("api_attempts", 0)
            and e["isf_classification"].get("usage") is None
        ]
        write_json(config.output / "experiment.json", summary)

    try:
        save()
        # Keep the single-candidate failure record behavior. For a batch, fail
        # once at setup instead of creating N identical missing-key failures.
        if count > 1 and not os.environ.get("DEEPSEEK_API_KEY", "").strip():
            summary.update(status="failed", error="DEEPSEEK_API_KEY is missing; no requests made")
            print(summary["error"], file=sys.stderr)
            return 1
        for entry in entries:
            output = config.output / entry["directory"]
            if count > 1:
                output.mkdir(parents=True, exist_ok=False)
            entry["status"] = "running"
            save()
            candidate_config = replace(config, output=output, candidate_id=entry["candidate_id"])
            result, code = run_candidate(candidate_config, original, existing_code,
                                         evaluation_engine=evaluation_engine,
                                         analysis_cache=analysis_cache)
            entry.update(status="passed" if code == 0 else "interrupted" if code == 130 else "failed",
                         generation=result["generation"], compilation=result["compilation"]["status"],
                         smoke=result["smoke"]["status"],
                         fuzzing=result["fuzzing"]["status"], exit_code=code,
                         api_attempted="api_elapsed_seconds" in result,
                         api_attempts=result.get("api_attempts", 0))
            entry["evaluation"] = result["evaluation"]
            entry["isf_classification"] = result.get("isf_classification")
            reported = result.get("usage")
            entry["usage_reported"] = isinstance(reported, dict) and all(
                isinstance(reported.get(key), int) and not isinstance(reported.get(key), bool)
                and reported[key] >= 0 for key in usage)
            if entry["usage_reported"]:
                for key in usage:
                    usage[key] += reported[key]
            classification_usage = result.get("isf_classification", {}).get("usage")
            if isinstance(classification_usage, dict) and all(
                    type(classification_usage.get(key)) is int and classification_usage[key] >= 0
                    for key in usage):
                for key in usage:
                    usage[key] += classification_usage[key]
            digest = result.get("harness_sha256")
            if digest:
                entry["harness_sha256"] = digest
                entry["duplicate_of"] = seen.get(digest)
                seen.setdefault(digest, entry["candidate_id"])
            save()
            if code == 130:
                summary["status"] = "interrupted"
                exit_code = 130
                break
            if result.get("http_status") in (401, 403):
                summary.update(status="failed", error="Authentication/authorization failed; remaining candidates not started")
                break
        else:
            exit_code = 0 if all(e["status"] == "passed" for e in entries) else 1
            summary["status"] = "completed" if exit_code == 0 else "partial_failure"
    except KeyboardInterrupt:
        summary["status"] = "interrupted"
        for entry in entries:
            if entry["status"] == "running":
                entry["status"] = "interrupted"
        exit_code = 130
    except OSError as exc:
        summary.update(status="failed", error=str(exc))
        for entry in entries:
            if entry["status"] == "running":
                entry["status"] = "failed"
        raise
    finally:
        save()
    print(f"experiment={summary['status']} generated={summary['generated_candidates']}/{count} "
          f"unique={summary['unique_harnesses']} output={config.output}")
    return exit_code
