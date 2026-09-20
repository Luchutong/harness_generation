"""Attempt-level Stage 4 outcome, including validation after code generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .records import write_json
from .validation import ValidationResult


STAGE4_OUTCOME_SCHEMA_VERSION = 1


def record_parse_result(attempt: Path, parsed: Mapping[str, Any]) -> None:
    """Record the Stage 4 parse and a provisional or final attempt outcome."""

    write_json(attempt / "parsed.json", dict(parsed), sort_keys=True, allow_nan=False)
    failed = parsed.get("status") == "failed"
    phase = parsed.get("phase") if failed else "awaiting_validation"
    write_json(attempt / "outcome.json", {
        "schema_version": STAGE4_OUTCOME_SCHEMA_VERSION,
        "status": "failed" if failed else "pending_validation",
        "phase": phase,
        "failure_type": f"{phase}_error" if failed else None,
        "error_type": parsed.get("error_type") if failed else None,
        "error": parsed.get("error") if failed else None,
        "parsed_status": parsed.get("status"),
        "parsed_artifact": "parsed.json",
        "validation_artifacts": {},
    }, sort_keys=True, allow_nan=False)


def record_validation_result(attempt: Path, result: ValidationResult) -> None:
    """Join the final validation result with this attempt's parse evidence."""

    metadata = result.metadata
    failed_stage = metadata.get("failed_stage")
    validator = metadata.get("validator")
    phase = (
        "validated" if result.accepted else
        failed_stage if isinstance(failed_stage, str) and failed_stage else
        validator if isinstance(validator, str) and validator else "validation"
    )
    failure_type = metadata.get("failure_type")
    reason = "; ".join(result.errors or result.warnings)
    write_json(attempt / "outcome.json", {
        "schema_version": STAGE4_OUTCOME_SCHEMA_VERSION,
        "status": result.status,
        "phase": phase,
        "failure_type": failure_type if not result.accepted else None,
        "error_type": None,
        "error": (reason or None) if not result.accepted else None,
        "parsed_status": _read_object(attempt / "parsed.json").get("status", "not_recorded"),
        "parsed_artifact": "parsed.json" if (attempt / "parsed.json").is_file() else None,
        "validation_artifacts": _validation_artifacts(attempt),
        "validation_result": result.to_dict(),
    }, sort_keys=True, allow_nan=False)


def record_validation_exception(attempt: Path, error: Exception) -> None:
    """Keep an unexpected validator exception attached to the same attempt."""

    write_json(attempt / "outcome.json", {
        "schema_version": STAGE4_OUTCOME_SCHEMA_VERSION,
        "status": "failed",
        "phase": "validation_exception",
        "failure_type": "validation_exception",
        "error_type": type(error).__name__,
        "error": str(error),
        "parsed_status": _read_object(attempt / "parsed.json").get("status", "not_recorded"),
        "parsed_artifact": "parsed.json" if (attempt / "parsed.json").is_file() else None,
        "validation_artifacts": _validation_artifacts(attempt),
    }, sort_keys=True, allow_nan=False)


def _validation_artifacts(attempt: Path) -> dict[str, str]:
    artifacts: dict[str, str] = {}
    for name in ("intermediate", "compiler", "linker", "runtime"):
        relative = Path("validation") / f"{name}.json"
        document = _read_object(attempt / relative)
        if isinstance(document.get("status"), str):
            artifacts[name] = relative.as_posix()
    return artifacts


def _read_object(path: Path) -> Mapping[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    return document if isinstance(document, dict) else {}
