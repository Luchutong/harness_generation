"""Attempt-level Stage 4 outcome, including validation after code generation.

An attempt directory used to record how far it got by which files happened to be
in it: a ``parsed.json`` with ``status: failed`` meant the parse failed, and a
``parsed.json`` with ``status: passed`` meant the attempt was fine -- even though
the build and the runtime check happen *after* that file is written, and can fail
the attempt on their own.  So the failure was real and recorded, but it was
recorded in ``validation/*.json`` while the attempt's own record said ``passed``.
Reading a directory tree to find out why an attempt died meant knowing which of
four files to distrust.

``outcome.json`` is the one file that answers that question.  It is written twice
on purpose: once with the parse result, provisionally ``pending_validation``, and
again when validation finishes.  An attempt that never reaches validation keeps
the provisional record rather than no record at all.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .artifacts import TripletArtifacts
from .validation import ValidationResult


STAGE4_OUTCOME_SCHEMA_VERSION = 1

#: The validators whose per-attempt copies ``_copy_attempt_validation`` writes.
#: Listed here so an outcome can point at the evidence for its own failure.
_VALIDATION_STAGES = ("intermediate", "compiler", "linker", "runtime")


def record_parse_result(
    layout: TripletArtifacts,
    attempt: Path,
    parsed: Mapping[str, Any],
) -> None:
    """Record the Stage 4 parse and a provisional or final attempt outcome.

    ``layout`` is the triplet's artifact layout, used for its ``write_json``
    rather than ``records.write_json`` directly: the layout refuses a path that
    escapes the artifact root, and an outcome is not worth recording if the
    record can be pointed somewhere else.
    """

    layout.write_json(attempt / "parsed.json", dict(parsed))
    failed = parsed.get("status") == "failed"
    phase = parsed.get("phase") if failed else "awaiting_validation"
    layout.write_json(attempt / "outcome.json", {
        "schema_version": STAGE4_OUTCOME_SCHEMA_VERSION,
        "status": "failed" if failed else "pending_validation",
        "phase": phase,
        "failure_type": f"{phase}_error" if failed else None,
        "error_type": parsed.get("error_type") if failed else None,
        "error": parsed.get("error") if failed else None,
        "parsed_status": parsed.get("status"),
        "parsed_artifact": "parsed.json",
        "validation_artifacts": {},
    })


def record_validation_result(
    layout: TripletArtifacts,
    attempt: Path,
    result: ValidationResult,
) -> None:
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
    layout.write_json(attempt / "outcome.json", {
        "schema_version": STAGE4_OUTCOME_SCHEMA_VERSION,
        "status": result.status,
        "phase": phase,
        "failure_type": failure_type if not result.accepted else None,
        "error_type": None,
        "error": (reason or None) if not result.accepted else None,
        "parsed_status": _read_object(attempt / "parsed.json").get(
            "status", "not_recorded"
        ),
        "parsed_artifact": (
            "parsed.json" if (attempt / "parsed.json").is_file() else None
        ),
        "validation_artifacts": _validation_artifacts(attempt),
        "validation_result": result.to_dict(),
    })


def record_validation_exception(
    layout: TripletArtifacts,
    attempt: Path,
    error: Exception,
) -> None:
    """Keep an unexpected validator exception attached to the same attempt.

    A validator that raises is the case most likely to leave an attempt looking
    healthy: nothing wrote a failure, because the thing that would have written
    one is the thing that broke.
    """

    layout.write_json(attempt / "outcome.json", {
        "schema_version": STAGE4_OUTCOME_SCHEMA_VERSION,
        "status": "failed",
        "phase": "validation_exception",
        "failure_type": "validation_exception",
        "error_type": type(error).__name__,
        "error": str(error),
        "parsed_status": _read_object(attempt / "parsed.json").get(
            "status", "not_recorded"
        ),
        "parsed_artifact": (
            "parsed.json" if (attempt / "parsed.json").is_file() else None
        ),
        "validation_artifacts": _validation_artifacts(attempt),
    })


def _validation_artifacts(attempt: Path) -> dict[str, str]:
    """Which validator copies this attempt actually has, by name to relative path."""

    artifacts: dict[str, str] = {}
    for name in _VALIDATION_STAGES:
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
