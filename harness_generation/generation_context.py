"""Deterministic project context supplied to code-generation prompts."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Mapping


def project_type_context(document: Mapping[str, Any]) -> dict[str, Any]:
    """Expose exact typedef declarations and usable header spellings."""
    structures = document.get("structs", [])
    if not isinstance(structures, list):
        structures = []
    types = []
    header_files = set()
    for item in structures:
        if not isinstance(item, Mapping):
            continue
        declaration = item.get("declaration")
        file = item.get("file")
        if not isinstance(declaration, str) or not declaration.strip():
            continue
        record = {
            "name": item.get("name"),
            "aliases": item.get("aliases", []),
            "declaration": declaration,
            "file": file,
        }
        types.append(record)
        if isinstance(file, str) and file.endswith(".h"):
            header_files.add(file)

    headers = []
    for file in sorted(header_files):
        path = PurePosixPath(file)
        parts = path.parts
        include = str(PurePosixPath(*parts[1:])) if parts[:1] == ("include",) else file
        headers.append({"file": file, "include": include})
    return {
        "headers": headers,
        "types": sorted(types, key=lambda item: str(item.get("name", ""))),
    }


def bounded_validation_feedback(
    context: Mapping[str, Any] | None,
    *,
    max_reason_characters: int = 1200,
) -> dict[str, Any]:
    """Return only the actionable, bounded fields from a previous failure."""
    if not context:
        return {}
    result = {
        key: context.get(key)
        for key in (
            "failed_stage", "validator", "failure_type", "attempt",
            "rollback_target", "reason",
        )
        if context.get(key) is not None
    }
    reason = result.get("reason")
    if isinstance(reason, str) and len(reason) > max_reason_characters:
        result["reason"] = reason[-max_reason_characters:]
    return result
