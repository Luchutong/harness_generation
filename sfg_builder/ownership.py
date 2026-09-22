"""Deterministic return-value ownership facts for Phase 1 artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Iterable

from .models import FunctionInfo, OwnershipRelation

OWNERSHIP_SCHEMA_VERSION = 1


def _cleanup_contract(function: FunctionInfo) -> tuple[str, str] | None:
    """Return resource type and argument mode from explicit cleanup evidence."""
    text = function.signature + " " + function.body + " " + function.documentation
    if re.search(
        r"\b(?:do\s+not|does\s+not|never)\s+(?:free|release|destroy|delete)\b",
        function.documentation, re.I,
    ):
        return None
    parameter = function.parameters[0] if len(function.parameters) == 1 else None
    match = re.search(
        r"(?:takes_ownership|cleanup_for)\s*\(\s*(?:const\s+)?([A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)?)\s*\*",
        text,
    )
    if match is None:
        if not re.search(r"\b(?:free|release|destroy|delete|deallocat\w*)\w*\b", function.documentation, re.IGNORECASE):
            return None
        declared_type = parameter.base_type if len(function.parameters) == 1 else None
    else:
        declared_type = " ".join(match.group(1).split())
    if len(function.parameters) != 1:
        return None
    if parameter is None or parameter.pointer_depth != 1 or parameter.is_const:
        return None
    if declared_type != parameter.base_type:
        return None
    mode = "address_of_return_value" if "address_of_return_value" in text else "return_value"
    return parameter.base_type, mode


def derive_ownership_relations(
    functions: Iterable[FunctionInfo],
    *,
    linkable_function_ids: Iterable[str] = (),
) -> tuple[OwnershipRelation, ...]:
    """Pair explicitly recognized owned returns with compatible cleanup APIs.

    A declaration alone is not enough to authorize a cleanup helper.  Callers
    may provide an explicit target-link manifest for declaration-only symbols;
    otherwise a project definition is required.
    """
    records = tuple(functions)
    linkable_ids = set(linkable_function_ids)
    cleanup_by_type: dict[str, list[FunctionInfo]] = {}
    for function in records:
        if "static" in function.storage:
            continue
        if not (function.defined or function.id in linkable_ids):
            continue
        contract = _cleanup_contract(function)
        if contract is None:
            continue
        resource_type, _argument = contract
        cleanup_by_type.setdefault(resource_type, []).append(function)

    relations = []
    for producer in records:
        ownership = producer.return_ownership
        if ownership is None or not ownership.owned or not ownership.cleanup_function:
            continue
        candidates = [cleanup for cleanup in cleanup_by_type.get(ownership.resource_type, ())
                      if cleanup.name == ownership.cleanup_function
                      and (_cleanup_contract(cleanup) or (None, None))[1] == ownership.cleanup_argument]
        if len(candidates) != 1:
            continue
        cleanup = candidates[0]
        identity = "\0".join((producer.id, cleanup.id, ownership.resource_type))
        digest = hashlib.sha256(("ownership-v1\0" + identity).encode("utf-8")).hexdigest()[:12]
        relations.append(OwnershipRelation(
            id=f"own_{producer.name}_{digest}",
            producer_function_id=producer.id,
            producer_function=producer.name,
            resource_type=ownership.resource_type,
            cleanup_function_id=cleanup.id,
            cleanup_function=cleanup.name,
            cleanup_argument=ownership.cleanup_argument,
            nullable=ownership.nullable,
            evidence=tuple(sorted(set(ownership.evidence + (
                f"cleanup contract accepts {ownership.resource_type} pointer",
                f"matched cleanup function: {cleanup.name}",
                "cleanup has external linkage plus a project definition or explicit link manifest entry",
            )))),
            confidence=min(ownership.confidence, 1.0),
            source=ownership.source,
        ))
    return tuple(sorted(relations, key=lambda relation: relation.id))


def ownership_document(relations: Iterable[OwnershipRelation]) -> dict:
    ordered = tuple(sorted(relations, key=lambda relation: relation.id))
    return {"schema_version": OWNERSHIP_SCHEMA_VERSION,
            "relations": [relation.to_dict() for relation in ordered]}


def write_ownership_json(relations: Iterable[OwnershipRelation], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(ownership_document(relations), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return path


def load_ownership_json(path: Path) -> tuple[dict, ...]:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return ()
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load ownership artifact: {type(error).__name__}") from error
    if not isinstance(document, dict) or document.get("schema_version") != OWNERSHIP_SCHEMA_VERSION:
        raise ValueError("unsupported ownership schema_version")
    records = document.get("relations")
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise ValueError("ownership relations must be an array of objects")
    return tuple(records)
