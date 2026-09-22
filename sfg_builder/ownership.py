"""Deterministic return-value ownership facts for Phase 1 artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Iterable

from .models import FunctionInfo, OwnershipRelation

OWNERSHIP_SCHEMA_VERSION = 1


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
        if function.name == "cJSON_Delete" and len(function.parameters) == 1:
            parameter = function.parameters[0]
            if parameter.base_type == "cJSON" and parameter.pointer_depth == 1:
                cleanup_by_type.setdefault("cJSON", []).append(function)
        if function.name == "cJSON_free" and len(function.parameters) == 1:
            parameter = function.parameters[0]
            if parameter.base_type == "void" and parameter.pointer_depth == 1:
                cleanup_by_type.setdefault("char", []).append(function)

    relations = []
    for producer in records:
        ownership = producer.return_ownership
        if ownership is None or not ownership.owned or not ownership.cleanup_function:
            continue
        for cleanup in cleanup_by_type.get(ownership.resource_type, ()):
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
                    f"cleanup declaration accepts {ownership.resource_type} pointer",
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
