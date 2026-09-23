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
    opaque_resource_types: Iterable[str] = (),
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
    explicit_producers = {relation.producer_function_id for relation in relations}
    relations.extend(_infer_opaque_handle_relations(
        records,
        frozenset(opaque_resource_types),
        linkable_ids,
        explicit_producers,
    ))
    return tuple(sorted(relations, key=lambda relation: relation.id))


_PRODUCER_WORD = re.compile(
    r"(?:^|_)(?:create|new|open|alloc|allocate|init|initialize|construct|make)(?:_|$)",
    re.IGNORECASE,
)
_CLEANUP_WORD = re.compile(
    r"(?:^|_)(?:free|destroy|delete|release|close|deinit|deinitialize)(?:_|$)",
    re.IGNORECASE,
)


def _infer_opaque_handle_relations(
    functions: tuple[FunctionInfo, ...],
    resource_types: frozenset[str],
    linkable_ids: set[str],
    explicit_producers: set[str],
) -> tuple[OwnershipRelation, ...]:
    """Infer high-confidence create/free pairs for typed opaque handles.

    The type relation is mandatory. Names, prose, and implementation tokens only
    raise confidence after producer/cleanup signatures agree on the same handle.
    """
    if not resource_types:
        return ()

    linkable = tuple(
        function for function in functions
        if "static" not in function.storage
        and (function.defined or function.id in linkable_ids)
    )
    inferred: list[OwnershipRelation] = []
    for resource_type in sorted(resource_types):
        producers = [
            function for function in linkable
            if function.id not in explicit_producers
            and function.return_base_type == resource_type
            and function.return_pointer_depth >= 1
            and _producer_evidence(function)
        ]
        cleanups = [
            function for function in linkable
            if _cleanup_parameter(function, resource_type) is not None
            and _cleanup_evidence(function)
        ]
        if not producers or not cleanups:
            continue
        scored_cleanups = sorted(
            ((_cleanup_score(function), function) for function in cleanups),
            key=lambda item: (-item[0], item[1].name, item[1].id),
        )
        if len(scored_cleanups) > 1 and scored_cleanups[0][0] == scored_cleanups[1][0]:
            # Ambiguous release APIs can encode different modes. Fail closed.
            continue
        cleanup_score, cleanup = scored_cleanups[0]
        for producer in sorted(producers, key=lambda item: (item.name, item.id)):
            producer_evidence = _producer_evidence(producer)
            cleanup_evidence = _cleanup_evidence(cleanup)
            confidence = min(
                0.99,
                0.55 + _producer_score(producer) + cleanup_score,
            )
            if confidence < 0.80:
                continue
            identity = "\0".join((producer.id, cleanup.id, resource_type))
            digest = hashlib.sha256(
                ("opaque-ownership-v1\0" + identity).encode("utf-8")
            ).hexdigest()[:12]
            inferred.append(OwnershipRelation(
                id=f"own_{producer.name}_{digest}",
                producer_function_id=producer.id,
                producer_function=producer.name,
                resource_type=resource_type,
                cleanup_function_id=cleanup.id,
                cleanup_function=cleanup.name,
                cleanup_argument="return_value",
                nullable=True,
                evidence=tuple(sorted({
                    f"opaque handle typedef: {resource_type}",
                    f"producer returns {resource_type} with effective pointer depth "
                    f"{producer.return_pointer_depth}",
                    f"cleanup accepts exactly one {resource_type} handle",
                    *producer_evidence,
                    *cleanup_evidence,
                })),
                confidence=confidence,
                source="opaque_handle_static_inference",
            ))
    return tuple(inferred)


def _cleanup_parameter(
    function: FunctionInfo, resource_type: str
):
    if function.return_base_type != "void" or len(function.parameters) != 1:
        return None
    parameter = function.parameters[0]
    if (
        parameter.base_type != resource_type
        or parameter.pointer_depth < 1
        or parameter.is_const
    ):
        return None
    return parameter


def _producer_evidence(function: FunctionInfo) -> tuple[str, ...]:
    evidence = []
    if _PRODUCER_WORD.search(_split_camel(function.name)):
        evidence.append(f"producer name denotes construction: {function.name}")
    if re.search(
        r"\b(?:constructs?|creates?|allocates?|opens?|initializes?)\b",
        function.documentation,
        re.IGNORECASE,
    ):
        evidence.append("producer documentation denotes construction")
    if re.search(r"\b(?:MALLOC|CALLOC|malloc|calloc)\s*\(", function.body):
        evidence.append("producer body contains allocation")
    return tuple(evidence)


def _cleanup_evidence(function: FunctionInfo) -> tuple[str, ...]:
    evidence = []
    if _CLEANUP_WORD.search(_split_camel(function.name)):
        evidence.append(f"cleanup name denotes release: {function.name}")
    if re.search(
        r"\b(?:frees?|releases?|destroys?|deletes?|closes?|deallocates?)\b",
        function.documentation,
        re.IGNORECASE,
    ):
        evidence.append("cleanup documentation denotes release")
    if re.search(r"\b(?:FREE|free|Delete|Destroy|Release)\s*\(", function.body):
        evidence.append("cleanup body contains release operations")
    return tuple(evidence)


def _producer_score(function: FunctionInfo) -> float:
    evidence = _producer_evidence(function)
    return min(0.25, 0.10 * len(evidence))


def _cleanup_score(function: FunctionInfo) -> float:
    evidence = _cleanup_evidence(function)
    return min(0.20, 0.10 * len(evidence))


def _split_camel(value: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)


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
