"""Stable data contracts and serialization for Function Triplets."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from sfg_builder.models import Serializable

from .records import write_json


TRIPLET_SCHEMA_VERSION = 4
SUPPORTED_TRIPLET_SCHEMA_VERSIONS = frozenset({1, 2, 3, TRIPLET_SCHEMA_VERSION})
_ROLE_ORDER = {"ISF": 0, "PRF": 1, "HPF": 2}


@dataclass(frozen=True)
class TripletFunction(Serializable):
    """A function reference with enough provenance to avoid name-only records."""

    function_id: str
    function: str
    roles: tuple[str, ...]
    file: str
    line: int

    def __post_init__(self) -> None:
        if not self.function_id or not self.function or not self.file:
            raise ValueError("triplet function identity and source are required")
        if self.line < 1:
            raise ValueError("triplet function line must be positive")
        object.__setattr__(self, "roles", _canonical_roles(self.roles))

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "function": self.function,
            "roles": list(self.roles),
            "file": self.file,
            "line": self.line,
        }


@dataclass(frozen=True)
class TripletEdge(Serializable):
    """A structural-flow edge retained inside a Function Triplet."""

    function_id: str
    function: str
    src: str
    dst: str
    roles: tuple[str, ...]
    file: str
    line: int
    inferred: bool = False
    inference_reason: str | None = None

    def __post_init__(self) -> None:
        if not all((self.function_id, self.function, self.src, self.dst, self.file)):
            raise ValueError("triplet edge identity, endpoints, and source are required")
        if self.line < 1:
            raise ValueError("triplet edge line must be positive")
        object.__setattr__(self, "roles", _canonical_roles(self.roles))

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "function": self.function,
            "src": self.src,
            "dst": self.dst,
            "roles": list(self.roles),
            "file": self.file,
            "line": self.line,
            "inferred": self.inferred,
            "inference_reason": self.inference_reason,
        }


@dataclass(frozen=True)
class TripletBypassSemantic(Serializable):
    """Non-SFG semantic evidence carried alongside one Function Triplet."""

    id: str
    kind: str
    function_id: str
    function: str
    summary: str
    evidence: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not all((self.id, self.kind, self.function_id, self.function, self.summary)):
            raise ValueError("bypass semantic identity and summary are required")
        if any(not isinstance(item, str) or not item for item in self.evidence):
            raise ValueError("bypass semantic evidence must contain non-empty strings")
        object.__setattr__(self, "evidence", tuple(sorted(set(self.evidence))))
        object.__setattr__(self, "metadata", _canonical_json_object(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "function_id": self.function_id,
            "function": self.function,
            "summary": self.summary,
            "evidence": list(self.evidence),
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class TripletOwnershipRelation(Serializable):
    """FT-scoped permission to release one producer return value."""

    id: str
    producer_function_id: str
    producer_function: str
    resource_type: str
    cleanup_function_id: str
    cleanup_function: str
    cleanup_argument: str = "return_value"
    consumers: tuple[str, ...] = ()
    nullable: bool = True
    evidence: tuple[str, ...] = ()
    confidence: float = 0.0
    source: str = "static"

    def __post_init__(self) -> None:
        if not all((self.id, self.producer_function_id, self.producer_function,
                    self.resource_type, self.cleanup_function_id,
                    self.cleanup_function)):
            raise ValueError("ownership relation identity is required")
        if self.cleanup_argument not in {"return_value", "address_of_return_value"}:
            raise ValueError("unsupported ownership cleanup argument")
        if not 0 <= self.confidence <= 1:
            raise ValueError("ownership relation confidence must be between 0 and 1")
        if not isinstance(self.nullable, bool):
            raise ValueError("ownership relation nullable must be a boolean")
        if any(not isinstance(value, str) or not value for value in self.consumers):
            raise ValueError("ownership relation consumers must be non-empty strings")
        if any(not isinstance(value, str) or not value for value in self.evidence):
            raise ValueError("ownership relation evidence must be non-empty strings")
        object.__setattr__(self, "consumers", tuple(sorted(set(self.consumers))))
        object.__setattr__(self, "evidence", tuple(sorted(set(self.evidence))))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "producer_function_id": self.producer_function_id,
            "producer_function": self.producer_function,
            "resource_type": self.resource_type,
            "cleanup_function_id": self.cleanup_function_id,
            "cleanup_function": self.cleanup_function,
            "cleanup_argument": self.cleanup_argument,
            "consumers": list(self.consumers),
            "nullable": self.nullable,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "source": self.source,
        }



@dataclass(frozen=True)
class FunctionTriplet(Serializable):
    """FT = (I, P, H), anchored by exactly one ISF."""

    isf: TripletFunction
    prfs: tuple[TripletFunction, ...]
    hpfs: tuple[TripletFunction, ...]
    functions: tuple[TripletFunction, ...]
    structures: tuple[str, ...]
    edges: tuple[TripletEdge, ...]
    metadata: Mapping[str, Any] = field(default_factory=dict)
    id: str | None = None
    bypass_semantics: tuple[TripletBypassSemantic, ...] = ()
    ownership_relations: tuple[TripletOwnershipRelation, ...] = ()

    def __post_init__(self) -> None:
        if "ISF" not in self.isf.roles:
            raise ValueError("FunctionTriplet.isf must have the ISF role")
        if any("PRF" not in function.roles for function in self.prfs):
            raise ValueError("every FunctionTriplet.prfs entry must have the PRF role")
        if any("HPF" not in function.roles for function in self.hpfs):
            raise ValueError("every FunctionTriplet.hpfs entry must have the HPF role")

        prfs = _canonical_functions(self.prfs)
        hpfs = _canonical_functions(self.hpfs)
        functions = _canonical_functions(self.functions)
        function_ids = {function.function_id for function in functions}
        required_ids = {
            self.isf.function_id,
            *(function.function_id for function in prfs),
            *(function.function_id for function in hpfs),
        }
        if not required_ids <= function_ids:
            raise ValueError("FunctionTriplet.functions must contain I, P, and H functions")
        if any(edge.function_id not in function_ids for edge in self.edges):
            raise ValueError("FunctionTriplet edge references a function outside functions")
        if any(semantic.function_id not in function_ids
               for semantic in self.bypass_semantics):
            raise ValueError("FunctionTriplet bypass semantic references a function outside functions")
        relation_ids = set()
        function_names = {function.function_id: function.function for function in functions}
        known_names = set(function_names.values())
        for relation in self.ownership_relations:
            if relation.id in relation_ids:
                raise ValueError(f"duplicate ownership relation: {relation.id}")
            relation_ids.add(relation.id)
            if relation.producer_function_id not in function_ids:
                raise ValueError("ownership relation producer is outside functions")
            if function_names[relation.producer_function_id] != relation.producer_function:
                raise ValueError("ownership relation producer name does not match its id")
            if any(consumer not in known_names for consumer in relation.consumers):
                raise ValueError("ownership relation consumer is outside functions")

        structures = tuple(sorted(set(self.structures)))
        if any(not structure for structure in structures):
            raise ValueError("FunctionTriplet structures cannot contain empty names")

        triplet_id = self.id or stable_triplet_id(self.isf.function_id)
        if not isinstance(triplet_id, str) or not triplet_id.startswith("ft_"):
            raise ValueError("FunctionTriplet.id must start with 'ft_'")
        object.__setattr__(self, "id", triplet_id)
        object.__setattr__(self, "prfs", prfs)
        object.__setattr__(self, "hpfs", hpfs)
        object.__setattr__(self, "functions", functions)
        object.__setattr__(self, "structures", structures)
        # Sorting, rather than deduplicating, preserves parallel edge records.
        object.__setattr__(self, "edges", tuple(sorted(self.edges, key=_edge_key)))
        object.__setattr__(
            self,
            "bypass_semantics",
            _canonical_bypass_semantics(self.bypass_semantics),
        )
        object.__setattr__(self, "ownership_relations", tuple(sorted(
            self.ownership_relations, key=lambda relation: relation.id
        )))
        object.__setattr__(self, "metadata", _canonical_json_object(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "isf": self.isf.to_dict(),
            "prfs": [function.to_dict() for function in self.prfs],
            "hpfs": [function.to_dict() for function in self.hpfs],
            "functions": [function.to_dict() for function in self.functions],
            "structures": list(self.structures),
            "edges": [edge.to_dict() for edge in self.edges],
            "bypass_semantics": [
                semantic.to_dict() for semantic in self.bypass_semantics
            ],
            "ownership_relations": [
                relation.to_dict() for relation in self.ownership_relations
            ],
            "metadata": dict(self.metadata),
        }


def stable_triplet_id(
    isf_function_id: str,
    *,
    function_name: str | None = None,
    relative_path: str | None = None,
    signature: str | None = None,
) -> str:
    """Derive a portable content identity from one unique ISF anchor.

    The keyword fields form the v2 identity. The function-id fallback keeps the
    public model usable for legacy callers while remaining process-independent.
    """
    if not isf_function_id:
        raise ValueError("ISF function_id is required")
    if function_name is None or relative_path is None:
        parts = isf_function_id.rsplit(":", 2)
        relative_path = parts[0] if relative_path is None and len(parts) == 3 else (
            relative_path or ""
        )
        function_name = parts[-1] if function_name is None else function_name
    if not function_name or not relative_path:
        raise ValueError("stable FT identity requires function name and source path")
    path = Path(relative_path)
    if path.is_absolute():
        raise ValueError("stable FT identity source path must be project-relative")
    normalized_path = path.as_posix()
    normalized_signature = " ".join((signature or "").split())
    identity = "\0".join((normalized_path, function_name, normalized_signature))
    digest = hashlib.sha256(
        ("function-triplet-v2\0" + identity).encode("utf-8")
    ).hexdigest()[:12]
    slug = re.sub(r"[^A-Za-z0-9]+", "_", function_name).strip("_").lower()
    if not slug:
        slug = "isf"
    return f"ft_{slug[:48]}_{digest}"


def triplets_document(triplets: Iterable[FunctionTriplet]) -> dict[str, Any]:
    """Return the canonical, deterministically ordered triplets document."""
    ordered = tuple(sorted(triplets, key=lambda triplet: triplet.id))
    ids = [triplet.id for triplet in ordered]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate FunctionTriplet id")
    return {
        "schema_version": TRIPLET_SCHEMA_VERSION,
        "triplets": [triplet.to_dict() for triplet in ordered],
    }


def write_triplets_json(triplets: Iterable[FunctionTriplet], path: Path) -> Path:
    """Atomically write canonical triplets JSON with stable object-key order."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, triplets_document(triplets), sort_keys=True, allow_nan=False)
    return path


def load_triplets_json(path: Path) -> tuple[FunctionTriplet, ...]:
    """Load the canonical triplets document through the public data model."""
    path = Path(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load {path}: {type(exc).__name__}") from None
    if (not isinstance(document, dict)
            or document.get("schema_version") not in SUPPORTED_TRIPLET_SCHEMA_VERSIONS):
        raise ValueError("unsupported or missing triplets schema_version")
    records = document.get("triplets")
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise ValueError("triplets must be an array of objects")
    triplets = tuple(_triplet_from_dict(item) for item in records)
    # Reuse canonical document validation for duplicate IDs and ordering invariants.
    triplets_document(triplets)
    return tuple(sorted(triplets, key=lambda triplet: triplet.id))


def _canonical_roles(roles: Iterable[str]) -> tuple[str, ...]:
    unique = set(roles)
    if any(not role for role in unique):
        raise ValueError("function roles cannot contain empty values")
    return tuple(sorted(unique, key=lambda role: (_ROLE_ORDER.get(role, len(_ROLE_ORDER)), role)))


def _canonical_functions(functions: Iterable[TripletFunction]) -> tuple[TripletFunction, ...]:
    by_id: dict[str, TripletFunction] = {}
    for function in functions:
        previous = by_id.setdefault(function.function_id, function)
        if previous != function:
            raise ValueError(f"conflicting function reference: {function.function_id}")
    return tuple(sorted(
        by_id.values(),
        key=lambda function: (
            function.file,
            function.line,
            function.function_id,
            function.function,
        ),
    ))


def _edge_key(edge: TripletEdge) -> tuple[Any, ...]:
    return (
        edge.src,
        edge.dst,
        edge.function_id,
        edge.function,
        edge.roles,
        edge.file,
        edge.line,
        edge.inferred,
        edge.inference_reason or "",
    )


def _canonical_bypass_semantics(
    semantics: Iterable[TripletBypassSemantic],
) -> tuple[TripletBypassSemantic, ...]:
    by_id: dict[str, TripletBypassSemantic] = {}
    for semantic in semantics:
        previous = by_id.setdefault(semantic.id, semantic)
        if previous != semantic:
            raise ValueError(f"conflicting bypass semantic: {semantic.id}")
    return tuple(sorted(
        by_id.values(),
        key=lambda semantic: (
            semantic.kind,
            semantic.function_id,
            semantic.id,
            semantic.summary,
        ),
    ))


def _canonical_json_object(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: _canonical_json_value(item)
        for key, item in sorted(value.items())
    }


def _canonical_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("metadata object keys must be strings")
        return _canonical_json_object(value)
    if isinstance(value, (list, tuple)):
        return [_canonical_json_value(item) for item in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise ValueError(f"metadata is not JSON serializable: {type(value).__name__}")


def _triplet_from_dict(value: Mapping[str, Any]) -> FunctionTriplet:
    isf = _function_from_dict(_object(value, "isf"))
    prfs = tuple(_function_from_dict(item) for item in _object_array(value, "prfs"))
    hpfs = tuple(_function_from_dict(item) for item in _object_array(value, "hpfs"))
    functions = tuple(
        _function_from_dict(item) for item in _object_array(value, "functions")
    )
    structures = _string_array(value, "structures")
    edges = tuple(_edge_from_dict(item) for item in _object_array(value, "edges"))
    bypass = tuple(
        _bypass_from_dict(item)
        for item in value.get("bypass_semantics", [])
    )
    ownership = tuple(
        _ownership_from_dict(item)
        for item in value.get("ownership_relations", [])
    )
    metadata = _object(value, "metadata")
    triplet_id = value.get("id")
    if not isinstance(triplet_id, str):
        raise ValueError("triplet id must be a string")
    return FunctionTriplet(
        isf,
        prfs,
        hpfs,
        functions,
        structures,
        edges,
        metadata,
        triplet_id,
        bypass,
        ownership,
    )


def _function_from_dict(value: Mapping[str, Any]) -> TripletFunction:
    return TripletFunction(
        _string(value, "function_id"),
        _string(value, "function"),
        _string_array(value, "roles"),
        _string(value, "file"),
        _positive_int(value, "line"),
    )


def _edge_from_dict(value: Mapping[str, Any]) -> TripletEdge:
    inferred = value.get("inferred", False)
    reason = value.get("inference_reason")
    if type(inferred) is not bool:
        raise ValueError("triplet edge inferred must be a boolean")
    if reason is not None and not isinstance(reason, str):
        raise ValueError("triplet edge inference_reason must be a string or null")
    return TripletEdge(
        _string(value, "function_id"),
        _string(value, "function"),
        _string(value, "src"),
        _string(value, "dst"),
        _string_array(value, "roles"),
        _string(value, "file"),
        _positive_int(value, "line"),
        inferred,
        reason,
    )


def _ownership_from_dict(value: Mapping[str, Any]) -> TripletOwnershipRelation:
    if not isinstance(value, Mapping):
        raise ValueError("triplet ownership relation must be an object")
    return TripletOwnershipRelation(
        _string(value, "id"),
        _string(value, "producer_function_id"),
        _string(value, "producer_function"),
        _string(value, "resource_type"),
        _string(value, "cleanup_function_id"),
        _string(value, "cleanup_function"),
        value.get("cleanup_argument", "return_value"),
        _string_array(value, "consumers") if "consumers" in value else (),
        value.get("nullable", True),
        _string_array(value, "evidence") if "evidence" in value else (),
        value.get("confidence", 0.0),
        value.get("source", "static"),
    )


def _bypass_from_dict(value: Mapping[str, Any]) -> TripletBypassSemantic:
    if not isinstance(value, Mapping):
        raise ValueError("triplet bypass_semantics must be objects")
    return TripletBypassSemantic(
        _string(value, "id"),
        _string(value, "kind"),
        _string(value, "function_id"),
        _string(value, "function"),
        _string(value, "summary"),
        _string_array(value, "evidence"),
        _object(value, "metadata"),
    )


def _object(value: Mapping[str, Any], field_name: str) -> Mapping[str, Any]:
    item = value.get(field_name)
    if not isinstance(item, dict):
        raise ValueError(f"triplet {field_name} must be an object")
    return item


def _object_array(value: Mapping[str, Any], field_name: str) -> list[Mapping[str, Any]]:
    items = value.get(field_name)
    if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
        raise ValueError(f"triplet {field_name} must be an array of objects")
    return items


def _string_array(value: Mapping[str, Any], field_name: str) -> tuple[str, ...]:
    items = value.get(field_name)
    if not isinstance(items, list) or any(not isinstance(item, str) for item in items):
        raise ValueError(f"triplet {field_name} must be an array of strings")
    return tuple(items)


def _string(value: Mapping[str, Any], field_name: str) -> str:
    item = value.get(field_name)
    if not isinstance(item, str) or not item:
        raise ValueError(f"triplet {field_name} must be a non-empty string")
    return item


def _positive_int(value: Mapping[str, Any], field_name: str) -> int:
    item = value.get(field_name)
    if type(item) is not int or item < 1:
        raise ValueError(f"triplet {field_name} must be a positive integer")
    return item
