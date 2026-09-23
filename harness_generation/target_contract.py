"""Evidence-bearing target input and resource contracts.

The contract is the boundary between project facts and harness policy.  It keeps
unknown or unavailable facts explicit and provides additive adapters for the
existing protocol and FunctionTriplet artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
from typing import Any, Iterable, Mapping


TARGET_CONTRACT_SCHEMA_VERSION = 1
CONTRACT_STATUSES = frozenset({"known", "inferred", "unknown", "unavailable"})
INPUT_MODES = frozenset({"raw_bytes", "raw_text", "framed", "grammar", "state_sequence"})


class TargetContractError(ValueError):
    """Raised when a target contract is malformed or loses provenance."""


def _text(value: Any, field_name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise TargetContractError(f"{field_name} must be non-empty text")
    return value


def _strings(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise TargetContractError(f"{field_name} must be an array of strings")
    result = tuple(values)
    if any(not isinstance(value, str) or not value.strip() for value in result):
        raise TargetContractError(f"{field_name} must contain non-empty strings")
    return tuple(dict.fromkeys(result))


def _status(value: str) -> str:
    if value not in CONTRACT_STATUSES:
        raise TargetContractError(
            f"status must be one of {', '.join(sorted(CONTRACT_STATUSES))}"
        )
    return value


def _confidence(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TargetContractError("confidence must be a number")
    value = float(value)
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise TargetContractError("confidence must be finite and between 0 and 1")
    return value


def _canonical(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    allow_nan=False))
    except (TypeError, ValueError) as error:
        raise TargetContractError("metadata must be JSON serializable") from error


def _digest(document: Mapping[str, Any], prefix: str) -> str:
    encoded = json.dumps(document, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    return f"{prefix}_{hashlib.sha256(encoded).hexdigest()[:16]}"


def _has_frame_evidence(frame: Any) -> bool:
    """Require substantive frame facts before selecting framed input mode."""

    if not isinstance(frame, Mapping) or not frame:
        return False
    fields = frame.get("fields")
    if isinstance(fields, list) and fields:
        return True
    return any(
        key in frame and frame[key] not in (None, "", [], {})
        for key in ("header_size", "payload_offset", "length", "checksum", "magic")
    )


@dataclass(frozen=True)
class ContractFact:
    """Provenance attached to a contract component or derived choice."""

    id: str
    status: str = "unknown"
    source: str = "unknown"
    evidence: tuple[str, ...] = ()
    confidence: float = 0.0
    immutable: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.id, "fact id")
        _status(self.status)
        _text(self.source, "fact source")
        object.__setattr__(self, "evidence", _strings(self.evidence, "fact evidence"))
        object.__setattr__(self, "confidence", _confidence(self.confidence))
        if not isinstance(self.immutable, bool):
            raise TargetContractError("fact immutable must be a boolean")
        object.__setattr__(self, "metadata", _canonical(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "source": self.source,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "immutable": self.immutable,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], owner: str = "fact") -> "ContractFact":
        if not isinstance(value, Mapping):
            raise TargetContractError(f"{owner} must be an object")
        return cls(
            id=_text(value.get("id"), f"{owner}.id"),
            status=_status(value.get("status", "unknown")),
            source=_text(value.get("source", "unknown"), f"{owner}.source"),
            evidence=_strings(value.get("evidence", ()), f"{owner}.evidence"),
            confidence=_confidence(value.get("confidence", 0.0)),
            immutable=value.get("immutable", True),
            metadata=value.get("metadata", {}),
        )


@dataclass(frozen=True)
class InputContract:
    """What the target accepts, without turning missing evidence into framing."""

    id: str
    mode: str = "raw_bytes"
    status: str = "unknown"
    source: str = "unknown"
    evidence: tuple[str, ...] = ()
    confidence: float = 0.0
    immutable: bool = True
    encoding: Mapping[str, Any] = field(default_factory=dict)
    frame: Mapping[str, Any] | None = None
    grammar: Mapping[str, Any] | None = None
    sequence: Mapping[str, Any] | None = None
    tunables: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.id, "input contract id")
        if self.mode not in INPUT_MODES:
            raise TargetContractError("unsupported input contract mode")
        _status(self.status)
        _text(self.source, "input contract source")
        object.__setattr__(self, "evidence", _strings(self.evidence, "input evidence"))
        object.__setattr__(self, "confidence", _confidence(self.confidence))
        if not isinstance(self.immutable, bool):
            raise TargetContractError("input immutable must be a boolean")
        for name in ("encoding", "tunables", "metadata"):
            object.__setattr__(self, name, _canonical(getattr(self, name)))
        for name in ("frame", "grammar", "sequence"):
            value = getattr(self, name)
            if value is not None:
                if not isinstance(value, Mapping):
                    raise TargetContractError(f"input {name} must be an object")
                object.__setattr__(self, name, _canonical(value))
        if self.mode == "framed" and self.frame is None:
            raise TargetContractError("framed input contract requires frame facts")
        if self.mode == "grammar" and self.grammar is None:
            raise TargetContractError("grammar input contract requires grammar facts")
        if self.mode == "grammar":
            grammar = self.grammar or {}
            start = grammar.get("start")
            rules = grammar.get("rules")
            if (not isinstance(start, str) or not start.strip()
                    or not isinstance(rules, Mapping) or not rules
                    or start not in rules
                    or any(not isinstance(name, str) or not name.strip()
                           or not isinstance(rule, str) or not rule.strip()
                           for name, rule in rules.items())):
                raise TargetContractError(
                    "grammar input contract requires a start symbol and non-empty rules"
                )
        if self.mode == "state_sequence" and self.sequence is None:
            raise TargetContractError("state_sequence input contract requires sequence facts")

    def to_dict(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "id": self.id,
            "mode": self.mode,
            "status": self.status,
            "source": self.source,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "immutable": self.immutable,
            "encoding": dict(self.encoding),
            "tunables": dict(self.tunables),
            "metadata": dict(self.metadata),
        }
        for name in ("frame", "grammar", "sequence"):
            value = getattr(self, name)
            if value is not None:
                document[name] = dict(value)
        return document

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], owner: str = "input") -> "InputContract":
        if not isinstance(value, Mapping):
            raise TargetContractError(f"{owner} must be an object")
        return cls(
            id=_text(value.get("id"), f"{owner}.id"),
            mode=value.get("mode", "raw_bytes"),
            status=value.get("status", "unknown"),
            source=_text(value.get("source", "unknown"), f"{owner}.source"),
            evidence=_strings(value.get("evidence", ()), f"{owner}.evidence"),
            confidence=value.get("confidence", 0.0),
            immutable=value.get("immutable", True),
            encoding=value.get("encoding", {}),
            frame=value.get("frame"),
            grammar=value.get("grammar"),
            sequence=value.get("sequence"),
            tunables=value.get("tunables", {}),
            metadata=value.get("metadata", {}),
        )

    @classmethod
    def raw_passthrough(cls, entry_function: str, *, text: bool = False) -> "InputContract":
        mode = "raw_text" if text else "raw_bytes"
        return cls(
            id=_digest({"entry_function": entry_function, "mode": mode}, "input"),
            mode=mode,
            status="unknown",
            source="absence_of_protocol_contract",
            evidence=("no structured input contract was supplied",),
            confidence=0.0,
            immutable=True,
        )


@dataclass(frozen=True)
class ResourceContract:
    """A resource lifecycle relation scoped to a target contract."""

    id: str
    producer_function_id: str
    producer_function: str
    resource_type: str
    cleanup_function_id: str
    cleanup_function: str
    cleanup_argument: str = "return_value"
    consumers: tuple[str, ...] = ()
    nullable: bool = True
    status: str = "known"
    source: str = "static"
    evidence: tuple[str, ...] = ()
    confidence: float = 0.0
    immutable: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in (
            "id", "producer_function_id", "producer_function", "resource_type",
            "cleanup_function_id", "cleanup_function",
        ):
            _text(getattr(self, name), f"resource {name}")
        if self.cleanup_argument not in {"return_value", "address_of_return_value"}:
            raise TargetContractError("unsupported resource cleanup argument")
        if not isinstance(self.nullable, bool):
            raise TargetContractError("resource nullable must be a boolean")
        _status(self.status)
        _text(self.source, "resource source")
        object.__setattr__(self, "consumers", _strings(self.consumers, "resource consumers"))
        object.__setattr__(self, "evidence", _strings(self.evidence, "resource evidence"))
        object.__setattr__(self, "confidence", _confidence(self.confidence))
        if not isinstance(self.immutable, bool):
            raise TargetContractError("resource immutable must be a boolean")
        object.__setattr__(self, "metadata", _canonical(self.metadata))

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
            "status": self.status,
            "source": self.source,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "immutable": self.immutable,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any], owner: str = "resource") -> "ResourceContract":
        if not isinstance(value, Mapping):
            raise TargetContractError(f"{owner} must be an object")
        return cls(
            id=_text(value.get("id"), f"{owner}.id"),
            producer_function_id=_text(value.get("producer_function_id"), f"{owner}.producer_function_id"),
            producer_function=_text(value.get("producer_function"), f"{owner}.producer_function"),
            resource_type=_text(value.get("resource_type"), f"{owner}.resource_type"),
            cleanup_function_id=_text(value.get("cleanup_function_id"), f"{owner}.cleanup_function_id"),
            cleanup_function=_text(value.get("cleanup_function"), f"{owner}.cleanup_function"),
            cleanup_argument=value.get("cleanup_argument", "return_value"),
            consumers=_strings(value.get("consumers", ()), f"{owner}.consumers"),
            nullable=value.get("nullable", True),
            status=value.get("status", "known"),
            source=_text(value.get("source", "static"), f"{owner}.source"),
            evidence=_strings(value.get("evidence", ()), f"{owner}.evidence"),
            confidence=value.get("confidence", 0.0),
            immutable=value.get("immutable", True),
            metadata=value.get("metadata", {}),
        )

    @classmethod
    def from_ownership(cls, relation: Any) -> "ResourceContract":
        """Adapt either OwnershipRelation or TripletOwnershipRelation."""

        if not hasattr(relation, "to_dict"):
            raise TargetContractError("ownership relation must be serializable")
        document = relation.to_dict()
        lifecycle_fields = {
            field: document[field]
            for field in (
                "producer_binding", "producer_argument_index",
                "cleanup_argument_index", "lifecycle_kind", "conditions",
                "path_kind", "support_total", "support_by_source",
                "usage_pattern_id", "observed_sequence",
            )
            if field in document
        }
        return cls.from_dict({
            **document,
            "status": "known",
            "metadata": {
                **dict(document.get("metadata", {})),
                **lifecycle_fields,
            },
        })


@dataclass(frozen=True)
class TargetContract:
    """Versioned aggregate consumed by planning and evaluation stages."""

    entry_function: str
    input: InputContract | None = None
    resources: tuple[ResourceContract, ...] = ()
    requirements: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    facts: tuple[ContractFact, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)
    legacy: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = TARGET_CONTRACT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _text(self.entry_function, "target contract entry_function")
        if self.schema_version != TARGET_CONTRACT_SCHEMA_VERSION:
            raise TargetContractError("unsupported target contract schema_version")
        resources = tuple(sorted(self.resources, key=lambda item: item.id))
        if len({item.id for item in resources}) != len(resources):
            raise TargetContractError("target contract resource ids must be unique")
        facts = tuple(sorted(self.facts, key=lambda item: item.id))
        if len({item.id for item in facts}) != len(facts):
            raise TargetContractError("target contract fact ids must be unique")
        object.__setattr__(self, "resources", resources)
        object.__setattr__(self, "facts", facts)
        object.__setattr__(self, "requirements", _strings(self.requirements, "requirements"))
        object.__setattr__(self, "notes", _strings(self.notes, "notes"))
        object.__setattr__(self, "metadata", _canonical(self.metadata))
        object.__setattr__(self, "legacy", _canonical(self.legacy))

    @property
    def id(self) -> str:
        return _digest(self._identity_document(), "contract")

    def _identity_document(self) -> dict[str, Any]:
        """Include semantic contract content, not only caller-selected IDs."""

        return {
            "schema_version": self.schema_version,
            "entry_function": self.entry_function,
            "input": None if self.input is None else self.input.to_dict(),
            "resources": [item.to_dict() for item in self.resources],
            "requirements": list(self.requirements),
            "notes": list(self.notes),
            "facts": [item.to_dict() for item in self.facts],
            "metadata": dict(self.metadata),
            "legacy": dict(self.legacy),
        }

    @property
    def contract_id(self) -> str:
        """Stable identity used by consumers that bind generated plans."""

        return self.id

    def normalized_id_document(self) -> dict[str, Any]:
        """Return the identity fields shared with HarnessPlan schema v2."""

        return {"contract_id": self.contract_id}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "entry_function": self.entry_function,
            "input": None if self.input is None else self.input.to_dict(),
            "resources": [item.to_dict() for item in self.resources],
            "requirements": list(self.requirements),
            "notes": list(self.notes),
            "facts": [item.to_dict() for item in self.facts],
            "metadata": dict(self.metadata),
            "legacy": dict(self.legacy),
        }

    def to_json(self) -> dict[str, Any]:
        """Return the canonical JSON-shaped representation."""

        return self.to_dict()

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TargetContract":
        if not isinstance(value, Mapping):
            raise TargetContractError("target contract must be an object")
        if value.get("schema_version") != TARGET_CONTRACT_SCHEMA_VERSION:
            raise TargetContractError("target contract requires schema_version 1")
        resources = value.get("resources", ())
        facts = value.get("facts", ())
        if not isinstance(resources, list) or not isinstance(facts, list):
            raise TargetContractError("target contract resources and facts must be arrays")
        result = cls(
            entry_function=_text(value.get("entry_function"), "entry_function"),
            input=(None if value.get("input") is None else InputContract.from_dict(value["input"])),
            resources=tuple(ResourceContract.from_dict(item, f"resources[{index}]") for index, item in enumerate(resources)),
            requirements=_strings(value.get("requirements", ()), "requirements"),
            notes=_strings(value.get("notes", ()), "notes"),
            facts=tuple(ContractFact.from_dict(item, f"facts[{index}]") for index, item in enumerate(facts)),
            metadata=value.get("metadata", {}),
            legacy=value.get("legacy", {}),
        )
        supplied_id = value.get("id")
        if supplied_id is not None and supplied_id != result.id:
            raise TargetContractError("target contract id does not match its contents")
        return result

    @classmethod
    def from_json(cls, value: Mapping[str, Any]) -> "TargetContract":
        """Strict inverse of :meth:`to_json`."""

        return cls.from_dict(value)

    @classmethod
    def from_protocol_document(cls, document: Mapping[str, Any]) -> "TargetContract":
        """Adapt legacy protocol.json without claiming its prose is typed facts."""
        if not isinstance(document, Mapping):
            raise TargetContractError("protocol document must be an object")
        raw_contract = document.get("contract", {})
        if not isinstance(raw_contract, Mapping):
            raise TargetContractError("protocol document contract must be an object")
        entry = _text(document.get("entry_function"), "entry_function")
        legacy = dict(raw_contract)
        contract = legacy
        frame = contract.get("frame") if isinstance(contract.get("frame"), Mapping) else None
        grammar = contract.get("grammar") if isinstance(contract.get("grammar"), Mapping) else None
        sequence = contract.get("command_loop") if isinstance(contract.get("command_loop"), Mapping) else None
        frame_known = _has_frame_evidence(frame)
        mode = "grammar" if grammar is not None else (
            "framed" if frame_known else "raw_bytes"
        )
        input_contract = InputContract(
            id=_digest({"entry_function": entry, "contract": contract}, "input"),
            mode=mode,
            status="known" if grammar is not None or frame_known else "unknown",
            source="legacy_protocol_document",
            evidence=("adapted from protocol.json",),
            confidence=1.0 if grammar is not None or frame_known else 0.0,
            frame=frame,
            grammar=grammar,
            sequence=sequence,
            metadata={"legacy_contract_keys": sorted(contract)},
        )
        return cls(
            entry_function=entry,
            input=input_contract,
            requirements=_strings(document.get("requirements", ()), "requirements"),
            notes=_strings(document.get("notes", ()), "notes"),
            legacy={key: value for key, value in document.items()
                    if key not in {"schema_version", "entry_function", "requirements", "notes"}},
        )

    @classmethod
    def from_protocol_ir(cls, ir: Any) -> "TargetContract":
        document = ir.to_protocol_contract()
        contract = document.get("contract", {})
        frame = contract.get("frame") if isinstance(contract, Mapping) else None
        sequence = contract.get("command_loop") if isinstance(contract, Mapping) else None
        frame_known = _has_frame_evidence(frame)
        sequence_known = isinstance(sequence, Mapping) and bool(sequence)
        mode = "framed" if frame_known else (
            "state_sequence" if sequence_known and sequence.get("preferred") else "raw_bytes"
        )
        input_contract = InputContract(
            id=_digest({"entry_function": ir.entry_function, "frame": frame, "sequence": sequence}, "input"),
            mode=mode,
            status="known" if frame_known else "unknown",
            source="protocol_ir",
            evidence=("derived from ProtocolIR.to_protocol_contract",),
            confidence=float(getattr(ir, "llm_confidence", 0.0) if sequence else 1.0),
            frame=frame,
            sequence=sequence,
            metadata={"protocol_ir_schema": 1},
        )
        return cls(
            entry_function=ir.entry_function,
            input=input_contract,
            requirements=tuple(document.get("requirements", ())),
            notes=tuple(document.get("notes", ())),
            legacy={"protocol": document},
        )

    @classmethod
    def from_triplet(cls, triplet: Any) -> "TargetContract":
        resources = tuple(ResourceContract.from_ownership(item)
                          for item in triplet.ownership_relations)
        return cls(
            entry_function=triplet.isf.function,
            input=InputContract.raw_passthrough(triplet.isf.function),
            resources=resources,
            metadata={"triplet_id": triplet.id},
        )


__all__ = [
    "CONTRACT_STATUSES",
    "INPUT_MODES",
    "TARGET_CONTRACT_SCHEMA_VERSION",
    "ContractFact",
    "InputContract",
    "ResourceContract",
    "TargetContract",
    "TargetContractError",
]
