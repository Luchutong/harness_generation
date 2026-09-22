"""Canonical IR that merges the A/B facts and the C conventions into one model.

The pipeline produces a protocol contract from two very different sources:

* :mod:`protocol_miner` recovers the **A** (frame format) and **B** (constant
  constraints) blocks statically from the target source.  Every fact there is a
  *measurement* and carries source evidence.
* :mod:`protocol_conventions` infers the **C** block (command loop, context
  lifetime, stateful opcodes, requirements, notes) with an LLM and merges
  samples through a consistency vote.  Every fact there is an *inference*.

Those two halves have to reach the prompt as a single object, and consumers
must be able to tell which half a given statement came from.  That is what this
module is for: it does not discover anything, it only re-homes both halves into
one shape where every element carries ``source`` and ``confidence``.

Provenance vocabulary (:data:`SOURCES`):

``source_static``
    Measured from source by the miner.  Confidence 1.0: the miner refuses to
    emit an evidence-free field, so an element with this source is backed by a
    concrete line of code.
``llm_inference``
    Voted out of several LLM samples.  Confidence is sample validity times mean
    field agreement -- how stable the vote was -- not a calibrated probability.
``engineering_choice``
    A default this IR supplied because nothing measured it (for example a
    fallback command-loop bound).  It is a decision, not a finding.
``unknown``
    Explicitly unresolved.  Carried as a first-class value rather than dropped,
    so the prompt can say "this is not known" instead of being handed a guess.

The C-block dataclasses (:class:`SequenceModel`, :class:`ContextModel`,
:class:`StatefulOperation`) are **re-exported** from
:mod:`protocol_conventions` rather than redefined here.  They already are the
canonical definitions and are consumed by the inference code; a second class of
the same name would silently break ``isinstance`` checks and the package
``__all__``.

Typical use::

    from harness_generation.protocol_ir import ProtocolIR

    ir = ProtocolIR.from_facts_and_conventions(facts, conventions)
    document = ir.to_protocol_contract()   # protocol.json shaped
    restored = ProtocolIR.from_json(ir.to_json())   # the same IR again
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field as dataclass_field
from typing import Any, Iterable, Mapping

from .protocol_conventions import (
    ContextModel,
    PROTOCOL_CONVENTION_SCHEMA_VERSION,
    ProtocolConventions,
    SequenceModel,
    StatefulOperation,
)
from .protocol_miner import (
    ROLE_PAYLOAD_LENGTH,
    Evidence,
    FieldFact,
    ProtocolFacts,
    ProtocolMinerError,
)
from .protocol_spec import PROTOCOL_SPEC_SCHEMA_VERSION


PROTOCOL_IR_SCHEMA_VERSION = 1

# Provenance vocabulary.  See the module docstring for the meaning of each.
SOURCE_STATIC = "source_static"
SOURCE_LLM = "llm_inference"
SOURCE_ENGINEERING = "engineering_choice"
SOURCE_UNKNOWN = "unknown"
SOURCES = (SOURCE_STATIC, SOURCE_LLM, SOURCE_ENGINEERING, SOURCE_UNKNOWN)

#: Width marker for a field whose size is decided by another field at runtime.
VARIABLE_WIDTH = "variable"

# Confidence is derived from provenance, never invented per element.  The LLM
# value is overridden per-instance with the observed sample agreement ratio.
_CONFIDENCE_BY_SOURCE = {
    SOURCE_STATIC: 1.0,
    SOURCE_ENGINEERING: 1.0,
    SOURCE_UNKNOWN: 0.0,
}
DEFAULT_LLM_CONFIDENCE = 0.6

# Named constants whose value coincides with `max_payload`; these prefixes pick
# the intended one when several constants share the value.
_PAYLOAD_SYMBOL_HINTS = ("max_payload", "max_body", "max_len", "payload_limit", "body_limit")


class ProtocolIRError(ValueError):
    """Raised when the two halves cannot be merged into one coherent IR."""


@dataclass(frozen=True)
class ProtocolEvidence:
    """One justification, from source or from an LLM."""

    source: str
    detail: str
    kind: str = ""
    location: str = ""
    line: int | None = None
    column: int | None = None
    snippet: str = ""

    @classmethod
    def from_miner_evidence(
        cls, evidence: Evidence, filename: str = "",
    ) -> ProtocolEvidence:
        """Re-home a miner :class:`~protocol_miner.Evidence` as static provenance."""

        location = f"{filename}:{evidence.line}:{evidence.column}" if filename else (
            f"{evidence.line}:{evidence.column}"
        )
        return cls(
            source=SOURCE_STATIC,
            detail=evidence.detail,
            kind=evidence.kind,
            location=location,
            line=evidence.line,
            column=evidence.column,
            snippet=evidence.snippet,
        )

    @classmethod
    def from_convention_text(cls, text: str) -> ProtocolEvidence:
        """Re-home one free-text convention sample as LLM provenance."""

        return cls(source=SOURCE_LLM, detail=text)

    @classmethod
    def from_engineering_choice(cls, detail: str) -> ProtocolEvidence:
        return cls(source=SOURCE_ENGINEERING, detail=detail)

    @classmethod
    def unresolved(cls, detail: str) -> ProtocolEvidence:
        return cls(source=SOURCE_UNKNOWN, detail=detail)

    def to_json(self) -> dict[str, Any]:
        document: dict[str, Any] = {"source": self.source, "detail": self.detail}
        for key, value in (
            ("kind", self.kind),
            ("location", self.location),
            ("line", self.line),
            ("column", self.column),
            ("snippet", self.snippet),
        ):
            if value not in ("", None):
                document[key] = value
        return document

    @classmethod
    def from_json(cls, document: Mapping[str, Any],
                  owner: str = "evidence") -> ProtocolEvidence:
        """Rebuild one justification from the document :meth:`to_json` wrote."""

        document = _document_object(document, owner)
        return cls(
            source=_required_string(document, "source", owner),
            detail=_required_string(document, "detail", owner),
            kind=_optional_string(document, "kind", owner),
            location=_optional_string(document, "location", owner),
            line=_optional_integer(document, "line", owner),
            column=_optional_integer(document, "column", owner),
            snippet=_optional_string(document, "snippet", owner),
        )


@dataclass(frozen=True)
class StateVariable:
    """A context member named by typed operation evidence."""

    name: str
    owner: str
    evidence: tuple[ProtocolEvidence, ...]


@dataclass(frozen=True)
class FieldRelation:
    """A source-backed relation between a length field and its payload.

    ``parse`` describes the measured on-wire dependency.  ``construct`` is a
    harness policy and must never be inferred merely from a parser load.
    """

    kind: str
    target: str
    direction: str
    source: str = SOURCE_STATIC
    confidence: float = 1.0
    evidence: tuple[ProtocolEvidence, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in {"size_of", "count_of", "offset_of"} or self.direction not in {
            "parse", "construct"
        }:
            raise ProtocolIRError("unsupported field relation")
        if not self.target or self.source not in SOURCES:
            raise ProtocolIRError("field relation requires a target and provenance")
        if not self.evidence:
            raise ProtocolIRError("field relation requires source evidence")

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind, "target": self.target, "direction": self.direction,
            "source": self.source, "confidence": self.confidence,
            "evidence": [item.to_json() for item in self.evidence],
        }

    def to_contract_block(self) -> dict[str, str]:
        return {"kind": self.kind, "target": self.target, "direction": self.direction}

    @classmethod
    def from_json(cls, document: Mapping[str, Any], owner: str) -> FieldRelation:
        document = _document_object(document, owner)
        return cls(
            kind=_required_string(document, "kind", owner),
            target=_required_string(document, "target", owner),
            direction=_required_string(document, "direction", owner),
            source=_required_string(document, "source", owner),
            confidence=_required_number(document, "confidence", owner),
            evidence=_evidence_tuple(_required(document, "evidence", owner), owner),
        )


# P1's size relation is the size_of member of the general field-relation model.
SizeRelation = FieldRelation


@dataclass(frozen=True)
class FrameField:
    """One field of the frame, with its provenance intact.

    ``width`` is an ``int`` for fixed-width fields and :data:`VARIABLE_WIDTH` (or
    the name of the field that sizes it) when the width is decided at runtime.
    """

    name: str
    offset: int
    width: int | str
    role: str
    value: str = ""
    endianness: str | None = None
    evidence: tuple[ProtocolEvidence, ...] = ()
    source: str = SOURCE_STATIC
    confidence: float = 1.0
    relation: FieldRelation | None = None

    def __post_init__(self) -> None:
        if self.source not in SOURCES:
            raise ProtocolIRError(f"unknown provenance {self.source!r}")
        if self.offset < 0:
            raise ProtocolIRError(f"field {self.name!r} has a negative offset")
        if isinstance(self.width, int) and self.width == 0:
            raise ProtocolIRError(f"field {self.name!r} has zero width")

    @property
    def is_variable_width(self) -> bool:
        return not isinstance(self.width, int)

    @property
    def size(self) -> SizeRelation | None:
        """The typed size relation, when this field has one."""
        return self.relation if self.relation and self.relation.kind == "size_of" else None

    def to_json(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "name": self.name,
            "role": self.role,
            "offset": self.offset,
            "width": self.width,
            "value": self.value,
        }
        if self.endianness:
            document["endianness"] = self.endianness
        document["source"] = self.source
        document["confidence"] = self.confidence
        document["evidence"] = [item.to_json() for item in self.evidence]
        if self.relation is not None:
            document["relation"] = self.relation.to_json()
        return document

    def to_contract_block(self) -> dict[str, Any]:
        """The LLM-facing projection: no provenance, ``width`` as written."""

        document: dict[str, Any] = {
            "name": self.name,
            "offset": self.offset,
            "width": self.width,
            "value": self.value,
        }
        if self.endianness:
            document["endianness"] = self.endianness
        if self.relation is not None:
            document["relation"] = self.relation.to_contract_block()
        return document

    @classmethod
    def from_json(cls, document: Mapping[str, Any],
                  owner: str = "frame field") -> FrameField:
        """Rebuild one field from the document :meth:`to_json` wrote.

        ``source`` is required rather than defaulted to the dataclass default:
        a field whose document never says where the fact came from must not be
        loaded as :data:`SOURCE_STATIC`, because that is exactly the "measured"
        claim this module exists to keep honest.
        """

        document = _document_object(document, owner)
        width = _required(document, "width", owner)
        if isinstance(width, bool) or not isinstance(width, (int, str)):
            raise ProtocolIRError(f"{owner}.width must be an integer or a string")
        source = _required_string(document, "source", owner)
        if source not in SOURCES:
            raise ProtocolIRError(
                f"{owner}.source must be one of {', '.join(SOURCES)}"
            )
        return cls(
            name=_required_string(document, "name", owner),
            offset=_required_integer(document, "offset", owner),
            width=width,
            role=_required_string(document, "role", owner),
            value=_required_string(document, "value", owner),
            endianness=_optional_string(document, "endianness", owner, default=None),
            evidence=_evidence_tuple(_required(document, "evidence", owner), owner),
            source=source,
            confidence=_required_number(document, "confidence", owner),
            relation=(
                FieldRelation.from_json(document["relation"], f"{owner}.relation")
                if "relation" in document else None
            ),
        )


@dataclass(frozen=True)
class FrameModel:
    """The A block (fields) plus the B block scalars that bound it."""

    fields: tuple[FrameField, ...] = ()
    header_size: int | None = None
    payload_offset: int | None = None
    max_payload: int | None = None
    max_payload_symbol: str = ""
    evidence: tuple[ProtocolEvidence, ...] = ()

    def __post_init__(self) -> None:
        offsets = [item.offset for item in self.fields]
        if len(set(offsets)) != len(offsets):
            raise ProtocolIRError("frame fields must not share an offset")
        names = {item.name for item in self.fields}
        for item in self.fields:
            if item.relation is not None and item.relation.target not in names:
                raise ProtocolIRError(
                    f"field {item.name!r} relation targets unknown field "
                    f"{item.relation.target!r}"
                )
        if (
            self.payload_offset is not None
            and self.header_size is not None
            and self.payload_offset < self.header_size
        ):
            raise ProtocolIRError(
                f"payload base {self.payload_offset} falls inside the "
                f"{self.header_size}-byte header"
            )

    @property
    def variable_width_fields(self) -> tuple[FrameField, ...]:
        return tuple(item for item in self.fields if item.is_variable_width)

    def to_json(self) -> dict[str, Any]:
        return {
            "header_size": self.header_size,
            "payload_offset": self.payload_offset,
            "max_payload": self.max_payload,
            "max_payload_symbol": self.max_payload_symbol,
            "evidence": [item.to_json() for item in self.evidence],
            "fields": [item.to_json() for item in self.fields],
        }

    def to_contract_block(self) -> dict[str, Any]:
        """Match the hand-written contract: `max_payload` prefers the symbol."""

        return {
            "header_size": self.header_size,
            "payload_offset": self.payload_offset,
            "max_payload": self.max_payload_symbol or self.max_payload,
            "fields": [item.to_contract_block() for item in self.fields],
        }

    @classmethod
    def from_json(cls, document: Mapping[str, Any],
                  owner: str = "frame") -> FrameModel:
        """Rebuild the A/B block from the document :meth:`to_json` wrote."""

        document = _document_object(document, owner)
        fields = _required(document, "fields", owner)
        if not isinstance(fields, list):
            raise ProtocolIRError(f"{owner}.fields must be an array")
        return cls(
            fields=tuple(
                FrameField.from_json(item, f"{owner}.fields[{index}]")
                for index, item in enumerate(fields)
            ),
            header_size=_optional_integer(document, "header_size", owner),
            payload_offset=_optional_integer(document, "payload_offset", owner),
            max_payload=_optional_integer(document, "max_payload", owner),
            max_payload_symbol=_required_string(document, "max_payload_symbol", owner),
            evidence=_evidence_tuple(_required(document, "evidence", owner), owner),
        )


@dataclass(frozen=True)
class ProtocolIR:
    """The unified protocol model: A/B measurements plus C inferences."""

    entry_function: str
    frame: FrameModel
    sequence: SequenceModel | None = None
    context: ContextModel | None = None
    stateful_operations: tuple[StatefulOperation, ...] = ()
    requirements: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    source_name: str = ""
    llm_confidence: float = DEFAULT_LLM_CONFIDENCE
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    # -- construction ------------------------------------------------------

    @classmethod
    def from_facts_and_conventions(
        cls,
        facts: ProtocolFacts,
        conventions: ProtocolConventions | None = None,
        *,
        default_max_steps: int | None = None,
        strict: bool = False,
    ) -> ProtocolIR:
        """Merge the two halves.

        ``conventions`` is optional: the miner runs without an LLM, and when the
        C block is absent the IR says so in ``limitations`` instead of inventing
        one.  ``default_max_steps`` is recorded as an engineering choice so a
        fallback loop bound is never mistaken for a measured one.
        """

        if conventions is not None and conventions.entry_function != facts.entry_function:
            raise ProtocolIRError(
                f"conventions describe {conventions.entry_function!r} but facts "
                f"describe {facts.entry_function!r}"
            )

        limitations = list(facts.limitations)
        if strict:
            unsupported = facts.fields_without_evidence()
            if unsupported:
                raise ProtocolMinerError(
                    "fields without source evidence: " + ", ".join(sorted(unsupported))
                )
            length = next(
                (item for item in facts.fields if item.role == ROLE_PAYLOAD_LENGTH), None
            )
            if length is not None and any(item.width < 0 for item in facts.fields):
                if not length.evidence:
                    raise ProtocolMinerError("size relation has no length-field evidence")
                for item in facts.fields:
                    if item.width < 0 and not item.evidence:
                        raise ProtocolMinerError(
                            f"size relation for {item.name} has no payload evidence"
                        )
        frame = _frame_model(facts, limitations)
        if strict and conventions is not None:
            for operation in conventions.stateful_operations:
                for symbol in (
                    *operation.writes, *operation.reads, *operation.guard_symbols
                ):
                    if not any(_has_symbol(line, symbol) for line in operation.evidence):
                        raise ProtocolMinerError(
                            f"state symbol {symbol} for {operation.opcode} has no evidence"
                        )

        if conventions is None:
            limitations.append(
                "convention block is absent: command loop, context lifetime and "
                "stateful opcodes are unknown"
            )
            return cls(
                entry_function=facts.entry_function,
                frame=frame,
                limitations=tuple(limitations),
                source_name=facts.filename,
            )

        confidence = _llm_confidence(conventions)
        sequence = conventions.sequence_model
        if default_max_steps is not None and sequence.max_steps.get("value") is None:
            sequence = SequenceModel(
                multi_frame=sequence.multi_frame,
                reason=sequence.reason,
                evidence=sequence.evidence,
                max_steps={
                    "value": default_max_steps,
                    "source": SOURCE_ENGINEERING,
                    "evidence": [
                        f"no measured bound; defaulted to {default_max_steps} "
                        f"as an engineering choice"
                    ],
                },
            )

        return cls(
            entry_function=facts.entry_function,
            frame=frame,
            sequence=sequence,
            context=conventions.context,
            stateful_operations=conventions.stateful_operations,
            requirements=conventions.requirements,
            notes=conventions.notes,
            limitations=tuple(limitations),
            source_name=facts.filename,
            llm_confidence=confidence,
            metadata=dict(conventions.metadata),
        )

    @classmethod
    def from_json(cls, document: Mapping[str, Any]) -> ProtocolIR:
        """Rebuild the IR from the document :meth:`to_json` produced.

        This is the inverse of :meth:`to_json` and it is deliberately not a
        lenient reader.  Every key ``to_json`` always writes is required here,
        so a truncated, hand-mangled or half-written ``protocol_ir.json`` raises
        :class:`ProtocolIRError` instead of loading as an IR that is silently
        missing facts -- a consumer told "the frame has no length field" cannot
        tell that from "the length field was lost on the way back in", and the
        harness that follows would be built on the difference.

        Two shapes need care on the way in:

        * The C block keys are re-read from their own documents, and the
          ``source``/``confidence`` keys :meth:`to_json` *injects* into them are
          ignored: they are projections of the IR-level ``confidence``, which is
          where this loader reads them from.  ``max_steps`` is preserved exactly
          as written rather than normalised into the three keys the vote usually
          fills, so an empty block stays empty instead of coming back as a
          different statement.
        * ``header_size``, ``payload_offset`` and ``max_payload`` are nullable
          in the document, so an explicit ``null`` and an absent key both load as
          ``None``.
        """

        document = _document_object(document, "protocol IR")
        version = document.get("schema_version")
        if version != PROTOCOL_IR_SCHEMA_VERSION:
            raise ProtocolIRError(
                f"protocol IR.schema_version must be {PROTOCOL_IR_SCHEMA_VERSION}"
            )

        sequence = document.get("sequence_model")
        if sequence is not None:
            sequence = _sequence_model_from_document(sequence)
        context = document.get("context")
        if context is not None:
            context = _context_model_from_document(context)
        operations = _required(document, "stateful_operations", "protocol IR")
        if not isinstance(operations, list):
            raise ProtocolIRError("protocol IR.stateful_operations must be an array")

        ir = cls(
            entry_function=_required_string(document, "entry_function", "protocol IR"),
            frame=FrameModel.from_json(_required(document, "frame", "protocol IR")),
            sequence=sequence,
            context=context,
            stateful_operations=tuple(
                _stateful_operation_from_document(item, f"stateful_operations[{index}]")
                for index, item in enumerate(operations)
            ),
            requirements=_string_list(document, "requirements", "protocol IR"),
            notes=_string_list(document, "notes", "protocol IR"),
            limitations=_string_list(document, "limitations", "protocol IR"),
            source_name=_required_string(document, "source", "protocol IR"),
            llm_confidence=_confidence(document, "protocol IR"),
            metadata=_metadata_from_document(_required(document, "metadata", "protocol IR")),
        )
        if "state_variables" in document and document["state_variables"] != [
            {"name": item.name, "owner": item.owner,
             "evidence": [entry.to_json() for entry in item.evidence]}
            for item in ir.state_variables
        ]:
            raise ProtocolIRError(
                "protocol IR.state_variables must match evidenced stateful operations"
            )
        return ir

    # -- views -------------------------------------------------------------

    def field_by_name(self, name: str) -> FrameField | None:
        for item in self.frame.fields:
            if item.name == name:
                return item
        return None

    def fields_by_role(self, role: str) -> tuple[FrameField, ...]:
        return tuple(item for item in self.frame.fields if item.role == role)

    @property
    def state_variables(self) -> tuple[StateVariable, ...]:
        """Context members supported by stateful-operation evidence."""

        names = sorted({
            symbol
            for operation in self.stateful_operations
            for symbol in (*operation.writes, *operation.reads, *operation.guard_symbols)
        })
        owner = self.context.type if self.context is not None else ""
        return tuple(StateVariable(
            name=name,
            owner=owner,
            evidence=tuple(
                ProtocolEvidence.from_convention_text(line)
                for line in dict.fromkeys(
                    line for operation in self.stateful_operations
                    for line in operation.evidence if _has_symbol(line, name)
                )
            ),
        ) for name in names)

    def evidence_index(self) -> tuple[ProtocolEvidence, ...]:
        """Every justification in the IR, from both halves, in one sequence.

        This is what makes the IR *unified* for consumers that care about
        provenance: an audit can ask for all evidence at once, or filter by
        ``source``, without knowing which half an element came from.
        """

        index: list[ProtocolEvidence] = list(self.frame.evidence)
        for item in self.frame.fields:
            index.extend(item.evidence)
        if self.sequence is not None:
            index.extend(
                ProtocolEvidence.from_convention_text(text)
                for text in self.sequence.evidence
            )
            index.extend(
                ProtocolEvidence.from_convention_text(text)
                for text in self.sequence.max_steps.get("evidence", [])
            )
        if self.context is not None:
            index.extend(
                ProtocolEvidence.from_convention_text(text)
                for text in self.context.evidence
            )
        for operation in self.stateful_operations:
            index.extend(
                ProtocolEvidence.from_convention_text(text)
                for text in operation.evidence
            )
        index.extend(
            ProtocolEvidence.from_convention_text(text) for text in self.requirements
        )
        index.extend(
            ProtocolEvidence.from_convention_text(text) for text in self.notes
        )
        return tuple(index)

    def unresolved_fields(self) -> tuple[str, ...]:
        """Field names whose provenance or shape is still open."""

        return tuple(
            item.name
            for item in self.frame.fields
            if item.source == SOURCE_UNKNOWN or not item.evidence
        )

    # -- serialisation -----------------------------------------------------

    def to_json(self) -> dict[str, Any]:
        """The full IR, provenance included."""

        document: dict[str, Any] = {
            "schema_version": PROTOCOL_IR_SCHEMA_VERSION,
            "entry_function": self.entry_function,
            "source": self.source_name,
            "confidence": self.llm_confidence,
            "frame": self.frame.to_json(),
            "requirements": list(self.requirements),
            "notes": list(self.notes),
            "limitations": list(self.limitations),
            "metadata": dict(self.metadata),
        }
        if self.sequence is not None:
            document["sequence_model"] = {
                **self.sequence.to_json(),
                "source": SOURCE_LLM,
                "confidence": self.llm_confidence,
            }
        if self.context is not None:
            document["context"] = {
                **self.context.to_json(),
                "source": SOURCE_LLM,
                "confidence": self.llm_confidence,
            }
        document["stateful_operations"] = [
            {
                **item.to_json(),
                "source": SOURCE_LLM,
                "confidence": self.llm_confidence,
            }
            for item in self.stateful_operations
        ]
        if self.state_variables:
            document["state_variables"] = [
                {"name": item.name, "owner": item.owner,
                 "evidence": [entry.to_json() for entry in item.evidence]}
                for item in self.state_variables
            ]
        return document

    def to_protocol_contract(self) -> dict[str, Any]:
        """Render a ``protocol.json`` document that :func:`load_protocol_spec` accepts.

        ``schema_version`` deliberately reuses
        :data:`~protocol_spec.PROTOCOL_SPEC_SCHEMA_VERSION` rather than the IR's
        own version: the output of this method is a contract, and it has to
        round-trip through the loader.
        """

        contract: dict[str, Any] = {"frame": self.frame.to_contract_block()}
        if self.sequence is not None:
            command_loop: dict[str, Any] = {"preferred": self.sequence.multi_frame}
            max_steps = self.sequence.max_steps.get("value")
            if max_steps is not None:
                command_loop["max_steps"] = max_steps
            if self.sequence.reason:
                command_loop["reason"] = self.sequence.reason
                contract["input_model"] = self.sequence.reason
            contract["command_loop"] = command_loop
        if self.context is not None:
            contract["context"] = _context_block(self.context)
        if self.stateful_operations:
            contract["stateful_operations"] = [
                {"opcode": item.opcode, **({"reason": item.reason} if item.reason else {})}
                for item in self.stateful_operations
            ]

        document: dict[str, Any] = {
            "schema_version": PROTOCOL_SPEC_SCHEMA_VERSION,
            "entry_function": self.entry_function,
            "contract": contract,
        }
        if self.requirements:
            document["requirements"] = list(self.requirements)
        if self.notes:
            document["notes"] = list(self.notes)
        if self.limitations:
            document["limitations"] = list(self.limitations)
        return document


# --------------------------------------------------------------------------
# builders
# --------------------------------------------------------------------------


def _frame_model(facts: ProtocolFacts, limitations: list[str]) -> FrameModel:
    """Project the miner's facts onto :class:`FrameModel`."""

    length_name = _length_field_name(facts)
    length_fact = next(
        (item for item in facts.fields if item.role == ROLE_PAYLOAD_LENGTH), None
    )
    fields: list[FrameField] = []
    for item in facts.fields:
        evidence = tuple(
            ProtocolEvidence.from_miner_evidence(entry, facts.filename)
            for entry in item.evidence
        )
        width: int | str = item.width
        if item.width < 0:
            width = length_name or VARIABLE_WIDTH
        name = item.suggested_name or item.name
        source = SOURCE_STATIC if evidence else SOURCE_UNKNOWN
        relation = None
        if item.width < 0 and length_name and length_fact is not None:
            relation_evidence = tuple(
                ProtocolEvidence.from_miner_evidence(entry, facts.filename)
                for entry in (*length_fact.evidence, *item.evidence)
            )
            if relation_evidence:
                relation = FieldRelation(
                    "size_of", name, "parse", evidence=relation_evidence
                )
        fields.append(FrameField(
            name=name,
            offset=item.offset,
            width=width,
            role=item.role,
            value=item.value,
            endianness=item.endianness,
            evidence=evidence,
            source=source,
            confidence=_CONFIDENCE_BY_SOURCE[source],
            relation=relation,
        ))

    evidence: list[ProtocolEvidence] = []
    for entry in facts.header_size_evidence:
        evidence.append(ProtocolEvidence.from_miner_evidence(entry, facts.filename))
    for entry in facts.max_payload_evidence:
        evidence.append(ProtocolEvidence.from_miner_evidence(entry, facts.filename))

    symbol = _max_payload_symbol(facts)
    if facts.max_payload is not None and not symbol:
        limitations.append(
            f"max payload {facts.max_payload} has no named constant behind it; "
            "the value is emitted without a symbol"
        )

    return FrameModel(
        fields=tuple(fields),
        header_size=facts.header_size,
        payload_offset=_resolve_payload_offset(facts, limitations),
        max_payload=facts.max_payload,
        max_payload_symbol=symbol,
        evidence=tuple(evidence),
    )


def _resolve_payload_offset(facts: ProtocolFacts, limitations: list[str]) -> int | None:
    """Payload base for the frame, preferring the miner's measured offset.

    Falls back to the header size when the miner did not establish one (older
    facts, or a parser with no ``data + K`` expression).  A measured base that
    falls *inside* the header is contradictory -- it means the only ``data + K``
    the miner saw was a header field load, not the payload -- so the header size
    wins and the conflict is recorded rather than silently published.
    """

    header = facts.header_size
    base = facts.resolved_payload_offset
    if base is None:
        return None
    if header is not None and base < header:
        limitations.append(
            f"measured payload base {base} falls inside the {header}-byte header; "
            "falling back to the header size"
        )
        return header
    return base


def _length_field_name(facts: ProtocolFacts) -> str:
    """Name of the field that sizes variable-width fields, if there is one."""

    for item in facts.fields:
        if item.role == ROLE_PAYLOAD_LENGTH:
            return item.suggested_name or item.name
    return ""


def _max_payload_symbol(facts: ProtocolFacts) -> str:
    """Recover the *name* of the max-payload constant behind the mined value.

    The miner resolves constants to integers, so the symbol has to be matched
    back by value.  When several constants share the value the hint prefixes
    break the tie; if that is still ambiguous the symbol is dropped rather than
    guessed, because the numeric value is the authoritative part.
    """

    if facts.max_payload is None:
        return ""
    candidates = [item for item in facts.constants if item.value == facts.max_payload]
    if not candidates:
        return ""
    if len(candidates) == 1:
        return candidates[0].name
    hinted = [
        item for item in candidates
        if any(hint in item.name.lower() for hint in _PAYLOAD_SYMBOL_HINTS)
    ]
    if len(hinted) == 1:
        return hinted[0].name
    return ""


def _llm_confidence(conventions: ProtocolConventions | None) -> float:
    """How stable the C-block inference was: sample validity x field agreement.

    Two things have to hold before an inferred convention can be relied on, and
    the number has to move when either one fails.  The samples must have parsed
    (``sample_validity``), and they must have *said the same thing*
    (``mean_field_agreement``).  Three samples that all parse but give three
    different answers are a coin flip, and they must not score the way three
    samples that agreed do; the old ratio of parsed samples could not tell those
    two apart.

    This is still not a probability that the statement is true.  It is a
    statement about the inference: a field the samples agreed on unanimously can
    still be unanimously wrong.

    The value is *read* from the vote summary, never recomputed here:
    :mod:`protocol_conventions` owns the arithmetic, and a second implementation
    could disagree with the summary a reader audits.  Artifacts written before
    the summary existed, and hand-built :class:`ProtocolConventions` in tests,
    carry no ``vote_summary``; those fall back to the parsed-sample ratio they
    were scored with, and then to :data:`DEFAULT_LLM_CONFIDENCE`.
    """

    if conventions is None:
        return DEFAULT_LLM_CONFIDENCE
    metadata = conventions.metadata or {}
    recorded = _recorded_confidence(metadata)
    if recorded is not None:
        return recorded
    requested = metadata.get("samples_requested")
    valid = metadata.get("valid_samples")
    if isinstance(requested, int) and isinstance(valid, int) and requested > 0:
        return round(min(max(valid / requested, 0.0), 1.0), 4)
    return DEFAULT_LLM_CONFIDENCE


def _recorded_confidence(metadata: Mapping[str, Any]) -> float | None:
    """The confidence the vote recorded, or ``None`` when it did not record one.

    Defensive on purpose: this reads a number out of a document an LLM-adjacent
    pipeline wrote and a human may have edited, and a bad value must fall through
    to the older fallback rather than propagate.  Non-numeric, ``NaN``, infinite,
    negative and greater-than-one values are all rejected -- and a ``bool`` with
    them, because ``True`` is an ``int`` in Python and would otherwise sail
    through as 1.0.
    """

    summary = metadata.get("vote_summary")
    if not isinstance(summary, Mapping):
        return None
    confidence = summary.get("confidence")
    if not isinstance(confidence, Mapping):
        return None
    value = confidence.get("value")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        return None
    return round(float(value), 4)


def _context_block(context: ContextModel) -> dict[str, Any]:
    """The LLM-facing context block: the four fields, without vote evidence."""

    return {
        "type": context.type,
        "init": context.init,
        "destroy": context.destroy,
        "lifetime": context.lifetime,
    }


# --------------------------------------------------------------------------
# deserialisation
# --------------------------------------------------------------------------
#
# One rule decides what :meth:`ProtocolIR.from_json` requires: a key whose value
# ``to_json`` always writes is required here, and a key it writes conditionally
# falls back to its dataclass default.  A missing required key therefore means
# the document was not written by ``to_json``, which is a fact worth failing on.
#
# The C-block loaders live here rather than as ``from_json`` classmethods on
# :mod:`protocol_conventions` because they are the inverse of how the *IR*
# serialises those objects -- with the ``source``/``confidence`` keys the IR
# injects -- and because every failure in this module is a
# :class:`ProtocolIRError`, which is defined here and which
# ``protocol_conventions`` cannot import without a cycle.


def _document_object(value: Any, owner: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProtocolIRError(f"{owner} must be a JSON object")
    return value


def _required(document: Mapping[str, Any], key: str, owner: str) -> Any:
    if key not in document:
        raise ProtocolIRError(f"{owner} is missing {key!r}")
    return document[key]


def _string(value: Any, owner: str, key: str) -> str:
    if not isinstance(value, str):
        raise ProtocolIRError(f"{owner}.{key} must be a string")
    return value


def _required_string(document: Mapping[str, Any], key: str, owner: str) -> str:
    return _string(_required(document, key, owner), owner, key)


def _optional_string(document: Mapping[str, Any], key: str, owner: str,
                     default: str | None = "") -> str | None:
    value = document.get(key, default)
    if value is None:
        return default
    return _string(value, owner, key)


def _integer(value: Any, owner: str, key: str) -> int:
    # ``True`` is an ``int`` in Python, so a boolean has to be rejected before
    # the numeric check rather than by it.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolIRError(f"{owner}.{key} must be an integer")
    return value


def _required_integer(document: Mapping[str, Any], key: str, owner: str) -> int:
    return _integer(_required(document, key, owner), owner, key)


def _optional_integer(document: Mapping[str, Any], key: str,
                      owner: str) -> int | None:
    value = document.get(key)
    return None if value is None else _integer(value, owner, key)


def _required_number(document: Mapping[str, Any], key: str, owner: str) -> float:
    value = _required(document, key, owner)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProtocolIRError(f"{owner}.{key} must be a number")
    return float(value)


def _required_boolean(document: Mapping[str, Any], key: str, owner: str) -> bool:
    value = _required(document, key, owner)
    if not isinstance(value, bool):
        raise ProtocolIRError(f"{owner}.{key} must be a boolean")
    return value


def _string_list(document: Mapping[str, Any], key: str, owner: str) -> tuple[str, ...]:
    value = _required(document, key, owner)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ProtocolIRError(f"{owner}.{key} must be an array of strings")
    return tuple(value)


def _evidence_tuple(value: Any, owner: str) -> tuple[ProtocolEvidence, ...]:
    if not isinstance(value, list):
        raise ProtocolIRError(f"{owner}.evidence must be an array")
    return tuple(
        ProtocolEvidence.from_json(item, f"{owner}.evidence[{index}]")
        for index, item in enumerate(value)
    )


def _confidence(document: Mapping[str, Any], owner: str) -> float:
    value = _required_number(document, "confidence", owner)
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ProtocolIRError(f"{owner}.confidence must be between 0 and 1")
    return value


def _metadata_from_document(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProtocolIRError("protocol IR.metadata must be a JSON object")
    return dict(value)


def _max_steps_from_document(value: Any, owner: str) -> dict[str, Any]:
    """The command-loop bound, checked and otherwise kept as written.

    The three keys the vote fills (``value``, ``source``, ``evidence``) are
    type-checked when they are present, but the mapping is not normalised into
    them: ``SequenceModel`` defaults ``max_steps`` to ``{}`` and normalising
    would make that empty block load back as an explicit ``value: null``, which
    is a different statement about the loop bound than an absent one.
    """

    block = _document_object(_required(value, "max_steps", owner), f"{owner}.max_steps")
    if block.get("value") is not None:
        _integer(block.get("value"), f"{owner}.max_steps", "value")
    if block.get("source") is not None:
        _string(block.get("source"), f"{owner}.max_steps", "source")
    evidence = block.get("evidence")
    if evidence is not None and (
        not isinstance(evidence, list)
        or any(not isinstance(item, str) for item in evidence)
    ):
        raise ProtocolIRError(f"{owner}.max_steps.evidence must be an array of strings")
    return dict(block)


def _sequence_model_from_document(document: Any,
                                  owner: str = "sequence_model") -> SequenceModel:
    document = _document_object(document, owner)
    return SequenceModel(
        multi_frame=_required_boolean(document, "multi_frame", owner),
        reason=_required_string(document, "reason", owner),
        evidence=_string_list(document, "evidence", owner),
        max_steps=_max_steps_from_document(document, owner),
    )


def _context_model_from_document(document: Any,
                                 owner: str = "context") -> ContextModel:
    document = _document_object(document, owner)
    return ContextModel(
        type=_required_string(document, "type", owner),
        init=_required_string(document, "init", owner),
        destroy=_required_string(document, "destroy", owner),
        lifetime=_required_string(document, "lifetime", owner),
        evidence=_string_list(document, "evidence", owner),
    )


def _stateful_operation_from_document(
    document: Any, owner: str = "stateful operation",
) -> StatefulOperation:
    document = _document_object(document, owner)
    operation = StatefulOperation(
        opcode=_required_string(document, "opcode", owner),
        reason=_required_string(document, "reason", owner),
        evidence=_string_list(document, "evidence", owner),
        writes=_optional_string_list(document, "writes", owner),
        reads=_optional_string_list(document, "reads", owner),
        guard_symbols=_optional_string_list(document, "guard_symbols", owner),
    )
    for symbol in (*operation.writes, *operation.reads, *operation.guard_symbols):
        if not any(_has_symbol(line, symbol) for line in operation.evidence):
            raise ProtocolIRError(f"{owner} state symbol {symbol!r} has no evidence")
    return operation


def _has_symbol(line: str, symbol: str) -> bool:
    return bool(re.search(rf"(?<!\w){re.escape(symbol)}(?!\w)", line))


def _optional_string_list(document: Mapping[str, Any], key: str,
                          owner: str) -> tuple[str, ...]:
    return _string_list(document, key, owner) if key in document else ()


__all__ = [
    "DEFAULT_LLM_CONFIDENCE",
    "PROTOCOL_IR_SCHEMA_VERSION",
    "SOURCES",
    "SOURCE_ENGINEERING",
    "SOURCE_LLM",
    "SOURCE_STATIC",
    "SOURCE_UNKNOWN",
    "VARIABLE_WIDTH",
    # C-block models, re-exported so `protocol_ir` is a complete surface.
    "ContextModel",
    "SequenceModel",
    "StatefulOperation",
    "StateVariable",
    "FrameField",
    "FieldRelation",
    "SizeRelation",
    "FrameModel",
    "ProtocolEvidence",
    "ProtocolIR",
    "ProtocolIRError",
]
