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
"""

from __future__ import annotations

import math
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
        return document


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
        frame = _frame_model(facts, limitations)

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

    # -- views -------------------------------------------------------------

    def field_by_name(self, name: str) -> FrameField | None:
        for item in self.frame.fields:
            if item.name == name:
                return item
        return None

    def fields_by_role(self, role: str) -> tuple[FrameField, ...]:
        return tuple(item for item in self.frame.fields if item.role == role)

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
    "FrameField",
    "FrameModel",
    "ProtocolEvidence",
    "ProtocolIR",
    "ProtocolIRError",
]
