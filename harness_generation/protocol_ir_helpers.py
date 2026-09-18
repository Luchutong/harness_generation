"""Protocol-declared helper calls, recovered from ProtocolIR provenance only.

Stage 4 audits the harness it is handed: a harness may call the FT's own
functions plus a small standard-C set, and nothing else.  That rule is what
keeps a generated harness from inventing project APIs.  It also, as written,
makes a *structured* harness impossible: repairing a frame envelope means
calling the protocol's own helpers (checksum, context lifecycle), and those
helpers are frequently not FT members -- the FT is built from the structural
edges an ISF shares with other functions, not from its call closure, so a
callee the ISF calls but shares no struct with never joins the FT.

This module supplies the missing justification.  It does **not** widen the
audit on its own and it deliberately holds no list of function names: every
name it returns was read out of the IR's own provenance, and each one carries
the exact text that justified it.  A helper Stage 4 has never heard of stays
forbidden.

Provenance tiers
----------------
Only sources that carry a location or a snippet are consulted:

``context.init`` / ``context.destroy``
    The context lifecycle expressions, e.g. ``mp_init(&ctx)``.  These are the
    convention block's own claims, and each is backed by ``context.evidence``.
``frame.fields[].value``
    A field's documented access form, e.g. ``le16() load``.
``frame.fields[].evidence``, ``frame.evidence``, ``context.evidence``,
``sequence.evidence``, ``stateful_operations[].evidence``
    Miner evidence (``ProtocolEvidence``) and convention evidence.  The
    checksum comparison is the important one here: its snippet
    ``mp_checksum(data + MP_HEADER_SIZE, len) != le16(data + 6)`` is what makes
    ``mp_checksum`` a legitimate call for a repairing harness.

``requirements`` and ``notes`` are prose written for a human reader.  They are
collected into :attr:`ProtocolHelperSet.weak` and are **never** allowed on
their own -- a sentence hoping the harness will "repair the envelope" must not
be able to authorise a call.  A name that appears in both a strong and a weak
source is allowed, and is reported against its strong origin.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .protocol_ir import ProtocolEvidence, ProtocolIR


#: Every helper this module returns is justified by the IR's own provenance.
SOURCE_PROTOCOL_IR_EVIDENCE = "protocol_ir_evidence"

#: The justification is a recorded snippet or a convention claim, not a guess.
CONFIDENCE_EVIDENCE_BACKED = "evidence_backed"

#: A C call expression: an identifier followed by ``(``, optionally spaced.
#: The identifier is anchored at a word boundary, so ``ctx->saved`` and
#: ``stored`` never match -- only a bare name that opens an argument list.
_CALL_PATTERN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")

#: C keywords that are followed by a parenthesis but are not function calls.
_NOT_CALLS = frozenset({
    "defined", "for", "if", "return", "sizeof", "switch", "while",
})


@dataclass(frozen=True)
class ProtocolHelper:
    """One project helper the protocol declares, with its justification."""

    name: str
    origin: str
    evidence: str
    source: str = SOURCE_PROTOCOL_IR_EVIDENCE
    confidence: str = CONFIDENCE_EVIDENCE_BACKED

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "origin": self.origin,
            "evidence": self.evidence,
            "source": self.source,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class ProtocolHelperSet:
    """Helpers the protocol declares, split by how strong the claim is."""

    helpers: tuple[ProtocolHelper, ...] = ()
    weak: tuple[str, ...] = ()

    @property
    def allowed(self) -> frozenset[str]:
        """Names Stage 4 may treat as declared by the protocol."""

        return frozenset(helper.name for helper in self.helpers)

    def evidence_for(self, name: str) -> tuple[str, ...]:
        return tuple(
            helper.evidence for helper in self.helpers if helper.name == name
        )

    def __bool__(self) -> bool:
        return bool(self.helpers)

    def to_dict(self) -> dict[str, Any]:
        return {
            "helpers": [helper.to_dict() for helper in self.helpers],
            "weak": list(self.weak),
        }


def collect_protocol_helpers(ir: ProtocolIR | None) -> ProtocolHelperSet:
    """Every project helper the IR's provenance names, deduplicated by name.

    Returns an empty set for ``None`` (no IR on disk), so a run without an IR
    keeps the pre-existing FT-only audit exactly as it was.
    """

    if ir is None:
        return ProtocolHelperSet()

    found: dict[str, ProtocolHelper] = {}
    order: list[str] = []

    def record(name: str, origin: str, evidence: str) -> None:
        if name in _NOT_CALLS:
            return
        if name not in found:
            order.append(name)
            found[name] = ProtocolHelper(name=name, origin=origin, evidence=evidence)

    for origin, text in _strong_sources(ir):
        for name in _calls_in(text):
            record(name, origin, text)

    weak = tuple(sorted({
        name
        for text in (*ir.requirements, *ir.notes)
        for name in _calls_in(text)
        if name not in found
    }))
    return ProtocolHelperSet(
        helpers=tuple(found[name] for name in order), weak=weak
    )


def _strong_sources(ir: ProtocolIR) -> Iterable[tuple[str, str]]:
    """``(origin, text)`` for every provenance entry that can authorize a call."""

    yield from _field_sources("frame.fields", ir.frame.fields)
    yield from _evidence_sources("frame.evidence", ir.frame.evidence)

    context = ir.context
    if context is not None:
        if context.init:
            yield "context.init", context.init
        if context.destroy:
            yield "context.destroy", context.destroy
        yield from _plain_sources("context.evidence", context.evidence)

    sequence = ir.sequence
    if sequence is not None:
        yield from _plain_sources("sequence.evidence", sequence.evidence)
        yield from _plain_sources(
            "sequence.max_steps.evidence",
            _strings(sequence.max_steps.get("evidence")),
        )

    for operation in ir.stateful_operations:
        origin = f"stateful_operations[{operation.opcode}].evidence"
        yield from _plain_sources(origin, operation.evidence)


def _field_sources(
    origin: str, fields: Sequence[Any]
) -> Iterable[tuple[str, str]]:
    for field in fields:
        if getattr(field, "value", ""):
            yield f"{origin}[{field.name}].value", str(field.value)
        yield from _evidence_sources(
            f"{origin}[{field.name}].evidence", getattr(field, "evidence", ())
        )


def _evidence_sources(
    origin: str, items: Sequence[Any]
) -> Iterable[tuple[str, str]]:
    """Read both miner ``ProtocolEvidence`` and convention plain strings."""

    for item in items:
        text = _evidence_text(item)
        if text:
            yield origin, text


def _plain_sources(origin: str, items: Sequence[Any]) -> Iterable[tuple[str, str]]:
    for item in items:
        if isinstance(item, str) and item:
            yield origin, item


def _evidence_text(item: Any) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, ProtocolEvidence):
        # ``detail`` explains, ``snippet`` quotes the source.  Both are scanned:
        # the checksum helper is named in the detail, the le16 loader in both.
        return " ".join(part for part in (item.snippet, item.detail) if part)
    return ""


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _calls_in(text: str) -> tuple[str, ...]:
    return tuple(_CALL_PATTERN.findall(text))


def helpers_to_json(helpers: ProtocolHelperSet) -> Mapping[str, Any]:
    """The audit record Stage 4 persists for a contract-driven run."""

    return helpers.to_dict()
