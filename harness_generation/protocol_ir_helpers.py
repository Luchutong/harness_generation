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
    Deliberately **not** a source.  These are the convention block's own claims,
    and the evidence that backs them is ``context.evidence``, listed below.  An
    expression read as its own justification authorizes every call it happens to
    mention: ``init: "mp_init(&ctx); invented(&ctx)"`` would license
    ``invented``.  :func:`read_lifecycle_expression` reads them for the *name*
    they state and nothing else, and :mod:`.protocol_reconciliation` decides
    whether that name may be called.
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

#: A whole expression that is one call: ``mp_init(&ctx)``, ``malloc(n)``.
_CALL_OPEN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")

#: A whole expression that is one bare name: ``mp_init``.  The miner's own
#: convention sample writes both roles this way, so this is the shape the
#: recorded IRs actually carry.
_BARE_NAME = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*$")

#: What may follow the call's closing parenthesis: nothing, or one statement
#: terminator.  Anything else is a second statement, and a slot that states two
#: things states neither.
_AFTER_CALL = re.compile(r"\s*;?\s*$")

#: A declaration rather than a call: ``mp_context ctx = {0}``, ``struct
#: mp_context ctx;``.  What separates it from prose is the *shape*, and the
#: shape has to be a whole one: an optional sequence of specifiers, the type,
#: the name it declares, then exactly one of an initializer, an array bound or a
#: terminator, and nothing after it.  A bare type and name is a fragment, and
#: the initializer is restricted to the forms this module can read without
#: parsing C -- a braced list, one name, one number.  The restrictions are what
#: keep the match from being a fiction: a slot that half-declares something has
#: not said how the context comes to exist, and ``mp_context ctx; free(ctx)``
#: would otherwise be read as a declaration that silently drops a call.
_DECLARATION = re.compile(
    r"^\s*(?:(?:auto|const|enum|extern|long|register|short|signed|static|struct"
    r"|union|unsigned|volatile)\s+)*"
    r"(?P<type>[A-Za-z_][A-Za-z0-9_]*)\s*\**\s*"
    r"[A-Za-z_][A-Za-z0-9_]*\s*"         # the name it declares
    r"(?:=\s*(?:\{[^{};]*\}|[A-Za-z_][A-Za-z0-9_]*|[0-9]+)\s*;?"
    r"|\[[0-9]+\]\s*;?"
    r"|;)\s*$"
)

#: The shapes a ``context`` slot can take.
LIFECYCLE_CALL = "call"
LIFECYCLE_NAME = "name"
LIFECYCLE_INITIALIZATION = "initialization"
LIFECYCLE_INVALID = "invalid"


@dataclass(frozen=True)
class LifecycleExpression:
    """One ``context.init`` / ``context.destroy`` value, read as C.

    ``kind`` is one of the four :data:`LIFECYCLE_CALL` ... :data:`LIFECYCLE_INVALID`
    constants.  Only the first two name a function, and only those carry one:
    a declaration has nothing to call, and prose has nothing at all.
    """

    text: str
    kind: str
    function: str | None = None
    declared_type: str | None = None


def read_lifecycle_expression(expression: Any) -> LifecycleExpression:
    """Classify one ``context`` slot, and name the function it names.

    A lifecycle slot is a piece of the harness's own control flow -- the plan
    prompt reads it as one -- so it is read as C: one call, one bare name, or one
    declaration.  A sentence is none of those, and reading one as a name (or
    writing it into a binding verbatim) is how a paragraph becomes a call the
    contract appears to require.

    The call has to be the *whole* expression.  ``"mp_init(&ctx); invented(&ctx)"``
    is two statements, and a slot that says two things authorizes neither: taking
    the leading call would read the rest of the string as evidence for it.
    """

    if not isinstance(expression, str) or not expression.strip():
        return LifecycleExpression("", LIFECYCLE_INVALID)

    call = _CALL_OPEN.match(expression)
    if call is not None:
        end = _closing_parenthesis(expression, call.end() - 1)
        if end is None or not _AFTER_CALL.match(expression[end:]):
            return LifecycleExpression(expression, LIFECYCLE_INVALID)
        name = call.group(1)
        if name in _NOT_CALLS:
            return LifecycleExpression(expression, LIFECYCLE_INVALID)
        return LifecycleExpression(expression, LIFECYCLE_CALL, name)

    bare = _BARE_NAME.match(expression)
    if bare is not None:
        name = bare.group(1)
        if name in _NOT_CALLS:
            return LifecycleExpression(expression, LIFECYCLE_INVALID)
        return LifecycleExpression(expression, LIFECYCLE_NAME, name)

    declaration = _DECLARATION.fullmatch(expression)
    if declaration is not None:
        return LifecycleExpression(
            expression, LIFECYCLE_INITIALIZATION,
            declared_type=declaration.group("type"),
        )
    return LifecycleExpression(expression, LIFECYCLE_INVALID)


def _closing_parenthesis(text: str, opened: int) -> int | None:
    """The index just past the ``)`` matching the ``(`` at ``opened``.

    Parentheses nest -- ``malloc(sizeof(mp_context))`` -- and one inside a
    literal is text rather than syntax, so both are counted for.
    """

    depth = 0
    index = opened
    while index < len(text):
        character = text[index]
        if character in "\"'":
            index = _after_literal(text, index)
            if index is None:
                return None
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return None


def _after_literal(text: str, opened: int) -> int | None:
    """The index just past the literal opening at ``opened``, or ``None``."""

    quote = text[opened]
    index = opened + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == quote:
            return index + 1
        index += 1
    return None


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
        # ``context.init`` and ``context.destroy`` are not read here.  They are
        # the convention block's claims, and a claim that justifies itself lets
        # one sentence authorize every call it mentions; the lifecycle's
        # justification is ``context.evidence`` below, and the slot itself is
        # settled by :func:`.protocol_reconciliation.reconcile_protocol_ir`.
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
