"""Static miner for the frame-format (A) and constant (B) blocks of a protocol contract.

The miner covers the two blocks that are *facts* about the target and therefore
must not be guessed:

* **A — frame format**: field offsets, widths, endianness and literal values.
* **B — constant constraints**: header size, maximum payload, opcode enum range.

Every fact carries :class:`Evidence` (source file, 1-based line/column, and the
exact snippet it was derived from).  Nothing is emitted without evidence, and
:meth:`ProtocolFacts.to_contract` refuses to build a contract when a field has
none.  Whatever the miner cannot decide statically is reported in
``limitations`` so a later completion stage knows precisely what remains open.

The convention block (C: command loop, context lifetime, requirements, notes)
is deliberately out of scope here: it does not live in the parser body at all.

Typical use::

    from harness_generation.protocol_miner import mine_protocol_facts

    facts = mine_protocol_facts(source_bytes, "mp_parse", filename="target.c")
    contract = facts.to_contract()
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .source_analysis import (
    SourceAnalysisError,
    _load_tree_sitter,
    _make_language,
    _make_parser,
    _text,
    _walk,
)


PROTOCOL_MINER_SCHEMA_VERSION = 1

# Roles a frame field can take, ordered by how confidently the miner assigns
# them.  ``unknown`` is a first-class outcome: it is reported, never guessed.
ROLE_MAGIC = "magic"
ROLE_VERSION = "version"
ROLE_OPCODE = "opcode"
ROLE_PAYLOAD_LENGTH = "payload_length"
ROLE_CHECKSUM = "checksum"
ROLE_PAYLOAD = "payload"
ROLE_UNKNOWN = "unknown"

# Evidence kinds.
EV_ENUM_CONSTANT = "enum_constant"
EV_MACRO_CONSTANT = "macro_constant"
EV_MIN_SIZE_GUARD = "min_size_guard"
EV_LITERAL_GUARD = "literal_guard"
EV_SYMBOLIC_LOAD = "symbolic_load"
EV_DISPATCH_SELECTOR = "dispatch_selector"
EV_DISPATCH_CASE = "dispatch_case"
EV_LENGTH_BOUND = "length_bound"
EV_LENGTH_RELATION = "length_relation"
EV_CHECKSUM_COMPARISON = "checksum_comparison"
EV_PAYLOAD_REGION = "payload_region"

_INTEGRAL_TYPES = {
    "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "char", "short", "int", "long", "size_t", "unsigned", "uintptr_t",
}
_BYTE_POINTER_TOKENS = {
    "uint8_t", "int8_t", "char", "unsigned", "signed", "void", "byte",
    "std::byte",
}
_SIZE_PARAMETER_NAMES = {
    "size", "len", "length", "n", "sz", "buf_len", "buffer_len", "data_len",
    "input_len",
}
_DATA_PARAMETER_NAMES = {
    "data", "buf", "buffer", "bytes", "input", "payload", "packet", "msg",
    "message", "p",
}

_HELPER_NAME = re.compile(r"^(?P<prefix>[a-z]{2})(?P<bits>8|16|32|64)$")
_HELPER_ENDIAN_PATTERNS = (
    re.compile(r"^(?P<endian>le|be)(?P<bits>8|16|32|64)$"),
    re.compile(r"(?:^|_)(?:read|get|load|decode)?_?(?:u)?(?P<bits>8|16|32|64)_?(?P<endian>le|be)(?:$|_)"),
    re.compile(r"(?:^|_)(?:read|get|load|decode)?_?(?P<endian>le|be)_?(?:u)?(?P<bits>8|16|32|64)(?:$|_)"),
    re.compile(r"(?:^|_)(?:read|get|load|decode)?_?(?:u?int)?(?P<bits>8|16|32|64)_?(?P<endian>le|be)(?:$|_)"),
)


class ProtocolMinerError(ValueError):
    """Raised when the miner cannot produce an evidence-backed contract."""


@dataclass(frozen=True)
class Evidence:
    """A single source-grounded justification for a fact."""

    kind: str
    line: int
    column: int
    snippet: str
    detail: str

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "detail": self.detail,
        }


@dataclass
class FieldFact:
    """One frame field, as recovered from the parser body."""

    name: str
    offset: int
    width: int
    role: str
    value: str
    endianness: str | None = None
    suggested_name: str | None = None
    evidence: list[Evidence] = dataclass_field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "name": self.suggested_name or self.name,
            "offset": self.offset,
            "width": self.width,
        }
        if self.endianness:
            document["endianness"] = self.endianness
        document["value"] = self.value
        document["role"] = self.role
        document["evidence"] = [item.to_json() for item in self.evidence]
        if self.suggested_name and self.suggested_name != self.name:
            document["structural_name"] = self.name
        return document


@dataclass
class ConstantFact:
    """A named integer constant recovered from an enum or a preprocessor macro."""

    name: str
    value: int | None
    expression: str
    kind: str
    evidence: list[Evidence] = dataclass_field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "expression": self.expression,
            "kind": self.kind,
            "evidence": [item.to_json() for item in self.evidence],
        }


@dataclass
class OpcodeFact:
    """A dispatch case value, resolved through the constant table when possible."""

    name: str
    value: int | None
    evidence: list[Evidence] = dataclass_field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "evidence": [item.to_json() for item in self.evidence],
        }


@dataclass
class ProtocolFacts:
    """Evidence-backed A/B facts plus an explicit list of what is still open."""

    entry_function: str
    filename: str
    fields: list[FieldFact] = dataclass_field(default_factory=list)
    constants: list[ConstantFact] = dataclass_field(default_factory=list)
    opcodes: list[OpcodeFact] = dataclass_field(default_factory=list)
    header_size: int | None = None
    # Where the payload starts.  This is *not* always the header size: a frame
    # can carry a fixed field between the header and the payload.  ``None``
    # means the miner did not establish it, in which case consumers fall back
    # to ``header_size``.
    payload_offset: int | None = None
    max_payload: int | None = None
    header_size_evidence: list[Evidence] = dataclass_field(default_factory=list)
    payload_offset_evidence: list[Evidence] = dataclass_field(default_factory=list)
    max_payload_evidence: list[Evidence] = dataclass_field(default_factory=list)
    limitations: list[str] = dataclass_field(default_factory=list)

    def fields_without_evidence(self) -> list[str]:
        return [item.name for item in self.fields if not item.evidence]

    @property
    def resolved_payload_offset(self) -> int | None:
        """Payload start, falling back to the header size for older facts.

        Facts serialised before ``payload_offset`` existed simply do not carry
        it, and for a plain header+payload frame the header size is the right
        answer anyway.
        """

        if self.payload_offset is not None:
            return self.payload_offset
        return self.header_size

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": PROTOCOL_MINER_SCHEMA_VERSION,
            "entry_function": self.entry_function,
            "source": self.filename,
            "header_size": self.header_size,
            "payload_offset": self.payload_offset,
            "max_payload": self.max_payload,
            "header_size_evidence": [item.to_json() for item in self.header_size_evidence],
            "payload_offset_evidence": [
                item.to_json() for item in self.payload_offset_evidence
            ],
            "max_payload_evidence": [item.to_json() for item in self.max_payload_evidence],
            "fields": [item.to_json() for item in self.fields],
            "constants": [item.to_json() for item in self.constants],
            "opcodes": [item.to_json() for item in self.opcodes],
            "limitations": list(self.limitations),
        }

    def to_contract(self, *, strict: bool = True) -> dict[str, Any]:
        """Build a ``protocol.json``-shaped contract from the mined facts.

        With ``strict`` (the default) the caller gets a hard error instead of a
        contract whose fields cannot be traced back to source.
        """

        unsupported = self.fields_without_evidence()
        if strict and unsupported:
            raise ProtocolMinerError(
                "fields without source evidence: " + ", ".join(sorted(unsupported))
            )
        frame: dict[str, Any] = {
            "header_size": self.header_size,
            "payload_offset": self.resolved_payload_offset,
            "max_payload": self.max_payload,
            "fields": [item.to_json() for item in self.fields],
        }
        return {
            "entry_function": self.entry_function,
            "contract": {"frame": frame},
            "opcodes": [item.to_json() for item in self.opcodes],
            "limitations": list(self.limitations),
        }


# --------------------------------------------------------------------------
# small tree-sitter helpers
# --------------------------------------------------------------------------


def _evidence(node: Any, source: bytes, filename: str, kind: str, detail: str) -> Evidence:
    snippet = _text(source, node).strip()
    if "\n" in snippet:
        snippet = snippet.split("\n", 1)[0].strip() + " ..."
    if len(snippet) > 160:
        snippet = snippet[:157] + "..."
    return Evidence(
        kind=kind,
        line=node.start_point[0] + 1,
        column=node.start_point[1] + 1,
        snippet=snippet,
        detail=detail,
    )


def _parse(source: bytes, filename: str) -> Any:
    tree_sitter, tree_sitter_c = _load_tree_sitter()
    language = _make_language(tree_sitter.Language, tree_sitter_c)
    parser = _make_parser(tree_sitter.Parser, language)
    tree = parser.parse(source)
    if tree is None or tree.root_node is None:
        raise ProtocolMinerError(f"could not parse {filename}")
    return tree.root_node


_CHAR_ESCAPES = {"n": 10, "t": 9, "r": 13, "0": 0, "\\": 92, "'": 39, '"': 34}


def _literal_int_from_text(text: str) -> int | None:
    """Resolve raw literal text such as ``7``, ``0x7``, ``'M'`` or ``'\\n'``."""

    value = text.strip()
    if not value:
        return None
    match = re.fullmatch(r"'(?:\\(?P<esc>.))'", value, re.DOTALL)
    if match:
        body = match.group("esc")
        return _CHAR_ESCAPES.get(body, ord(body))
    match = re.fullmatch(r"'(?P<char>.)'", value, re.DOTALL)
    if match:
        return ord(match.group("char"))
    try:
        return int(value, 0)
    except ValueError:
        return None


def _literal_int(node: Any, source: bytes) -> int | None:
    """Resolve a literal node to an int, covering ``7``, ``0x7`` and ``'M'``."""

    if node is None:
        return None
    if node.type in {"number_literal", "char_literal"}:
        return _literal_int_from_text(_text(source, node))
    if node.type == "preproc_arg":
        # `#define X 'M'` gives the value as one opaque preproc_arg token.
        return _literal_int_from_text(_text(source, node))
    return None


def _resolve_int(
    node: Any, source: bytes, constants: Mapping[str, ConstantFact] | None = None,
) -> int | None:
    """Resolve small integer expressions used in protocol guards.

    This intentionally stays conservative: it supports literals, named integer
    constants and simple arithmetic/bitwise expressions.  If an expression
    depends on runtime data, ``None`` is returned instead of guessing.
    """

    if node is None:
        return None
    current = _unwrap(node)
    literal = _literal_int(current, source)
    if literal is not None:
        return literal
    symbol = _identifier_text(current, source)
    if symbol is not None and constants and symbol in constants:
        return constants[symbol].value
    if current.type == "binary_expression":
        operator = current.child_by_field_name("operator")
        left = _resolve_int(current.child_by_field_name("left"), source, constants)
        right = _resolve_int(current.child_by_field_name("right"), source, constants)
        if operator is None or left is None or right is None:
            return None
        op = _text(source, operator).strip()
        if op == "+":
            return left + right
        if op == "-":
            return left - right
        if op == "<<":
            return left << right
        if op == ">>":
            return left >> right
        if op == "|":
            return left | right
        if op == "&":
            return left & right
    return None


def _literal_repr(node: Any, source: bytes) -> str:
    return _text(source, node).strip()


def _comparisons(
    entry: Any, source: bytes,
) -> Iterable[tuple[Any, str, Any, Any]]:
    """Yield ``(node, operator, left, right)`` for every complete binary expression.

    Most of the extraction passes below are scans of the same shape, so they
    share this walk instead of repeating the field lookups.
    """

    for node in _walk(entry):
        if node.type != "binary_expression":
            continue
        operator = node.child_by_field_name("operator")
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if operator is None or left is None or right is None:
            continue
        yield node, _text(source, operator).strip(), left, right


def _identifier_text(node: Any, source: bytes) -> str | None:
    if node is None:
        return None
    if node.type == "identifier":
        return _text(source, node)
    return None


def _is_data_subscript(
    node: Any, source: bytes, data_param: str,
    aliases: Mapping[str, int] | None = None,
) -> int | None:
    """Return the fixed index of ``data[N]`` / aliased ``p[N]``, else ``None``."""

    if node is None or node.type != "subscript_expression":
        return None
    argument = node.child_by_field_name("argument")
    index = node.child_by_field_name("index")
    if argument is None or index is None:
        return None
    base_name = _identifier_text(argument, source)
    base_offset = 0
    if base_name == data_param:
        base_offset = 0
    elif aliases and base_name in aliases:
        base_offset = aliases[base_name]
    else:
        return None
    resolved = _literal_int(index, source)
    return None if resolved is None else base_offset + resolved


def _data_offset_argument(
    node: Any, source: bytes, data_param: str,
    constants: Mapping[str, ConstantFact] | None = None,
    aliases: Mapping[str, int] | None = None,
) -> int | None:
    """Return ``K`` for ``data + K`` / ``&data[K]``, else ``None``.

    ``K`` may be a literal (``data + 4``) or a named constant
    (``data + MP_HEADER_SIZE``), which is resolved through ``constants``.
    """

    if node is None:
        return None
    node = _unwrap(node)
    if _identifier_text(node, source) == data_param:
        return 0
    symbol = _identifier_text(node, source)
    if aliases and symbol in aliases:
        return aliases[symbol]
    direct = _is_data_subscript(node, source, data_param, aliases)
    if direct is not None:
        return direct
    if node.type == "pointer_expression":  # &data[4]
        inner = next((c for c in node.named_children), None)
        return _is_data_subscript(inner, source, data_param, aliases)
    if node.type != "binary_expression":
        return None
    operator = node.child_by_field_name("operator")
    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if operator is None or _text(source, operator) != "+":
        return None
    if _identifier_text(left, source) == data_param:
        return _resolve_int(right, source, constants)
    if _identifier_text(right, source) == data_param:
        return _resolve_int(left, source, constants)
    left_symbol = _identifier_text(left, source)
    if aliases and left_symbol in aliases:
        delta = _resolve_int(right, source, constants)
        return None if delta is None else aliases[left_symbol] + delta
    right_symbol = _identifier_text(right, source)
    if aliases and right_symbol in aliases:
        delta = _resolve_int(left, source, constants)
        return None if delta is None else aliases[right_symbol] + delta
    return None


# --------------------------------------------------------------------------
# constants (B block)
# --------------------------------------------------------------------------


def _collect_constants(root: Any, source: bytes, filename: str) -> dict[str, ConstantFact]:
    """Collect enumerators (with implicit values resolved) and integer macros."""

    table: dict[str, ConstantFact] = {}

    for node in _walk(root):
        if node.type != "enumerator_list":
            continue
        running = -1
        for child in node.named_children:
            if child.type != "enumerator":
                continue
            name_node = child.child_by_field_name("name")
            if name_node is None:
                continue
            value_node = child.child_by_field_name("value")
            if value_node is not None:
                resolved = _literal_int(value_node, source)
                expression = _literal_repr(value_node, source)
            else:
                resolved = running + 1 if running >= 0 else 0
                expression = f"{resolved} (implicit)"
            running = resolved if resolved is not None else running + 1
            name = _text(source, name_node)
            table[name] = ConstantFact(
                name=name,
                value=resolved,
                expression=expression,
                kind="enum",
                evidence=[_evidence(
                    child, source, filename, EV_ENUM_CONSTANT,
                    f"{name} = {expression}",
                )],
            )

    for node in _walk(root):
        if node.type != "preproc_def":
            continue
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None:
            continue
        name = _text(source, name_node)
        body = _literal_repr(value_node, source) if value_node is not None else ""
        resolved = _resolve_int(value_node, source, table)
        table[name] = ConstantFact(
            name=name,
            value=resolved,
            expression=body,
            kind="macro",
            evidence=[_evidence(
                node, source, filename, EV_MACRO_CONSTANT, f"#define {name} {body}".strip(),
            )],
        )

    return table


# --------------------------------------------------------------------------
# endian helpers
# --------------------------------------------------------------------------


_TRANSPARENT = {"cast_expression", "parenthesized_expression", "unary_expression"}


def _unwrap(node: Any) -> Any:
    """Strip casts and parentheses from a node."""

    current = node
    while current is not None and current.type in _TRANSPARENT:
        current = next((child for child in current.named_children), None)
    return current


def _enclosing_shift(node: Any, source: bytes) -> int:
    """Return ``N`` if ``node`` is shifted by ``N`` bits, else ``0``.

    Climbs through casts and parentheses because the canonical helper writes
    ``(uint16_t)p[1] << 8``, so the ``<<`` sits above a ``cast_expression``.
    """

    current = node.parent
    while current is not None and current.type in _TRANSPARENT:
        current = current.parent
    if current is None or current.type != "binary_expression":
        return 0
    operator = current.child_by_field_name("operator")
    right = current.child_by_field_name("right")
    if operator is None or _text(source, operator) != "<<" or right is None:
        return 0
    return _literal_int(_unwrap(right), source) or 0


def _endian_helpers(root: Any, source: bytes) -> dict[str, tuple[int, str]]:
    """Map helper names to ``(width, endianness)``.

    Recognises the ``le16``/``be32`` shape: a single return whose expression
    references ``p[i]`` shifted by ``8 * i`` (little-endian) or by
    ``8 * (width - 1 - i)`` (big-endian).
    """

    helpers: dict[str, tuple[int, str]] = {}

    for node in _walk(root):
        if node.type != "function_definition":
            continue
        declarator = node.child_by_field_name("declarator")
        name = _function_name(node, source)
        if not name:
            continue
        body = node.child_by_field_name("body")
        if body is None:
            continue

        pointer_param = None
        params = declarator.child_by_field_name("parameters") if declarator is not None else None
        if params is not None:
            for child in params.named_children:
                decl = child.child_by_field_name("declarator")
                if decl is not None and "*" in _text(source, child):
                    pointer_param = _declarator_leaf(decl, source)
                    break
        if pointer_param is None:
            continue

        returns = [n for n in _walk(body) if n.type == "return_statement"]
        if len(returns) != 1:
            continue

        pairs: list[tuple[int, int]] = []
        for candidate in _walk(returns[0]):
            if candidate.type != "subscript_expression":
                continue
            argument = candidate.child_by_field_name("argument")
            index = candidate.child_by_field_name("index")
            if argument is None or index is None:
                continue
            if _identifier_text(argument, source) != pointer_param:
                continue
            position = _literal_int(index, source)
            if position is None:
                continue
            pairs.append((position, _enclosing_shift(candidate, source)))

        if not pairs:
            continue
        positions = sorted(position for position, _ in pairs)
        if positions != list(range(len(positions))):
            continue
        width = len(positions)
        if width not in (2, 4, 8):
            continue
        little = all(shift == 8 * position for position, shift in pairs)
        big = all(shift == 8 * (width - 1 - position) for position, shift in pairs)
        if little:
            helpers[name] = (width, "little_endian")
        elif big:
            helpers[name] = (width, "big_endian")

    return helpers


def _helper_shape_from_name(name: str) -> tuple[int, str] | None:
    """Infer endian helper shape from common names when the body is unavailable."""

    normalized = name.lower()
    if any(word in normalized for word in ("crc", "checksum", "hash", "sum")):
        return None
    for pattern in _HELPER_ENDIAN_PATTERNS:
        match = pattern.search(normalized)
        if not match:
            continue
        width = int(match.group("bits")) // 8
        if width not in (1, 2, 4, 8):
            continue
        endian = "little_endian" if match.group("endian") == "le" else "big_endian"
        return width, endian
    return None


def _declarator_leaf(node: Any, source: bytes) -> str | None:
    direct = node.child_by_field_name("declarator")
    if direct is not None:
        found = _declarator_leaf(direct, source)
        if found:
            return found
    if node.type == "identifier":
        return _text(source, node)
    return None


# --------------------------------------------------------------------------
# the entry function
# --------------------------------------------------------------------------


def _function_name(node: Any, source: bytes) -> str | None:
    """Return the name a ``function_definition`` declares.

    Only the declarator chain is consulted.  Walking every identifier under the
    declarator would also match *parameter* names, so a helper whose parameter
    happens to share the entry point's name would be selected instead of the
    entry point itself.
    """

    declarator = node.child_by_field_name("declarator")
    if declarator is None:
        return None
    return _declarator_leaf(declarator, source)


def _find_entry(root: Any, source: bytes, function: str) -> Any:
    for node in _walk(root):
        if node.type != "function_definition":
            continue
        if _function_name(node, source) == function:
            return node
    raise ProtocolMinerError(f"entry function {function!r} not found")


def _parameters(entry: Any, source: bytes) -> tuple[str | None, str | None]:
    """Return ``(data_param, size_param)`` for the byte-buffer entry point."""

    declarator = entry.child_by_field_name("declarator")
    params = declarator.child_by_field_name("parameters") if declarator is not None else None
    if params is None:
        return None, None

    data_param: str | None = None
    size_param: str | None = None
    pointer_candidates: list[tuple[int, str]] = []
    integer_candidates: list[tuple[int, str]] = []
    for index, child in enumerate(params.named_children):
        if child.type != "parameter_declaration":
            continue
        text = _text(source, child)
        decl = child.child_by_field_name("declarator")
        name = _declarator_leaf(decl, source) if decl is not None else None
        if name is None:
            continue
        base = (
            text.replace("*", " ")
            .replace("const", " ")
            .replace("volatile", " ")
            .replace("restrict", " ")
            .replace("struct", " ")
        )
        words = [word for word in re.split(r"[^A-Za-z0-9_:]+", base) if word]
        tokens = set(words)
        lower_name = name.lower()
        if "*" in text:
            score = 0
            if tokens & _BYTE_POINTER_TOKENS:
                score += 5
            if lower_name in _DATA_PARAMETER_NAMES:
                score += 3
            # Later pointer parameters are frequently contexts; prefer earlier
            # byte-like pointers when the type information is ambiguous.
            pointer_candidates.append((score * 100 - index, name))
        else:
            score = 0
            if tokens & _INTEGRAL_TYPES:
                score += 4
            if lower_name in _SIZE_PARAMETER_NAMES:
                score += 3
            integer_candidates.append((score * 100 - index, name))
    if pointer_candidates:
        pointer_candidates.sort(reverse=True)
        if pointer_candidates[0][0] > 0:
            data_param = pointer_candidates[0][1]
    if integer_candidates:
        integer_candidates.sort(reverse=True)
        if integer_candidates[0][0] > 0:
            size_param = integer_candidates[0][1]
    return data_param, size_param


# --------------------------------------------------------------------------
# A block extraction
# --------------------------------------------------------------------------


def _min_size_guard(
    entry: Any, source: bytes, filename: str, constants: Mapping[str, ConstantFact],
    size_param: str | None,
) -> tuple[int | None, list[Evidence]]:
    """Recover ``header_size`` from ``size < HEADER`` style guards."""

    evidence: list[Evidence] = []
    resolved: int | None = None
    if size_param is None:
        return None, evidence

    for node, operator, left, right in _comparisons(entry, source):
        if operator not in {"<", "<=", ">", ">="}:
            continue
        if _identifier_text(left, source) != size_param:
            continue
        constant = _identifier_text(right, source)
        value = _resolve_int(right, source, constants)
        if value is None:
            continue
        if operator == ">=" and (constant is None or "MAX" not in constant.upper()):
            continue
        resolved = value
        label = constant if constant is not None else _literal_repr(right, source)
        evidence.append(_evidence(
            node, source, filename, EV_MIN_SIZE_GUARD,
            f"guard `{_text(source, node).strip()}` bounds size by {label} = {value}",
        ))

    for node, operator, left, right in _comparisons(entry, source):
        if _text(source, left).strip() != size_param or right.type != "binary_expression":
            continue
        inner_operator = right.child_by_field_name("operator")
        if inner_operator is None or _text(source, inner_operator) != "-":
            continue
        constant_node = right.child_by_field_name("right")
        constant = _identifier_text(constant_node, source)
        value = _resolve_int(constant_node, source, constants)
        if value is None or value == resolved:
            continue
        resolved = value
        label = constant if constant is not None else _literal_repr(constant_node, source)
        evidence.append(_evidence(
            node, source, filename, EV_MIN_SIZE_GUARD,
            f"`{_text(source, node).strip()}` offsets size by {label} = {value}",
        ))

    return resolved, evidence


def _max_payload_guard(
    entry: Any, source: bytes, filename: str, constants: Mapping[str, ConstantFact],
    length_var: str | None,
) -> tuple[int | None, list[Evidence]]:
    """Recover ``max_payload`` from ``len > MAX_PAYLOAD`` style guards."""

    evidence: list[Evidence] = []
    resolved: int | None = None
    if length_var is None:
        return None, evidence

    for node, operator, left, right in _comparisons(entry, source):
        if operator not in {">", ">="}:
            continue
        if _identifier_text(left, source) != length_var:
            continue
        constant = _identifier_text(right, source)
        value = _resolve_int(right, source, constants)
        if value is None:
            continue
        if operator == ">=" and (constant is None or "MAX" not in constant.upper()):
            continue
        resolved = value
        label = constant if constant is not None else _literal_repr(right, source)
        evidence.append(_evidence(
            node, source, filename, EV_LENGTH_BOUND,
            f"`{_text(source, node).strip()}` bounds payload length by {label} = {value}",
        ))

    return resolved, evidence


def _literal_guards(
    entry: Any, source: bytes, filename: str, data_param: str | None,
    constants: Mapping[str, ConstantFact],
) -> dict[int, tuple[str, int | None, Evidence]]:
    """Recover single-byte fields compared against a literal or a constant."""

    found: dict[int, tuple[str, int | None, Evidence]] = {}
    if data_param is None:
        return found

    for node, operator, left, right in _comparisons(entry, source):
        if operator not in {"!=", "=="}:
            continue

        offset = _is_data_subscript(left, source, data_param)
        literal_node = right
        if offset is None:
            offset = _is_data_subscript(right, source, data_param)
            literal_node = left
        if offset is None:
            continue

        index_evidence = _evidence(
            node, source, filename, EV_LITERAL_GUARD,
            f"byte at offset {offset} is compared against a constant in a guard",
        )

        resolved = _literal_int(literal_node, source)
        if literal_node.type in {"number_literal", "char_literal"}:
            representation = _literal_repr(literal_node, source)
        else:
            symbol = _identifier_text(literal_node, source)
            if symbol is None or symbol not in constants:
                continue
            resolved = constants[symbol].value
            representation = f"{symbol}"
            index_evidence = Evidence(
                kind=EV_LITERAL_GUARD,
                line=index_evidence.line,
                column=index_evidence.column,
                snippet=index_evidence.snippet,
                detail=(
                    f"byte at offset {offset} compared against {symbol}"
                    f" = {constants[symbol].expression}"
                ),
            )

        if offset in found:
            existing = found[offset][2]
            merged = Evidence(
                kind=existing.kind,
                line=existing.line,
                column=existing.column,
                snippet=existing.snippet,
                detail=f"{existing.detail}; {index_evidence.detail}",
            )
            previous_value, previous_int, _ = found[offset]
            found[offset] = (
                f"{previous_value} | {representation}",
                previous_int if previous_int == resolved else None,
                merged,
            )
        else:
            found[offset] = (representation, resolved, index_evidence)

    return found


def _symbolic_loads(
    entry: Any, source: bytes, filename: str, data_param: str | None,
    helpers: Mapping[str, tuple[int, str]], constants: Mapping[str, ConstantFact],
    aliases: Mapping[str, int] | None = None,
) -> tuple[dict[int, tuple[int, str, str, Evidence]], dict[str, int]]:
    """Recover multi-byte fields loaded through endian helpers.

    Returns the field table keyed by offset, plus a map from the variable that
    received the load to that offset (used later for role classification).
    """

    fields: dict[int, tuple[int, str, str, Evidence]] = {}
    variables: dict[str, int] = {}
    if data_param is None:
        return fields, variables

    for node in _walk(entry):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        name = _identifier_text(function, source)
        if name is None:
            continue
        shape = helpers.get(name) or _helper_shape_from_name(name)
        if shape is None:
            continue
        arguments = node.child_by_field_name("arguments")
        if arguments is None:
            continue
        argument_nodes = [c for c in arguments.named_children]
        if not argument_nodes:
            continue
        offset = _data_offset_argument(
            argument_nodes[0], source, data_param, constants, aliases
        )
        if offset is None:
            continue

        width, endianness = shape
        detail = f"{name}() reads {width} bytes at offset {offset} ({endianness})"
        if len(argument_nodes) > 1:
            size_arg = _identifier_text(argument_nodes[1], source)
            if size_arg is not None:
                detail += f", sized by {size_arg}"
        evidence = _evidence(node, source, filename, EV_SYMBOLIC_LOAD, detail)
        fields[offset] = (width, endianness, f"{name}() load", evidence)

        parent = node.parent
        if parent is not None and parent.type == "init_declarator":
            declarator = parent.child_by_field_name("declarator")
            variable = _declarator_leaf(declarator, source) if declarator is not None else None
            if variable:
                variables[variable] = offset

    return fields, variables


def _inline_buffer_loads(
    entry: Any, source: bytes, filename: str, data_param: str | None,
    aliases: Mapping[str, int] | None = None,
) -> tuple[dict[int, tuple[int, str | None, str, Evidence]], dict[str, int]]:
    """Recover fields decoded directly from byte expressions.

    This covers common parser idioms that do not use a named helper, e.g.
    ``uint16_t len = (buf[2] << 8) | buf[3]`` and
    ``uint16_t len = buf[2] | (buf[3] << 8)``.
    """

    fields: dict[int, tuple[int, str | None, str, Evidence]] = {}
    variables: dict[str, int] = {}
    if data_param is None:
        return fields, variables

    for node in _walk(entry):
        if node.type != "init_declarator":
            continue
        declarator = node.child_by_field_name("declarator")
        variable = _declarator_leaf(declarator, source) if declarator is not None else None
        value = node.child_by_field_name("value")
        if variable is None or value is None:
            continue

        decoded = _decoded_field_from_expression(value, source, data_param, aliases)
        if decoded is None:
            continue
        offset, width, endianness = decoded
        variables[variable] = offset
        if width <= 1:
            continue
        detail = (
            f"inline expression reads {width} bytes at offset {offset}"
            + (f" ({endianness})" if endianness else "")
        )
        fields[offset] = (
            width,
            endianness,
            "inline byte expression",
            _evidence(value, source, filename, EV_SYMBOLIC_LOAD, detail),
        )

    for node in _walk(entry):
        if node.type != "binary_expression":
            continue
        decoded = _decoded_field_from_expression(node, source, data_param, aliases)
        if decoded is None:
            continue
        offset, width, endianness = decoded
        if width <= 1 or offset in fields:
            continue
        detail = (
            f"inline expression reads {width} bytes at offset {offset}"
            + (f" ({endianness})" if endianness else "")
        )
        fields[offset] = (
            width,
            endianness,
            "inline byte expression",
            _evidence(node, source, filename, EV_SYMBOLIC_LOAD, detail),
        )

    return fields, variables


def _decoded_field_from_expression(
    expression: Any, source: bytes, data_param: str,
    aliases: Mapping[str, int] | None = None,
) -> tuple[int, int, str | None] | None:
    """Return ``(offset, width, endianness)`` for a byte-combining expression."""

    positions: list[tuple[int, int]] = []
    for candidate in _walk(expression):
        offset = _is_data_subscript(candidate, source, data_param, aliases)
        if offset is not None:
            positions.append((offset, _enclosing_shift(candidate, source)))
    if not positions:
        return None
    unique = sorted(set(positions))
    offsets = sorted({offset for offset, _ in unique})
    if len(offsets) == 1:
        return offsets[0], 1, None
    if offsets != list(range(offsets[0], offsets[-1] + 1)):
        return None
    width = len(offsets)
    if width not in (2, 4, 8):
        return None
    shift_by_offset = {offset: shift for offset, shift in unique}
    base = offsets[0]
    little = all(shift_by_offset.get(offset) == 8 * (offset - base) for offset in offsets)
    big = all(
        shift_by_offset.get(offset) == 8 * (width - 1 - (offset - base))
        for offset in offsets
    )
    if little:
        return base, width, "little_endian"
    if big:
        return base, width, "big_endian"
    return None


def _payload_region(
    entry: Any, source: bytes, filename: str, data_param: str | None,
    constants: Mapping[str, ConstantFact], aliases: Mapping[str, int] | None = None,
) -> tuple[int | None, list[Evidence]]:
    """Find the offset at which payload bytes start.

    A parser refers to several ``data + K`` expressions, and most of them are
    header field loads, so the payload base is taken to be the *largest* fixed
    offset seen: a field can sit anywhere inside the header, while the payload
    begins after the last fixed field.  Only the selected offset is reported as
    evidence -- the other expressions are not payload bases, and describing them
    as such would put a false claim behind a real fact.
    """

    if data_param is None:
        return None, []

    candidates: list[tuple[int, Any, str]] = []
    for node, operator, _left, _right in _comparisons(entry, source):
        if operator != "+":
            continue
        value = _data_offset_argument(node, source, data_param, constants, aliases)
        if value is None:
            continue
        candidates.append((value, node, _text(source, node).strip()))

    if not candidates:
        return None, []

    offset, node, text = max(candidates, key=lambda item: item[0])
    return offset, [_evidence(
        node, source, filename, EV_PAYLOAD_REGION,
        f"`{text}` is the largest fixed offset from the input buffer, "
        f"so payload bytes start at {offset}",
    )]


def _pointer_aliases(
    entry: Any, source: bytes, data_param: str | None,
    constants: Mapping[str, ConstantFact],
) -> dict[str, int]:
    """Recover simple pointer aliases such as ``p = data + 8``.

    Aliases are intentionally limited to fixed offsets from the original input
    buffer or another alias.  This gives later passes a cheap source-level
    approximation without pretending to be full pointer analysis.
    """

    aliases: dict[str, int] = {}
    if data_param is None:
        return aliases

    changed = True
    while changed:
        changed = False
        for node in _walk(entry):
            if node.type == "init_declarator":
                declarator = node.child_by_field_name("declarator")
                variable = _declarator_leaf(declarator, source) if declarator is not None else None
                value = node.child_by_field_name("value")
                if variable is None or value is None or variable in aliases:
                    continue
                offset = _data_offset_argument(value, source, data_param, constants, aliases)
                if offset is not None:
                    aliases[variable] = offset
                    changed = True
            elif node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                variable = _identifier_text(left, source)
                if variable is None or right is None or variable in aliases:
                    continue
                offset = _data_offset_argument(right, source, data_param, constants, aliases)
                if offset is not None:
                    aliases[variable] = offset
                    changed = True

    return aliases


def _dispatch(
    entry: Any, source: bytes, filename: str, data_param: str | None,
    constants: Mapping[str, ConstantFact], variables: Mapping[str, int],
    aliases: Mapping[str, int] | None = None,
) -> tuple[int | None, list[OpcodeFact], list[Evidence]]:
    """Recover the dispatch selector offset and its case values."""

    if data_param is None:
        return None, [], []

    for node in _walk(entry):
        if node.type != "switch_statement":
            continue
        condition = node.child_by_field_name("condition")
        if condition is None:
            continue
        selector = None
        for candidate in _walk(condition):
            offset = _is_data_subscript(candidate, source, data_param, aliases)
            if offset is not None:
                selector = (offset, candidate)
                break
            name = _identifier_text(candidate, source)
            if name is not None and name in variables:
                selector = (variables[name], candidate)
                break
        if selector is None:
            continue

        offset, selector_node = selector
        evidence = [_evidence(
            selector_node, source, filename, EV_DISPATCH_SELECTOR,
            f"byte at offset {offset} selects the command handler",
        )]

        body = node.child_by_field_name("body")
        opcodes: list[OpcodeFact] = []
        for candidate in _walk(body) if body is not None else []:
            if candidate.type != "case_statement":
                continue
            value_node = candidate.child_by_field_name("value")
            if value_node is None:
                continue
            symbol = _identifier_text(value_node, source)
            resolved = _literal_int(value_node, source)
            if symbol is not None and symbol in constants:
                resolved = constants[symbol].value
                label = symbol
            else:
                label = _literal_repr(value_node, source)
            opcodes.append(OpcodeFact(
                name=label,
                value=resolved,
                evidence=[_evidence(
                    candidate, source, filename, EV_DISPATCH_CASE,
                    f"case {label}" + (f" = {resolved}" if resolved is not None else ""),
                )],
            ))
        return offset, opcodes, evidence

    return _if_else_dispatch(
        entry, source, filename, data_param, constants, variables, aliases
    )


def _if_else_dispatch(
    entry: Any, source: bytes, filename: str, data_param: str | None,
    constants: Mapping[str, ConstantFact], variables: Mapping[str, int],
    aliases: Mapping[str, int] | None = None,
) -> tuple[int | None, list[OpcodeFact], list[Evidence]]:
    """Recover selector fields from ``if (type == CMD_X)`` chains.

    A single equality may be a magic/version guard, so this promotes an offset
    to a dispatch selector only when at least two distinct equality cases are
    observed for that same offset.
    """

    if data_param is None:
        return None, [], []

    by_offset: dict[int, list[OpcodeFact]] = {}
    evidence_by_offset: dict[int, Evidence] = {}
    for node, operator, left, right in _comparisons(entry, source):
        if operator != "==":
            continue
        offset, value_node = _selector_side(
            left, right, source, data_param, variables, aliases
        )
        if offset is None:
            offset, value_node = _selector_side(
                right, left, source, data_param, variables, aliases
            )
        if offset is None or value_node is None:
            continue
        symbol = _identifier_text(value_node, source)
        resolved = _resolve_int(value_node, source, constants)
        label = symbol if symbol is not None else _literal_repr(value_node, source)
        by_offset.setdefault(offset, []).append(OpcodeFact(
            name=label,
            value=resolved,
            evidence=[_evidence(
                node, source, filename, EV_DISPATCH_CASE,
                f"if/else case {label}" + (f" = {resolved}" if resolved is not None else ""),
            )],
        ))
        evidence_by_offset.setdefault(offset, _evidence(
            node, source, filename, EV_DISPATCH_SELECTOR,
            f"field at offset {offset} selects a command branch",
        ))

    candidates = [
        (offset, opcodes) for offset, opcodes in by_offset.items()
        if len({item.name for item in opcodes}) >= 2
    ]
    if not candidates:
        return None, [], []
    candidates.sort(key=lambda item: item[0])
    offset, opcodes = candidates[0]
    return offset, opcodes, [evidence_by_offset[offset]]


def _selector_side(
    candidate: Any, value: Any, source: bytes, data_param: str,
    variables: Mapping[str, int], aliases: Mapping[str, int] | None = None,
) -> tuple[int | None, Any | None]:
    offset = _is_data_subscript(candidate, source, data_param, aliases)
    if offset is not None:
        return offset, value
    name = _identifier_text(candidate, source)
    if name is not None and name in variables:
        return variables[name], value
    return None, None


def _length_relations(
    entry: Any, source: bytes, filename: str, variables: Mapping[str, int],
    size_param: str | None, header_size: int | None,
) -> tuple[set[int], list[Evidence]]:
    """Find loads whose variable is related to the input size (length fields)."""

    offsets: set[int] = set()
    evidence: list[Evidence] = []
    if size_param is None:
        return offsets, evidence

    for node, _, left, right in _comparisons(entry, source):
        variable = _identifier_text(left, source)
        if variable is None or variable not in variables:
            continue
        if right.type != "binary_expression":
            continue
        minus = right.child_by_field_name("operator")
        if minus is None or _text(source, minus) != "-":
            continue
        if _identifier_text(right.child_by_field_name("left"), source) != size_param:
            continue
        if header_size is not None:
            resolved_header = _resolve_int(right.child_by_field_name("right"), source)
            if resolved_header is not None and resolved_header != header_size:
                continue
        offset = variables[variable]
        offsets.add(offset)
        evidence.append(_evidence(
            node, source, filename, EV_LENGTH_RELATION,
            f"`{_text(source, node).strip()}` relates the offset-{offset} field "
            f"to the remaining input size",
        ))

    return offsets, evidence


def _checksum_relations(
    entry: Any, source: bytes, filename: str, data_param: str | None,
    payload_offset: int | None, helpers: Mapping[str, tuple[int, str]],
    constants: Mapping[str, ConstantFact], aliases: Mapping[str, int] | None = None,
) -> tuple[set[int], list[Evidence]]:
    """Find loads compared against a call over the payload region (checksums)."""

    offsets: set[int] = set()
    evidence: list[Evidence] = []
    if data_param is None or payload_offset is None:
        return offsets, evidence

    for node, operator, left, right in _comparisons(entry, source):
        if operator not in {"!=", "=="}:
            continue

        for call_side, load_side in ((left, right), (right, left)):
            if call_side.type != "call_expression":
                continue
            called = _identifier_text(call_side.child_by_field_name("function"), source)
            if called is None:
                continue
            arguments = call_side.child_by_field_name("arguments")
            if arguments is None:
                continue
            argument_nodes = [c for c in arguments.named_children]
            if not argument_nodes:
                continue
            if _data_offset_argument(
                argument_nodes[0], source, data_param, constants, aliases
            ) != payload_offset:
                continue

            offset = None
            if load_side.type == "call_expression":
                called_load = _identifier_text(load_side.child_by_field_name("function"), source)
                load_args = load_side.child_by_field_name("arguments")
                if (called_load in helpers or (
                    called_load is not None and _helper_shape_from_name(called_load)
                )) and load_args is not None:
                    load_argument_nodes = [c for c in load_args.named_children]
                    if load_argument_nodes:
                        offset = _data_offset_argument(
                            load_argument_nodes[0], source, data_param, constants, aliases
                        )
            if offset is None:
                offset = _is_data_subscript(load_side, source, data_param, aliases)
            if offset is None:
                decoded = _decoded_field_from_expression(load_side, source, data_param, aliases)
                if decoded is not None:
                    offset = decoded[0]
            if offset is None:
                continue

            offsets.add(offset)
            evidence.append(_evidence(
                node, source, filename, EV_CHECKSUM_COMPARISON,
                f"`{_text(source, node).strip()}` compares the offset-{offset} field "
                f"against {called}() over the payload region",
            ))

    return offsets, evidence


# --------------------------------------------------------------------------
# public API
# --------------------------------------------------------------------------


def mine_protocol_facts(
    source: bytes, function: str, filename: str = "<source>",
) -> ProtocolFacts:
    """Recover A/B facts for ``function`` from C source, with evidence."""

    root = _parse(source, filename)
    constants = _collect_constants(root, source, filename)
    entry = _find_entry(root, source, function)
    data_param, size_param = _parameters(entry, source)
    helpers = _endian_helpers(root, source)
    aliases = _pointer_aliases(entry, source, data_param, constants)

    facts = ProtocolFacts(entry_function=function, filename=filename)

    if data_param is None:
        facts.limitations.append(
            "no byte-buffer pointer parameter was identified; frame fields cannot be derived"
        )
    if not helpers:
        facts.limitations.append(
            "no little/big-endian load helper was recognised; multi-byte field widths "
            "and endianness remain unknown"
        )

    literal_fields = _literal_guards(entry, source, filename, data_param, constants)
    load_fields, variables = _symbolic_loads(
        entry, source, filename, data_param, helpers, constants, aliases
    )
    inline_fields, inline_variables = _inline_buffer_loads(
        entry, source, filename, data_param, aliases
    )
    for offset, field in inline_fields.items():
        load_fields.setdefault(offset, field)
    variables = {**inline_variables, **variables}
    payload_offset, payload_evidence = _payload_region(
        entry, source, filename, data_param, constants, aliases
    )
    header_size, header_evidence = _min_size_guard(
        entry, source, filename, constants, size_param
    )
    if header_size is None and payload_offset is not None:
        header_size = payload_offset
        header_evidence = list(payload_evidence)
        facts.limitations.append(
            "header size was derived from the payload base offset, not from an "
            "explicit size guard"
        )

    if payload_offset is not None and header_size is not None and payload_offset < header_size:
        # Both numbers were measured from this same function, so they cannot
        # both be right: every `data + K` the parser had was a header field
        # load, and the largest of them is not a payload base.  This is a
        # measurement conflict, not a gap -- so reject the offset and leave the
        # limitation behind instead of publishing a payload field on top of a
        # real one.  Downstream (the IR, and later the validation gate) reads
        # the limitation as the signal that this parse needs another look;
        # silently falling back would erase the only trace of the conflict.
        facts.limitations.append(
            f"the largest `data + K` offset ({payload_offset}) falls inside the "
            f"{header_size}-byte header, so it was rejected as a payload base"
        )
        payload_offset = None
        payload_evidence = []

    length_offsets, length_evidence = _length_relations(
        entry, source, filename, variables, size_param, header_size
    )
    if payload_offset is None and header_size is not None and length_offsets:
        payload_offset = header_size
        payload_evidence = list(length_evidence)
        facts.limitations.append(
            "payload base was inferred from the length/size relation, not from "
            "an explicit data+offset expression"
        )
    checksum_offsets, checksum_evidence = _checksum_relations(
        entry, source, filename, data_param, payload_offset, helpers, constants, aliases
    )
    max_payload, max_payload_evidence = _max_payload_guard(
        entry, source, filename, constants,
        next((name for name, offset in variables.items() if offset in length_offsets), None),
    )

    dispatch_offset, opcodes, dispatch_evidence = _dispatch(
        entry, source, filename, data_param, constants, variables, aliases
    )

    # --- assemble fields -------------------------------------------------
    offsets = sorted(set(literal_fields) | set(load_fields))
    magic_index = 0
    for offset in offsets:
        if offset in load_fields:
            width, endianness, value, evidence = load_fields[offset]
            if offset in checksum_offsets:
                role = ROLE_CHECKSUM
            elif offset in length_offsets:
                role = ROLE_PAYLOAD_LENGTH
            elif offset == dispatch_offset:
                role = ROLE_OPCODE
            else:
                role = ROLE_UNKNOWN
            reasons = [
                item for item in checksum_evidence + length_evidence + dispatch_evidence
                if f"offset-{offset}" in item.detail
            ]
            field_fact = FieldFact(
                name=f"field_{offset}",
                offset=offset,
                width=width,
                role=role,
                value=value,
                endianness=endianness,
                evidence=[evidence, *reasons],
            )
        else:
            representation, resolved, evidence = literal_fields[offset]
            if offset == dispatch_offset:
                role = ROLE_OPCODE
            elif _looks_like_magic_field(offset, representation, resolved):
                role = ROLE_MAGIC
                magic_index += 1
            else:
                role = ROLE_VERSION
            field_fact = FieldFact(
                name=f"field_{offset}",
                offset=offset,
                width=1,
                role=role,
                value=representation,
                evidence=[evidence, *[
                    item for item in dispatch_evidence if f"offset-{offset}" in item.detail
                ]],
            )

        if role == ROLE_MAGIC:
            field_fact.suggested_name = f"magic{magic_index - 1}"
        elif role == ROLE_VERSION:
            field_fact.suggested_name = "version"
        elif role == ROLE_OPCODE:
            field_fact.suggested_name = "opcode"
        elif role == ROLE_PAYLOAD_LENGTH:
            field_fact.suggested_name = "payload_length"
        elif role == ROLE_CHECKSUM:
            field_fact.suggested_name = "checksum"

        facts.fields.append(field_fact)

    if payload_offset is not None:
        facts.fields.append(FieldFact(
            name=f"field_{payload_offset}",
            offset=payload_offset,
            width=-1,  # variable; resolved against the length field
            role=ROLE_PAYLOAD,
            value="fuzzer-controlled bytes",
            suggested_name="payload",
            evidence=list(payload_evidence) or [
                Evidence(
                    kind=EV_PAYLOAD_REGION,
                    line=1,
                    column=1,
                    snippet="",
                    detail="payload base inferred from the length/checksum relations",
                )
            ],
        ))

    # The dispatch selector is read by `switch (data[N])`, which is neither a
    # comparison nor an endian-helper load, so it is added here explicitly.
    if dispatch_offset is not None and dispatch_offset not in offsets:
        resolved_values = [item.value for item in opcodes if item.value is not None]
        span = (
            f"{min(resolved_values)}..{max(resolved_values)}"
            if resolved_values else "unresolved"
        )
        facts.fields.append(FieldFact(
            name=f"field_{dispatch_offset}",
            offset=dispatch_offset,
            width=1,
            role=ROLE_OPCODE,
            value=f"dispatch selector over {len(opcodes)} cases, values {span}",
            suggested_name="opcode",
            evidence=list(dispatch_evidence),
        ))

    facts.fields.sort(key=lambda item: item.offset)
    facts.header_size = header_size
    facts.header_size_evidence = header_evidence
    facts.payload_offset = payload_offset
    facts.payload_offset_evidence = list(payload_evidence)
    facts.max_payload = max_payload
    facts.max_payload_evidence = max_payload_evidence
    facts.constants = sorted(constants.values(), key=lambda item: item.name)
    facts.opcodes = opcodes

    # --- record what is still open (this is what a later stage may fill) --
    if facts.header_size is None:
        facts.limitations.append("header size could not be derived from guards or payload base")
    if facts.max_payload is None:
        facts.limitations.append(
            "maximum payload length could not be derived; no constant bound was found"
        )
    if not facts.opcodes:
        facts.limitations.append("no dispatch selector was found; opcode range is unknown")
    elif any(item.value is None for item in facts.opcodes):
        facts.limitations.append("some dispatch cases could not be resolved to integers")
    missing_width = [item.name for item in facts.fields if item.width == -1]
    for name in missing_width:
        facts.limitations.append(
            f"{name} has a variable width; it must be tied to the length field by a later stage"
        )
    facts.limitations.append(
        "convention block (command loop, context lifetime, requirements, notes) is out of "
        "scope for static mining: it is not present in the parser body"
    )
    return facts


def _looks_like_magic_field(offset: int, representation: str, resolved: int | None) -> bool:
    """Return whether a fixed constant is more likely magic than a version.

    Printable byte constants are obvious magic.  Many binary protocols also use
    non-printable or high-bit magic bytes at the beginning of the frame, so the
    first two fixed byte constants are treated as magic unless they look like a
    small version number.
    """

    if not isinstance(resolved, int):
        return False
    if 32 <= resolved <= 126:
        return True
    if offset <= 1 and resolved not in {0, 1, 2, 3}:
        return True
    return representation.lower().startswith("0x") and offset <= 1


def mine_source_file(path: str | Path, function: str) -> ProtocolFacts:
    location = Path(path)
    try:
        source = location.read_bytes()
    except OSError as error:
        raise ProtocolMinerError(f"could not read {location}: {type(error).__name__}") from None
    return mine_protocol_facts(source, function, filename=location.name)


def write_contract(facts: ProtocolFacts, path: str | Path) -> dict[str, Any]:
    contract = facts.to_contract()
    Path(path).write_text(
        json.dumps(contract, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return contract


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Mine the frame-format and constant blocks of a protocol contract",
    )
    parser.add_argument("--source", type=Path, required=True, help="C source to analyse")
    parser.add_argument("--function", required=True, help="entry function name")
    parser.add_argument("--output", type=Path, help="write the mined contract as JSON")
    parser.add_argument("--facts", action="store_true", help="emit raw facts instead of a contract")
    arguments = parser.parse_args(argv)

    try:
        facts = mine_source_file(arguments.source, arguments.function)
    except (ProtocolMinerError, SourceAnalysisError) as error:
        parser.error(str(error))
        return 2

    payload = facts.to_json() if arguments.facts else facts.to_contract()
    if arguments.output:
        arguments.output.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    if facts.limitations:
        print("\nlimitations (for a later completion stage):", file=sys.stderr)
        for item in facts.limitations:
            print(f"  - {item}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
