"""Tree-sitter backed C syntax summaries for prompt construction."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable


ANALYSIS_SCHEMA_VERSION = 2
PARSER_NAME = "tree-sitter-c"
PARSER_VERSION = "1"
MAX_ITEMS = 80
MAX_FACTS = 64
MAX_TEXT = 240


class SourceAnalysisError(Exception):
    """The source cannot be summarized with the configured parser."""


@dataclass(frozen=True)
class _FunctionRecord:
    name: str
    signature: str
    return_type: str
    parameters: tuple[dict[str, Any], ...]
    defined: bool
    storage: tuple[str, ...]
    line: int
    node: Any


def analyze_c_source(source: bytes, function: str) -> dict[str, Any]:
    """Return a bounded syntax summary; function bodies are not emitted."""
    tree_sitter, tree_sitter_c = _load_tree_sitter()
    language = _make_language(tree_sitter.Language, tree_sitter_c)
    parser = _make_parser(tree_sitter.Parser, language)
    tree = parser.parse(source)
    root = tree.root_node
    error_count = sum(1 for node in _walk(root) if node.type == "ERROR" or getattr(node, "is_error", False))
    if root.has_error or error_count:
        raise SourceAnalysisError(f"tree-sitter parse failed with {error_count or 1} error node(s)")

    functions = _collect_functions(root, source)
    target = _select_target(functions, function)
    if target is None:
        raise SourceAnalysisError(f"target function {function!r} was not found by tree-sitter")

    summary = {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "language": "c",
        "parser": {
            "name": PARSER_NAME,
            "version": PARSER_VERSION,
            "tree_has_error": bool(root.has_error),
            "error_count": error_count,
        },
        "omitted": [
            "function bodies",
            "source comments",
            "local declarations outside selected target body facts",
        ],
        "target_function": function,
        "target": _public_function(target, include_body_facts=True, source=source),
        "includes": _collect_external_text(root, source, {"preproc_include"}),
        "macros": _collect_external_text(root, source, {"preproc_def", "preproc_function_def"}),
        "types": _collect_types(root, source),
        "enumerators": _collect_enumerators(root, source),
        # This is deliberately a syntax-only pre-filter.  The complete function
        # inventory is not exposed to the harness-generation prompt.
        "pointer_candidates": _pointer_candidates(functions, source),
        "related_functions": _related_functions(target, functions, source),
        "harness_hints": _harness_hints(target, functions),
    }
    return summary


def c_declarations_equivalent(left: str, right: str) -> bool:
    """Compare C declarations by parsed tokens, not presentation whitespace.

    A documentation model may legitimately normalize whitespace or omit the
    trailing declaration semicolon.  Parameter names, types, qualifiers,
    pointer depth, and every other C token must still match the source
    declaration exactly.
    """
    left_tokens = _declaration_tokens(left)
    right_tokens = _declaration_tokens(right)
    return left_tokens is not None and left_tokens == right_tokens


def _declaration_tokens(value: str) -> tuple[str, ...] | None:
    if not isinstance(value, str) or not value.strip():
        return None
    declaration = value.strip()
    if not declaration.endswith(";"):
        declaration += ";"
    encoded = declaration.encode("utf-8")
    try:
        tree_sitter, tree_sitter_c = _load_tree_sitter()
        language = _make_language(tree_sitter.Language, tree_sitter_c)
        parser = _make_parser(tree_sitter.Parser, language)
        root = parser.parse(encoded).root_node
    except SourceAnalysisError:
        return None
    if root.has_error or len(root.named_children) != 1:
        return None
    declaration_node = root.named_children[0]
    if declaration_node.type != "declaration":
        return None
    tokens = []
    for node in _walk(declaration_node):
        if node.child_count == 0 and node.type != "comment":
            tokens.append(_text(encoded, node))
    return tuple(tokens)


def _load_tree_sitter():
    try:
        import tree_sitter
        import tree_sitter_c
    except ImportError as exc:
        raise SourceAnalysisError(
            "tree-sitter dependencies are missing; install the project dependencies first"
        ) from exc
    return tree_sitter, tree_sitter_c


def _make_language(language_type, tree_sitter_c):
    raw = tree_sitter_c.language()
    return raw if isinstance(raw, language_type) else language_type(raw)


def _make_parser(parser_type, language):
    try:
        return parser_type(language)
    except TypeError:
        parser = parser_type()
        if hasattr(parser, "set_language"):
            parser.set_language(language)
        else:
            parser.language = language
        return parser


def _walk(node) -> Iterable[Any]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _text(source: bytes, node) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)


def _strip_comments(value: str) -> str:
    return _COMMENT.sub(" ", value)


def _clean(value: str) -> str:
    value = _strip_comments(value).strip()
    value = re.sub(r"\s+", " ", value)
    value = value.replace(" ;", ";").replace("( ", "(").replace(" )", ")")
    return value


def _bounded(value: str, limit: int = MAX_TEXT) -> str:
    value = _clean(value)
    return value if len(value) <= limit else value[:limit].rstrip() + "..."


def _is_external(node) -> bool:
    current = node.parent
    while current is not None:
        if current.type in {"function_definition", "compound_statement"}:
            return False
        current = current.parent
    return True


def _collect_external_text(root, source: bytes, node_types: set[str]) -> list[str]:
    seen = set()
    values = []
    for node in _walk(root):
        if node.type not in node_types or not _is_external(node):
            continue
        value = _bounded(_text(source, node))
        if value and value not in seen:
            seen.add(value)
            values.append(value)
        if len(values) >= MAX_ITEMS:
            break
    return values


def _collect_types(root, source: bytes) -> list[dict[str, str]]:
    values = []
    seen = set()
    for node in _walk(root):
        if not _is_external(node) or node.type not in {"type_definition", "enum_specifier", "struct_specifier"}:
            continue
        if _has_ancestor(node, {"type_definition"}) and node.type != "type_definition":
            continue
        if node.type in {"enum_specifier", "struct_specifier"} and _has_ancestor(node, {"declaration"}):
            continue
        text = _bounded(_text(source, node))
        if node.type in {"enum_specifier", "struct_specifier"} and not text.endswith(";"):
            text += ";"
        if text in seen:
            continue
        seen.add(text)
        values.append({"kind": node.type, "declaration": text})
        if len(values) >= MAX_ITEMS:
            break
    return values


def _collect_enumerators(root, source: bytes) -> list[dict[str, str | None]]:
    values = []
    seen = set()
    for node in _walk(root):
        if node.type != "enumerator" or not _is_external(node):
            continue
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = _text(source, name_node)
        if name in seen:
            continue
        value_node = node.child_by_field_name("value")
        values.append({"name": name, "value": _bounded(_text(source, value_node)) if value_node else None})
        seen.add(name)
        if len(values) >= MAX_ITEMS:
            break
    return values


def _collect_functions(root, source: bytes) -> list[_FunctionRecord]:
    by_key: dict[tuple[str, str], _FunctionRecord] = {}
    order: list[tuple[str, str]] = []
    for node in _walk(root):
        record = None
        if node.type == "function_definition" and _is_external(node):
            record = _function_from_definition(node, source)
        elif node.type == "declaration" and _is_external(node):
            record = _function_from_declaration(node, source)
        if record is None:
            continue
        key = (record.name, record.signature)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = record
            order.append(key)
        elif record.defined and not existing.defined:
            by_key[key] = record
    return [by_key[key] for key in order]


def _function_from_definition(node, source: bytes) -> _FunctionRecord | None:
    declarator = node.child_by_field_name("declarator")
    body = node.child_by_field_name("body")
    name = _declarator_name(declarator, source) if declarator else None
    if not name or body is None:
        return None
    signature = _bounded(_text(source, _Range(node.start_byte, body.start_byte, node.start_point))) + ";"
    return _FunctionRecord(
        name=name,
        signature=signature,
        return_type=_return_type(node, source, declarator),
        parameters=tuple(_parameters(declarator, source)),
        defined=True,
        storage=_storage(node, source),
        line=node.start_point[0] + 1,
        node=node,
    )


def _function_from_declaration(node, source: bytes) -> _FunctionRecord | None:
    declarator = next((child for child in _walk(node) if child.type == "function_declarator"), None)
    name = _declarator_name(declarator, source) if declarator else None
    if not name:
        return None
    return _FunctionRecord(
        name=name,
        signature=_bounded(_text(source, node)),
        return_type=_return_type(node, source, declarator),
        parameters=tuple(_parameters(declarator, source)),
        defined=False,
        storage=_storage(node, source),
        line=node.start_point[0] + 1,
        node=node,
    )


@dataclass(frozen=True)
class _Range:
    start_byte: int
    end_byte: int
    start_point: Any


def _return_type(node, source: bytes, declarator) -> str:
    type_node = node.child_by_field_name("type")
    if type_node is not None:
        return _bounded(_text(source, type_node))
    return _bounded(source[node.start_byte:declarator.start_byte].decode("utf-8", errors="replace"))


def _storage(node, source: bytes) -> tuple[str, ...]:
    return tuple(_text(source, child) for child in node.named_children if child.type == "storage_class_specifier")


def _parameters(declarator, source: bytes) -> list[dict[str, Any]]:
    params = declarator.child_by_field_name("parameters") if declarator else None
    if params is None:
        return []
    result = []
    for child in params.named_children:
        if child.type == "variadic_parameter":
            result.append({"declaration": "...", "name": None, "type": "...", "role": "variadic"})
            continue
        if child.type != "parameter_declaration":
            continue
        declaration = _bounded(_text(source, child))
        if declaration == "void":
            continue
        decl_node = child.child_by_field_name("declarator")
        type_node = child.child_by_field_name("type")
        name = _declarator_name(decl_node, source) if decl_node else None
        qualifiers = tuple(_text(source, n) for n in child.named_children if n.type == "type_qualifier")
        pointer_depth = declaration.count("*")
        if pointer_depth == 0:
            role = "scalar"
        elif "const" in qualifiers:
            role = "input_pointer"
        else:
            role = "writable_pointer"
        result.append({
            "declaration": declaration,
            "name": name,
            "type": _bounded(_text(source, type_node)) if type_node else None,
            "qualifiers": list(qualifiers),
            "pointer_depth": pointer_depth,
            "role_hint": role,
        })
    return result


def _declarator_name(node, source: bytes) -> str | None:
    if node is None:
        return None
    direct = node.child_by_field_name("declarator")
    if direct is not None and direct.type == "identifier":
        return _text(source, direct)
    if node.type in {"identifier", "field_identifier", "type_identifier"}:
        return _text(source, node)
    for child in reversed(node.named_children):
        value = _declarator_name(child, source)
        if value:
            return value
    return None


def _select_target(functions: list[_FunctionRecord], function: str) -> _FunctionRecord | None:
    matches = [record for record in functions if record.name == function]
    return next((record for record in matches if record.defined), matches[0] if matches else None)


def _public_function(record: _FunctionRecord, *, include_body_facts: bool, source: bytes) -> dict[str, Any]:
    value = {
        "name": record.name,
        "signature": record.signature,
        "return_type": record.return_type,
        "parameters": list(record.parameters),
        "defined": record.defined,
        "storage": list(record.storage),
        "line": record.line,
    }
    if include_body_facts and record.defined:
        value["body_facts"] = _body_facts(record.node, source)
    return value


def _pointer_candidates(functions: list[_FunctionRecord], source: bytes) -> list[dict[str, Any]]:
    values = []
    for record in functions:
        pointer_parameters = [parameter for parameter in record.parameters
                              if parameter.get("pointer_depth", 0) > 0]
        if not pointer_parameters:
            continue
        values.append({
            "name": record.name,
            "signature": record.signature,
            "defined": record.defined,
            "line": record.line,
            "pointer_parameters": pointer_parameters,
        })
        if len(values) >= MAX_ITEMS:
            break
    return values


def _related_functions(target: _FunctionRecord, functions: list[_FunctionRecord],
                       source: bytes) -> list[dict[str, Any]]:
    """Keep only declarations the selected target actually calls.

    These helpers are required to construct valid harnesses (for example an
    init/destroy pair), but they are not part of ISF discovery.
    """
    called = set(_body_facts(target.node, source).get("called_functions", []))
    values = []
    seen = set()
    for record in functions:
        if record.name == target.name or record.name not in called or record.name in seen:
            continue
        values.append(_public_function(record, include_body_facts=False, source=source))
        seen.add(record.name)
        if len(values) >= MAX_ITEMS:
            break
    return values


def _body_facts(node, source: bytes) -> dict[str, Any]:
    body = node.child_by_field_name("body")
    if body is None:
        return {}
    calls = []
    conditions = []
    subscripts = []
    fields = []
    constants = []
    switches = []
    for current in _walk(body):
        if current.type == "call_expression":
            called = current.child_by_field_name("function")
            if called is not None:
                _add_unique(calls, _bounded(_text(source, called)), MAX_FACTS)
        elif current.type == "if_statement":
            condition = current.child_by_field_name("condition")
            if condition is not None:
                _add_unique(conditions, _bounded(_text(source, condition)), MAX_FACTS)
        elif current.type == "switch_statement":
            condition = current.child_by_field_name("condition")
            switch_body = current.child_by_field_name("body")
            cases = []
            if switch_body is not None:
                for child in _walk(switch_body):
                    if child.type == "case_statement":
                        value = child.child_by_field_name("value")
                        _add_unique(cases, _bounded(_text(source, value)) if value else "default", MAX_FACTS)
            switches.append({"condition": _bounded(_text(source, condition)) if condition else None,
                             "cases": cases[:MAX_FACTS]})
        elif current.type == "subscript_expression":
            _add_unique(subscripts, _bounded(_text(source, current)), MAX_FACTS)
        elif current.type == "field_expression":
            _add_unique(fields, _bounded(_text(source, current)), MAX_FACTS)
        elif current.type in {"number_literal", "char_literal", "string_literal"}:
            _add_unique(constants, _bounded(_text(source, current)), MAX_FACTS)
    return {
        "if_conditions": conditions,
        "switches": switches[:MAX_FACTS],
        "called_functions": calls,
        "subscript_expressions": subscripts,
        "field_expressions": fields,
        "literal_tokens": constants,
    }


def _add_unique(values: list[Any], value: Any, limit: int) -> None:
    if len(values) < limit and value not in values:
        values.append(value)


def _harness_hints(target: _FunctionRecord, functions: list[_FunctionRecord]) -> list[str]:
    hints = []
    params = list(target.parameters)
    helper_names = {record.name for record in functions if record.name != target.name}
    for param in params:
        if param["role_hint"] == "writable_pointer":
            hints.append(f"initialize valid writable storage for parameter {param['name'] or param['declaration']}")
        elif param["role_hint"] == "input_pointer":
            hints.append(f"keep memory valid for the const pointer parameter {param['name'] or param['declaration']}")
    for index, left in enumerate(params[:-1]):
        right = params[index + 1]
        if (left["role_hint"] == "input_pointer" and right["type"] in {"size_t", "int", "uint32_t", "uint16_t"}
                and (right["name"] or "").lower() in {"size", "len", "length", "n"}):
            hints.append(f"{left['name']} and {right['name']} look like a buffer plus length pair")
    if "mp_init" in helper_names and "mp_destroy" in helper_names:
        hints.append("mp_init/mp_destroy are available helpers for mp_context lifetime management")
    if "mp_checksum" in helper_names:
        hints.append("mp_checksum is available as a helper for constructing parser inputs")
    return hints[:MAX_FACTS]


def _has_ancestor(node, node_types: set[str]) -> bool:
    current = node.parent
    while current is not None:
        if current.type in node_types:
            return True
        current = current.parent
    return False
