"""Project-level tree-sitter C parsing and conservative type resolution."""

from __future__ import annotations

from dataclasses import dataclass, replace
import fnmatch
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable

from .models import (AccessHint, FunctionInfo, ParameterInfo, ReturnValueOwnership,
                     StructInfo)


DEFAULT_IGNORES = (".git", "build", "out", "cmake-build*", "third_party",
                   "vendor", "external")
SOURCE_SUFFIXES = {".c", ".h"}
FUNCTIONS_SCHEMA_VERSION = 2


class ProjectParseError(Exception):
    pass


@dataclass(frozen=True)
class ParseResult:
    functions: tuple[FunctionInfo, ...]
    structs: tuple[StructInfo, ...]
    files: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class _ParsedFunction:
    function: FunctionInfo
    return_base_type: str


class CProjectParser:
    def __init__(self, ignored_directories: Iterable[str] = DEFAULT_IGNORES):
        self.ignored_directories = tuple(ignored_directories)

    def parse(self, project: Path) -> ParseResult:
        project = project.resolve()
        if not project.is_dir():
            raise ProjectParseError(f"project is not a directory: {project}")
        parser = _make_parser()
        paths = tuple(self._source_files(project))
        structs: list[StructInfo] = []
        raw_functions: list[_ParsedFunction] = []
        warnings = []
        for path in paths:
            relative = path.relative_to(project).as_posix()
            try:
                source = path.read_bytes()
                tree = parser.parse(source)
                errors = [node for node in _walk(tree.root_node)
                          if node.type == "ERROR" or getattr(node, "is_error", False)]
                if tree.root_node.has_error or errors:
                    warnings.append(f"{relative}: tree-sitter reported {len(errors) or 1} parse error(s)")
                structs.extend(_extract_structs(tree.root_node, source, relative))
                raw_functions.extend(_extract_functions(tree.root_node, source, relative))
            except OSError as exc:
                warnings.append(f"{relative}: could not read source ({type(exc).__name__})")
        resolver = TypeResolver(structs)
        functions = tuple(_resolve_function(item.function, resolver) for item in raw_functions)
        functions = _deduplicate_functions(functions)
        return ParseResult(functions, resolver.structs, tuple(
            path.relative_to(project).as_posix() for path in paths), tuple(warnings))

    def _source_files(self, project: Path) -> Iterable[Path]:
        for path in sorted(project.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            relative_parts = path.relative_to(project).parts[:-1]
            if any(any(fnmatch.fnmatch(part, pattern) for pattern in self.ignored_directories)
                   for part in relative_parts):
                continue
            yield path


class TypeResolver:
    def __init__(self, structs: Iterable[StructInfo]):
        groups: list[list[StructInfo]] = []
        group_aliases: list[set[str]] = []
        for info in structs:
            normalized = {_normalize_base(alias) for alias in info.aliases}
            matches = [index for index, aliases in enumerate(group_aliases)
                       if aliases.intersection(normalized)]
            if not matches:
                groups.append([info])
                group_aliases.append(normalized)
                continue
            target = matches[0]
            groups[target].append(info)
            group_aliases[target].update(normalized)
            for index in reversed(matches[1:]):
                groups[target].extend(groups.pop(index))
                group_aliases[target].update(group_aliases.pop(index))

        resolved_structs = []
        aliases: dict[str, str] = {}
        for group in groups:
            typedef = next((info for info in group
                            if info.declaration.lstrip().startswith("typedef")), None)
            canonical_name = (typedef or group[0]).name
            definition = next((info for info in group if "{" in info.declaration), group[0])
            names = tuple(dict.fromkeys(
                value for info in group for value in (info.name, *info.aliases)
            ))
            merged = replace(definition, name=canonical_name, aliases=names)
            resolved_structs.append(merged)
            for alias in names:
                aliases[_normalize_base(alias)] = canonical_name
            aliases[_normalize_base(canonical_name)] = canonical_name
        self.structs = tuple(sorted(resolved_structs, key=lambda item: item.name))
        self._aliases = aliases

    def resolve(self, base_type: str) -> str | None:
        return self._aliases.get(_normalize_base(base_type))


def _make_parser():
    try:
        import tree_sitter
        import tree_sitter_c
    except ImportError as exc:
        raise ProjectParseError("tree-sitter dependencies are missing") from exc
    raw = tree_sitter_c.language()
    language = raw if isinstance(raw, tree_sitter.Language) else tree_sitter.Language(raw)
    try:
        return tree_sitter.Parser(language)
    except TypeError:
        parser = tree_sitter.Parser()
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
        stack.extend(reversed(current.named_children))


def _text(source: bytes, node) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _clean(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _normalize_base(value: str) -> str:
    value = re.sub(r"\b(const|volatile|restrict|_Atomic)\b", " ", value)
    value = re.sub(r"\b(struct|union)\s+", "", value)
    return _clean(value.replace("*", " "))


def _extract_structs(root, source: bytes, relative: str) -> list[StructInfo]:
    result = []
    consumed = set()
    for node in _walk(root):
        if node.type != "type_definition" or not _is_external_declaration(node):
            continue
        struct_node = next((child for child in node.named_children
                            if child.type == "struct_specifier"), None)
        if struct_node is None:
            continue
        aliases = [child for child in node.named_children if child.type == "type_identifier"]
        alias = _text(source, aliases[-1]) if aliases else None
        tag_node = struct_node.child_by_field_name("name")
        tag = _text(source, tag_node) if tag_node else None
        name = alias or tag
        if not name:
            continue
        all_aliases = tuple(dict.fromkeys(value for value in
                            (alias, f"struct {tag}" if tag else None, tag) if value))
        result.append(StructInfo(name, all_aliases, _clean(_text(source, node)), relative,
                                 node.start_point[0] + 1, node.end_point[0] + 1))
        consumed.add((struct_node.start_byte, struct_node.end_byte))
    for node in _walk(root):
        if (node.type != "struct_specifier"
                or not _is_external_declaration(node)
                or (node.start_byte, node.end_byte) in consumed
                or node.child_by_field_name("body") is None):
            continue
        tag_node = node.child_by_field_name("name")
        if tag_node is None:
            continue
        tag = _text(source, tag_node)
        result.append(StructInfo(tag, (tag, f"struct {tag}"), _clean(_text(source, node)),
                                 relative, node.start_point[0] + 1, node.end_point[0] + 1))
    return result


def _extract_functions(root, source: bytes, relative: str) -> list[_ParsedFunction]:
    result = []
    for node in _walk(root):
        if not _is_external_declaration(node):
            continue
        defined = node.type == "function_definition"
        if not defined and node.type != "declaration":
            continue
        declarator = node.child_by_field_name("declarator")
        function_declarator = _find_function_declarator(declarator)
        if function_declarator is None:
            continue
        name_node = _declarator_identifier(function_declarator)
        if name_node is None:
            continue
        name = _text(source, name_node)
        type_node = node.child_by_field_name("type")
        body_node = node.child_by_field_name("body") if defined else None
        signature_end = body_node.start_byte if body_node is not None else node.end_byte
        signature = _clean(source[node.start_byte:signature_end].decode("utf-8", errors="replace"))
        signature = signature.rstrip("; ") + ";"
        return_base, return_depth, return_type, annotations = _return_type_details(
            source, node, declarator, function_declarator, name_node, type_node, signature
        )
        parameters = tuple(_extract_parameters(function_declarator, source))
        body = _text(source, body_node) if body_node is not None else ""
        storage = tuple(_text(source, child) for child in node.named_children
                        if child.type == "storage_class_specifier")
        function_id = f"{relative}:{node.start_point[0] + 1}:{name}"
        function = FunctionInfo(
            function_id, name, relative, node.start_point[0] + 1, node.end_point[0] + 1,
            return_type, return_base, return_depth, False, parameters,
            signature, body, defined, storage,
            return_ownership=_return_ownership(name, return_base, return_depth, signature),
            return_type_annotations=annotations,
        )
        result.append(_ParsedFunction(function, return_base))
    return result


def _is_external_declaration(node) -> bool:
    current = node.parent
    while current is not None:
        if current.type in {"function_definition", "compound_statement"}:
            return False
        current = current.parent
    return True


def _find_function_declarator(node):
    if node is None:
        return None
    if node.type == "function_declarator":
        return node
    for child in node.named_children:
        found = _find_function_declarator(child)
        if found is not None:
            return found
    return None


def _declarator_identifier(node):
    current = node.child_by_field_name("declarator") if node is not None else None
    while current is not None:
        if current.type == "identifier":
            return current
        next_node = current.child_by_field_name("declarator")
        if next_node is None:
            return next((child for child in current.named_children if child.type == "identifier"), None)
        current = next_node
    return None


def _return_type_details(source: bytes, node, declarator, function_declarator,
                         name_node, type_node, signature: str):
    """Recover a normalized return type, including annotation-wrapped declarations."""
    ast_base = _clean(_text(source, type_node)) if type_node is not None else ""
    depth = _return_pointer_depth(declarator, function_declarator)
    annotations: list[str] = []
    name = _text(source, name_node)
    prefix = signature.split(name, 1)[0].strip() if name in signature else ast_base
    macro = re.search(
        r"\b(CJSON_PUBLIC)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)",
        prefix,
    )
    if macro:
        macro_name, macro_args = macro.groups()
        annotations.append(macro_name)
        candidate = _clean(macro_args)
        if candidate:
            ast_base = candidate
            depth = candidate.count("*")
    if not ast_base:
        ast_base = _clean(prefix)
    ast_base = re.sub(r"\b(?:static|extern|inline|const|volatile|restrict)\b", " ", ast_base)
    ast_base = re.sub(r"\b[A-Za-z_]\w*\s*\([^;{}]*\)", " ", ast_base)
    ast_base = _clean(ast_base)
    qualifiers = []
    if re.search(r"\bconst\b", prefix):
        qualifiers.append("const")
    base = _normalize_base(ast_base)
    return base, depth, _render_type(base, depth, qualifiers), tuple(dict.fromkeys(annotations))


def _return_ownership(name: str, base_type: str, pointer_depth: int,
                      signature: str) -> ReturnValueOwnership | None:
    if pointer_depth == 1 and base_type == "cJSON" and name.startswith("cJSON_Parse"):
        return ReturnValueOwnership(
            "owned_pointer", "cJSON", True, True, "cJSON_Delete", "return_value",
            (f"{name} returns cJSON *", "cJSON parse results are caller-owned"),
            1.0, "static_signature_and_api_family",
        )
    if pointer_depth == 1 and base_type == "char" and name in {
        "cJSON_Print", "cJSON_PrintUnformatted",
    }:
        return ReturnValueOwnership(
            "owned_pointer", "char", True, True, "cJSON_free", "return_value",
            (f"{name} returns char *", "cJSON print results are caller-owned"),
            1.0, "static_signature_and_api_family",
        )
    return None


def _return_pointer_depth(declarator, function_declarator) -> int:
    depth = 0
    current = declarator
    while current is not None and current != function_declarator:
        if current.type in {"pointer_declarator", "abstract_pointer_declarator"}:
            depth += 1
        current = current.child_by_field_name("declarator")
    return depth


def _extract_parameters(function_declarator, source: bytes) -> list[ParameterInfo]:
    parameters = function_declarator.child_by_field_name("parameters")
    if parameters is None:
        return []
    result = []
    for node in parameters.named_children:
        if node.type != "parameter_declaration":
            continue
        declaration = _clean(_text(source, node))
        if declaration == "void":
            continue
        type_node = node.child_by_field_name("type")
        declarator = node.child_by_field_name("declarator")
        base = _clean(_text(source, type_node)) if type_node is not None else declaration
        depth = _declarator_pointer_depth(declarator)
        name_node = _declarator_leaf_identifier(declarator)
        name = _text(source, name_node) if name_node is not None else None
        qualifiers = [_text(source, child) for child in node.named_children
                      if child.type == "type_qualifier"]
        rendered_type = _render_type(base, depth, qualifiers)
        result.append(ParameterInfo(name, rendered_type, declaration, depth > 0,
                                    "const" in qualifiers, _normalize_base(base), depth))
    return result


def _declarator_pointer_depth(declarator) -> int:
    """Count pointers that qualify this declarator, excluding nested parameter types."""
    depth = 0
    current = declarator
    while current is not None:
        if current.type in {"identifier", "field_identifier", "type_identifier"}:
            break
        if current.type in {"pointer_declarator", "abstract_pointer_declarator"}:
            depth += 1
        current = current.child_by_field_name("declarator")
    return depth


def _render_type(base: str, pointer_depth: int, qualifiers: Iterable[str] = ()) -> str:
    return _clean(" ".join((*qualifiers, base, "*" * pointer_depth)))


def _declarator_leaf_identifier(node):
    if node is None:
        return None
    if node.type == "identifier":
        return node
    direct = node.child_by_field_name("declarator")
    if direct is not None:
        found = _declarator_leaf_identifier(direct)
        if found is not None:
            return found
    for child in node.named_children:
        found = _declarator_leaf_identifier(child)
        if found is not None:
            return found
    return None


def _resolve_function(function: FunctionInfo, resolver: TypeResolver) -> FunctionInfo:
    parameters = []
    for parameter in function.parameters:
        resolved = resolver.resolve(parameter.base_type)
        parameters.append(replace(parameter, base_type=resolved or parameter.base_type,
                                  is_struct_like=resolved is not None))
    return_struct = resolver.resolve(function.return_base_type)
    function = replace(function, parameters=tuple(parameters),
                       return_base_type=return_struct or function.return_base_type,
                       return_is_struct_like=return_struct is not None)
    return replace(function, access_hints=_access_hints(function))


def _access_hints(function: FunctionInfo) -> tuple[AccessHint, ...]:
    if not function.body:
        return ()
    parser = _make_parser()
    source = function.body.encode("utf-8")
    root = parser.parse(source).root_node
    hints = []
    for parameter in function.parameters:
        if not parameter.is_pointer or not parameter.is_struct_like or not parameter.name:
            continue
        reads = False
        writes = False
        evidence = []
        for node in _walk(root):
            if node.type != "field_expression":
                continue
            argument = node.child_by_field_name("argument")
            if argument is None or _clean(_text(source, argument)) != parameter.name:
                continue
            access = _clean(_text(source, node))
            read, write = _field_access_mode(node, source)
            reads |= read
            writes |= write
            marker = ("read+write: " if read and write else "write: " if write else "read: ") + access
            if marker not in evidence:
                evidence.append(marker)
        hints.append(AccessHint(parameter.name, reads, writes, tuple(evidence[:16])))
    return tuple(hints)


def _field_access_mode(node, source: bytes) -> tuple[bool, bool]:
    current = node
    while current.parent is not None:
        parent = current.parent
        if parent.type == "update_expression":
            return True, True
        if parent.type == "assignment_expression":
            left = parent.child_by_field_name("left")
            if left is not None and _contains(left, node):
                operator_text = _clean(source[left.end_byte:parent.child_by_field_name("right").start_byte]
                                       .decode("utf-8", errors="replace"))
                return operator_text != "=", True
            return True, False
        if parent.type in {"expression_statement", "return_statement", "argument_list"}:
            break
        current = parent
    return True, False


def _contains(ancestor, node) -> bool:
    return ancestor.start_byte <= node.start_byte and ancestor.end_byte >= node.end_byte


def _deduplicate_functions(functions: tuple[FunctionInfo, ...]) -> tuple[FunctionInfo, ...]:
    groups: dict[tuple[Any, ...], list[FunctionInfo]] = {}
    for function in functions:
        key = (
            function.name,
            function.return_base_type,
            function.return_pointer_depth,
            tuple((parameter.base_type, parameter.pointer_depth, parameter.is_const)
                  for parameter in function.parameters),
        )
        groups.setdefault(key, []).append(function)
    result = []
    for values in groups.values():
        definitions = [value for value in values if value.defined]
        if definitions:
            result.extend(definitions)
        else:
            result.append(values[0])
    return tuple(sorted(result, key=lambda item: (item.file, item.start_line, item.name)))


def write_functions_json(result: ParseResult, path: Path, *, project: Path | None = None) -> Path:
    """Persist parser output without invoking candidate, semantic, or graph stages."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": FUNCTIONS_SCHEMA_VERSION,
        "files": list(result.files),
        "structs": [info.to_dict() for info in result.structs],
        "functions": [function.to_dict() for function in result.functions],
        "warnings": list(result.warnings),
    }
    if project is not None:
        project_root = Path(project).resolve()
        artifact_root = path.parent.resolve()
        payload["project"] = Path(
            os.path.relpath(project_root, artifact_root)
        ).as_posix()
        payload["source_path_base"] = "project"
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return path
