"""Deterministic project context supplied to code-generation prompts."""

from __future__ import annotations

import json
import re
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Mapping


_LOCAL_INCLUDE = re.compile(r'^\s*#\s*include\s+"([^"]+)"', re.MULTILINE)
_MAX_HEADERS = 40
_MAX_API_CORPUS_ITEMS = 24
_MAX_API_CORPUS_TEXT = 20000

# A callback member of a struct: ``int (*enter_block)(MD_BLOCKTYPE, void*)``.
_CALLBACK_MEMBER = re.compile(
    r"([A-Za-z_][A-Za-z0-9_\s\*]*?)\s*\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\(([^;]*?)\)\s*;"
)
# A typedef naming a function pointer: ``typedef int(*F)(const char*);``.
_CALLBACK_TYPEDEF = re.compile(
    r"typedef\s+([^;()]*?)\s*\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\(([^;]*?)\)\s*;",
    re.DOTALL,
)
# Upstream comments that license leaving a callback null.
_NULLABLE_MARKERS = ("optional", "reserved", "may be null", "can be null")


def project_type_context(
    document: Mapping[str, Any],
    *,
    functions_path: str | Path | None = None,
    source_files: list[str] | tuple[str, ...] = (),
    functions: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...] = (),
) -> dict[str, Any]:
    """Expose exact typedef declarations and usable header spellings."""
    structures = document.get("structs", [])
    if not isinstance(structures, list):
        structures = []
    types = []
    struct_header_files = set()
    for item in structures:
        if not isinstance(item, Mapping):
            continue
        declaration = item.get("declaration")
        file = item.get("file")
        if not isinstance(declaration, str) or not declaration.strip():
            continue
        record = {
            "name": item.get("name"),
            "aliases": item.get("aliases", []),
            "declaration": declaration,
            "file": file,
        }
        types.append(record)
        if isinstance(file, str) and file.endswith(".h"):
            struct_header_files.add(file)

    headers = []
    header_order = _context_header_order(
        document,
        struct_header_files=struct_header_files,
        functions_path=functions_path,
        source_files=source_files,
    )
    project_root = _project_root(document, functions_path)
    unsafe_headers = _cplusplus_unsafe_headers(project_root, header_order)
    for file in header_order:
        include = _include_spelling(file)
        headers.append({"file": file, "include": include})
    callback_tables = callback_table_declarations(types)
    callback_typedefs = _callback_typedefs(project_root, header_order)
    declared_names = _declared_function_names(project_root, header_order)
    return {
        "headers": headers,
        "cplusplus_unsafe_headers": sorted(unsafe_headers),
        "callback_tables": callback_tables,
        "callback_typedefs": callback_typedefs,
        "portable_abi_declarations": _portable_abi_declarations(
            _portable_abi_functions(
                functions,
                expose_public=bool(unsafe_headers) or not header_order,
                declared_names=declared_names,
            ),
            callback_typedefs,
        ),
        "api_corpus": _api_corpus_context(functions_path),
        "types": sorted(types, key=lambda item: str(item.get("name", ""))),
    }


def callback_table_declarations(
    types: list[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Return every struct that carries function-pointer members.

    ``required`` is true for members whose declaring comment grants no license to
    leave them null. A harness that passes such a table to the target must fill
    those members with real functions of the declared signature: the target
    dereferences them unconditionally.
    """
    tables = []
    for item in types:
        declaration = item.get("declaration")
        name = item.get("name")
        if not isinstance(declaration, str) or not isinstance(name, str) or not name:
            continue
        fields = []
        # Semicolons and braces inside comments are not member terminators, so
        # blank the comment bodies first. Offsets stay aligned with the original
        # declaration, which is what the boundary search and the comment slice
        # both index into.
        blanked = _blank_comments(declaration)
        for match in _CALLBACK_MEMBER.finditer(declaration):
            # The optionality comment is the one attached to this member: the
            # text since the previous member terminator. A fixed lookback window
            # would either miss a long comment or read the previous member's.
            boundary = max(
                blanked.rfind(";", 0, match.start()),
                blanked.rfind("{", 0, match.start()),
            )
            comment = declaration[boundary + 1:match.start()].lower()
            fields.append({
                "name": match.group(2),
                "declarator": re.sub(
                    r"\s+", " ", _blank_comments(match.group(0))[:-1]
                ).strip(),
                "return_type": _normalize_declaration_text(match.group(1)),
                "parameter_types": _parameter_types(match.group(3)),
                "required": not any(word in comment for word in _NULLABLE_MARKERS),
            })
        if fields:
            tables.append({"type": name, "file": item.get("file"), "fields": fields})
    return sorted(tables, key=lambda entry: str(entry.get("type", "")))


def _callback_typedefs(
    project_root: Path | None, headers: list[str]
) -> list[dict[str, Any]]:
    """Return every function-pointer typedef declared by the project's headers."""
    found: dict[str, dict[str, Any]] = {}
    for header in headers:
        text = _read_project_file(project_root, header)
        for match in _CALLBACK_TYPEDEF.finditer(text):
            name = match.group(2)
            found.setdefault(name, {
                "name": name,
                "file": header,
                "declaration": re.sub(r"\s+", " ", match.group(0)).strip(),
                "return_type": _normalize_declaration_text(match.group(1)),
                "parameter_types": _parameter_types(match.group(3)),
            })
    return [found[name] for name in sorted(found)]


def _parameter_types(parameters: str) -> list[str]:
    """Split a parameter list on top-level commas and normalize each entry."""
    entries = []
    depth = 0
    current = ""
    for character in parameters:
        if character in "([":
            depth += 1
        elif character in ")]":
            depth -= 1
        if character == "," and depth == 0:
            entries.append(current)
            current = ""
            continue
        current += character
    entries.append(current)
    normalized = [
        _strip_parameter_name(_normalize_declaration_text(entry))
        for entry in entries if entry.strip()
    ]
    if normalized == ["void"]:
        return []
    return normalized


def _strip_parameter_name(declared: str) -> str:
    """Drop a trailing parameter name so only the declared type remains."""
    tokens = declared.split()
    if len(tokens) < 2:
        return declared
    last = tokens[-1]
    if "*" in last or "(" in last or ")" in last or "[" in last or "]" in last:
        return declared
    if not last.isidentifier():
        return declared
    return " ".join(tokens[:-1])


def _blank_comments(value: str) -> str:
    """Replace comment bodies with spaces so offsets survive the removal."""
    return re.sub(
        r"/\*.*?\*/",
        lambda match: re.sub(r"[^\n]", " ", match.group(0)),
        value,
        flags=re.DOTALL,
    )


def _normalize_declaration_text(value: str) -> str:
    """Drop comments and collapse whitespace inside a declared type."""
    without_comments = re.sub(r"/\*.*?\*/", " ", value, flags=re.DOTALL)
    return re.sub(r"\s+", " ", without_comments).strip()


def _callback_parameter_names(
    base_type: str, callback_typedefs: list[dict[str, Any]]
) -> str:
    """Return the callback typedef a parameter spells, or an empty string."""
    normalized = _normalize_declaration_text(base_type)
    for typedef in callback_typedefs:
        if typedef["name"] == normalized:
            return str(typedef["name"])
    if normalized.endswith(("Fun", "Callback")):
        return normalized
    return ""


def _context_header_order(
    document: Mapping[str, Any],
    *,
    struct_header_files: set[str],
    functions_path: str | Path | None,
    source_files: list[str] | tuple[str, ...],
) -> list[str]:
    project_files = document.get("files")
    known_files = set()
    if isinstance(project_files, list):
        known_files.update(
            _posix_path(file) for file in project_files
            if isinstance(file, str) and file.strip()
        )
    known_files.update(_posix_path(file) for file in struct_header_files)
    known_headers = {file for file in known_files if file.endswith(".h")}
    roots = [_posix_path(file) for file in source_files if isinstance(file, str)]
    roots.extend(sorted(_posix_path(file) for file in struct_header_files))

    project_root = _project_root(document, functions_path)
    seen_headers: set[str] = set()
    seen_files: set[str] = set()
    ordered: list[str] = []

    def add_header(file: str) -> None:
        if file in seen_headers or len(ordered) >= _MAX_HEADERS:
            return
        seen_headers.add(file)
        ordered.append(file)

    def visit(file: str) -> None:
        if file in seen_files or len(ordered) >= _MAX_HEADERS:
            return
        seen_files.add(file)
        for include in _local_includes(project_root, file):
            resolved = _resolve_local_include(file, include, known_files, known_headers)
            if resolved is None:
                continue
            add_header(resolved)
            visit(resolved)

    for root in roots:
        if root.endswith(".h"):
            add_header(root)
        visit(root)

    for file in sorted(struct_header_files):
        add_header(_posix_path(file))
    return ordered


def _project_root(
    document: Mapping[str, Any], functions_path: str | Path | None
) -> Path | None:
    root = document.get("project")
    if not isinstance(root, str) or not root.strip():
        return None
    path = Path(root)
    if not path.is_absolute() and functions_path is not None:
        path = Path(functions_path).resolve().parent / path
    return path.resolve()


def _api_corpus_context(functions_path: str | Path | None) -> list[dict[str, Any]]:
    if functions_path is None:
        return []
    root = Path(functions_path).resolve().parent
    json_path = root / "api_corpus.json"
    text_path = root / "api_corpus.txt"
    if json_path.is_file():
        try:
            loaded = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return []
        records = loaded.get("items", loaded) if isinstance(loaded, Mapping) else loaded
        if not isinstance(records, list):
            return []
        result = []
        for record in records[:_MAX_API_CORPUS_ITEMS]:
            if isinstance(record, Mapping):
                text = record.get("text", record.get("content", ""))
                if not isinstance(text, str) or not text.strip():
                    continue
                result.append({
                    "title": str(record.get("title", record.get("source", "api evidence"))),
                    "text": _bounded_text(text),
                })
            elif isinstance(record, str) and record.strip():
                result.append({"title": "api evidence", "text": _bounded_text(record)})
        return result
    if text_path.is_file():
        try:
            text = text_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return []
        if text.strip():
            return [{"title": "api evidence", "text": _bounded_text(text)}]
    return []


def _bounded_text(value: str) -> str:
    normalized = re.sub(r"\s+\n", "\n", value).strip()
    if len(normalized) <= _MAX_API_CORPUS_TEXT:
        return normalized
    return normalized[:_MAX_API_CORPUS_TEXT].rstrip() + "\n[truncated]"


def _local_includes(project_root: Path | None, file: str) -> tuple[str, ...]:
    if project_root is None:
        return ()
    path = (project_root / file).resolve()
    try:
        path.relative_to(project_root)
    except ValueError:
        return ()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()
    return tuple(_LOCAL_INCLUDE.findall(text))


def _resolve_local_include(
    owner: str,
    include: str,
    known_files: set[str],
    known_headers: set[str],
) -> str | None:
    owner_path = PurePosixPath(owner)
    candidates = (
        _posix_path(owner_path.parent / include),
        _posix_path(include),
    )
    for candidate in candidates:
        if candidate in known_headers:
            return candidate
    matches = sorted(file for file in known_headers if file.endswith("/" + include))
    return matches[0] if len(matches) == 1 else None


def _include_spelling(file: str) -> str:
    path = PurePosixPath(file)
    parts = path.parts
    return str(PurePosixPath(*parts[1:])) if parts[:1] == ("include",) else file


def _posix_path(value: str | PurePosixPath) -> str:
    return str(PurePosixPath(str(value)))


def _cplusplus_unsafe_headers(project_root: Path | None, headers: list[str]) -> set[str]:
    unsafe = {
        header for header in headers
        if _header_is_directly_cplusplus_unsafe(project_root, header)
    }
    unsafe_typedefs = set()
    for header in unsafe:
        unsafe_typedefs.update(_typedef_names(_read_project_file(project_root, header)))
    changed = True
    while changed:
        changed = False
        for header in headers:
            if header in unsafe:
                continue
            text = _read_project_file(project_root, header)
            if any(re.search(rf"\b{re.escape(name)}\b", text)
                   for name in unsafe_typedefs):
                unsafe.add(header)
                unsafe_typedefs.update(_typedef_names(text))
                changed = True
    return unsafe


def _header_is_directly_cplusplus_unsafe(project_root: Path | None, file: str) -> bool:
    text = _read_project_file(project_root, file)
    return bool(re.search(r"\btypedef\s+[^;]*\bbool\s*;", text))


def _read_project_file(project_root: Path | None, file: str) -> str:
    if project_root is None:
        return ""
    path = (project_root / file).resolve()
    try:
        path.relative_to(project_root)
    except ValueError:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _typedef_names(text: str) -> set[str]:
    function_pointer = re.compile(
        r"typedef\b[^;]*\(\s*\*\s*([A-Za-z_]\w*)\s*\)[^;]*;",
        re.DOTALL,
    )
    names = set(function_pointer.findall(text))
    reduced = function_pointer.sub(" ", text)
    names.update(re.findall(
        r"typedef\s+(?:struct|enum|union)\b.*?\}\s*([A-Za-z_]\w*)\s*;",
        reduced,
        re.DOTALL,
    ))
    for typedef in re.finditer(r"typedef\b([^{}();]+);", reduced, re.DOTALL):
        match = re.search(
            r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$",
            typedef.group(1).strip(),
        )
        if match:
            names.add(match.group(1))
    return names


def _portable_abi_declarations(
    functions: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    callback_typedefs: list[dict[str, Any]] = (),
) -> list[dict[str, str]]:
    declarations = []
    for record in functions:
        name = record.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        parameters = record.get("parameters", [])
        if not isinstance(parameters, list):
            parameters = []
        return_type = _portable_return_type(record, name)
        arguments = [
            _portable_parameter(parameter, index)
            for index, parameter in enumerate(parameters)
            if isinstance(parameter, Mapping)
        ]
        entry = {
            "function": name,
            "declaration": (
                f'extern "C" {return_type} {name}('
                + (", ".join(arguments) if arguments else "void")
                + ");"
            ),
        }
        callbacks = [
            {"parameter": parameter.get("name"),
             "typedef": _callback_parameter_names(
                 str(parameter.get("base_type") or ""), callback_typedefs
             )}
            for parameter in parameters
            if isinstance(parameter, Mapping)
            and _callback_parameter_names(
                str(parameter.get("base_type") or ""), callback_typedefs
            )
        ]
        if callbacks:
            entry["callback_parameters"] = callbacks
        declarations.append(entry)
    return declarations


def _portable_abi_functions(
    functions: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
    *,
    expose_public: bool,
    declared_names: set[str],
) -> tuple[Mapping[str, Any], ...]:
    if expose_public:
        return tuple(functions)
    selected = []
    for record in functions:
        name = record.get("name")
        storage = record.get("storage", ())
        if (
            isinstance(name, str)
            and (
                name not in declared_names
                or
                (
                    isinstance(storage, list)
                    and "static" in storage
                )
            )
        ):
            selected.append(record)
    return tuple(selected)


def _declared_function_names(
    project_root: Path | None,
    headers: list[str],
) -> set[str]:
    names: set[str] = set()
    if project_root is None:
        return names
    for header in headers:
        path = (project_root / header).resolve()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        names.update(
            match.group(1)
            for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text)
        )
    return names


def _portable_return_type(record: Mapping[str, Any], name: str) -> str:
    signature = record.get("signature")
    if isinstance(signature, str):
        match = re.search(rf"\b{re.escape(name)}\s*\(", signature)
        if match:
            prefix = signature[:match.start()].strip()
            tokens = [
                token for token in prefix.split()
                if token not in {"static", "inline", "extern", "export"}
            ]
            if tokens:
                return _portable_type(" ".join(tokens), record.get("return_base_type"), 0, False)
    return _portable_type(str(record.get("return_type") or "void"), record.get("return_base_type"), 0, False)


def _portable_parameter(parameter: Mapping[str, Any], index: int) -> str:
    name = parameter.get("name")
    parameter_name = name if isinstance(name, str) and name.strip() else f"arg{index}"
    return (
        _portable_type(
            str(parameter.get("type") or parameter.get("base_type") or "void"),
            parameter.get("base_type"),
            int(parameter.get("pointer_depth") or 0),
            bool(parameter.get("is_const")),
        )
        + f" {parameter_name}"
    )


_TYPE_ALIASES = {
    "u8": "uint8_t",
    "u16": "uint16_t",
    "u32": "uint32_t",
    "u64": "uint64_t",
    "i8": "int8_t",
    "i16": "int16_t",
    "i32": "int32_t",
    "i64": "int64_t",
    "bool": "uint8_t",
}
_SCALAR_TYPES = {
    "char", "signed char", "unsigned char", "short", "unsigned short",
    "signed", "unsigned", "signed int", "unsigned int", "int",
    "long", "unsigned long", "long long", "unsigned long long",
    "float", "double", "long double", "size_t", "uint8_t", "uint16_t",
    "uint32_t", "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t", "void",
}


def _is_type_name(value: str) -> bool:
    """Return whether a spelling can be a declared type name in C or C++."""
    return bool(re.fullmatch(r"[A-Za-z_]\w*", value))


def _portable_type(
    declared_type: str,
    base_type: Any,
    pointer_depth: int,
    is_const: bool,
) -> str:
    declared = declared_type.replace("const", "").replace("*", " ").strip()
    declared = re.sub(r"\s+", " ", declared)
    base = str(base_type or declared).strip()
    if pointer_depth <= 0 and base.endswith(("Fun", "Callback")):
        return "void *"
    scalar = None
    for candidate in (declared, base):
        mapped = _TYPE_ALIASES.get(candidate, candidate)
        if mapped in _SCALAR_TYPES:
            scalar = mapped
            break
    if scalar is None:
        scalar = _TYPE_ALIASES.get(declared) or _TYPE_ALIASES.get(base) or base
    if scalar not in _SCALAR_TYPES:
        if pointer_depth > 0 and _is_type_name(scalar):
            # A pointer to a named project type keeps its name: the declaring
            # header is what the harness includes, so spelling it here matches
            # that declaration. Collapsing to void* would instead make the
            # portable declaration conflict with the header's own.
            pass
        else:
            scalar = (
                "void" if pointer_depth > 0 or base.endswith(("Fun", "Callback"))
                else "int"
            )
    if pointer_depth <= 0:
        return scalar
    prefix = "const " if is_const else ""
    return prefix + scalar + " " + "*" * pointer_depth


def bounded_validation_feedback(
    context: Mapping[str, Any] | None,
    *,
    max_reason_characters: int = 1200,
) -> dict[str, Any]:
    """Return only the actionable, bounded fields from a previous failure."""
    if not context:
        return {}
    result = {
        key: context.get(key)
        for key in (
            "failed_stage", "validator", "failure_type", "attempt",
            "rollback_target", "reason",
        )
        if context.get(key) is not None
    }
    reason = result.get("reason")
    if isinstance(reason, str) and len(reason) > max_reason_characters:
        result["reason"] = reason[-max_reason_characters:]
    return result
