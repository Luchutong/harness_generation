"""Tree-sitter based intermediate validation without compile or runtime checks."""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .artifacts import ArtifactStore
from .policy import (
    DEFAULT_ALLOWED_FUNCTIONS,
    FORBIDDEN_IO_FUNCTIONS,
    FORBIDDEN_LOGGING_FUNCTIONS,
)
from .records import write_json
from .source_paths import SUPPORTED_FUNCTIONS_SCHEMA_VERSIONS
from .triplet import FunctionTriplet, TripletOwnershipRelation


VALIDATION_SCHEMA_VERSION = 1
VALIDATION_STATUSES = frozenset({
    "passed", "failed", "skipped", "unavailable", "passed_with_limitations",
})


def is_stable_eligible(status: str | None) -> bool:
    """Return whether a validation status may publish a stable artifact."""

    return status == "passed"


_CPP_EVIDENCE = re.compile(
    r"(?:\b(?:class|delete|namespace|new|nullptr|template|typename|using)\b|::|"
    r"\[[=&, ]*\]\s*\()"
)
_CPP_SOURCE_HINTS = re.compile(
    r"(?:extern\s+\"C\"|\bstd\s*::|\b(?:class|namespace|template|typename|using)\b|"
    r"\[[=&, ]*\]\s*\()"
)
_STD_FUNCTION_ALLOWLIST = frozenset({
    "std::abs", "std::begin", "std::copy", "std::copy_n", "std::data",
    "std::end", "std::fill", "std::fill_n", "std::max", "std::memcpy",
    "std::memmove", "std::memset", "std::min", "std::size", "std::strlen",
})


@dataclass(frozen=True)
class ValidationResult:
    success: bool | None
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    metadata: Mapping[str, Any]
    status: str | None = None

    def __post_init__(self) -> None:
        status = self.status
        if status is None:
            if type(self.success) is not bool:
                raise ValueError(
                    "ValidationResult.success must be boolean when status is omitted"
                )
            status = "passed" if self.success else "failed"
            object.__setattr__(self, "status", status)
        if status not in VALIDATION_STATUSES:
            raise ValueError("ValidationResult.status is invalid")
        if status in {"passed", "passed_with_limitations"}:
            consistent = self.success is True and not self.errors
        elif status == "failed":
            consistent = self.success is False and bool(self.errors)
        else:
            consistent = self.success is None and not self.errors
        if not consistent:
            raise ValueError(
                "ValidationResult.success/errors must agree with status"
            )

    @property
    def accepted(self) -> bool:
        """Accept only a passed policy, with declared limitations if needed."""

        return self.status in {"passed", "passed_with_limitations"}

    @property
    def stable_eligible(self) -> bool:
        """Stable publication requires an unqualified validation pass."""

        return is_stable_eligible(self.status)

    def to_dict(self) -> dict[str, Any]:
        validator = self.metadata.get("validator", "intermediate")
        return {
            "validator": validator,
            "status": self.status,
            "success": self.success,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
        }

    def save(self, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_json(destination, self.to_dict(), sort_keys=True, allow_nan=False)
        return destination


@dataclass(frozen=True)
class _SyntaxFacts:
    calls: tuple[str, ...]
    indirect_calls: tuple[str, ...]
    definitions: tuple[str, ...]
    syntax_error_count: int
    cpp_evidence: tuple[str, ...]
    parser: str


class IntermediateValidator:
    """Validate generated C at an intermediate pipeline checkpoint."""

    def __init__(
        self,
        *,
        allowed_functions: Iterable[str] = DEFAULT_ALLOWED_FUNCTIONS,
        forbidden_io_functions: Iterable[str] = FORBIDDEN_IO_FUNCTIONS,
        forbidden_logging_functions: Iterable[str] = FORBIDDEN_LOGGING_FUNCTIONS,
    ) -> None:
        self.allowed_functions = _names(allowed_functions, "allowed_functions")
        self.forbidden_io_functions = _names(
            forbidden_io_functions, "forbidden_io_functions"
        )
        self.forbidden_logging_functions = _names(
            forbidden_logging_functions, "forbidden_logging_functions"
        )

    def validate(
        self,
        source: str | Path,
        *,
        expected_functions: Iterable[str],
        target_functions: Iterable[str],
        validation_path: str | Path,
        stage: str = "intermediate",
        allowed_functions: Iterable[str] = (),
        ownership_cleanup: Iterable[str] = (),
        ownership_relations: Iterable[TripletOwnershipRelation] = (),
    ) -> ValidationResult:
        expected = _names(expected_functions, "expected_functions")
        targets = _names(target_functions, "target_functions")
        extra_allowed = _names(allowed_functions, "allowed_functions")
        scoped_cleanup = _names(ownership_cleanup, "ownership_cleanup")
        relations = tuple(ownership_relations)
        relation_cleanup = {relation.cleanup_function for relation in relations}
        if scoped_cleanup and not scoped_cleanup <= relation_cleanup:
            raise ValueError("ownership cleanup names require matching relations")
        errors: list[str] = []
        warnings: list[str] = []

        try:
            text = _source_text(source)
        except (OSError, UnicodeError, ValueError) as error:
            errors.append(f"cannot read validation source: {type(error).__name__}")
            result = _result(
                errors,
                warnings,
                {
                    "schema_version": VALIDATION_SCHEMA_VERSION,
                    "validator": "intermediate",
                    "stage": stage,
                    "parser": "not-run",
                    "expected_functions": sorted(expected),
                    "target_functions": sorted(targets),
                },
            )
            result.save(validation_path)
            return result

        try:
            facts = _syntax_facts(text)
        except ImportError:
            errors.append("tree-sitter C/C++ dependencies are unavailable")
            result = _result(
                errors,
                warnings,
                {
                    "schema_version": VALIDATION_SCHEMA_VERSION,
                    "validator": "intermediate",
                    "stage": stage,
                    "parser": "unavailable",
                    "expected_functions": sorted(expected),
                    "target_functions": sorted(targets),
                },
            )
            result.save(validation_path)
            return result

        calls = set(facts.calls)
        definitions = Counter(facts.definitions)
        local_functions = set(definitions)
        allowed = self.allowed_functions | _STD_FUNCTION_ALLOWLIST | extra_allowed
        missing = sorted(expected - calls)
        forbidden_logging = sorted(calls & self.forbidden_logging_functions)
        forbidden_io = sorted(calls & self.forbidden_io_functions)
        forbidden = set(forbidden_logging) | set(forbidden_io)
        unexpected_target = sorted((calls & targets) - expected - extra_allowed)
        unknown = sorted(calls - targets - local_functions - allowed - forbidden)
        ownership_calls = sorted(calls & scoped_cleanup)
        unauthorized_ownership = sorted(
            (calls & scoped_cleanup) - extra_allowed
        )
        duplicates = {
            name: count for name, count in sorted(definitions.items()) if count > 1
        }
        redefined = sorted(local_functions & targets)

        if facts.syntax_error_count:
            errors.append(
                f"invalid {facts.parser} syntax: "
                f"{facts.syntax_error_count} tree-sitter error node(s)"
            )
        if missing:
            errors.append("missing expected functions: " + ", ".join(missing))
        if unexpected_target:
            errors.append(
                "unexpected target function calls: " + ", ".join(unexpected_target)
            )
        if duplicates:
            errors.append("duplicate function definitions: " + ", ".join(
                f"{name} ({count})" for name, count in duplicates.items()
            ))
        if forbidden_logging:
            errors.append("forbidden logging calls: " + ", ".join(forbidden_logging))
        if forbidden_io:
            errors.append("forbidden I/O calls: " + ", ".join(forbidden_io))
        if redefined:
            errors.append("redefined target functions: " + ", ".join(redefined))
        if unknown:
            errors.append("calls to unknown target APIs: " + ", ".join(unknown))
        if unauthorized_ownership:
            errors.append(
                "ownership cleanup calls lack a scoped allowance: "
                + ", ".join(unauthorized_ownership)
            )
        if facts.indirect_calls:
            warnings.append(
                "indirect function calls could not be resolved statically: "
                + ", ".join(facts.indirect_calls)
            )

        metadata = {
            "schema_version": VALIDATION_SCHEMA_VERSION,
            "validator": "intermediate",
            "stage": stage,
            "parser": facts.parser,
            "expected_functions": sorted(expected),
            "target_functions": sorted(targets),
            "allowed_functions": sorted(allowed),
            "observed_function_calls": sorted(calls),
            "function_call_counts": dict(sorted(Counter(facts.calls).items())),
            "indirect_function_calls": list(facts.indirect_calls),
            "function_definitions": list(facts.definitions),
            "duplicate_function_definitions": duplicates,
            "missing_expected_functions": missing,
            "unexpected_function_calls": sorted(
                set(unexpected_target) | set(unknown) | forbidden
            ),
            "unknown_target_api_calls": unknown,
            "ownership_cleanup_calls": ownership_calls,
            "ownership_relations": [relation.to_dict() for relation in relations],
            "unauthorized_ownership_cleanup_calls": unauthorized_ownership,
            "redefined_target_functions": redefined,
            "forbidden_logging_calls": forbidden_logging,
            "forbidden_io_calls": forbidden_io,
            "syntax_error_count": facts.syntax_error_count,
            "cpp_evidence": list(facts.cpp_evidence),
        }
        result = _result(errors, warnings, metadata)
        result.save(validation_path)
        return result

    def validate_triplet(
        self,
        source: str | Path,
        triplet: FunctionTriplet,
        *,
        functions_json: str | Path,
        artifacts: str | Path,
        stage: str,
        allowed_functions: Iterable[str] = (),
    ) -> ValidationResult:
        targets = _load_target_functions(Path(functions_json))
        layout = ArtifactStore(Path(artifacts)).for_triplet(triplet.id)
        ownership_cleanup = tuple(relation.cleanup_function for relation in triplet.ownership_relations)
        allowed = tuple(dict.fromkeys((*allowed_functions, *ownership_cleanup)))
        result = self.validate(
            source,
            expected_functions=(function.function for function in triplet.functions),
            target_functions=targets,
            validation_path=layout.intermediate_validation,
            stage=stage,
            allowed_functions=allowed,
            ownership_cleanup=ownership_cleanup,
            ownership_relations=triplet.ownership_relations,
        )
        layout.write_validation("intermediate", result.to_dict())
        return result


def validate_intermediate(
    source: str | Path,
    *,
    expected_functions: Iterable[str],
    target_functions: Iterable[str],
    validation_path: str | Path,
    stage: str = "intermediate",
    allowed_functions: Iterable[str] = (),
) -> ValidationResult:
    return IntermediateValidator().validate(
        source,
        expected_functions=expected_functions,
        target_functions=target_functions,
        validation_path=validation_path,
        stage=stage,
        allowed_functions=allowed_functions,
    )


def _syntax_facts(source: str) -> _SyntaxFacts:
    import tree_sitter

    parser_name, language = _select_language(source, tree_sitter)
    parser = _make_parser(tree_sitter, language)
    encoded = source.encode("utf-8")
    tree = parser.parse(encoded)

    nodes = list(_walk(tree.root_node))
    function_pointers = set()
    local_callables = set()
    for node in nodes:
        if node.type != "function_declarator":
            continue
        declarator = node.child_by_field_name("declarator")
        if declarator is None or not any(
            child.type == "pointer_declarator" for child in _walk(declarator)
        ):
            continue
        name = _declarator_identifier(declarator, encoded)
        if name is not None:
            function_pointers.add(name)
    for node in nodes:
        if node.type != "init_declarator":
            continue
        value = node.child_by_field_name("value")
        if value is None or not any(
            child.type == "lambda_expression" for child in _walk(value)
        ):
            continue
        name = _declarator_identifier(node.child_by_field_name("declarator"), encoded)
        if name is not None:
            local_callables.add(name)

    calls = []
    indirect = []
    definitions = []
    error_nodes = []
    cpp_tokens = []
    for node in nodes:
        node_text = _text(encoded, node)
        if (parser_name == "tree-sitter-c"
                and node.type == "type_identifier"
                and node_text in {"class", "namespace", "template", "typename", "using"}):
            cpp_tokens.append(node_text)
        elif (parser_name == "tree-sitter-c"
              and node.type == "statement_identifier"
              and node_text in {"private", "protected", "public"}):
            cpp_tokens.append(node_text)
        elif parser_name == "tree-sitter-c" and node.type == "identifier" and node_text == "nullptr":
            cpp_tokens.append(node_text)
        if node.type == "ERROR" or getattr(node, "is_missing", False):
            error_nodes.append(node)
        elif node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if callee is None:
                continue
            if callee.type == "identifier":
                name = _text(encoded, callee)
                if name in function_pointers or name in local_callables:
                    indirect.append(name)
                else:
                    calls.append(name)
            elif callee.type == "qualified_identifier":
                qualified = _qualified_identifier_name(callee, encoded)
                if qualified:
                    calls.append(qualified)
                else:
                    indirect.append(_bounded(_text(encoded, callee)))
            elif callee.type == "template_function":
                name = _template_function_name(callee, encoded)
                if name:
                    calls.append(name)
                else:
                    indirect.append(_bounded(_text(encoded, callee)))
            elif callee.type == "field_expression":
                field = callee.child_by_field_name("field")
                indirect.append(
                    _bounded(_text(encoded, field) if field is not None else _text(encoded, callee))
                )
            else:
                indirect.append(_bounded(_text(encoded, callee)))
        elif node.type == "function_definition":
            name = _declarator_identifier(
                node.child_by_field_name("declarator"), encoded
            )
            if name is not None:
                definitions.append(name)

    cpp_evidence = list(cpp_tokens)
    for node in error_nodes:
        evidence = _CPP_EVIDENCE.findall(_text(encoded, node))
        cpp_evidence.extend(item for item in evidence if item)
    return _SyntaxFacts(
        calls=tuple(sorted(calls)),
        indirect_calls=tuple(sorted(set(indirect))),
        definitions=tuple(sorted(definitions)),
        syntax_error_count=(len(error_nodes) or int(tree.root_node.has_error)),
        cpp_evidence=tuple(sorted(set(cpp_evidence))),
        parser=parser_name,
    )


def _select_language(source: str, tree_sitter: Any) -> tuple[str, Any]:
    if _looks_like_cpp(source):
        try:
            import tree_sitter_cpp
        except ImportError as error:
            raise ImportError("tree-sitter C++ dependencies are unavailable") from error
        return "tree-sitter-cpp", _language(tree_sitter, tree_sitter_cpp.language())
    import tree_sitter_c
    return "tree-sitter-c", _language(tree_sitter, tree_sitter_c.language())


def _looks_like_cpp(source: str) -> bool:
    return bool(_CPP_SOURCE_HINTS.search(source))


def _language(tree_sitter: Any, language_value: Any) -> Any:
    return (
        language_value if isinstance(language_value, tree_sitter.Language)
        else tree_sitter.Language(language_value)
    )


def _make_parser(tree_sitter: Any, language: Any) -> Any:
    try:
        return tree_sitter.Parser(language)
    except TypeError:
        parser = tree_sitter.Parser()
        if hasattr(parser, "set_language"):
            parser.set_language(language)
        else:
            parser.language = language
        return parser


def _qualified_identifier_name(node: Any, source: bytes) -> str | None:
    scope = node.child_by_field_name("scope")
    name = node.child_by_field_name("name")
    if name is None:
        return None
    terminal = _template_function_name(name, source)
    if terminal is None:
        terminal = _text(source, name).split("<", 1)[0].strip()
    if scope is None:
        return terminal
    return f"{_text(source, scope)}::{terminal}"


def _template_function_name(node: Any, source: bytes) -> str | None:
    if node.type == "identifier":
        return _text(source, node)
    name = node.child_by_field_name("name")
    if name is not None:
        return _text(source, name)
    for child in node.children:
        if child.type in {"identifier", "field_identifier"}:
            return _text(source, child)
    return None


def _load_target_functions(path: Path) -> frozenset[str]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load functions.json: {type(error).__name__}") from error
    if (not isinstance(document, Mapping)
            or document.get("schema_version") not in SUPPORTED_FUNCTIONS_SCHEMA_VERSIONS):
        raise ValueError("functions.json requires schema_version 1 or 2")
    records = document.get("functions")
    if not isinstance(records, list) or any(not isinstance(item, Mapping)
                                            for item in records):
        raise ValueError("functions.json functions must be an array of objects")
    return _names(
        (_required_string(record, "name", "functions.json") for record in records),
        "functions.json function names",
    )


def _source_text(source: str | Path) -> str:
    if isinstance(source, Path):
        value = source.read_text(encoding="utf-8")
    elif isinstance(source, str):
        value = source
    else:
        raise ValueError("validation source must be text or a Path")
    if not value.strip():
        raise ValueError("validation source is empty")
    return value


def _result(errors: Iterable[str], warnings: Iterable[str],
            metadata: Mapping[str, Any]) -> ValidationResult:
    canonical_errors = tuple(dict.fromkeys(errors))
    canonical_warnings = tuple(dict.fromkeys(warnings))
    return ValidationResult(
        success=not canonical_errors,
        errors=canonical_errors,
        warnings=canonical_warnings,
        metadata=dict(metadata),
    )


def _names(values: Iterable[str], field: str) -> frozenset[str]:
    result = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{field} must contain non-empty strings")
        result.add(value)
    return frozenset(result)


def _walk(node: Any) -> Iterable[Any]:
    if node is None:
        return
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.children))


def _declarator_identifier(node: Any, source: bytes) -> str | None:
    if node is None:
        return None
    if node.type == "identifier":
        return _text(source, node)
    declarator = node.child_by_field_name("declarator")
    if declarator is not None:
        name = _declarator_identifier(declarator, source)
        if name is not None:
            return name
    return next(
        (_text(source, child) for child in _walk(node)
         if child.type == "identifier"),
        None,
    )


def _text(source: bytes, node: Any) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _bounded(value: str, limit: int = 120) -> str:
    compact = " ".join(value.split())
    return compact if len(compact) <= limit else compact[:limit - 3] + "..."


def _required_string(value: Mapping[str, Any], field: str, owner: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item.strip():
        raise ValueError(f"{field} must be non-empty text for {owner}")
    return item
