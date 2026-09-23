"""Mine evidence-backed project API usage traces and resource lifecycles."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from .models import FunctionInfo


USAGE_SCHEMA_VERSION = 1
_CLEANUP_RE = re.compile(
    r"(?:free|destroy|delete|close|cleanup|dispose|release|unref|decref)(?:$|_)",
    re.IGNORECASE,
)
_RETAIN_RE = re.compile(
    r"(?:^|_)(?:retain|incref|addref|ref|acquire)(?:$|_)", re.IGNORECASE
)
_PRODUCER_RE = re.compile(
    r"(?:create|new|open|alloc|make|init|from|load|construct)", re.IGNORECASE
)
_ERROR_RE = re.compile(r"(?:error|err\b|fail|invalid|goto)", re.IGNORECASE)


@dataclass(frozen=True)
class UsageCall:
    function_id: str
    function: str
    ordinal: int
    line: int
    result_binding: str | None
    arguments: tuple[str, ...]
    argument_bindings: tuple[tuple[str, ...], ...]
    conditions: tuple[str, ...] = ()
    branch: str = "unconditional"
    exit_path: bool = False

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["arguments"] = list(self.arguments)
        value["argument_bindings"] = [list(item) for item in self.argument_bindings]
        value["conditions"] = list(self.conditions)
        return value


@dataclass(frozen=True)
class UsageTrace:
    caller_function_id: str
    caller_function: str
    file: str
    source_kind: str
    calls: tuple[UsageCall, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "caller_function_id": self.caller_function_id,
            "caller_function": self.caller_function,
            "file": self.file,
            "source_kind": self.source_kind,
            "calls": [call.to_dict() for call in self.calls],
        }


@dataclass(frozen=True)
class UsagePattern:
    id: str
    lifecycle_kind: str
    resource_type: str
    producer_function_id: str
    producer_function: str
    producer_binding: str
    producer_argument_index: int | None
    consumers: tuple[str, ...]
    consumer_function_ids: tuple[str, ...]
    consumer_argument_indices: tuple[int, ...]
    cleanup_function_id: str
    cleanup_function: str
    cleanup_argument_index: int
    cleanup_argument: str
    sequence: tuple[str, ...]
    conditions: tuple[str, ...]
    path_kind: str
    nullable: bool
    support_total: int
    support_by_source: Mapping[str, int]
    evidence: tuple[str, ...]
    semantic_review: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.lifecycle_kind not in {"owned_resource", "reference_count"}:
            raise ValueError("unsupported usage lifecycle kind")
        if self.producer_binding not in {"return_value", "out_parameter", "existing_argument"}:
            raise ValueError("unsupported usage producer binding")
        if self.producer_binding == "return_value" and self.producer_argument_index is not None:
            raise ValueError("return-value producer cannot have an argument index")
        if self.producer_binding != "return_value" and (
            type(self.producer_argument_index) is not int
            or self.producer_argument_index < 0
        ):
            raise ValueError("argument producer requires a non-negative argument index")
        if self.path_kind not in {"normal", "conditional", "error"}:
            raise ValueError("unsupported usage path kind")
        if type(self.cleanup_argument_index) is not int or self.cleanup_argument_index < 0:
            raise ValueError("cleanup argument index must be non-negative")
        if not (len(self.consumers) == len(self.consumer_function_ids)
                == len(self.consumer_argument_indices)):
            raise ValueError("usage consumer names, IDs, and positions must align")
        if (not self.sequence or self.sequence[0] != self.producer_function
                or self.sequence[-1] != self.cleanup_function):
            raise ValueError("usage sequence must run from producer to cleanup")
        if type(self.support_total) is not int or self.support_total < 1:
            raise ValueError("usage support_total must be positive")
        if (any(type(value) is not int or value < 0
                for value in self.support_by_source.values())
                or sum(self.support_by_source.values()) != self.support_total):
            raise ValueError("usage support counts must be non-negative and sum to total")
        if self.semantic_review is not None and not isinstance(self.semantic_review, Mapping):
            raise ValueError("usage semantic_review must be an object")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        for field in ("consumers", "consumer_function_ids", "consumer_argument_indices",
                      "sequence", "conditions", "evidence"):
            value[field] = list(value[field])
        value["support_by_source"] = dict(sorted(self.support_by_source.items()))
        if self.semantic_review is not None:
            value["semantic_review"] = dict(self.semantic_review)
        return value


@dataclass(frozen=True)
class UsageMiningResult:
    traces: tuple[UsageTrace, ...]
    patterns: tuple[UsagePattern, ...]
    warnings: tuple[str, ...] = ()
    semantic_reviews: tuple[Mapping[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": USAGE_SCHEMA_VERSION,
            "traces": [trace.to_dict() for trace in self.traces],
            "patterns": [pattern.to_dict() for pattern in self.patterns],
            "warnings": list(self.warnings),
            "semantic_reviews": [dict(review) for review in self.semantic_reviews],
        }


@dataclass(frozen=True)
class _RawPattern:
    lifecycle_kind: str
    resource_type: str
    producer_function_id: str
    producer_function: str
    producer_binding: str
    producer_argument_index: int | None
    consumers: tuple[str, ...]
    consumer_function_ids: tuple[str, ...]
    consumer_argument_indices: tuple[int, ...]
    cleanup_function_id: str
    cleanup_function: str
    cleanup_argument_index: int
    cleanup_argument: str
    sequence: tuple[str, ...]
    conditions: tuple[str, ...]
    path_kind: str
    nullable: bool
    source_kind: str
    evidence: str

    @property
    def key(self) -> tuple[Any, ...]:
        return (
            self.lifecycle_kind, self.resource_type,
            self.producer_function_id, self.producer_binding,
            self.producer_argument_index, self.consumer_function_ids,
            self.consumer_argument_indices, self.cleanup_function_id,
            self.cleanup_argument_index, self.cleanup_argument,
            self.sequence, self.conditions, self.path_kind, self.nullable,
        )


def mine_usage_patterns(functions: Iterable[FunctionInfo]) -> UsageMiningResult:
    """Mine call traces and same-variable lifecycles from project-owned C bodies."""
    functions = tuple(functions)
    by_name: dict[str, list[FunctionInfo]] = {}
    by_id = {function.id: function for function in functions}
    for function in sorted(functions, key=lambda item: (not item.defined, item.id)):
        by_name.setdefault(function.name, []).append(function)
    traces: list[UsageTrace] = []
    raw_patterns: list[_RawPattern] = []
    warnings: list[str] = []
    for caller in sorted(functions, key=lambda item: item.id):
        if not caller.defined or not caller.body.strip():
            continue
        try:
            calls = _extract_calls(caller, _resolve_callees(caller, by_name))
        except Exception as error:  # one malformed body must not abort Phase 1
            warnings.append(f"{caller.file}:{caller.start_line}: usage mining failed ({type(error).__name__})")
            continue
        if not calls:
            continue
        source_kind = _source_kind(caller.file)
        trace = UsageTrace(caller.id, caller.name, caller.file, source_kind, calls)
        traces.append(trace)
        raw_patterns.extend(_patterns_from_trace(trace, by_id))
    return UsageMiningResult(
        tuple(traces), _aggregate_patterns(raw_patterns), tuple(sorted(set(warnings)))
    )


def write_usage_json(result: UsageMiningResult, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(result.to_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(path)
    return path


def load_usage_json(path: Path) -> tuple[Mapping[str, Any], ...]:
    path = Path(path)
    if not path.exists():
        return ()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load {path}: {type(error).__name__}") from None
    if not isinstance(document, dict) or document.get("schema_version") != USAGE_SCHEMA_VERSION:
        raise ValueError("unsupported usage_patterns.json schema_version")
    patterns = document.get("patterns")
    if not isinstance(patterns, list) or any(not isinstance(item, dict) for item in patterns):
        raise ValueError("usage_patterns.json patterns must be an array of objects")
    for pattern in patterns:
        _validate_pattern_record(pattern)
    return tuple(patterns)


def _validate_pattern_record(pattern: Mapping[str, Any]) -> None:
    required_strings = (
        "id", "lifecycle_kind", "resource_type", "producer_function_id",
        "producer_function", "producer_binding", "cleanup_function_id",
        "cleanup_function", "cleanup_argument", "path_kind",
    )
    if any(not isinstance(pattern.get(field), str) or not pattern.get(field)
           for field in required_strings):
        raise ValueError("usage pattern identity fields must be non-empty strings")
    for field in ("consumers", "consumer_function_ids", "consumer_argument_indices",
                  "sequence", "conditions", "evidence"):
        if not isinstance(pattern.get(field), list):
            raise ValueError(f"usage pattern {field} must be an array")
    if not (len(pattern["consumers"]) == len(pattern["consumer_function_ids"])
            == len(pattern["consumer_argument_indices"])):
        raise ValueError("usage pattern consumer arrays must align")
    support = pattern.get("support_by_source")
    total = pattern.get("support_total")
    if (not isinstance(support, dict) or type(total) is not int or total < 1
            or any(type(value) is not int or value < 0 for value in support.values())
            or sum(support.values()) != total):
        raise ValueError("usage pattern support counts are invalid")
    review = pattern.get("semantic_review")
    if review is not None and not isinstance(review, dict):
        raise ValueError("usage pattern semantic_review must be an object or null")


def _extract_calls(caller: FunctionInfo, known: Mapping[str, FunctionInfo]) -> tuple[UsageCall, ...]:
    import tree_sitter
    import tree_sitter_c

    raw = tree_sitter_c.language()
    language = raw if isinstance(raw, tree_sitter.Language) else tree_sitter.Language(raw)
    try:
        parser = tree_sitter.Parser(language)
    except TypeError:
        parser = tree_sitter.Parser()
        parser.language = language
    body = caller.body.strip()
    source = ("void __usage_probe(void) " + body).encode("utf-8")
    root = parser.parse(source).root_node
    records = []
    nodes = sorted(
        (node for node in _walk(root) if node.type == "call_expression"),
        key=lambda node: node.start_byte,
    )
    for node in nodes:
        function_node = node.child_by_field_name("function")
        name = _text(source, function_node)
        if name not in known:
            continue
        aliases = _aliases_before(root, source, node.start_byte)
        arguments_node = node.child_by_field_name("arguments")
        argument_nodes = tuple(arguments_node.named_children) if arguments_node else ()
        arguments = tuple(_text(source, item).strip() for item in argument_nodes)
        bindings = tuple(tuple(sorted({
            _root_alias(_text(source, current), aliases)
            for current in _walk(item) if current.type == "identifier"
        })) for item in argument_nodes)
        conditions, branch, exit_path = _control_context(node, source)
        records.append(UsageCall(
            known[name].id, name, len(records),
            caller.start_line + max(0, node.start_point[0] - 1),
            _result_binding(node, source, aliases), arguments, bindings,
            conditions, branch, exit_path,
        ))
    return tuple(records)


def _patterns_from_trace(
    trace: UsageTrace, known: Mapping[str, FunctionInfo]
) -> tuple[_RawPattern, ...]:
    patterns: list[_RawPattern] = []
    calls = trace.calls
    # Owned return and out-parameter producers.
    for index, call in enumerate(calls):
        function = known[call.function_id]
        producers: list[tuple[str, str, int | None]] = []
        if call.result_binding and (
            function.return_pointer_depth > 0
            or function.return_is_struct_like
            or function.return_is_opaque_handle
        ):
            producers.append((call.result_binding, function.return_base_type, None))
        for argument_index, bindings in enumerate(call.argument_bindings):
            if argument_index >= len(function.parameters):
                continue
            parameter = function.parameters[argument_index]
            raw_argument = call.arguments[argument_index].lstrip()
            if (raw_argument.startswith("&") and len(bindings) == 1
                    and _is_out_producer_argument(function, argument_index)):
                producers.append((bindings[0], parameter.base_type, argument_index))
        for binding, resource_type, out_index in producers:
            later = _bound_calls(
                _tail_until_redefinition(calls[index + 1:], binding, known), binding
            )
            for cleanup_offset, cleanup_call, cleanup_arg in _cleanup_candidates(later, known):
                preceding = [
                    item for item in later[:cleanup_offset]
                    if not _is_cleanup_call(item[0], known, terminal=False)
                ]
                consumers = tuple(item.function for item, _ in preceding)
                consumer_ids = tuple(item.function_id for item, _ in preceding)
                consumer_args = tuple(arg for _, arg in preceding)
                conditions = _normalize_conditions(cleanup_call.conditions, binding)
                path_kind = _path_kind(cleanup_call)
                patterns.append(_RawPattern(
                    "owned_resource", resource_type or "unknown",
                    call.function_id, call.function,
                    "out_parameter" if out_index is not None else "return_value",
                    out_index, consumers, consumer_ids, consumer_args,
                    cleanup_call.function_id, cleanup_call.function, cleanup_arg,
                    "address_of_resource" if cleanup_call.arguments[cleanup_arg].lstrip().startswith("&") else "resource",
                    (call.function, *consumers, cleanup_call.function),
                    conditions, path_kind,
                    _nullable_guard(cleanup_call.conditions, binding), trace.source_kind,
                    f"{trace.file}:{cleanup_call.line} ({trace.caller_function})",
                ))
    # Reference-count lifecycles operate on a pre-existing value.
    for index, call in enumerate(calls):
        if not _RETAIN_RE.search(call.function):
            continue
        for producer_arg, bindings in enumerate(call.argument_bindings):
            if len(bindings) != 1:
                continue
            binding = bindings[0]
            later = _bound_calls(
                _tail_until_redefinition(calls[index + 1:], binding, known), binding
            )
            for cleanup_offset, cleanup_call, cleanup_arg in _cleanup_candidates(later, known):
                if not re.search(r"(?:unref|decref|release)", cleanup_call.function, re.I):
                    continue
                preceding = [
                    item for item in later[:cleanup_offset]
                    if not _is_cleanup_call(item[0], known, terminal=False)
                ]
                producer_info = known[call.function_id]
                resource = (producer_info.parameters[producer_arg].base_type
                            if producer_arg < len(producer_info.parameters) else "unknown")
                patterns.append(_RawPattern(
                    "reference_count", resource, call.function_id, call.function,
                    "existing_argument", producer_arg,
                    tuple(item.function for item, _ in preceding),
                    tuple(item.function_id for item, _ in preceding),
                    tuple(arg for _, arg in preceding),
                    cleanup_call.function_id, cleanup_call.function, cleanup_arg,
                    "resource", (call.function, *(item.function for item, _ in preceding),
                                 cleanup_call.function),
                    _normalize_conditions(cleanup_call.conditions, binding), _path_kind(cleanup_call),
                    _nullable_guard(cleanup_call.conditions, binding), trace.source_kind,
                    f"{trace.file}:{cleanup_call.line} ({trace.caller_function})",
                ))
    return tuple(patterns)


def _bound_calls(calls: tuple[UsageCall, ...], binding: str) -> list[tuple[UsageCall, int]]:
    return [
        (call, index)
        for call in calls
        for index, bindings in enumerate(call.argument_bindings)
        if binding in bindings
    ]


def _tail_until_redefinition(
    calls: tuple[UsageCall, ...], binding: str, known: Mapping[str, FunctionInfo]
) -> tuple[UsageCall, ...]:
    result = []
    for call in calls:
        if call.result_binding == binding:
            break
        function = known[call.function_id]
        redefines = any(
            call.arguments[index].lstrip().startswith("&")
            and binding in bindings
            and _is_out_producer_argument(function, index)
            for index, bindings in enumerate(call.argument_bindings)
        )
        if redefines:
            break
        result.append(call)
    return tuple(result)


def _is_out_producer_argument(function: FunctionInfo, index: int) -> bool:
    if index >= len(function.parameters):
        return False
    parameter = function.parameters[index]
    if parameter.pointer_depth >= 2:
        return True
    writes = any(
        hint.parameter == parameter.name and hint.writes
        for hint in function.access_hints
    )
    return (parameter.pointer_depth >= 1
            and _PRODUCER_RE.search(function.name) is not None
            and (writes or function.return_base_type != "void"))


def _cleanup_candidates(
    calls: list[tuple[UsageCall, int]], known: Mapping[str, FunctionInfo]
) -> list[tuple[int, UsageCall, int]]:
    result = []
    for offset, (call, arg_index) in enumerate(calls):
        if _is_cleanup_call(call, known, terminal=(offset == len(calls) - 1)):
            result.append((offset, call, arg_index))
    return result


def _is_cleanup_call(
    call: UsageCall, known: Mapping[str, FunctionInfo], *, terminal: bool
) -> bool:
    function = known[call.function_id]
    return (_CLEANUP_RE.search(call.function) is not None
            or (terminal and function.return_base_type == "void"))


def _resolve_callees(
    caller: FunctionInfo,
    candidates: Mapping[str, list[FunctionInfo]],
) -> dict[str, FunctionInfo]:
    """Resolve duplicate static names to the definition visible to this caller."""
    resolved = {}
    for name, values in candidates.items():
        same_file = [item for item in values if item.file == caller.file and item.defined]
        external = [
            item for item in values
            if item.defined and "static" not in item.storage
        ]
        pool = same_file or external or [item for item in values if item.defined] or values
        resolved[name] = sorted(pool, key=lambda item: item.id)[0]
    return resolved


def _aggregate_patterns(raw: Iterable[_RawPattern]) -> tuple[UsagePattern, ...]:
    groups: dict[tuple[Any, ...], list[_RawPattern]] = {}
    for pattern in raw:
        groups.setdefault(pattern.key, []).append(pattern)
    result = []
    for key, observations in sorted(groups.items(), key=lambda item: repr(item[0])):
        sample = observations[0]
        support: dict[str, int] = {}
        for observation in observations:
            support[observation.source_kind] = support.get(observation.source_kind, 0) + 1
        identity = json.dumps(key, sort_keys=True, default=list, separators=(",", ":"))
        digest = hashlib.sha256(("usage-pattern-v1\0" + identity).encode()).hexdigest()[:12]
        result.append(UsagePattern(
            f"up_{digest}", sample.lifecycle_kind, sample.resource_type,
            sample.producer_function_id, sample.producer_function,
            sample.producer_binding, sample.producer_argument_index,
            sample.consumers, sample.consumer_function_ids,
            sample.consumer_argument_indices, sample.cleanup_function_id,
            sample.cleanup_function, sample.cleanup_argument_index,
            sample.cleanup_argument, sample.sequence, sample.conditions,
            sample.path_kind, sample.nullable, len(observations), support,
            tuple(sorted({item.evidence for item in observations})),
        ))
    return tuple(sorted(result, key=lambda item: item.id))


def _source_kind(path: str) -> str:
    parts = tuple(part.casefold() for part in Path(path).parts)
    stem = Path(path).stem.casefold()
    if (any(re.fullmatch(r"tests?|testing|check", part) for part in parts)
            or re.search(r"(?:^test[_-]|[_-]test$|tests?)", stem)):
        return "test"
    if (any(re.fullmatch(r"examples?|samples?|demos?", part) for part in parts)
            or re.search(r"(?:example|sample|demo)", stem)):
        return "example"
    return "production"


def _aliases_before(root: Any, source: bytes, before_byte: int) -> dict[str, str]:
    aliases: dict[str, str] = {}
    nodes = sorted(
        (item for item in _walk(root)
         if item.type in {"assignment_expression", "init_declarator"}
         and item.start_byte < before_byte),
        key=lambda item: item.start_byte,
    )
    for node in nodes:
        left = node.child_by_field_name("left") or node.child_by_field_name("declarator")
        right = node.child_by_field_name("right") or node.child_by_field_name("value")
        left_name = _simple_identifier(left, source)
        if left_name is None:
            continue
        if right is not None and any(item.type == "call_expression" for item in _walk(right)):
            aliases.pop(left_name, None)
            continue
        right_name = _simple_identifier(right, source)
        if left_name and right_name:
            aliases[left_name] = _root_alias(right_name, aliases)
        else:
            aliases.pop(left_name, None)
    return aliases


def _result_binding(node: Any, source: bytes, aliases: Mapping[str, str]) -> str | None:
    current = node
    while current.parent is not None and current.parent.type not in {
        "expression_statement", "declaration", "compound_statement"
    }:
        current = current.parent
        if current.type in {"assignment_expression", "init_declarator"}:
            value = current.child_by_field_name("right") or current.child_by_field_name("value")
            if value is not None and value.start_byte <= node.start_byte < value.end_byte:
                target = current.child_by_field_name("left") or current.child_by_field_name("declarator")
                name = _simple_identifier(target, source)
                return name
    return None


def _control_context(node: Any, source: bytes) -> tuple[tuple[str, ...], str, bool]:
    conditions: list[str] = []
    branches: list[str] = []
    exit_path = False
    current = node.parent
    while current is not None:
        if current.type == "if_statement":
            condition = current.child_by_field_name("condition")
            consequence = current.child_by_field_name("consequence")
            alternative = current.child_by_field_name("alternative")
            branch = "then" if _contains(consequence, node) else "else" if _contains(alternative, node) else "unknown"
            selected = consequence if branch == "then" else alternative if branch == "else" else None
            if selected is not None and any(
                item.type in {"return_statement", "goto_statement"}
                for item in _walk(selected)
            ):
                exit_path = True
            conditions.append(_text(source, condition).strip())
            branches.append(branch)
        current = current.parent
    label = _enclosing_label(node, source)
    if label is not None:
        root = node
        while root.parent is not None:
            root = root.parent
        for goto in _walk(root):
            if goto.type != "goto_statement":
                continue
            target = next((
                _text(source, item) for item in goto.named_children
                if item.type in {"identifier", "statement_identifier"}
            ), None)
            if target != label:
                continue
            exit_path = True
            ancestor = goto.parent
            while ancestor is not None:
                if ancestor.type == "if_statement":
                    condition = ancestor.child_by_field_name("condition")
                    rendered = _text(source, condition).strip()
                    if rendered and rendered not in conditions:
                        conditions.append(rendered)
                        branches.append("goto")
                ancestor = ancestor.parent
    conditions.reverse()
    branches.reverse()
    return (tuple(conditions),
            "/".join(branches) if branches else "unconditional",
            exit_path)


def _enclosing_label(node: Any, source: bytes) -> str | None:
    current = node.parent
    while current is not None:
        if current.type == "labeled_statement":
            label = current.child_by_field_name("label")
            if label is None:
                label = next((
                    item for item in current.named_children
                    if item.type in {"identifier", "statement_identifier"}
                ), None)
            value = _text(source, label).strip()
            return value or None
        current = current.parent
    return None


def _path_kind(call: UsageCall) -> str:
    if not call.conditions:
        return "normal"
    condition = " ".join(call.conditions)
    return "error" if call.exit_path or _ERROR_RE.search(condition) else "conditional"


def _nullable_guard(conditions: tuple[str, ...], binding: str) -> bool:
    token = re.escape(binding)
    return any(re.search(
        rf"(?:\b{token}\b\s*(?:!=|==)\s*(?:NULL|nullptr|0)|"
        rf"(?:NULL|nullptr|0)\s*(?:!=|==)\s*\b{token}\b|"
        rf"!?\s*\b{token}\b\s*\)?$)",
        condition,
    ) for condition in conditions)


def _normalize_conditions(
    conditions: tuple[str, ...], binding: str
) -> tuple[str, ...]:
    token = re.compile(r"\b" + re.escape(binding) + r"\b")
    def normalize(condition: str) -> str:
        condition = token.sub("__USAGE_RESOURCE__", condition)
        def replace_identifier(match: re.Match[str]) -> str:
            value = match.group(0)
            if value == "__USAGE_RESOURCE__":
                return "$resource"
            if value in {"NULL", "nullptr", "true", "false", "sizeof"}:
                return value
            if value.isupper():
                return value
            return "$value"
        return re.sub(r"\b[A-Za-z_]\w*\b", replace_identifier, condition)
    return tuple(normalize(condition) for condition in conditions)


def _simple_identifier(node: Any, source: bytes) -> str | None:
    if node is None:
        return None
    identifiers = [_text(source, item) for item in _walk(node) if item.type == "identifier"]
    return identifiers[-1] if len(identifiers) == 1 else None


def _root_alias(name: str, aliases: Mapping[str, str]) -> str:
    seen = set()
    while name in aliases and name not in seen:
        seen.add(name)
        name = aliases[name]
    return name


def _contains(parent: Any, child: Any) -> bool:
    return parent is not None and parent.start_byte <= child.start_byte < parent.end_byte


def _text(source: bytes, node: Any) -> str:
    return "" if node is None else source[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _walk(node: Any):
    if node is None:
        return
    yield node
    for child in node.children:
        yield from _walk(child)
