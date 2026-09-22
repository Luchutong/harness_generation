"""Stage 4: transform Stage 3 rough code into an audited C++ libFuzzer harness."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .artifacts import ArtifactStore
from .generation_output import normalize_c_response
from .generation_context import (bounded_validation_feedback,
                                 project_type_context)
from .llm import LLMClient, LLMGeneration
from .policy import FORBIDDEN_LOGGING_FUNCTIONS
from .prompts import stage4_harness_plan, stage4_harness_transform
from .sfg_adapter import is_null_node
from .source_paths import SUPPORTED_FUNCTIONS_SCHEMA_VERSIONS
from .stage4_outcome import record_parse_result
from .triplet import FunctionTriplet, TripletOwnershipRelation


FUZZ_ENTRY = "LLVMFuzzerTestOneInput"
_FILE_IO_CALLS = {
    "fopen", "freopen", "fdopen", "fclose", "fread", "fwrite",
    "fseek", "ftell", "fgetpos", "fsetpos", "rewind", "tmpfile",
}
_STANDARD_C_CALLS = {
    "abort", "assert", "calloc", "free", "malloc", "memcmp", "memcpy",
    "memmove", "memset", "realloc", "strchr", "strcmp", "strlen",
    "strncmp", "strnlen", "strrchr",
}


class Stage4Error(ValueError):
    """The Stage 4 input or generated harness violates the frozen contract."""


@dataclass(frozen=True)
class HarnessPlan:
    """Structured Stage 4 plan that constrains final C++ harness generation."""

    triplet_id: str
    entrypoint: str
    input_strategy: Mapping[str, Any]
    state_objects: tuple[Mapping[str, Any], ...]
    call_sequence: tuple[Mapping[str, Any], ...]
    cleanup_sequence: tuple[Mapping[str, Any], ...]
    constraints: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    generation_metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "triplet_id": self.triplet_id,
            "entrypoint": self.entrypoint,
            "input_strategy": dict(self.input_strategy),
            "state_objects": [dict(item) for item in self.state_objects],
            "call_sequence": [dict(item) for item in self.call_sequence],
            "cleanup_sequence": [dict(item) for item in self.cleanup_sequence],
            "constraints": list(self.constraints),
            "notes": list(self.notes),
            "generation_metadata": dict(self.generation_metadata),
        }


@dataclass(frozen=True)
class Stage4Result:
    triplet_id: str
    harness_code: str
    harness_path: Path
    stable_path: Path | None
    generation_metadata: Mapping[str, Any]
    attempt_directory: Path
    harness_plan: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class _Parameter:
    name: str | None
    base_type: str
    qualifiers: tuple[str, ...]
    pointer_depth: int


@dataclass(frozen=True)
class _Argument:
    text: str
    identifiers: tuple[str, ...]
    has_string_literal: bool


@dataclass(frozen=True)
class _Call:
    name: str
    arguments: tuple[_Argument, ...]
    start_byte: int
    assignment_target: str | None = None
    guard_texts: tuple[str, ...] = ()
    preceding_returns: tuple[str | None, ...] = ()


@dataclass(frozen=True)
class _FunctionDefinition:
    name: str
    return_type: str
    parameters: tuple[_Parameter, ...]
    calls: tuple[_Call, ...]
    identifiers: tuple[str, ...]


@dataclass(frozen=True)
class _HarnessAnalysis:
    functions: tuple[_FunctionDefinition, ...]
    calls: tuple[_Call, ...]


class Stage4Generator:
    """Generate, validate, and publish one FT-specific libFuzzer harness."""

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def run(
        self,
        triplet: FunctionTriplet,
        *,
        rough_code: str | Path,
        functions_json: str | Path,
        artifacts: str | Path,
        publish: bool = True,
        rollback_source: str | None = None,
        retry_reason: str | None = None,
        retry_context: Mapping[str, Any] | None = None,
    ) -> Stage4Result:
        rough_source = _load_rough_code(rough_code)
        function_metadata, all_project_functions, project_context = _load_function_metadata(
            Path(functions_json), triplet
        )
        isf_metadata = function_metadata[triplet.isf.function_id]
        validation_feedback = _stage4_validation_feedback(
            retry_context,
            triplet_id=triplet.id,
            unique_isf_function_id=str(isf_metadata.get("id", "")),
        )
        plan_prompt = stage4_harness_plan(
            triplet_id=triplet.id,
            rough_code=rough_source,
            unique_isf={
                **isf_metadata,
                "structural_edges": [
                    edge.to_dict()
                    for edge in triplet.edges
                    if edge.function_id == triplet.isf.function_id
                ],
            },
            function_metadata=[
                function_metadata[function.function_id]
                for function in triplet.functions
            ],
            bypass_semantics=[
                semantic.to_dict() for semantic in triplet.bypass_semantics
            ],
            ownership_relations=[
                relation.to_dict() for relation in triplet.ownership_relations
            ],
            project_context=project_context,
            validation_feedback=validation_feedback,
        )
        layout = ArtifactStore(Path(artifacts)).for_triplet(triplet.id)
        layout.ensure_generation()
        attempt, attempt_directory = layout.next_attempt("stage4")
        layout.write_text(attempt_directory / "plan_prompt.txt", plan_prompt.content)
        try:
            plan_generation = self.llm.generate(plan_prompt)
            harness_plan = parse_harness_plan(
                plan_generation.content,
                triplet=triplet,
                isf_metadata=isf_metadata,
            )
            harness_plan = replace(
                harness_plan,
                generation_metadata=_generation_metadata(plan_generation),
            )
        except Exception as error:
            response = (
                "" if "plan_generation" not in locals()
                else plan_generation.content
            )
            layout.write_text(attempt_directory / "plan_response.txt", response)
            layout.write_json(attempt_directory / "metadata.json", _attempt_metadata(
                triplet.id, attempt, None, rollback_source, retry_reason,
                retry_context, client=self.llm,
                prompt_version=plan_prompt.prompt_version,
                plan_prompt_version=plan_prompt.prompt_version,
            ))
            record_parse_result(attempt_directory, {
                "status": "failed",
                "phase": "harness_plan",
                "error_type": type(error).__name__,
                "error": str(error),
            })
            raise
        layout.write_text(
            attempt_directory / "plan_response.txt", plan_generation.content
        )
        layout.write_json(attempt_directory / "plan.json", harness_plan.to_dict())

        prompt = stage4_harness_transform(
            harness_plan=harness_plan.to_dict(),
            rough_code=rough_source,
            unique_isf={
                **isf_metadata,
                "structural_edges": [
                    edge.to_dict()
                    for edge in triplet.edges
                    if edge.function_id == triplet.isf.function_id
                ],
            },
            function_metadata=[
                function_metadata[function.function_id]
                for function in triplet.functions
            ],
            ownership_relations=[
                relation.to_dict() for relation in triplet.ownership_relations
            ],
            project_context=project_context,
            validation_feedback=validation_feedback,
        )
        layout.write_text(attempt_directory / "prompt.txt", prompt.content)
        try:
            generation = self.llm.generate(prompt)
        except Exception as error:
            layout.write_text(attempt_directory / "response.txt", "")
            layout.write_json(attempt_directory / "metadata.json", _attempt_metadata(
                triplet.id, attempt, None, rollback_source, retry_reason,
                retry_context, client=self.llm,
                prompt_version=prompt.prompt_version,
                plan_prompt_version=plan_prompt.prompt_version,
            ))
            record_parse_result(attempt_directory, {
                "status": "failed",
                "phase": "harness_code",
                "error_type": type(error).__name__,
                "error": str(error),
            })
            raise
        harness = normalize_cpp_harness(normalize_c_response(generation.content))
        layout.write_text(attempt_directory / "response.txt", generation.content)
        layout.write_text(attempt_directory / "harness.c", harness + "\n")
        layout.write_json(attempt_directory / "metadata.json", _attempt_metadata(
            triplet.id, attempt, generation, rollback_source, retry_reason,
            retry_context, plan_prompt_version=plan_prompt.prompt_version,
            plan_generation=plan_generation,
        ))
        try:
            analysis = _analyze_cpp(harness)
            _validate_harness(
                analysis,
                triplet,
                isf_metadata,
                all_project_functions,
                harness_plan,
            )
        except Exception as error:
            record_parse_result(attempt_directory, {
                "status": "failed",
                "phase": "harness_code",
                "error_type": type(error).__name__,
                "error": str(error),
            })
            raise

        harness_path = layout.stage4_harness
        persisted = harness + "\n"
        layout.write_json(layout.stage4_harness_plan, harness_plan.to_dict())
        layout.write_text(harness_path, persisted)
        stable_path = None
        if publish:
            stable_path = layout.harness
            layout.write_text(stable_path, persisted)
        record_parse_result(attempt_directory, {
            "status": "passed",
            "harness_plan": harness_plan.to_dict(),
            "definitions": [function.name for function in analysis.functions],
            "calls": sorted({call.name for call in analysis.calls}),
        })
        return Stage4Result(
            triplet_id=triplet.id,
            harness_code=harness,
            harness_path=harness_path,
            stable_path=stable_path,
            generation_metadata=_generation_metadata(generation),
            attempt_directory=attempt_directory,
            harness_plan=harness_plan.to_dict(),
        )


def generate_stage4_harness(
    triplet: FunctionTriplet,
    llm: LLMClient,
    *,
    rough_code: str | Path,
    functions_json: str | Path,
    artifacts: str | Path,
    publish: bool = True,
) -> Stage4Result:
    return Stage4Generator(llm).run(
        triplet,
        rough_code=rough_code,
        functions_json=functions_json,
        artifacts=artifacts,
        publish=publish,
    )


def _load_rough_code(value: str | Path) -> str:
    if isinstance(value, Path):
        try:
            source = value.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise Stage4Error(f"cannot load Stage 3 rough code: {type(error).__name__}") from error
    elif isinstance(value, str):
        source = value
    else:
        raise Stage4Error("rough_code must be C source text or a Path")
    if not source.strip():
        raise Stage4Error("Stage 3 rough code is empty")
    return source


def normalize_cpp_harness(source: str) -> str:
    """Constrain Stage 4 output to a C++ libFuzzer translation unit.

    LLMs often emit the right body but omit the standard integer/size headers
    or the C linkage required when a C target is linked with a C++ harness.  This
    normalization is intentionally mechanical and auditable: it does not invent
    target calls or alter function ordering.
    """

    harness = source.strip()
    harness = _ensure_cpp_standard_headers(harness)
    harness = _wrap_project_header_includes_for_c_linkage(harness)
    harness = _ensure_extern_c_fuzzer_entry(harness)
    return harness.strip()


def _ensure_cpp_standard_headers(source: str) -> str:
    required = []
    if not re.search(r'^\s*#\s*include\s*[<"](?:stddef\.h|cstddef)[>"]',
                     source, re.MULTILINE):
        required.append("#include <stddef.h>")
    if not re.search(r'^\s*#\s*include\s*[<"](?:stdint\.h|cstdint)[>"]',
                     source, re.MULTILINE):
        required.append("#include <stdint.h>")
    if not required:
        return source
    return "\n".join((*required, source))


def _wrap_project_header_includes_for_c_linkage(source: str) -> str:
    lines = source.splitlines()
    wrapped: list[str] = []
    extern_depth = 0
    extern_opener = re.compile(r'^\s*extern\s+"C"\s*\{')
    quoted_include = re.compile(r'^(\s*)#\s*include\s*"([^"]+)"\s*$')
    for line in lines:
        in_extern_block = extern_depth > 0
        if extern_opener.search(line):
            extern_depth += line.count("{") - line.count("}")
            wrapped.append(line)
            continue
        match = quoted_include.match(line)
        if match and not in_extern_block:
            indent = match.group(1)
            wrapped.append(f'{indent}extern "C" {{')
            wrapped.append(line)
            wrapped.append(f"{indent}}}")
        else:
            wrapped.append(line)
        if in_extern_block:
            extern_depth += line.count("{") - line.count("}")
            if extern_depth < 0:
                extern_depth = 0
    return "\n".join(wrapped)


def _ensure_extern_c_fuzzer_entry(source: str) -> str:
    if re.search(r'extern\s+"C"\s+int\s+LLVMFuzzerTestOneInput\s*\(', source):
        return source
    return re.sub(
        r'(?m)^(\s*)int\s+LLVMFuzzerTestOneInput\s*\(',
        r'\1extern "C" int LLVMFuzzerTestOneInput(',
        source,
        count=1,
    )


def parse_harness_plan(
    content: str,
    *,
    triplet: FunctionTriplet,
    isf_metadata: Mapping[str, Any],
) -> HarnessPlan:
    """Parse and validate the strict JSON HarnessPlan returned by the LLM."""

    if not isinstance(content, str) or not content.strip():
        raise Stage4Error("HarnessPlan response is empty")
    if "```" in content:
        raise Stage4Error("HarnessPlan must be strict JSON without Markdown fences")
    try:
        document = json.loads(content)
    except json.JSONDecodeError as error:
        raise Stage4Error(f"HarnessPlan is not valid JSON: {error}") from error
    if not isinstance(document, Mapping):
        raise Stage4Error("HarnessPlan must be a JSON object")
    if document.get("schema_version") != 1:
        raise Stage4Error("HarnessPlan requires schema_version 1")
    if document.get("triplet_id") != triplet.id:
        raise Stage4Error("HarnessPlan triplet_id does not match the FT")
    if document.get("entrypoint") != FUZZ_ENTRY:
        raise Stage4Error(f"HarnessPlan entrypoint must be {FUZZ_ENTRY}")
    forbidden_keys = {"harness_code", "c_source", "source_code", "final_code"}
    if forbidden_keys & set(document):
        raise Stage4Error("HarnessPlan must not contain final C source fields")
    serialized = json.dumps(document, sort_keys=True)
    if "#include" in serialized or f"{FUZZ_ENTRY}(" in serialized:
        raise Stage4Error("HarnessPlan must not embed final C harness source")

    input_strategy = document.get("input_strategy")
    if not isinstance(input_strategy, Mapping):
        raise Stage4Error("HarnessPlan input_strategy must be an object")
    if input_strategy.get("data_identifier") != "data" or \
            input_strategy.get("size_identifier") != "size":
        raise Stage4Error("HarnessPlan must bind fuzzer data and size identifiers")

    call_sequence = _plan_object_list(document, "call_sequence")
    cleanup_sequence = _plan_object_list(document, "cleanup_sequence")
    state_objects = _plan_object_list(document, "state_objects")
    constraints = _plan_string_list(document, "constraints")
    notes = _plan_string_list(document, "notes")

    expected = {function.function for function in triplet.functions}
    ownership_by_id = {relation.id: relation for relation in triplet.ownership_relations}
    ownership_by_cleanup: dict[str, list[TripletOwnershipRelation]] = {}
    for relation in triplet.ownership_relations:
        ownership_by_cleanup.setdefault(relation.cleanup_function, []).append(relation)
    planned_calls = [_plan_function(item, "call_sequence") for item in call_sequence]
    planned_cleanup = [
        _plan_function(item, "cleanup_sequence") for item in cleanup_sequence
    ]
    relation_items: dict[str, Mapping[str, Any]] = {}
    for item, function in zip(cleanup_sequence, planned_cleanup):
        relation_id = item.get("relation_id")
        matching = ownership_by_id.get(relation_id) if isinstance(relation_id, str) else None
        if matching is None:
            candidates = ownership_by_cleanup.get(function, ())
            if candidates:
                raise Stage4Error(
                    f"ownership cleanup {function} requires a valid relation_id"
                )
            continue
        if relation_id in relation_items:
            raise Stage4Error(f"ownership relation {relation_id} appears more than once")
        if function != matching.cleanup_function:
            raise Stage4Error(
                f"ownership relation {relation_id} requires cleanup function "
                f"{matching.cleanup_function}"
            )
        relation_items[relation_id] = item
        _validate_ownership_plan_item(item, matching)

    missing_relations = sorted(set(ownership_by_id) - set(relation_items))
    if missing_relations:
        raise Stage4Error(
            "HarnessPlan must include exactly one cleanup for ownership relations: "
            + ", ".join(missing_relations)
        )
    external_cleanup = sorted(
        set(planned_cleanup) & set(ownership_by_cleanup) - expected
    )
    all_planned = planned_calls + planned_cleanup
    unknown = sorted(set(all_planned) - expected - set(external_cleanup))
    if unknown:
        raise Stage4Error(
            "HarnessPlan references functions outside the FT: " + ", ".join(unknown)
        )
    missing = sorted(expected - set(all_planned))
    if missing:
        raise Stage4Error("HarnessPlan omits FT functions: " + ", ".join(missing))
    duplicated = sorted(
        name for name in set(all_planned) if all_planned.count(name) > 1
    )
    if duplicated:
        raise Stage4Error(
            "HarnessPlan duplicates FT functions: " + ", ".join(duplicated)
        )
    if triplet.isf.function not in planned_calls:
        raise Stage4Error("HarnessPlan must place the unique ISF in call_sequence")
    if triplet.isf.function in planned_cleanup:
        raise Stage4Error("HarnessPlan must not place the unique ISF in cleanup_sequence")

    isf_step = next(
        item for item in call_sequence
        if item.get("function") == triplet.isf.function
    )
    if _isf_requires_stream_size(isf_metadata) and (
        isf_step.get("uses_fuzzer_data") is not True
        or isf_step.get("uses_fuzzer_size") is not True
    ):
        raise Stage4Error(
            "HarnessPlan ISF step must use both fuzzer data and fuzzer size"
        )

    prf_names = {function.function for function in triplet.prfs}
    for function in triplet.functions:
        if "PRF" in function.roles and "HPF" in function.roles:
            if function.function not in planned_calls:
                raise Stage4Error(
                    "HarnessPlan must keep PRF+HPF functions in call_sequence: "
                    + function.function
                )
        elif "HPF" in function.roles and function.function_id != triplet.isf.function_id:
            if function.function not in prf_names and function.function not in planned_cleanup:
                raise Stage4Error(
                    "HarnessPlan must place pure HPF cleanup in cleanup_sequence: "
                    + function.function
                )

    return HarnessPlan(
        triplet_id=triplet.id,
        entrypoint=FUZZ_ENTRY,
        input_strategy=dict(input_strategy),
        state_objects=tuple(dict(item) for item in state_objects),
        call_sequence=tuple(dict(item) for item in call_sequence),
        cleanup_sequence=tuple(dict(item) for item in cleanup_sequence),
        constraints=tuple(constraints),
        notes=tuple(notes),
    )


def _validate_ownership_plan_item(
    item: Mapping[str, Any], relation: TripletOwnershipRelation
) -> None:
    if item.get("producer_function") != relation.producer_function:
        raise Stage4Error(
            f"ownership cleanup {relation.cleanup_function} requires its producer_function"
        )
    if item.get("resource_type") != relation.resource_type:
        raise Stage4Error(
            f"ownership cleanup {relation.cleanup_function} requires its resource_type"
        )
    after = item.get("after", [])
    if not isinstance(after, list) or any(not isinstance(value, str) for value in after):
        raise Stage4Error(
            f"HarnessPlan cleanup_sequence after must be strings: {relation.cleanup_function}"
        )
    required_after = set(relation.consumers) | {relation.producer_function}
    if not required_after <= set(after):
        raise Stage4Error(
            f"ownership cleanup {relation.cleanup_function} must occur after producer and consumers"
        )
    arguments = item.get("arguments", [])
    if not isinstance(arguments, list) or len(arguments) != 1:
        raise Stage4Error(
            f"ownership cleanup {relation.cleanup_function} requires one bound argument"
        )
    binding = item.get("producer_return_binding")
    if not isinstance(binding, Mapping):
        raise Stage4Error(
            f"ownership cleanup {relation.cleanup_function} requires producer_return_binding"
        )
    identifier = binding.get("identifier")
    kind = binding.get("kind")
    if not isinstance(identifier, str) or not identifier or kind != relation.cleanup_argument:
        raise Stage4Error(
            f"ownership cleanup {relation.cleanup_function} has invalid producer binding"
        )
    expected_argument = identifier if kind == "return_value" else "&" + identifier
    if arguments[0].strip() != expected_argument:
        raise Stage4Error(
            f"ownership cleanup {relation.cleanup_function} argument must bind {expected_argument}"
        )
    if relation.nullable:
        conditions = item.get("conditions")
        if not isinstance(conditions, list) or not conditions or any(
            not isinstance(value, str) or not value.strip() for value in conditions
        ):
            raise Stage4Error(
                f"nullable ownership cleanup {relation.cleanup_function} requires explicit conditions"
            )


def _plan_object_list(document: Mapping[str, Any], field: str) -> tuple[Mapping[str, Any], ...]:
    value = document.get(field)
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise Stage4Error(f"HarnessPlan {field} must be an array of objects")
    return tuple(value)


def _plan_string_list(document: Mapping[str, Any], field: str) -> tuple[str, ...]:
    value = document.get(field, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise Stage4Error(f"HarnessPlan {field} must be an array of strings")
    return tuple(value)


def _plan_function(item: Mapping[str, Any], field: str) -> str:
    function = item.get("function")
    if not isinstance(function, str) or not function.strip():
        raise Stage4Error(f"HarnessPlan {field} item requires function")
    arguments = item.get("arguments", [])
    if not isinstance(arguments, list) or any(not isinstance(value, str)
                                             for value in arguments):
        raise Stage4Error(f"HarnessPlan {field} arguments must be strings")
    return function


def _isf_requires_stream_size(metadata: Mapping[str, Any]) -> bool:
    parameters = metadata.get("parameters", [])
    if not isinstance(parameters, list):
        return False
    has_stream = any(
        isinstance(parameter, Mapping)
        and parameter.get("is_pointer") is True
        and parameter.get("is_struct_like") is not True
        and parameter.get("base_type") in {
            "void", "char", "unsigned char", "int8_t", "uint8_t"
        }
        for parameter in parameters
    )
    has_length = any(
        isinstance(parameter, Mapping)
        and parameter.get("is_pointer") is not True
        and str(parameter.get("name", "")).lower() in {
            "size", "len", "length", "n", "data_size", "buffer_size"
        }
        for parameter in parameters
    )
    return has_stream and has_length


def _load_function_metadata(
    path: Path,
    triplet: FunctionTriplet,
) -> tuple[dict[str, dict[str, Any]], set[str], dict[str, Any]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise Stage4Error(f"cannot load functions.json: {type(error).__name__}") from error
    if (not isinstance(document, Mapping)
            or document.get("schema_version") not in SUPPORTED_FUNCTIONS_SCHEMA_VERSIONS):
        raise Stage4Error("functions.json requires schema_version 1 or 2")
    records = document.get("functions")
    if not isinstance(records, list) or any(not isinstance(item, Mapping)
                                            for item in records):
        raise Stage4Error("functions.json functions must be an array of objects")

    by_id = {}
    all_names = set()
    for record in records:
        function_id = _required_string(record, "id", "functions.json")
        name = _required_string(record, "name", function_id)
        if function_id in by_id:
            raise Stage4Error(f"duplicate functions.json function id: {function_id}")
        by_id[function_id] = record
        all_names.add(name)

    selected = {}
    for function in triplet.functions:
        record = by_id.get(function.function_id)
        if record is None or record.get("name") != function.function:
            raise Stage4Error(
                f"FT function is missing or mismatched in functions.json: {function.function_id}"
            )
        parameters = record.get("parameters", [])
        if not isinstance(parameters, list) or any(not isinstance(item, Mapping)
                                                   for item in parameters):
            raise Stage4Error(f"invalid parameters for {function.function_id}")
        selected[function.function_id] = {
            "id": function.function_id,
            "name": function.function,
            "roles": list(function.roles),
            "signature": record.get("signature"),
            "return_type": record.get("return_type"),
            "parameters": [dict(parameter) for parameter in parameters],
            "file": record.get("file"),
            "start_line": record.get("start_line"),
        }
    return selected, all_names, project_type_context(document)


def _analyze_cpp(source: str) -> _HarnessAnalysis:
    if not source:
        raise Stage4Error("LLM returned an empty Stage 4 harness")
    if "```" in source:
        raise Stage4Error("Stage 4 harness must not contain Markdown fences")
    try:
        import tree_sitter
        import tree_sitter_cpp
    except ImportError as error:
        raise Stage4Error("tree-sitter C++ dependencies are required for Stage 4") from error

    language_value = tree_sitter_cpp.language()
    language = (language_value if isinstance(language_value, tree_sitter.Language)
                else tree_sitter.Language(language_value))
    try:
        parser = tree_sitter.Parser(language)
    except TypeError:
        parser = tree_sitter.Parser()
        if hasattr(parser, "set_language"):
            parser.set_language(language)
        else:
            parser.language = language
    encoded = source.encode("utf-8")
    tree = parser.parse(encoded)
    if tree.root_node.has_error:
        raise Stage4Error("LLM returned invalid C++ syntax")

    functions = []
    all_calls = []
    for node in _walk(tree.root_node):
        if node.type != "function_definition":
            continue
        declarator = node.child_by_field_name("declarator")
        function_declarator = _find_function_declarator(declarator)
        name = _declarator_identifier(declarator, encoded)
        if name is None or function_declarator is None:
            raise Stage4Error("could not inspect a generated function definition")
        body = node.child_by_field_name("body")
        calls = tuple(_calls(body, encoded))
        all_calls.extend(calls)
        functions.append(_FunctionDefinition(
            name=name,
            return_type=_node_text(encoded, node.child_by_field_name("type")),
            parameters=tuple(_parameters(function_declarator, encoded)),
            calls=calls,
            identifiers=tuple(sorted({
                _node_text(encoded, current)
                for current in _walk(body)
                if current.type == "identifier"
            })) if body is not None else (),
        ))
    return _HarnessAnalysis(tuple(functions), tuple(all_calls))


def _validate_harness(
    analysis: _HarnessAnalysis,
    triplet: FunctionTriplet,
    isf_metadata: Mapping[str, Any],
    all_project_functions: set[str],
    plan: HarnessPlan,
) -> None:
    definitions = [function.name for function in analysis.functions]
    if definitions.count(FUZZ_ENTRY) != 1:
        raise Stage4Error(f"Stage 4 requires exactly one {FUZZ_ENTRY} definition")
    if "main" in definitions:
        raise Stage4Error("Stage 4 harness must not contain a demo main")
    redefined = sorted((set(definitions) - {FUZZ_ENTRY}) & all_project_functions)
    if redefined:
        raise Stage4Error("Stage 4 redefines project APIs: " + ", ".join(redefined))

    entry = next(function for function in analysis.functions if function.name == FUZZ_ENTRY)
    _validate_entry_signature(entry)
    if not {"data", "size"} <= set(entry.identifiers):
        raise Stage4Error("Stage 4 harness must use both external data and size")

    calls = {call.name for call in analysis.calls}
    forbidden_logging = sorted(calls & FORBIDDEN_LOGGING_FUNCTIONS)
    if forbidden_logging:
        raise Stage4Error("Stage 4 harness contains logging calls: " +
                          ", ".join(forbidden_logging))
    forbidden_file_io = sorted(calls & _FILE_IO_CALLS)
    if forbidden_file_io:
        raise Stage4Error("Stage 4 harness contains unnecessary file I/O: " +
                          ", ".join(forbidden_file_io))

    local_functions = set(definitions)
    expected = {function.function for function in triplet.functions}
    ownership_cleanup = {
        relation.cleanup_function: relation for relation in triplet.ownership_relations
    }
    planned_cleanup = {
        item.get("function"): item for item in plan.cleanup_sequence
    }
    allowed_cleanup = set(ownership_cleanup) & set(planned_cleanup)
    for cleanup_name, relation in ownership_cleanup.items():
        if cleanup_name not in planned_cleanup or cleanup_name in expected:
            continue
        item = planned_cleanup[cleanup_name]
        if relation.nullable and not item.get("conditions"):
            raise Stage4Error(
                f"nullable ownership cleanup {cleanup_name} requires explicit conditions"
            )
    outside_ft = sorted(
        calls & (all_project_functions - expected - allowed_cleanup)
    )
    if outside_ft:
        raise Stage4Error("Stage 4 harness calls project APIs outside the FT: " +
                          ", ".join(outside_ft))
    allowed = expected | local_functions | _STANDARD_C_CALLS | allowed_cleanup
    unknown = sorted(calls - allowed)
    if unknown:
        raise Stage4Error("Stage 4 harness calls unknown APIs: " + ", ".join(unknown))

    entry_calls = tuple(entry.calls)
    invoked_in_entry = {call.name for call in entry_calls}
    missing = sorted(expected - invoked_in_entry)
    if missing:
        raise Stage4Error("Stage 4 harness omits FT functions: " + ", ".join(missing))

    isf_calls = [call for call in entry_calls if call.name == triplet.isf.function]
    if not isf_calls:
        raise Stage4Error("Stage 4 harness does not invoke the unique ISF")
    if not any(_isf_uses_external_input(call, isf_metadata) for call in isf_calls):
        raise Stage4Error("Stage 4 ISF call is not connected to external data/size")

    first_isf = min(call.start_byte for call in isf_calls)
    prf_names = {function.function for function in triplet.prfs}
    cleanup_names = {
        function.function
        for function in triplet.hpfs
        if function.function_id != triplet.isf.function_id
        and function.function not in prf_names
        and any(
            edge.function_id == function.function_id and is_null_node(edge.dst)
            for edge in triplet.edges
        )
    }
    cleanup_names.update(ownership_cleanup)
    cleanup_before_entry = sorted({
        call.name for call in entry_calls
        if call.name in cleanup_names and call.start_byte < first_isf
    })
    if cleanup_before_entry:
        raise Stage4Error("Stage 4 cleanup occurs before ISF initialization: " +
                          ", ".join(cleanup_before_entry))
    _validate_cleanup_order(entry_calls, cleanup_names, triplet)
    _validate_ownership_calls(entry_calls, triplet, plan)


def _validate_ownership_calls(
    calls: tuple[_Call, ...],
    triplet: FunctionTriplet,
    plan: HarnessPlan,
) -> None:
    """Require each owned result to be saved and released exactly once."""
    plan_by_relation = {
        item.get("relation_id"): item
        for item in plan.cleanup_sequence
        if isinstance(item.get("relation_id"), str)
    }
    for relation in triplet.ownership_relations:
        item = plan_by_relation.get(relation.id)
        if item is None:
            raise Stage4Error(
                f"ownership relation {relation.id} has no cleanup plan item"
            )
        binding = item.get("producer_return_binding")
        identifier = binding.get("identifier") if isinstance(binding, Mapping) else None
        if not isinstance(identifier, str) or not identifier:
            raise Stage4Error(
                f"ownership relation {relation.id} has no producer result identifier"
            )
        producer_calls = [call for call in calls if call.name == relation.producer_function]
        if len(producer_calls) != 1:
            raise Stage4Error(
                f"ownership producer {relation.producer_function} must be invoked exactly once"
            )
        producer = producer_calls[0]
        if producer.assignment_target != identifier:
            raise Stage4Error(
                f"ownership producer {relation.producer_function} must save its return value as {identifier}"
            )
        cleanup_calls = [call for call in calls if call.name == relation.cleanup_function]
        if len(cleanup_calls) != 1:
            raise Stage4Error(
                f"ownership cleanup {relation.cleanup_function} must be invoked exactly once"
            )
        cleanup = cleanup_calls[0]
        expected_argument = identifier if relation.cleanup_argument == "return_value" else "&" + identifier
        if len(cleanup.arguments) != 1 or cleanup.arguments[0].text.strip() != expected_argument:
            raise Stage4Error(
                f"ownership cleanup {relation.cleanup_function} must receive {expected_argument}"
            )
        if cleanup.start_byte <= producer.start_byte:
            raise Stage4Error(
                f"ownership cleanup {relation.cleanup_function} occurs before its producer"
            )
        if any(
            _non_null_guard(condition, identifier)
            for condition in cleanup.preceding_returns
            if condition is not None
        ):
            raise Stage4Error(
                f"ownership cleanup {relation.cleanup_function} is unreachable on a non-null return path"
            )
        if relation.nullable and not any(
            _non_null_guard(guard, identifier) for guard in cleanup.guard_texts
        ):
            raise Stage4Error(
                f"nullable ownership cleanup {relation.cleanup_function} lacks a null guard for {identifier}"
            )


def _non_null_guard(condition: str, identifier: str) -> bool:
    compact = re.sub(r"\s+", "", condition).strip("()")
    token = re.escape(identifier)
    comparisons = (
        rf"{token}(?:!=|>)\s*(?:nullptr|NULL|0)",
        rf"(?:nullptr|NULL|0)\s*(?:!=|<)\s*{token}",
    )
    return any(re.fullmatch(pattern, compact) for pattern in comparisons) \
        or compact == identifier



def _validate_cleanup_order(calls: tuple[_Call, ...], cleanup_names: set[str],
                            triplet: FunctionTriplet) -> None:
    positions: dict[str, list[int]] = {}
    for call in calls:
        positions.setdefault(call.name, []).append(call.start_byte)
    outgoing: dict[str, set[str]] = {}
    for edge in triplet.edges:
        if not is_null_node(edge.src) and not is_null_node(edge.dst):
            outgoing.setdefault(edge.src, set()).add(edge.dst)

    for relation in triplet.ownership_relations:
        cleanup_positions = positions.get(relation.cleanup_function, [])
        if not cleanup_positions:
            continue
        required = {relation.producer_function, *relation.consumers}
        late = sorted(
            name for name in required
            if positions.get(name)
            and max(positions[name]) > min(cleanup_positions)
        )
        if late:
            raise Stage4Error(
                f"Stage 4 ownership cleanup {relation.cleanup_function} occurs before: "
                + ", ".join(late)
            )

    for cleanup in sorted(cleanup_names):
        cleanup_positions = positions.get(cleanup, [])
        if not cleanup_positions:
            continue
        relation = next(
            (item for item in triplet.ownership_relations
             if item.cleanup_function == cleanup),
            None,
        )
        if relation is not None:
            required = {relation.producer_function, *relation.consumers}
            late = sorted(
                name for name in required
                if positions.get(name)
                and max(positions[name]) > min(cleanup_positions)
            )
            if late:
                raise Stage4Error(
                    f"Stage 4 ownership cleanup {cleanup} occurs before: "
                    + ", ".join(late)
                )
            continue
        sources = {
            edge.src for edge in triplet.edges
            if edge.function == cleanup and is_null_node(edge.dst)
        }
        relevant_structures = set(sources)
        pending = list(sources)
        while pending:
            current = pending.pop()
            for target in outgoing.get(current, ()):
                if target not in relevant_structures:
                    relevant_structures.add(target)
                    pending.append(target)
        processing = {
            edge.function for edge in triplet.edges
            if edge.function not in cleanup_names and edge.src in relevant_structures
        }
        downstream_cleanup = {
            edge.function for edge in triplet.edges
            if edge.function in cleanup_names
            and edge.function != cleanup
            and edge.src in (relevant_structures - sources)
        }
        required_before = processing | downstream_cleanup
        late = sorted(
            function for function in required_before
            if positions.get(function)
            and max(positions[function]) > min(cleanup_positions)
        )
        if late:
            raise Stage4Error(
                f"Stage 4 cleanup {cleanup} occurs before downstream processing: "
                + ", ".join(late)
            )


def _validate_entry_signature(entry: _FunctionDefinition) -> None:
    if entry.return_type != "int" or len(entry.parameters) != 2:
        raise Stage4Error("invalid LLVMFuzzerTestOneInput signature")
    data, size = entry.parameters
    if (data.name != "data" or data.base_type != "uint8_t"
            or data.pointer_depth != 1 or "const" not in data.qualifiers):
        raise Stage4Error("first fuzzer parameter must be const uint8_t *data")
    if size.name != "size" or size.base_type != "size_t" or size.pointer_depth != 0:
        raise Stage4Error("second fuzzer parameter must be size_t size")


def _isf_uses_external_input(call: _Call, metadata: Mapping[str, Any]) -> bool:
    parameters = metadata.get("parameters", [])
    if len(call.arguments) != len(parameters):
        return False
    stream_indexes = [
        index for index, parameter in enumerate(parameters)
        if parameter.get("is_pointer") is True
        and parameter.get("is_struct_like") is not True
        and parameter.get("base_type") in {
            "void", "char", "unsigned char", "int8_t", "uint8_t"
        }
    ]
    length_indexes = [
        index for index, parameter in enumerate(parameters)
        if parameter.get("is_pointer") is not True
        and str(parameter.get("name", "")).lower() in {
            "size", "len", "length", "n", "data_size", "buffer_size"
        }
    ]
    if not stream_indexes:
        return False
    if not any(
        "data" in call.arguments[index].identifiers
        and not call.arguments[index].has_string_literal
        for index in stream_indexes
    ):
        return False
    return not length_indexes or any(
        "size" in call.arguments[index].identifiers
        for index in length_indexes
    )


def _parameters(function_declarator: Any, source: bytes) -> Iterable[_Parameter]:
    parameters = function_declarator.child_by_field_name("parameters")
    if parameters is None:
        return
    for node in parameters.named_children:
        if node.type != "parameter_declaration":
            continue
        type_node = node.child_by_field_name("type")
        declarator = node.child_by_field_name("declarator")
        yield _Parameter(
            name=_declarator_identifier(declarator, source),
            base_type=_node_text(source, type_node),
            qualifiers=tuple(
                _node_text(source, child)
                for child in node.named_children
                if child.type == "type_qualifier"
            ),
            pointer_depth=sum(
                current.type == "pointer_declarator"
                for current in _walk(declarator)
            ) if declarator is not None else 0,
        )


def _calls(body: Any, source: bytes) -> Iterable[_Call]:
    if body is None:
        return
    for node in _walk(body):
        if node.type != "call_expression":
            continue
        callee = node.child_by_field_name("function")
        if callee is None or callee.type != "identifier":
            continue
        arguments_node = node.child_by_field_name("arguments")
        arguments = []
        if arguments_node is not None:
            for argument in arguments_node.named_children:
                arguments.append(_Argument(
                    text=_node_text(source, argument),
                    identifiers=tuple(sorted({
                        _node_text(source, current)
                        for current in _walk(argument)
                        if current.type == "identifier"
                    })),
                    has_string_literal=any(
                        current.type in {"string_literal", "concatenated_string"}
                        for current in _walk(argument)
                    ),
                ))
        assignment_target, guard_texts = _call_context(node, source)
        preceding_returns = _preceding_returns(node, body, source)
        yield _Call(
            name=_node_text(source, callee),
            arguments=tuple(arguments),
            start_byte=node.start_byte,
            assignment_target=assignment_target,
            guard_texts=guard_texts,
            preceding_returns=preceding_returns,
        )


def _call_context(node: Any, source: bytes) -> tuple[str | None, tuple[str, ...]]:
    assignment_target = None
    current = node
    while current is not None:
        parent = current.parent
        if parent is None:
            break
        if parent.type == "init_declarator":
            value = parent.child_by_field_name("value")
            if value is not None and _contains_node(value, node):
                assignment_target = _declarator_identifier(
                    parent.child_by_field_name("declarator"), source
                )
                break
        if parent.type == "assignment_expression":
            right = parent.child_by_field_name("right")
            if right is not None and _contains_node(right, node):
                left = parent.child_by_field_name("left")
                assignment_target = _node_text(source, left) if left is not None else None
                break
        if parent.type in {
            "expression_statement", "declaration", "return_statement",
            "compound_statement", "if_statement",
        }:
            break
        current = parent

    guards: list[str] = []
    current = node.parent
    while current is not None:
        if current.type == "if_statement":
            condition = current.child_by_field_name("condition")
            if condition is not None:
                guards.append(_node_text(source, condition))
        current = current.parent
    return assignment_target, tuple(guards)


def _preceding_returns(node: Any, body: Any, source: bytes) -> tuple[str | None, ...]:
    """Return conditions for returns before a call in the same function."""
    if body is None:
        return ()
    result: list[str | None] = []
    for current in _walk(body):
        if current.type != "return_statement" or current.start_byte >= node.start_byte:
            continue
        condition = None
        parent = current.parent
        while parent is not None and parent is not body:
            if parent.type == "if_statement":
                condition_node = parent.child_by_field_name("condition")
                if condition_node is not None:
                    condition = _node_text(source, condition_node)
                break
            parent = parent.parent
        result.append(condition)
    return tuple(result)


def _contains_node(ancestor: Any, node: Any) -> bool:
    return (
        ancestor is not None
        and ancestor.start_byte <= node.start_byte
        and ancestor.end_byte >= node.end_byte
    )


def _find_function_declarator(node: Any) -> Any:
    if node is None:
        return None
    if node.type == "function_declarator":
        return node
    child = node.child_by_field_name("declarator")
    if child is not None:
        found = _find_function_declarator(child)
        if found is not None:
            return found
    return next(
        (current for current in _walk(node)
         if current.type == "function_declarator"),
        None,
    )


def _declarator_identifier(node: Any, source: bytes) -> str | None:
    if node is None:
        return None
    if node.type == "identifier":
        return _node_text(source, node)
    child = node.child_by_field_name("declarator")
    if child is not None:
        name = _declarator_identifier(child, source)
        if name is not None:
            return name
    return next(
        (_node_text(source, current) for current in _walk(node)
         if current.type == "identifier"),
        None,
    )


def _walk(node: Any) -> Iterable[Any]:
    if node is None:
        return
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.children))


def _node_text(source: bytes, node: Any) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8") if node is not None else ""


def _required_string(value: Mapping[str, Any], field: str, owner: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item.strip():
        raise Stage4Error(f"{field} must be non-empty text for {owner}")
    return item


def _generation_metadata(generation: LLMGeneration) -> dict[str, Any]:
    metadata = {
        "model": generation.model,
        "provider": generation.provider,
        "prompt_version": generation.prompt_version,
        "usage": dict(generation.usage),
    }
    if generation.response_id is not None:
        metadata["response_id"] = generation.response_id
    if generation.finish_reason is not None:
        metadata["finish_reason"] = generation.finish_reason
    return metadata


def _attempt_metadata(
    ft_id: str,
    attempt: int,
    generation: LLMGeneration | None,
    rollback_source: str | None,
    retry_reason: str | None,
    retry_context: Mapping[str, Any] | None,
    *,
    client: LLMClient | None = None,
    prompt_version: str | None = None,
    plan_prompt_version: str | None = None,
    plan_generation: LLMGeneration | None = None,
) -> dict[str, Any]:
    metadata = {} if generation is None else dict(generation.metadata)
    context = dict(retry_context or {})
    plan_metadata = {} if plan_generation is None else _generation_metadata(plan_generation)
    return {
        "schema_version": 1,
        "stage": "stage4",
        "attempt": attempt,
        "ft_id": ft_id,
        "prompt_version": (
            prompt_version if generation is None else generation.prompt_version
        ),
        "plan_prompt_version": plan_prompt_version,
        "plan_generation_metadata": plan_metadata,
        "model": (
            getattr(client, "model", None) if generation is None else generation.model
        ),
        "provider": (
            getattr(client, "provider", None)
            if generation is None else generation.provider
        ),
        "temperature": metadata.get("temperature"),
        "max_tokens": metadata.get("max_tokens"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rollback_source": rollback_source,
        "retry_reason": retry_reason,
        "failed_stage": context.get("failed_stage"),
        "validator": context.get("validator"),
        "failure_type": context.get("failure_type"),
        "rollback_target": context.get("rollback_target"),
        "rollback_attempt": context.get("attempt"),
    }


def _stage4_validation_feedback(
    retry_context: Mapping[str, Any] | None,
    *,
    triplet_id: str,
    unique_isf_function_id: str,
) -> dict[str, Any]:
    """Add Stage4-specific repair instructions to bounded retry feedback."""

    feedback = bounded_validation_feedback(retry_context)
    if not feedback:
        return {}
    correction = {
        "required_triplet_id": triplet_id,
        "instruction": (
            "For HarnessPlan JSON, set triplet_id exactly to "
            f"{triplet_id!r}. Do not use a function id, source path, line "
            "number, or unique_isf.id as triplet_id."
        ),
    }
    if unique_isf_function_id:
        correction["do_not_use_as_triplet_id"] = unique_isf_function_id
    feedback["stage4_triplet_id_correction"] = correction
    return feedback
