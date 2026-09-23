"""Stage 3: dependency-aware assembly and auditing of Stage 2 snippets."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .artifacts import ArtifactStore
from .generation_output import normalize_c_response
from .generation_context import (bounded_validation_feedback,
                                 project_type_context)
from .llm import LLMClient, LLMGeneration
from .prompts import stage3_rough_assembly
from .sfg_adapter import is_null_node, normalize_null_node
from .source_paths import SUPPORTED_FUNCTIONS_SCHEMA_VERSIONS
from .triplet import FunctionTriplet


STAGE2_SNIPPETS_SCHEMA_VERSION = 1
STAGE3_METADATA_SCHEMA_VERSION = 1


class Stage3Error(ValueError):
    """Stage 2 inputs or the generated rough C source are invalid."""


@dataclass(frozen=True)
class Stage2Snippet:
    """The minimum Stage 2 processing-unit contract consumed by Stage 3."""

    id: str
    input_structure: str
    output_structure: str
    functions: tuple[str, ...]
    dependencies: tuple[str, ...]
    generated_code: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise Stage3Error("Stage 2 snippet id must be non-empty")
        if not isinstance(self.generated_code, str) or not self.generated_code.strip():
            raise Stage3Error(f"Stage 2 snippet code is empty: {self.id}")
        if any(not isinstance(item, str) or not item for item in self.functions):
            raise Stage3Error(f"Stage 2 snippet functions are invalid: {self.id}")
        if any(not isinstance(item, str) or not item for item in self.dependencies):
            raise Stage3Error(f"Stage 2 snippet dependencies are invalid: {self.id}")
        object.__setattr__(self, "input_structure",
                           normalize_null_node(self.input_structure))
        object.__setattr__(self, "output_structure",
                           normalize_null_node(self.output_structure))
        object.__setattr__(self, "functions", tuple(dict.fromkeys(self.functions)))
        object.__setattr__(self, "dependencies", tuple(dict.fromkeys(self.dependencies)))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "input_structure": self.input_structure,
            "output_structure": self.output_structure,
            "functions": list(self.functions),
            "dependencies": list(self.dependencies),
            "generated_code": self.generated_code,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Stage2Snippet":
        unit_id = value.get("id", value.get("unit_id"))
        functions = value.get("functions")
        dependencies = value.get("dependencies", [])
        metadata = value.get("metadata", {})
        if not isinstance(unit_id, str):
            raise Stage3Error("Stage 2 snippet requires id or unit_id")
        if not isinstance(functions, list) or any(not isinstance(item, str)
                                                   for item in functions):
            raise Stage3Error(f"Stage 2 snippet functions must be strings: {unit_id}")
        if not isinstance(dependencies, list) or any(not isinstance(item, str)
                                                      for item in dependencies):
            raise Stage3Error(f"Stage 2 snippet dependencies must be strings: {unit_id}")
        if not isinstance(metadata, Mapping):
            raise Stage3Error(f"Stage 2 snippet metadata must be an object: {unit_id}")
        return cls(
            id=unit_id,
            input_structure=_required_node(value, "input_structure", unit_id),
            output_structure=_required_node(value, "output_structure", unit_id),
            functions=tuple(functions),
            dependencies=tuple(dependencies),
            generated_code=_required_string(value, "generated_code", unit_id),
            metadata=dict(metadata),
        )


@dataclass(frozen=True)
class Stage3Metadata:
    triplet_id: str
    invoked_functions: tuple[str, ...]
    missing_functions: tuple[str, ...]
    unexpected_functions: tuple[str, ...]
    involved_structures: tuple[str, ...]
    assembly_order: tuple[str, ...]
    dependency_warnings: tuple[str, ...]
    generation_metadata: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": STAGE3_METADATA_SCHEMA_VERSION,
            "stage": "stage3_rough_assembly",
            "triplet_id": self.triplet_id,
            "invoked_functions": list(self.invoked_functions),
            "missing_functions": list(self.missing_functions),
            "unexpected_functions": list(self.unexpected_functions),
            "involved_structures": list(self.involved_structures),
            "assembly_order": list(self.assembly_order),
            "dependency_warnings": list(self.dependency_warnings),
            "generation_metadata": dict(self.generation_metadata),
        }


@dataclass(frozen=True)
class Stage3Result:
    triplet_id: str
    rough_code: str
    metadata: Stage3Metadata
    rough_code_path: Path
    metadata_path: Path
    attempt_directory: Path


class Stage3Assembler:
    """Ask an LLM to merge ordered snippets, then audit the resulting C source."""

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def run(
        self,
        triplet: FunctionTriplet,
        *,
        snippets: Sequence[Stage2Snippet] | str | Path,
        functions_json: str | Path,
        artifacts: str | Path,
        rollback_source: str | None = None,
        retry_reason: str | None = None,
        retry_context: Mapping[str, Any] | None = None,
    ) -> Stage3Result:
        units = (load_stage2_snippets(snippets, triplet_id=triplet.id)
                 if isinstance(snippets, (str, Path)) else tuple(snippets))
        _validate_snippets(units, triplet)
        ordered, warnings = _order_snippets(units, triplet)
        function_metadata, all_project_functions, project_context = _load_ft_function_metadata(
            Path(functions_json), triplet
        )

        prompt = stage3_rough_assembly(
            snippets=[unit.to_dict() for unit in ordered],
            structural_dependencies={
                **_structural_dependencies(triplet, ordered),
                "ownership_relations": [
                    relation.to_dict() for relation in triplet.ownership_relations
                ],
            },
            function_metadata=function_metadata,
            project_context=project_context,
            validation_feedback=bounded_validation_feedback(retry_context),
        )
        layout = ArtifactStore(Path(artifacts)).for_triplet(triplet.id)
        layout.ensure_generation()
        attempt, attempt_directory = layout.next_attempt("stage3")
        layout.write_text(attempt_directory / "prompt.txt", prompt.content)
        try:
            generation = self.llm.generate(prompt)
        except Exception as error:
            layout.write_text(attempt_directory / "response.txt", "")
            layout.write_json(attempt_directory / "metadata.json", _attempt_metadata(
                triplet.id, attempt, None, rollback_source, retry_reason,
                retry_context, client=self.llm,
                prompt_version=prompt.prompt_version
            ))
            layout.write_json(attempt_directory / "parsed.json", {
                "status": "failed",
                "error_type": type(error).__name__,
                "error": str(error),
            })
            raise
        rough_code = normalize_c_response(generation.content)
        layout.write_text(attempt_directory / "response.txt", generation.content)
        layout.write_text(attempt_directory / "rough.c", rough_code + "\n")
        layout.write_json(attempt_directory / "metadata.json", _attempt_metadata(
            triplet.id, attempt, generation, rollback_source, retry_reason,
            retry_context
        ))
        try:
            analysis = _analyze_rough_c(rough_code)
            if "LLVMFuzzerTestOneInput" in analysis.definitions or \
                    "LLVMFuzzerTestOneInput" in analysis.calls:
                raise Stage3Error(
                    "Stage 3 output must not contain the final fuzzer entry point"
                )
            if "main" in analysis.definitions:
                raise Stage3Error(
                    "Stage 3 output must not define main or demo driver entry points"
                )
            redefined = sorted(set(analysis.definitions) & all_project_functions)
            if redefined:
                raise Stage3Error(
                    "Stage 3 output redefines project API functions: "
                    + ", ".join(redefined)
                )
        except Exception as error:
            layout.write_json(attempt_directory / "parsed.json", {
                "status": "failed",
                "error_type": type(error).__name__,
                "error": str(error),
            })
            raise

        expected = {function.function for function in triplet.functions}
        invoked = tuple(sorted(analysis.calls))
        metadata = Stage3Metadata(
            triplet_id=triplet.id,
            invoked_functions=invoked,
            missing_functions=tuple(sorted(expected - set(invoked))),
            unexpected_functions=tuple(sorted(set(invoked) - expected)),
            involved_structures=tuple(sorted({
                *triplet.structures,
                *(unit.input_structure for unit in ordered
                  if not is_null_node(unit.input_structure)),
                *(unit.output_structure for unit in ordered
                  if not is_null_node(unit.output_structure)),
            })),
            assembly_order=tuple(unit.id for unit in ordered),
            dependency_warnings=warnings,
            generation_metadata=_generation_metadata(generation),
        )

        rough_path = layout.stage3_rough
        metadata_path = layout.stage3_metadata
        layout.write_text(rough_path, rough_code + "\n")
        layout.write_json(metadata_path, metadata.to_dict())
        layout.write_json(attempt_directory / "parsed.json", {
            "status": "passed",
            "metadata": metadata.to_dict(),
        })
        return Stage3Result(
            triplet_id=triplet.id,
            rough_code=rough_code,
            metadata=metadata,
            rough_code_path=rough_path,
            metadata_path=metadata_path,
            attempt_directory=attempt_directory,
        )


def assemble_stage3(
    triplet: FunctionTriplet,
    llm: LLMClient,
    *,
    snippets: Sequence[Stage2Snippet] | str | Path,
    functions_json: str | Path,
    artifacts: str | Path,
) -> Stage3Result:
    return Stage3Assembler(llm).run(
        triplet,
        snippets=snippets,
        functions_json=functions_json,
        artifacts=artifacts,
    )


def load_stage2_snippets(path: str | Path, *,
                         triplet_id: str | None = None) -> tuple[Stage2Snippet, ...]:
    """Read the minimal Stage 2 contract without implementing Stage 2 itself."""

    source = Path(path)
    try:
        document = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise Stage3Error(f"cannot load Stage 2 snippets: {type(error).__name__}") from error
    if not isinstance(document, Mapping):
        raise Stage3Error("stage2_snippets.json must contain an object")
    version = document.get("schema_version", STAGE2_SNIPPETS_SCHEMA_VERSION)
    if version != STAGE2_SNIPPETS_SCHEMA_VERSION:
        raise Stage3Error("unsupported stage2_snippets.json schema_version")
    recorded_triplet = document.get("triplet_id")
    if recorded_triplet is not None and not isinstance(recorded_triplet, str):
        raise Stage3Error("stage2_snippets.json triplet_id must be text or null")
    if triplet_id is not None and recorded_triplet not in (None, triplet_id):
        raise Stage3Error("Stage 2 snippets belong to a different FunctionTriplet")
    records = document.get("units", document.get("snippets"))
    if not isinstance(records, list) or any(not isinstance(item, Mapping)
                                            for item in records):
        raise Stage3Error("stage2_snippets.json requires an array of units")
    return tuple(Stage2Snippet.from_dict(item) for item in records)


def _validate_snippets(units: Sequence[Stage2Snippet],
                       triplet: FunctionTriplet) -> None:
    if not units:
        raise Stage3Error("Stage 3 requires at least one Stage 2 snippet")
    ids = [unit.id for unit in units]
    if len(ids) != len(set(ids)):
        raise Stage3Error("Stage 2 snippet ids must be unique")
    expected = {function.function for function in triplet.functions}
    unknown = sorted({function for unit in units for function in unit.functions} - expected)
    if unknown:
        raise Stage3Error(
            "Stage 2 snippets reference functions outside the FT: " + ", ".join(unknown)
        )


def _order_snippets(
    units: Sequence[Stage2Snippet],
    triplet: FunctionTriplet | None = None,
) -> tuple[tuple[Stage2Snippet, ...], tuple[str, ...]]:
    by_id = {unit.id: unit for unit in units}
    dependencies: dict[str, set[str]] = {unit.id: set() for unit in units}
    warnings = []

    for unit in units:
        for dependency in unit.dependencies:
            if dependency in by_id and dependency != unit.id:
                dependencies[unit.id].add(dependency)
            elif dependency not in by_id:
                warnings.append(
                    f"{unit.id}: dependency {dependency!r} is not a snippet id; preserved for LLM"
                )

    for producer in units:
        if is_null_node(producer.output_structure):
            continue
        for consumer in units:
            if producer.id != consumer.id and \
                    producer.output_structure == consumer.input_structure:
                dependencies[consumer.id].add(producer.id)

    descendants = _structure_descendants(units)
    if triplet is not None:
        by_function = {
            function: unit.id
            for unit in units
            for function in unit.functions
        }
        for relation in triplet.ownership_relations:
            producer_unit = by_function.get(relation.producer_function)
            cleanup_unit = by_function.get(relation.cleanup_function)
            if producer_unit is None:
                warnings.append(
                    f"ownership {relation.id}: producer is absent from Stage 2 units"
                )
            if cleanup_unit is None:
                warnings.append(
                    f"ownership {relation.id}: cleanup is absent from Stage 2 units"
                )
            if producer_unit and cleanup_unit and producer_unit != cleanup_unit:
                dependencies[cleanup_unit].add(producer_unit)
            for consumer in relation.consumers:
                consumer_unit = by_function.get(consumer)
                if consumer_unit and cleanup_unit and consumer_unit != cleanup_unit:
                    dependencies[cleanup_unit].add(consumer_unit)

    for cleanup in units:
        if not is_null_node(cleanup.output_structure):
            continue
        downstream = descendants.get(cleanup.input_structure, set())
        for unit in units:
            if unit.id == cleanup.id:
                continue
            if (unit.input_structure == cleanup.input_structure
                    and not is_null_node(unit.output_structure)):
                dependencies[cleanup.id].add(unit.id)
            elif unit.input_structure in downstream:
                dependencies[cleanup.id].add(unit.id)

    remaining = set(by_id)
    ordered = []
    completed: set[str] = set()
    while remaining:
        ready = sorted(
            unit_id for unit_id in remaining
            if dependencies[unit_id] <= completed
        )
        if not ready:
            selected = min(remaining)
            warnings.append(
                "dependency cycle detected; deterministic fallback selected " + selected
            )
            ready = [selected]
        for unit_id in ready:
            ordered.append(by_id[unit_id])
            completed.add(unit_id)
            remaining.remove(unit_id)
    return tuple(ordered), tuple(sorted(set(warnings)))


def _structure_descendants(units: Sequence[Stage2Snippet]) -> dict[str, set[str]]:
    outgoing: dict[str, set[str]] = {}
    structures = set()
    for unit in units:
        if is_null_node(unit.input_structure) or is_null_node(unit.output_structure):
            continue
        outgoing.setdefault(unit.input_structure, set()).add(unit.output_structure)
        structures.update((unit.input_structure, unit.output_structure))
    result = {}
    for start in structures:
        visited = set()
        pending = list(outgoing.get(start, ()))
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            pending.extend(outgoing.get(current, ()))
        visited.discard(start)
        result[start] = visited
    return result


def _structural_dependencies(
    triplet: FunctionTriplet,
    ordered: Sequence[Stage2Snippet],
) -> dict[str, Any]:
    metadata = {
        "assembly_order": [unit.id for unit in ordered],
        "units": [
            {
                "id": unit.id,
                "input_structure": unit.input_structure,
                "output_structure": unit.output_structure,
                "depends_on": list(unit.dependencies),
            }
            for unit in ordered
        ],
        "ft_edges": [edge.to_dict() for edge in triplet.edges],
        "ownership_relations": [
            relation.to_dict() for relation in triplet.ownership_relations
        ],
    }
    return metadata

def _load_ft_function_metadata(
    path: Path,
    triplet: FunctionTriplet,
) -> tuple[list[Mapping[str, Any]], set[str], dict[str, Any]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise Stage3Error(f"cannot load functions.json: {type(error).__name__}") from error
    if (not isinstance(document, Mapping)
            or document.get("schema_version") not in SUPPORTED_FUNCTIONS_SCHEMA_VERSIONS):
        raise Stage3Error("unsupported functions.json schema_version")
    records = document.get("functions")
    if not isinstance(records, list) or any(not isinstance(item, Mapping)
                                            for item in records):
        raise Stage3Error("functions.json functions must be an array of objects")
    by_id = {}
    all_names = set()
    for record in records:
        function_id = _required_string(record, "id", "functions.json")
        name = _required_string(record, "name", function_id)
        if function_id in by_id:
            raise Stage3Error(f"duplicate functions.json function id: {function_id}")
        by_id[function_id] = record
        all_names.add(name)
    selected = []
    for function in triplet.functions:
        record = by_id.get(function.function_id)
        if record is None or record.get("name") != function.function:
            raise Stage3Error(
                f"FT function is missing or mismatched in functions.json: {function.function_id}"
            )
        selected.append({
            "id": function.function_id,
            "name": function.function,
            "roles": list(function.roles),
            "signature": record.get("signature"),
            "return_type": record.get("return_type"),
            "parameters": record.get("parameters", []),
            "file": record.get("file"),
            "start_line": record.get("start_line"),
        })
    source_files = tuple(
        record.get("file") for record in selected
        if isinstance(record.get("file"), str)
    )
    return selected, all_names, project_type_context(
        document, functions_path=path, source_files=source_files,
        functions=tuple(selected),
    )


@dataclass(frozen=True)
class _CAnalysis:
    calls: tuple[str, ...]
    definitions: tuple[str, ...]


def _analyze_rough_c(source: str) -> _CAnalysis:
    if not source:
        raise Stage3Error("LLM returned empty Stage 3 source")
    if "```" in source:
        raise Stage3Error("Stage 3 source must not contain Markdown fences")
    try:
        import tree_sitter
        import tree_sitter_c
    except ImportError as error:
        raise Stage3Error("tree-sitter C dependencies are required for Stage 3") from error
    language_value = tree_sitter_c.language()
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
    synthetic_wrapper = False
    if tree.root_node.has_error:
        prefix = b"void __stage3_sequence(void) {\n"
        wrapped = prefix + encoded + b"\n}\n"
        tree = parser.parse(wrapped)
        if tree.root_node.has_error:
            raise Stage3Error("LLM returned C source that tree-sitter cannot parse")
        encoded = wrapped
        synthetic_wrapper = True

    calls = set()
    definitions = set()
    for node in _walk(tree.root_node):
        if node.type == "call_expression":
            callee = node.child_by_field_name("function")
            if callee is not None and callee.type == "identifier":
                calls.add(_node_text(encoded, callee))
        elif node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            name = _declarator_identifier(declarator, encoded)
            if name and not (synthetic_wrapper and name == "__stage3_sequence"):
                definitions.add(name)
    return _CAnalysis(tuple(sorted(calls)), tuple(sorted(definitions)))


def _walk(node: Any) -> Iterable[Any]:
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.children))


def _declarator_identifier(node: Any, source: bytes) -> str | None:
    if node is None:
        return None
    if node.type == "identifier":
        return _node_text(source, node)
    declarator = node.child_by_field_name("declarator")
    if declarator is not None:
        return _declarator_identifier(declarator, source)
    return next(
        (_node_text(source, child) for child in _walk(node)
         if child.type == "identifier"),
        None,
    )


def _node_text(source: bytes, node: Any) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8")


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
) -> dict[str, Any]:
    metadata = {} if generation is None else dict(generation.metadata)
    context = dict(retry_context or {})
    return {
        "schema_version": 1,
        "stage": "stage3",
        "attempt": attempt,
        "ft_id": ft_id,
        "prompt_version": (
            prompt_version if generation is None else generation.prompt_version
        ),
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


def _required_string(value: Mapping[str, Any], field: str, owner: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item.strip():
        raise Stage3Error(f"{field} must be non-empty text for {owner}")
    return item


def _required_node(value: Mapping[str, Any], field: str, owner: str) -> Any:
    item = value.get(field)
    if item is None or isinstance(item, str) and item.strip():
        return item
    raise Stage3Error(f"{field} must be a structure name or null for {owner}")
