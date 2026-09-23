"""Stage 1: function-local documentation generation for one Function Triplet."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .artifacts import ArtifactStore
from .llm import LLMClient, LLMGeneration
from .prompts import stage1_function_doc
from .source_analysis import c_declarations_equivalent
from .source_paths import (SUPPORTED_FUNCTIONS_SCHEMA_VERSIONS,
                           SourcePathResolver)
from .triplet import FunctionTriplet, TripletFunction


STAGE1_SCHEMA_VERSION = 1
_DOCUMENT_FIELDS = {
    "function",
    "signature",
    "functionality",
    "application_scenario",
    "example_code",
    "parameter_notes",
    "return_semantics",
    "resource_lifecycle_notes",
    "notes",
}


class Stage1Error(ValueError):
    """Stage 1 inputs or a generated documentation record are invalid."""


@dataclass(frozen=True)
class FunctionDocumentation:
    function_id: str
    function: str
    signature: str
    functionality: str
    application_scenario: str
    example_code: str
    parameter_notes: tuple[str, ...]
    return_semantics: str | None
    resource_lifecycle_notes: tuple[str, ...]
    notes: tuple[str, ...]
    generation_metadata: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "function": self.function,
            "signature": self.signature,
            "functionality": self.functionality,
            "application_scenario": self.application_scenario,
            "example_code": self.example_code,
            "parameter_notes": list(self.parameter_notes),
            "return_semantics": self.return_semantics,
            "resource_lifecycle_notes": list(self.resource_lifecycle_notes),
            "notes": list(self.notes),
            "generation_metadata": dict(self.generation_metadata),
        }


@dataclass(frozen=True)
class Stage1Result:
    triplet_id: str
    documents: tuple[FunctionDocumentation, ...]
    output_path: Path
    raw_directory: Path

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": STAGE1_SCHEMA_VERSION,
            "stage": "stage1_function_doc",
            "triplet_id": self.triplet_id,
            "documents": [document.to_dict() for document in self.documents],
        }


class Stage1Generator:
    """Generate and persist documentation for only the functions in one FT."""

    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def run(self, triplet: FunctionTriplet, *, functions_json: str | Path,
            artifacts: str | Path, project_root: str | Path | None = None,
            attempt: int = 1, rollback_source: str | None = None,
            retry_reason: str | None = None,
            retry_context: Mapping[str, Any] | None = None,
            ) -> Stage1Result:
        functions_path = Path(functions_json)
        document = _load_functions_document(functions_path)
        try:
            source_paths = SourcePathResolver.from_functions_document(
                document, functions_path, project_root=project_root
            )
        except ValueError as error:
            raise Stage1Error(str(error)) from error
        functions_by_id = _index_functions(document)
        selected = _select_triplet_functions(triplet, functions_by_id)

        layout = ArtifactStore(Path(artifacts)).for_triplet(triplet.id)
        layout.ensure_generation()
        raw_directory = layout.raw
        raw_names = _raw_response_names(triplet.functions)

        generated_documents = []
        for reference, function in selected:
            source = _read_function_source(source_paths, function)
            prompt = stage1_function_doc(
                function_signature=function["signature"],
                function_source=source,
                usage_context=_usage_context(triplet, reference, function),
            )
            stem = Path(raw_names[reference.function_id]).stem
            layout.write_json_copies(
                (
                    layout.stage1_prompts / f"{stem}.json",
                    layout.prompts / f"{stem}.json",
                ),
                prompt.to_dict(),
            )
            raw_path = raw_directory / raw_names[reference.function_id]
            scoped_raw_path = layout.stage1_raw / raw_names[reference.function_id]
            try:
                generation = self.llm.generate(prompt)
            except Exception as error:
                layout.write_text_copies((scoped_raw_path, raw_path), "")
                failed_metadata = _failed_generation_metadata(
                    self.llm,
                    prompt.prompt_version,
                    attempt=attempt,
                    rollback_source=rollback_source,
                    retry_reason=retry_reason,
                    retry_context=retry_context,
                    error=error,
                )
                layout.write_json_copies(
                    (
                        layout.stage1_raw / f"{stem}.metadata.json",
                        raw_directory / f"{stem}.metadata.json",
                    ),
                    failed_metadata,
                )
                layout.write_json_copies(
                    (
                        layout.stage1_raw / f"{stem}.parsed.json",
                        raw_directory / f"{stem}.parsed.json",
                    ),
                    {
                        "status": "failed",
                        "error_type": type(error).__name__,
                        "error": str(error),
                    },
                )
                raise
            layout.write_text_copies(
                (scoped_raw_path, raw_path), generation.content
            )
            generation_metadata = _generation_metadata(
                generation,
                attempt=attempt,
                rollback_source=rollback_source,
                retry_reason=retry_reason,
                retry_context=retry_context,
            )
            layout.write_json_copies(
                (
                    layout.stage1_raw / f"{stem}.metadata.json",
                    raw_directory / f"{stem}.metadata.json",
                ),
                generation_metadata,
            )
            parsed = _parse_documentation(
                reference,
                function,
                generation,
                generation_metadata=_stable_generation_metadata(
                    generation_metadata
                ),
            )
            layout.write_json_copies(
                (
                    layout.stage1_raw / f"{stem}.parsed.json",
                    raw_directory / f"{stem}.parsed.json",
                ),
                parsed.to_dict(),
            )
            generated_documents.append(parsed)

        output_path = layout.stage1_docs
        result = Stage1Result(
            triplet_id=triplet.id,
            documents=tuple(generated_documents),
            output_path=output_path,
            raw_directory=raw_directory,
        )
        layout.write_json_copies(
            (layout.stage1_scoped_docs, output_path), result.to_dict()
        )
        return result


def generate_stage1_documentation(
    triplet: FunctionTriplet,
    llm: LLMClient,
    *,
    functions_json: str | Path,
    artifacts: str | Path,
    project_root: str | Path | None = None,
) -> Stage1Result:
    """Convenience entry point for one complete Stage 1 run."""

    return Stage1Generator(llm).run(
        triplet,
        functions_json=functions_json,
        artifacts=artifacts,
        project_root=project_root,
    )


def _load_functions_document(path: Path) -> Mapping[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise Stage1Error(
            f"cannot load functions artifact: {type(error).__name__}"
        ) from error
    if (not isinstance(document, dict)
            or document.get("schema_version") not in SUPPORTED_FUNCTIONS_SCHEMA_VERSIONS):
        raise Stage1Error("unsupported functions.json schema_version")
    functions = document.get("functions")
    if not isinstance(functions, list) or any(not isinstance(item, dict) for item in functions):
        raise Stage1Error("functions.json functions must be an array of objects")
    return document


def _index_functions(document: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for function in document["functions"]:
        function_id = function.get("id")
        if not isinstance(function_id, str) or not function_id:
            raise Stage1Error("functions.json function id must be a non-empty string")
        if function_id in result:
            raise Stage1Error(f"duplicate functions.json function id: {function_id}")
        result[function_id] = function
    return result


def _select_triplet_functions(
    triplet: FunctionTriplet,
    functions_by_id: Mapping[str, Mapping[str, Any]],
) -> tuple[tuple[TripletFunction, Mapping[str, Any]], ...]:
    selected = []
    for reference in triplet.functions:
        function = functions_by_id.get(reference.function_id)
        if function is None:
            raise Stage1Error(
                f"FT function is missing from functions.json: {reference.function_id}"
            )
        if function.get("name") != reference.function:
            raise Stage1Error(f"function name mismatch for {reference.function_id}")
        if function.get("defined") is not True:
            raise Stage1Error(f"FT function has no source definition: {reference.function_id}")
        _required_string(function, "signature", reference.function)
        selected.append((reference, function))
    return tuple(selected)


def _read_function_source(
    resolver: SourcePathResolver, function: Mapping[str, Any]
) -> str:
    name = _required_string(function, "name", "function")
    try:
        stored_path = _required_string(function, "file", name)
        source_path = resolver.resolve(stored_path)
    except ValueError as error:
        raise Stage1Error(f"invalid function source path for {name}: {error}") from error
    if not source_path.is_file():
        raise Stage1Error(f"function source file does not exist: {stored_path}")

    start = function.get("start_line")
    end = function.get("end_line")
    if type(start) is not int or type(end) is not int or start < 1 or end < start:
        raise Stage1Error(f"invalid source range for function: {name}")
    try:
        lines = source_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise Stage1Error(f"cannot read function source: {type(error).__name__}") from error
    if end > len(lines):
        raise Stage1Error(f"source range exceeds file for function: {name}")
    source = "\n".join(lines[start - 1:end]).strip()
    if not source:
        raise Stage1Error(f"empty source range for function: {name}")
    return source


def _usage_context(triplet: FunctionTriplet,
                   function: TripletFunction,
                   metadata: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "triplet_id": triplet.id,
        "target_function": function.function,
        "roles": list(function.roles),
        "source": {
            "file": metadata.get("file"),
            "start_line": metadata.get("start_line"),
            "end_line": metadata.get("end_line"),
        },
        "return_type": metadata.get("return_type"),
        "parameters": metadata.get("parameters", []),
        "access_hints": metadata.get("access_hints", []),
        "structures": list(triplet.structures),
        "related_functions": [
            {"function": item.function, "roles": list(item.roles)}
            for item in triplet.functions
        ],
        "ownership_relations": [
            relation.to_dict()
            for relation in triplet.ownership_relations
            if relation.producer_function_id == function.function_id
            or function.function in relation.consumers
        ],
        "structural_edges": [
            {
                "source": edge.src,
                "target": edge.dst,
                "function": edge.function,
                "roles": list(edge.roles),
            }
            for edge in triplet.edges
        ],
    }


def _parse_documentation(
    reference: TripletFunction,
    function: Mapping[str, Any],
    generation: LLMGeneration,
    *,
    generation_metadata: Mapping[str, Any] | None = None,
) -> FunctionDocumentation:
    response = _strict_json_object(generation.content, reference.function)
    fields = set(response)
    if fields != _DOCUMENT_FIELDS:
        missing = sorted(_DOCUMENT_FIELDS - fields)
        unexpected = sorted(fields - _DOCUMENT_FIELDS)
        detail = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if unexpected:
            detail.append("unexpected=" + ",".join(unexpected))
        raise Stage1Error(
            f"invalid documentation fields for {reference.function}: {'; '.join(detail)}"
        )

    signature = _required_string(function, "signature", reference.function)
    if response["function"] != reference.function:
        raise Stage1Error(f"documentation function mismatch for {reference.function}")
    if not c_declarations_equivalent(response["signature"], signature):
        raise Stage1Error(f"documentation signature mismatch for {reference.function}")

    functionality = _response_string(response, "functionality", reference.function)
    scenario = _response_string(response, "application_scenario", reference.function)
    example = _response_string(response, "example_code", reference.function)
    if re.search(rf"\b{re.escape(reference.function)}\s*\(", example) is None:
        raise Stage1Error(
            f"example_code does not call documented function: {reference.function}"
        )
    return_semantics = response["return_semantics"]
    if return_semantics is not None and not isinstance(return_semantics, str):
        raise Stage1Error(
            f"return_semantics must be text or null for {reference.function}"
        )
    if isinstance(return_semantics, str) and not return_semantics.strip():
        raise Stage1Error(
            f"return_semantics must be non-empty text or null for {reference.function}"
        )

    return FunctionDocumentation(
        function_id=reference.function_id,
        function=reference.function,
        signature=signature,
        functionality=functionality,
        application_scenario=scenario,
        example_code=example,
        parameter_notes=_string_list(response, "parameter_notes", reference.function),
        return_semantics=return_semantics,
        resource_lifecycle_notes=_string_list(
            response, "resource_lifecycle_notes", reference.function
        ),
        notes=_string_list(response, "notes", reference.function),
        generation_metadata=(
            dict(generation_metadata)
            if generation_metadata is not None else _generation_metadata(generation)
        ),
    )


def _strict_json_object(text: str, function: str) -> Mapping[str, Any]:
    def object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise Stage1Error(f"duplicate JSON field for {function}: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise Stage1Error(f"invalid JSON constant for {function}: {value}")

    try:
        response = json.loads(
            text,
            object_pairs_hook=object_without_duplicates,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as error:
        raise Stage1Error(f"LLM returned invalid JSON for {function}") from error
    if not isinstance(response, dict):
        raise Stage1Error(f"LLM response must be a JSON object for {function}")
    return response


def _generation_metadata(
    generation: LLMGeneration,
    *,
    attempt: int = 1,
    rollback_source: str | None = None,
    retry_reason: str | None = None,
    retry_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    context = dict(retry_context or {})
    metadata = {
        "model": generation.model,
        "provider": generation.provider,
        "prompt_version": generation.prompt_version,
        "usage": dict(generation.usage),
        "attempt": attempt,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rollback_source": rollback_source,
        "retry_reason": retry_reason,
        "failed_stage": context.get("failed_stage"),
        "failure_type": context.get("failure_type"),
        "rollback_target": context.get("rollback_target"),
    }
    if generation.response_id is not None:
        metadata["response_id"] = generation.response_id
    if generation.finish_reason is not None:
        metadata["finish_reason"] = generation.finish_reason
    return metadata


def _stable_generation_metadata(
    metadata: Mapping[str, Any],
) -> dict[str, Any]:
    """Keep wall-clock data in the per-call audit file, not canonical docs."""

    return {
        key: value for key, value in metadata.items() if key != "timestamp"
    }


def _failed_generation_metadata(
    client: LLMClient,
    prompt_version: str,
    *,
    attempt: int,
    rollback_source: str | None,
    retry_reason: str | None,
    retry_context: Mapping[str, Any] | None,
    error: Exception,
) -> dict[str, Any]:
    context = dict(retry_context or {})
    return {
        "model": getattr(client, "model", None),
        "provider": getattr(client, "provider", type(client).__name__),
        "prompt_version": prompt_version,
        "attempt": attempt,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rollback_source": rollback_source,
        "retry_reason": retry_reason,
        "failed_stage": context.get("failed_stage"),
        "failure_type": context.get("failure_type"),
        "rollback_target": context.get("rollback_target"),
        "status": "failed",
        "error_type": type(error).__name__,
    }


def _raw_response_names(functions: tuple[TripletFunction, ...]) -> dict[str, str]:
    names: dict[str, str] = {}
    used: set[str] = set()
    for function in functions:
        stem = re.sub(r"[^A-Za-z0-9_.-]", "_", function.function)
        candidate = f"stage1_{stem}.txt"
        if candidate in used:
            suffix = re.sub(r"[^A-Za-z0-9]", "_", function.function_id)[-24:]
            candidate = f"stage1_{stem}_{suffix}.txt"
        if candidate in used:
            raise Stage1Error(f"cannot create unique raw response name: {function.function_id}")
        used.add(candidate)
        names[function.function_id] = candidate
    return names


def _response_string(response: Mapping[str, Any], field: str, function: str) -> str:
    value = response.get(field)
    if not isinstance(value, str) or not value.strip():
        raise Stage1Error(f"{field} must be non-empty text for {function}")
    return value


def _string_list(response: Mapping[str, Any], field: str,
                 function: str) -> tuple[str, ...]:
    value = response.get(field)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise Stage1Error(f"{field} must be an array of strings for {function}")
    return tuple(value)


def _required_string(value: Mapping[str, Any], field: str, owner: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item.strip():
        raise Stage1Error(f"{field} must be non-empty text for {owner}")
    return item
