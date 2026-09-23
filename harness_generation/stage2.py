"""Stage 2: generate local snippets for Function Triplet structural units."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .artifacts import ArtifactStore
from .generation_output import normalize_c_response
from .llm import LLMClient, LLMGeneration
from .prompts import stage2_structure_snippet
from .sfg_adapter import is_null_node
from .stage3 import STAGE2_SNIPPETS_SCHEMA_VERSION, Stage2Snippet
from .triplet import FunctionTriplet


class Stage2Error(ValueError):
    """Stage 1 artifacts or generated structural snippets are invalid."""


@dataclass(frozen=True)
class Stage2Result:
    triplet_id: str
    snippets: tuple[Stage2Snippet, ...]
    output_path: Path
    snippets_directory: Path
    raw_directory: Path
    prompts_directory: Path

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": STAGE2_SNIPPETS_SCHEMA_VERSION,
            "stage": "stage2_structure_snippet",
            "triplet_id": self.triplet_id,
            "units": [snippet.to_dict() for snippet in self.snippets],
        }


class Stage2Generator:
    def __init__(self, llm: LLMClient) -> None:
        self.llm = llm

    def run(
        self,
        triplet: FunctionTriplet,
        *,
        stage1_docs: str | Path,
        artifacts: str | Path,
        attempt: int = 1,
        rollback_source: str | None = None,
        retry_reason: str | None = None,
        retry_context: Mapping[str, Any] | None = None,
    ) -> Stage2Result:
        documents = _load_documentation(Path(stage1_docs), triplet)
        units = _structural_units(triplet)
        layout = ArtifactStore(Path(artifacts)).for_triplet(triplet.id)
        layout.ensure_generation()
        snippets_directory = layout.snippets
        raw_directory = layout.raw
        prompts_directory = layout.prompts

        snippets = []
        for unit in units:
            prompt = stage2_structure_snippet(
                input_structure=unit["input_structure"],
                output_structure=unit["output_structure"],
                functions=unit["functions"],
                dependencies=unit["dependencies"],
                documentation=[
                    {
                        **_documentation_for_prompt(documents[name]),
                        "ownership_relations": [
                            relation.to_dict()
                            for relation in triplet.ownership_relations
                            if name in (
                                relation.producer_function,
                                relation.cleanup_function,
                                *relation.consumers,
                            )
                        ],
                    }
                    for name in unit["functions"]
                ],
            )
            layout.write_json_copies(
                (
                    layout.stage2_prompts / f"{unit['id']}.json",
                    prompts_directory / f"{unit['id']}.json",
                ),
                prompt.to_dict(),
            )
            response_path = raw_directory / f"stage2_{unit['id']}.txt"
            scoped_response_path = (
                layout.stage2_raw / f"stage2_{unit['id']}.txt"
            )
            try:
                generation = self.llm.generate(prompt)
            except Exception as error:
                layout.write_text_copies(
                    (scoped_response_path, response_path), ""
                )
                layout.write_json_copies(
                    (
                        layout.stage2_raw / f"stage2_{unit['id']}.metadata.json",
                        raw_directory / f"stage2_{unit['id']}.metadata.json",
                    ),
                    _failed_generation_metadata(
                        self.llm,
                        prompt.prompt_version,
                        attempt=attempt,
                        rollback_source=rollback_source,
                        retry_reason=retry_reason,
                        retry_context=retry_context,
                        error=error,
                    ),
                )
                raise
            layout.write_text_copies(
                (scoped_response_path, response_path), generation.content
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
                    layout.stage2_raw / f"stage2_{unit['id']}.metadata.json",
                    raw_directory / f"stage2_{unit['id']}.metadata.json",
                ),
                generation_metadata,
            )
            code = normalize_c_response(generation.content)
            if not code:
                raise Stage2Error(f"LLM returned an empty snippet for {unit['id']}")
            if "```" in code:
                raise Stage2Error(
                    f"Stage 2 snippet must not contain Markdown fences: {unit['id']}"
                )
            layout.write_text_copies(
                (
                    layout.stage2_code_snippets / f"{unit['id']}.c",
                    snippets_directory / f"{unit['id']}.c",
                ),
                code + "\n",
            )
            snippets.append(Stage2Snippet(
                id=unit["id"],
                input_structure=unit["input_structure"],
                output_structure=unit["output_structure"],
                functions=tuple(unit["functions"]),
                dependencies=tuple(unit["dependencies"]),
                generated_code=code,
                metadata=_stable_generation_metadata(generation_metadata),
            ))

        result = Stage2Result(
            triplet_id=triplet.id,
            snippets=tuple(snippets),
            output_path=layout.stage2_snippets,
            snippets_directory=snippets_directory,
            raw_directory=raw_directory,
            prompts_directory=prompts_directory,
        )
        layout.write_json_copies(
            (layout.stage2_scoped_snippets, result.output_path), result.to_dict()
        )
        return result


def generate_stage2_snippets(
    triplet: FunctionTriplet,
    llm: LLMClient,
    *,
    stage1_docs: str | Path,
    artifacts: str | Path,
) -> Stage2Result:
    return Stage2Generator(llm).run(
        triplet, stage1_docs=stage1_docs, artifacts=artifacts
    )


def required_processing_units(
    triplet: FunctionTriplet,
) -> tuple[dict[str, Any], ...]:
    """Expose the deterministic Stage 2 unit contract for validation."""

    return _structural_units(triplet)


def _load_documentation(
    path: Path,
    triplet: FunctionTriplet,
) -> dict[str, Mapping[str, Any]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise Stage2Error(
            f"cannot load Stage 1 documentation: {type(error).__name__}"
        ) from error
    if not isinstance(document, Mapping) or document.get("schema_version") != 1:
        raise Stage2Error("stage1_docs.json requires schema_version 1")
    if document.get("triplet_id") != triplet.id:
        raise Stage2Error("Stage 1 documentation belongs to a different triplet")
    records = document.get("documents")
    if not isinstance(records, list) or any(
        not isinstance(item, Mapping) for item in records
    ):
        raise Stage2Error("stage1_docs.json documents must be an array of objects")
    by_name = {}
    for record in records:
        name = record.get("function")
        if not isinstance(name, str) or not name:
            raise Stage2Error("Stage 1 documentation function must be non-empty")
        if name in by_name:
            raise Stage2Error(f"duplicate Stage 1 documentation: {name}")
        by_name[name] = record
    expected = {function.function for function in triplet.functions}
    missing = sorted(expected - set(by_name))
    if missing:
        raise Stage2Error("missing Stage 1 documentation: " + ", ".join(missing))
    return by_name


def _structural_units(triplet: FunctionTriplet) -> tuple[dict[str, Any], ...]:
    ordered = [(step.source, step.target, step.functions)
               for step in triplet.structural_steps()]
    ids = [f"unit_{index:04d}" for index in range(1, len(ordered) + 1)]
    units = []
    for index, (source, target, functions) in enumerate(ordered):
        dependencies = set()
        if not is_null_node(source):
            for producer_index, (producer_source, producer_target, _) in enumerate(ordered):
                if (
                    producer_target == source
                    and (producer_source, producer_target) != (source, target)
                ):
                    dependencies.add(ids[producer_index])
        if is_null_node(target):
            for peer_index, (peer_source, peer_target, _) in enumerate(ordered):
                if peer_source == source and not is_null_node(peer_target):
                    dependencies.add(ids[peer_index])
        units.append({
            "id": ids[index],
            "input_structure": source,
            "output_structure": target,
            "functions": tuple(functions),
            "dependencies": tuple(sorted(dependencies)),
        })
    return tuple(units)


def _generation_metadata(
    generation: LLMGeneration,
    *,
    attempt: int,
    rollback_source: str | None,
    retry_reason: str | None,
    retry_context: Mapping[str, Any] | None,
) -> dict[str, Any]:
    context = dict(retry_context or {})
    metadata = {
        "prompt_version": generation.prompt_version,
        "model": generation.model,
        "provider": generation.provider,
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
    return {
        key: value for key, value in metadata.items() if key != "timestamp"
    }


def _documentation_for_prompt(
    document: Mapping[str, Any],
) -> dict[str, Any]:
    """Do not feed provider/audit metadata back into later LLM prompts."""

    return {
        key: value for key, value in document.items()
        if key != "generation_metadata"
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
