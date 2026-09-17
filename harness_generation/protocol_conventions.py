"""LLM-assisted convention-block inference for protocol contracts.

The A/B miner in :mod:`protocol_miner` recovers source-grounded frame facts.
This module handles the C block: command-loop policy, context lifetime,
stateful opcode interpretation, requirements and notes.  These are deliberately
kept separate because they are partly semantic and partly engineering choices.

The LLM is not allowed to produce free-form prose as the canonical result.  It
must return strict JSON, and multiple samples are merged through a consistency
table: a field is kept only when it appears in a majority of valid samples.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field as dataclass_field
from typing import Any, Iterable, Mapping, Sequence

from .generation_output import normalize_c_response
from .llm import LLMClient, LLMError, LLMGeneration
from .prompts import protocol_convention_refinement
from .protocol_miner import ProtocolFacts


PROTOCOL_CONVENTION_SCHEMA_VERSION = 1


class ProtocolConventionError(ValueError):
    """Raised when no valid convention block can be inferred."""


@dataclass(frozen=True)
class SequenceModel:
    multi_frame: bool
    reason: str = ""
    evidence: tuple[str, ...] = ()
    max_steps: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "multi_frame": self.multi_frame,
            "reason": self.reason,
            "evidence": list(self.evidence),
            "max_steps": dict(self.max_steps),
        }


@dataclass(frozen=True)
class ContextModel:
    type: str = ""
    init: str = ""
    destroy: str = ""
    lifetime: str = ""
    evidence: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "init": self.init,
            "destroy": self.destroy,
            "lifetime": self.lifetime,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class StatefulOperation:
    opcode: str
    reason: str = ""
    evidence: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "opcode": self.opcode,
            "reason": self.reason,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class ProtocolConventions:
    """Stable, voted convention block ready to merge into a protocol contract."""

    entry_function: str
    sequence_model: SequenceModel
    context: ContextModel
    stateful_operations: tuple[StatefulOperation, ...] = ()
    requirements: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = dataclass_field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": PROTOCOL_CONVENTION_SCHEMA_VERSION,
            "entry_function": self.entry_function,
            "sequence_model": self.sequence_model.to_json(),
            "context": self.context.to_json(),
            "stateful_operations": [
                item.to_json() for item in self.stateful_operations
            ],
            "requirements": list(self.requirements),
            "notes": list(self.notes),
            "metadata": dict(self.metadata),
        }

    def to_contract_block(self) -> dict[str, Any]:
        """Return the C block without inference metadata."""

        return {
            "sequence_model": self.sequence_model.to_json(),
            "context": self.context.to_json(),
            "stateful_operations": [
                item.to_json() for item in self.stateful_operations
            ],
            "requirements": list(self.requirements),
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class ConventionInferenceResult:
    conventions: ProtocolConventions
    generations: tuple[LLMGeneration, ...]
    accepted_samples: tuple[Mapping[str, Any], ...]
    rejected_samples: tuple[Mapping[str, Any], ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": PROTOCOL_CONVENTION_SCHEMA_VERSION,
            "conventions": self.conventions.to_json(),
            "generations": [item.to_dict() for item in self.generations],
            "accepted_samples": [dict(item) for item in self.accepted_samples],
            "rejected_samples": [dict(item) for item in self.rejected_samples],
        }


def infer_protocol_conventions(
    facts: ProtocolFacts | Mapping[str, Any],
    source_context: str,
    llm: LLMClient,
    *,
    samples: int = 3,
) -> ConventionInferenceResult:
    """Infer and vote the convention block using an LLM.

    Invalid JSON, schema errors and provider errors are recorded as rejected
    samples.  They do not crash the caller unless no valid sample remains.
    """

    if samples <= 0:
        raise ValueError("samples must be positive")
    entry_function = _entry_function(facts)
    prompt_facts = facts.to_json() if isinstance(facts, ProtocolFacts) else dict(facts)
    prompt = protocol_convention_refinement(
        entry_function=entry_function,
        protocol_facts=prompt_facts,
        source_context=source_context,
    )

    generations: list[LLMGeneration] = []
    accepted: list[Mapping[str, Any]] = []
    rejected: list[Mapping[str, Any]] = []
    for index in range(1, samples + 1):
        try:
            generation = llm.generate(prompt)
            generations.append(generation)
            document = parse_convention_response(generation.content)
            accepted.append(document)
        except (LLMError, ProtocolConventionError, ValueError) as error:
            rejected.append({
                "sample": index,
                "error": type(error).__name__,
                "message": str(error),
            })

    if not accepted:
        raise ProtocolConventionError("no valid protocol convention samples")

    conventions = _vote_conventions(
        entry_function,
        accepted,
        prompt_version=prompt.prompt_version,
        model=getattr(llm, "model", "unknown"),
        provider=getattr(llm, "provider", "unknown"),
        rejected_samples=rejected,
    )
    return ConventionInferenceResult(
        conventions=conventions,
        generations=tuple(generations),
        accepted_samples=tuple(accepted),
        rejected_samples=tuple(rejected),
    )


def parse_convention_response(content: str) -> dict[str, Any]:
    """Parse one strict JSON convention response."""

    raw = _strip_json_fence(content)
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ProtocolConventionError("LLM response is not valid JSON") from error
    if not isinstance(document, Mapping):
        raise ProtocolConventionError("convention response must be a JSON object")
    _validate_sample(document)
    return dict(document)


def _strip_json_fence(content: str) -> str:
    text = content.strip()
    if text.startswith("```"):
        normalized = normalize_c_response(text).strip()
        if normalized != text:
            return normalized
        match = re.fullmatch(r"```(?:json|JSON)?\s*\n(.*?)\n```", text, re.DOTALL)
        if match:
            return match.group(1).strip()
    return text


def _validate_sample(document: Mapping[str, Any]) -> None:
    if document.get("schema_version") != PROTOCOL_CONVENTION_SCHEMA_VERSION:
        raise ProtocolConventionError("convention response requires schema_version 1")
    sequence = document.get("sequence_model")
    context = document.get("context")
    operations = document.get("stateful_operations")
    if not isinstance(sequence, Mapping):
        raise ProtocolConventionError("sequence_model must be an object")
    if not isinstance(sequence.get("multi_frame"), bool):
        raise ProtocolConventionError("sequence_model.multi_frame must be boolean")
    max_steps = sequence.get("max_steps")
    if not isinstance(max_steps, Mapping):
        raise ProtocolConventionError("sequence_model.max_steps must be an object")
    value = max_steps.get("value")
    if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
        raise ProtocolConventionError("sequence_model.max_steps.value must be integer or null")
    if not isinstance(context, Mapping):
        raise ProtocolConventionError("context must be an object")
    for key in ("type", "init", "destroy", "lifetime"):
        if key in context and not isinstance(context.get(key), str):
            raise ProtocolConventionError(f"context.{key} must be a string")
    if not isinstance(operations, list):
        raise ProtocolConventionError("stateful_operations must be a list")
    for item in operations:
        if not isinstance(item, Mapping):
            raise ProtocolConventionError("stateful operation must be an object")
        if not _non_empty_string(item.get("opcode")):
            raise ProtocolConventionError("stateful operation opcode is required")
        if not _strings(item.get("evidence", [])):
            raise ProtocolConventionError("stateful operation evidence must be strings")
        if not item.get("evidence"):
            raise ProtocolConventionError("stateful operation evidence is required")
    if not _strings(document.get("requirements", [])):
        raise ProtocolConventionError("requirements must be strings")
    if not _strings(document.get("notes", [])):
        raise ProtocolConventionError("notes must be strings")
    for holder, field in ((sequence, "evidence"), (context, "evidence"), (max_steps, "evidence")):
        if field in holder and not _strings(holder.get(field, [])):
            raise ProtocolConventionError(f"{field} must be strings")


def _vote_conventions(
    entry_function: str,
    samples: Sequence[Mapping[str, Any]],
    *,
    prompt_version: str,
    model: str,
    provider: str,
    rejected_samples: Sequence[Mapping[str, Any]],
) -> ProtocolConventions:
    threshold = len(samples) // 2 + 1
    sequences = [sample["sequence_model"] for sample in samples]
    contexts = [sample["context"] for sample in samples]

    multi_frame = bool(_mode([item["multi_frame"] for item in sequences], default=False))
    max_values = [
        item.get("max_steps", {}).get("value") for item in sequences
        if isinstance(item.get("max_steps", {}).get("value"), int)
    ]
    voted_max_value = _majority_mode(max_values, threshold)
    max_sources = [
        _clean_string(item.get("max_steps", {}).get("source")) for item in sequences
    ]
    voted_max_source = _majority_mode(
        [item for item in max_sources if item], threshold
    ) or ""
    max_step_evidence = _voted_strings(
        [item.get("max_steps", {}).get("evidence", []) for item in sequences],
        threshold,
    )
    max_steps: dict[str, Any] = {
        "value": voted_max_value,
        "source": voted_max_source,
        "evidence": list(max_step_evidence),
    }

    sequence = SequenceModel(
        multi_frame=multi_frame,
        reason=_mode_string([item.get("reason", "") for item in sequences]),
        evidence=_voted_strings([item.get("evidence", []) for item in sequences], threshold),
        max_steps=max_steps,
    )
    context = ContextModel(
        type=_majority_or_mode_string([item.get("type", "") for item in contexts], threshold),
        init=_majority_or_mode_string([item.get("init", "") for item in contexts], threshold),
        destroy=_majority_or_mode_string([item.get("destroy", "") for item in contexts], threshold),
        lifetime=_majority_or_mode_string([item.get("lifetime", "") for item in contexts], threshold),
        evidence=_voted_strings([item.get("evidence", []) for item in contexts], threshold),
    )
    operations = _vote_stateful_operations(samples, threshold)
    requirements = _voted_strings(
        [sample.get("requirements", []) for sample in samples], threshold
    )
    notes = _voted_strings([sample.get("notes", []) for sample in samples], threshold)
    return ProtocolConventions(
        entry_function=entry_function,
        sequence_model=sequence,
        context=context,
        stateful_operations=operations,
        requirements=requirements,
        notes=notes,
        metadata={
            "prompt_version": prompt_version,
            "model": model,
            "provider": provider,
            "samples_requested": len(samples) + len(rejected_samples),
            "valid_samples": len(samples),
            "rejected_samples": [dict(item) for item in rejected_samples],
            "vote_threshold": threshold,
        },
    )


def _vote_stateful_operations(
    samples: Sequence[Mapping[str, Any]], threshold: int,
) -> tuple[StatefulOperation, ...]:
    by_opcode: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for sample in samples:
        seen: set[str] = set()
        for item in sample.get("stateful_operations", []):
            if not isinstance(item, Mapping):
                continue
            opcode = _clean_string(item.get("opcode"))
            if not opcode or opcode in seen:
                continue
            seen.add(opcode)
            by_opcode[opcode].append(item)

    voted: list[StatefulOperation] = []
    for opcode in sorted(by_opcode):
        items = by_opcode[opcode]
        if len(items) < threshold:
            continue
        evidence = _voted_strings([item.get("evidence", []) for item in items], 1)
        if not evidence:
            continue
        voted.append(StatefulOperation(
            opcode=opcode,
            reason=_mode_string([item.get("reason", "") for item in items]),
            evidence=evidence,
        ))
    return tuple(voted)


def _entry_function(facts: ProtocolFacts | Mapping[str, Any]) -> str:
    if isinstance(facts, ProtocolFacts):
        return facts.entry_function
    value = facts.get("entry_function")
    if not _non_empty_string(value):
        raise ValueError("protocol facts require entry_function")
    return value


def _voted_strings(values: Iterable[Any], threshold: int) -> tuple[str, ...]:
    counter: Counter[str] = Counter()
    for group in values:
        if isinstance(group, str):
            items = [group]
        elif isinstance(group, Iterable):
            items = list(group)
        else:
            items = []
        seen: set[str] = set()
        for item in items:
            normalized = _normalize_text(item)
            if normalized and normalized not in seen:
                seen.add(normalized)
                counter[normalized] += 1
    return tuple(
        item for item, count in sorted(counter.items(), key=lambda pair: (-pair[1], pair[0]))
        if count >= threshold
    )


def _mode(values: Sequence[Any], *, default: Any = None) -> Any:
    if not values:
        return default
    counter = Counter(values)
    return sorted(counter.items(), key=lambda pair: (-pair[1], str(pair[0])))[0][0]


def _majority_mode(values: Sequence[Any], threshold: int) -> Any | None:
    if not values:
        return None
    counter = Counter(values)
    value, count = sorted(counter.items(), key=lambda pair: (-pair[1], str(pair[0])))[0]
    return value if count >= threshold else None


def _mode_string(values: Sequence[Any]) -> str:
    strings = [_clean_string(item) for item in values if _clean_string(item)]
    return _mode(strings, default="") or ""


def _majority_or_mode_string(values: Sequence[Any], threshold: int) -> str:
    strings = [_clean_string(item) for item in values if _clean_string(item)]
    return _majority_mode(strings, threshold) or _mode_string(strings)


def _normalize_text(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.strip().split())


def _clean_string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)
