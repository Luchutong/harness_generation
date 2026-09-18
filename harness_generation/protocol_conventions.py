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
from typing import Any, Callable, Iterable, Mapping, Sequence

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
    fail_fast_on_llm_error: bool = False,
) -> ConventionInferenceResult:
    """Infer and vote the convention block using an LLM.

    Invalid JSON, schema errors and provider errors are recorded as rejected
    samples.  They do not crash the caller unless no valid sample remains.

    ``fail_fast_on_llm_error`` trades that tolerance for a shorter wait: the
    first sample that fails ends the run instead of being voted around, so the
    caller does not pay for the remaining samples after a failure that says the
    provider or the response contract is unusable.  It is about *failed samples*
    only -- valid samples that contradict each other are the ordinary input to
    the vote and are never a reason to stop.  The abort re-raises the sample's
    own error type with the sample position added to the message, so a caller
    branching on ``LLMError`` (provider/transport, including timeouts) keeps
    that branch, a caller branching on ``ProtocolConventionError`` (invalid
    JSON, schema violations) keeps its own, and ``from error`` keeps the
    original failure in the chain.  Note that with a single sample the flag has
    nothing to shorten and a first-sample failure surfaces the sample's error
    rather than the ``no valid protocol convention samples`` error below.
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
            if fail_fast_on_llm_error:
                # Same type, enriched message.  Every type this clause catches
                # is built from one message string, so reconstructing the class
                # is safe here; keeping the class is what lets a caller tell a
                # provider failure from a schema failure, while the position is
                # what lets a reader of the CLI tell "stopped at sample 1" from
                # "voted over all three and this was the first failure".
                raise type(error)(
                    f"sample {index} of {samples} failed: {error}"
                ) from error

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

    # Every field below is tallied exactly once, and both the selected value and
    # the recorded tally are read off that single counter.  Counting again for
    # the summary would let the two disagree, and a vote_summary that describes a
    # value nobody selected is worse than no summary at all -- the point of
    # persisting it is that a reader can trust it without re-running the vote.
    fields: dict[str, dict[str, Any]] = {}

    counter, valid = _tally(
        [item["multi_frame"] for item in sequences], normalize=_identity
    )
    multi_frame = bool(_mode_from(counter, default=False))
    _record_scalar(fields, "sequence_model.multi_frame", counter, valid, multi_frame)

    max_values = [
        item.get("max_steps", {}).get("value") for item in sequences
        if isinstance(item.get("max_steps", {}).get("value"), int)
    ]
    counter, valid = _tally(max_values, normalize=_identity)
    voted_max_value = _majority_from(counter, threshold)
    _record_scalar(
        fields, "sequence_model.max_steps.value", counter, valid, voted_max_value
    )

    counter, valid = _tally(
        [_clean_string(item.get("max_steps", {}).get("source")) for item in sequences],
        normalize=_clean_string,
    )
    voted_max_source = _majority_from(counter, threshold) or ""
    _record_scalar(
        fields, "sequence_model.max_steps.source", counter, valid, voted_max_source
    )

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

    context_fields: dict[str, str] = {}
    for name in ("type", "init", "destroy", "lifetime"):
        counter, valid = _tally(
            [item.get(name, "") for item in contexts], normalize=_clean_string
        )
        context_fields[name] = _majority_or_mode_from(counter, threshold)
        _record_scalar(fields, f"context.{name}", counter, valid, context_fields[name])
    context = ContextModel(
        type=context_fields["type"],
        init=context_fields["init"],
        destroy=context_fields["destroy"],
        lifetime=context_fields["lifetime"],
        evidence=_voted_strings([item.get("evidence", []) for item in contexts], threshold),
    )

    by_opcode, operations_valid = _tally_stateful_operations(samples)
    operations = _stateful_operations_from(by_opcode, threshold)
    _record_set(fields, "stateful_operations", by_opcode, operations_valid, operations)

    requirements = _voted_strings(
        [sample.get("requirements", []) for sample in samples], threshold
    )
    notes = _voted_strings([sample.get("notes", []) for sample in samples], threshold)

    # `fields` is built in a fixed order above and sorted here, so the document
    # does not depend on the order the sequence/context keys happened to be read
    # in.  The artifact writer sorts keys too; this makes the in-memory value
    # deterministic as well, for callers that never serialise it.
    fields = dict(sorted(fields.items()))
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
            "vote_summary": _vote_summary(
                fields,
                samples_requested=len(samples) + len(rejected_samples),
                valid_samples=len(samples),
            ),
        },
    )


def _vote_stateful_operations(
    samples: Sequence[Mapping[str, Any]], threshold: int,
) -> tuple[StatefulOperation, ...]:
    by_opcode, _ = _tally_stateful_operations(samples)
    return _stateful_operations_from(by_opcode, threshold)


def _tally_stateful_operations(
    samples: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, list[Mapping[str, Any]]], int]:
    """Group the stateful opcodes by sample: the set field's tally.

    Each sample counts once per opcode it names, however many times it names it,
    so a sample's ``stateful_operations`` list is a *set* of opcodes and the
    count against an opcode is the number of samples that voted for it.  The
    second element is the number of samples that named at least one opcode, which
    is the set field's ``valid_samples``: the denominator every per-opcode count
    is divided by, and therefore the one that has to come from this same pass.
    """

    by_opcode: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    offered = 0
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
        if seen:
            offered += 1
    return dict(by_opcode), offered


def _stateful_operations_from(
    by_opcode: Mapping[str, list[Mapping[str, Any]]], threshold: int,
) -> tuple[StatefulOperation, ...]:
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


def _record_scalar(
    fields: dict[str, dict[str, Any]],
    key: str,
    counter: Counter[Any],
    valid: int,
    selected: Any,
) -> None:
    """Record one scalar field's tally, alongside the value it selected.

    A field no sample offered a candidate for is *not* recorded.  Writing it
    down with ``agreement: 1.0`` would make a field nobody answered look
    unanimous, and it would then pull the mean field agreement up rather than
    being visibly absent from ``fields_counted``.

    ``votes`` is the count the selected value reached, so ``votes`` sits inside
    ``valid_samples`` by construction and ``agreement`` cannot exceed 1.0.  A
    selection that fell back to a value no sample voted for -- a ``max_steps``
    bound no candidate carried a majority for, recorded as ``null`` -- has
    ``votes: 0``, which reads as the total disagreement it is.
    """

    if not valid:
        return
    votes = counter.get(selected, 0) if selected is not None else 0
    entry: dict[str, Any] = {
        "selected": selected,
        "votes": votes,
        "valid_samples": valid,
        "agreement": round(votes / valid, 4),
    }
    # Only a contested field carries alternatives: recording a single candidate
    # as a one-entry map would say nothing the selected value does not.
    if len(counter) > 1:
        entry["alternatives"] = _alternatives(counter)
    fields[key] = entry


def _record_set(
    fields: dict[str, dict[str, Any]],
    key: str,
    by_opcode: Mapping[str, list[Mapping[str, Any]]],
    valid: int,
    operations: Sequence[StatefulOperation],
) -> None:
    """Record the set field's tally.

    The shape differs from a scalar field on purpose, and a reader should not go
    looking for the missing key.  ``selected`` is the sorted list of opcodes the
    vote selected -- the same list, in the same order, that
    ``_stateful_operations_from`` builds -- and there is no ``votes``: for a union
    there is no one count to report, and any single number chosen for it would not
    satisfy ``votes / valid_samples == agreement`` -- exactly the sort of number
    that looks auditable and is not.  ``agreement`` is instead the mean over the
    union of opcodes of ``count / valid_samples``, and ``alternatives`` is always
    present because for a set the tally *is* the union: dropping it would hide
    the opcodes a minority voted for.
    """

    if not valid or not by_opcode:
        return
    union = sorted(by_opcode)
    fields[key] = {
        "selected": [item.opcode for item in operations],
        "valid_samples": valid,
        "agreement": round(
            sum(len(by_opcode[opcode]) for opcode in union) / (valid * len(union)), 4
        ),
        "alternatives": {opcode: len(by_opcode[opcode]) for opcode in union},
    }


def _alternatives(counter: Counter[Any]) -> dict[str, int]:
    """The full tally as JSON keys, including the candidates that lost."""

    return {
        _candidate_key(value): count
        for value, count in sorted(
            counter.items(), key=lambda pair: _candidate_key(pair[0])
        )
    }


def _candidate_key(value: Any) -> str:
    """One candidate as the key it is written under.

    A boolean is spelled the way JSON spells it: ``str(True)`` is ``"True"``,
    and a reader comparing the summary against a hand-written expectation would
    be comparing against the wrong spelling.  Everything else is its string form,
    which is what the vote keyed on for the string fields anyway.
    """

    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _vote_summary(
    fields: Mapping[str, dict[str, Any]],
    *,
    samples_requested: int,
    valid_samples: int,
) -> dict[str, Any]:
    """The per-field tallies and the confidence they imply.

    This is the only place the confidence formula lives.  :class:`ProtocolIR`
    reads ``confidence.value`` rather than recomputing it, so the number a
    consumer acts on and the number an auditor can check against ``fields`` are
    the same number; the arithmetic done twice would eventually be done twice
    differently.

    ``mean_field_agreement`` averages only the fields that were recorded.  With
    nothing recorded it is 1.0: there is no field whose samples disagreed, and
    penalising the absence of a question would score an unasked field as a
    wrong answer.  ``fields_counted`` names what was averaged, so that rule is
    visible in the artefact rather than implied by the arithmetic.
    """

    agreements = [entry["agreement"] for entry in fields.values()]
    mean_agreement = (
        round(sum(agreements) / len(agreements), 4) if agreements else 1.0
    )
    validity = round(valid_samples / samples_requested, 4) if samples_requested else 0.0
    return {
        "fields": dict(fields),
        "confidence": {
            "sample_validity": validity,
            "mean_field_agreement": mean_agreement,
            "fields_counted": sorted(fields),
            "value": round(validity * mean_agreement, 4),
        },
    }


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


def _tally(
    values: Iterable[Any], *, normalize: Callable[[Any], Any] = _normalize_text,
) -> tuple[Counter[Any], int]:
    """Count one field's candidates, in a single pass, ready to be voted on.

    ``values`` holds one entry per sample: either one candidate or an iterable
    of them.  Returns the counter and the number of samples that offered at
    least one candidate, which is the field's ``valid_samples``.

    The selection rules take the counter this returns rather than the raw list,
    so the count a value was selected on *is* the count the vote summary
    records.  Counting twice would be two chances to drift, and the summary is
    only worth persisting if it describes the value that actually won.

    ``normalize`` decides what a candidate is: it maps one offered value to its
    vote key, and anything it maps to ``None`` or ``""`` counts as "this sample
    offered nothing here".  The text fields normalise whitespace; the boolean
    and integer fields pass their real values through, because a ``False`` or a
    ``0`` is a candidate and must not be mistaken for an absent one.
    """

    counter: Counter[Any] = Counter()
    offered = 0
    for group in values:
        candidates = _candidates(group, normalize)
        if not candidates:
            continue
        offered += 1
        for candidate in candidates:
            counter[candidate] += 1
    return counter, offered


def _candidates(group: Any, normalize: Callable[[Any], Any]) -> list[Any]:
    """The distinct candidates one sample offered for a field."""

    if isinstance(group, str):
        items: list[Any] = [group]
    elif isinstance(group, Iterable):
        items = list(group)
    else:
        items = [group]
    candidates: list[Any] = []
    seen: set[Any] = set()
    for item in items:
        candidate = normalize(item)
        if candidate is None or candidate == "" or candidate in seen:
            continue
        seen.add(candidate)
        candidates.append(candidate)
    return candidates


def _identity(value: Any) -> Any:
    """Keep a non-string candidate as it is, ``None`` meaning "nothing offered"."""

    return value


def _vote_order(pair: tuple[Any, int]) -> tuple[int, str]:
    """Most votes first, ties broken by the candidate's string form.

    The string form, not the value, because the tied candidates need not be
    comparable: a field can hold a boolean and a string while a half-written
    sample is being voted on, and ``sorted`` on the values would raise there.
    """

    return (-pair[1], str(pair[0]))


def _voted_strings_from(counter: Counter[str], threshold: int) -> tuple[str, ...]:
    """Every candidate that reached the threshold, most-voted first."""

    return tuple(
        item for item, count in sorted(counter.items(), key=_vote_order)
        if count >= threshold
    )


def _mode_from(counter: Counter[Any], *, default: Any = None) -> Any:
    """The most-voted candidate, whatever its count."""

    if not counter:
        return default
    return sorted(counter.items(), key=_vote_order)[0][0]


def _majority_from(counter: Counter[Any], threshold: int) -> Any | None:
    """The most-voted candidate, or ``None`` when it fell short of the threshold."""

    if not counter:
        return None
    value, count = sorted(counter.items(), key=_vote_order)[0]
    return value if count >= threshold else None


def _majority_or_mode_from(counter: Counter[str], threshold: int) -> str:
    """The majority candidate, or the plain mode when there is no majority.

    A field the samples split on still has a most-common answer and the C block
    has to carry something; recording the tally is what makes that fallback
    visible instead of silent, and it is why this rule has to read the same
    counter the summary does.
    """

    return _majority_from(counter, threshold) or _mode_from(counter, default="") or ""


def _voted_strings(values: Iterable[Any], threshold: int) -> tuple[str, ...]:
    counter, _ = _tally(values)
    return _voted_strings_from(counter, threshold)


def _mode(values: Sequence[Any], *, default: Any = None) -> Any:
    counter, _ = _tally(values, normalize=_identity)
    return _mode_from(counter, default=default)


def _majority_mode(values: Sequence[Any], threshold: int) -> Any | None:
    counter, _ = _tally(values, normalize=_identity)
    return _majority_from(counter, threshold)


def _mode_string(values: Sequence[Any]) -> str:
    counter, _ = _tally(values, normalize=_clean_string)
    return _mode_from(counter, default="") or ""


def _majority_or_mode_string(values: Sequence[Any], threshold: int) -> str:
    counter, _ = _tally(values, normalize=_clean_string)
    return _majority_or_mode_from(counter, threshold)
