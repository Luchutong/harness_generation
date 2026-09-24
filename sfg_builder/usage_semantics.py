"""Constrained LLM review for statically mined usage lifecycles."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from typing import Any, Iterable, Mapping

from .base import SemanticAnalyzer, SemanticBudgetExceeded, SemanticDecision
from .models import FunctionAnnotation, FunctionInfo
from .prompts import USAGE_REVIEW_PROMPT_VERSION, usage_review_prompt
from .usage import UsageMiningResult, UsagePattern


USAGE_SEMANTICS_VERSION = "usage-semantics-v1"


def review_usage_semantics(
    result: UsageMiningResult,
    functions: tuple[FunctionInfo, ...],
    annotations: tuple[FunctionAnnotation, ...],
    analyzer: SemanticAnalyzer,
    *,
    batch_size: int = 12,
    singleton_retries: int = 1,
) -> UsageMiningResult:
    """Review and safely group patterns while preserving static dataflow facts."""
    if not result.patterns:
        return result
    backend = str(getattr(analyzer, "semantic_backend", "custom"))
    method = getattr(analyzer, "review_usage_patterns", None)
    if not callable(method):
        return replace(result, patterns=tuple(
            replace(pattern, semantic_review={
                **_fallback_review(pattern, "not_supported"), "backend": backend,
            })
            for pattern in result.patterns
        ))
    isf_names = {
        annotation.function for annotation in annotations if "ISF" in annotation.labels
    }
    decisions: dict[str, dict[str, Any]] = {}
    traces: list[Mapping[str, Any]] = []
    groups: dict[str, list[UsagePattern]] = {}
    for pattern in result.patterns:
        groups.setdefault(pattern.resource_type, []).append(pattern)

    if batch_size < 1 or singleton_retries < 0:
        raise ValueError("usage review batch size and retry count are invalid")

    def review_batch(
        batch: tuple[UsagePattern, ...], retries_left: int = singleton_retries
    ) -> None:
        records = tuple(_review_record(pattern) for pattern in batch)
        prompt = usage_review_prompt(records, functions)
        try:
            decision = method(records, functions)
            if not isinstance(decision, SemanticDecision):
                raise TypeError("semantic analyzer returned an invalid usage decision")
            batch_decisions = decision.data.get("decisions", [])
            for item in batch_decisions:
                pattern = next(value for value in batch if value.id == item.get("pattern_id"))
                decisions[pattern.id] = _constrain_decision(
                    pattern, item, isf_names, decision.prompt_version
                )
                decisions[pattern.id]["backend"] = backend
            traces.append(_trace(
                batch, decision.prompt, decision.prompt_version,
                decision.response, decision.confidence, "ok", None, backend,
            ))
        except SemanticBudgetExceeded:
            raise
        except Exception as error:
            traces.append(_trace(
                batch, prompt, USAGE_REVIEW_PROMPT_VERSION, {}, 0.0,
                "error", type(error).__name__, backend,
            ))
            if len(batch) > 1:
                middle = len(batch) // 2
                review_batch(batch[:middle])
                review_batch(batch[middle:])
                return
            if retries_left > 0:
                review_batch(batch, retries_left - 1)
                return
            pattern = batch[0]
            decisions[pattern.id] = _fallback_review(
                pattern, "provider_error", error=type(error).__name__
            )
            decisions[pattern.id]["backend"] = backend

    for resource_type in sorted(groups):
        patterns = sorted(groups[resource_type], key=lambda item: item.id)
        for offset in range(0, len(patterns), batch_size):
            batch = tuple(patterns[offset:offset + batch_size])
            review_batch(batch)
    reviewed = _assign_safe_groups(result.patterns, decisions)
    return replace(
        result,
        patterns=reviewed,
        semantic_reviews=tuple(traces),
    )


def _review_record(pattern: UsagePattern) -> Mapping[str, Any]:
    value = pattern.to_dict()
    value.pop("semantic_review", None)
    return value


def _constrain_decision(
    pattern: UsagePattern,
    raw: Mapping[str, Any],
    isf_names: set[str],
    prompt_version: str,
) -> dict[str, Any]:
    confidence = raw.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        return _fallback_review(pattern, "invalid_response")
    confidence = max(0.0, min(1.0, float(confidence)))
    valid = raw.get("is_valid_lifecycle") is True
    kind = raw.get("lifecycle_kind")
    required = raw.get("required_sequence")
    optional = raw.get("optional_calls")
    merge_group = raw.get("merge_group")
    reason = raw.get("reason")
    safe = (
        raw.get("pattern_id") == pattern.id
        and kind in {pattern.lifecycle_kind, "not_lifecycle"}
        and isinstance(required, list)
        and all(isinstance(item, str) and item for item in required)
        and _is_subsequence(tuple(required), pattern.sequence)
        and bool(required)
        and required[0] == pattern.producer_function
        and required[-1] == pattern.cleanup_function
        and all(required.count(name) >= pattern.sequence.count(name)
                for name in isf_names if name in pattern.sequence)
        and isinstance(optional, list)
        and all(isinstance(item, str) and item in pattern.sequence for item in optional)
        and isinstance(merge_group, str) and bool(merge_group.strip())
        and isinstance(reason, str)
    )
    if not safe:
        return _fallback_review(pattern, "invalid_response")
    status = (
        "accepted" if valid and kind == pattern.lifecycle_kind
        else "rejected" if not valid and confidence >= 0.8
        else "uncertain"
    )
    return {
        "status": status,
        "confidence": confidence,
        "lifecycle_kind": kind,
        "required_sequence": list(required),
        "optional_calls": list(optional),
        "merge_group": merge_group.strip(),
        "reason": reason,
        "prompt_version": prompt_version,
        "guardrail": "static_same_variable_dataflow",
    }


def _fallback_review(
    pattern: UsagePattern, status: str, *, error: str | None = None
) -> dict[str, Any]:
    return {
        "status": status,
        "confidence": 0.0,
        "lifecycle_kind": pattern.lifecycle_kind,
        "required_sequence": list(pattern.sequence),
        "optional_calls": [],
        "merge_group": pattern.id,
        "reason": "static lifecycle retained without a usable semantic review",
        "prompt_version": USAGE_REVIEW_PROMPT_VERSION,
        "guardrail": "static_same_variable_dataflow",
        **({"error": error} if error else {}),
    }


def _assign_safe_groups(
    patterns: tuple[UsagePattern, ...],
    decisions: Mapping[str, Mapping[str, Any]],
) -> tuple[UsagePattern, ...]:
    keys: dict[tuple[Any, ...], list[UsagePattern]] = {}
    for pattern in patterns:
        review = decisions.get(pattern.id, _fallback_review(pattern, "not_reviewed"))
        # Static lifecycle identity and control-path conditions cannot be overridden
        # by a model-provided merge label.
        merge_token = (review.get("merge_group")
                       if review.get("status") == "accepted" else pattern.id)
        key = (
            merge_token, pattern.lifecycle_kind,
            pattern.resource_type, pattern.producer_function_id,
            pattern.producer_binding, pattern.producer_argument_index,
            pattern.cleanup_function_id, pattern.cleanup_argument_index,
            pattern.cleanup_argument, pattern.path_kind, pattern.conditions,
            tuple(review.get("required_sequence", pattern.sequence)),
            review.get("status"),
        )
        keys.setdefault(key, []).append(pattern)
    output = []
    for key, members in sorted(keys.items(), key=lambda item: repr(item[0])):
        identity = json.dumps(key, sort_keys=True, default=list, separators=(",", ":"))
        group_id = "usg_" + hashlib.sha256(
            (USAGE_SEMANTICS_VERSION + "\0" + identity).encode()
        ).hexdigest()[:12]
        support: dict[str, int] = {}
        evidence = set()
        for member in members:
            evidence.update(member.evidence)
            for source, count in member.support_by_source.items():
                support[source] = support.get(source, 0) + int(count)
        member_ids = sorted(member.id for member in members)
        for member in members:
            review = dict(decisions.get(
                member.id, _fallback_review(member, "not_reviewed")
            ))
            review.update({
                "semantic_group_id": group_id,
                "group_member_pattern_ids": member_ids,
                "group_support_total": sum(support.values()),
                "group_support_by_source": dict(sorted(support.items())),
                "group_evidence": sorted(evidence),
            })
            output.append(replace(member, semantic_review=review))
    return tuple(sorted(output, key=lambda item: item.id))


def _trace(
    patterns: Iterable[UsagePattern], prompt: str, prompt_version: str,
    response: Mapping[str, Any], confidence: float, status: str,
    error: str | None, backend: str,
) -> Mapping[str, Any]:
    ids = tuple(pattern.id for pattern in patterns)
    digest = hashlib.sha256("\0".join(ids).encode()).hexdigest()[:12]
    return {
        "id": "usr_" + digest,
        "pattern_ids": list(ids),
        "prompt": prompt,
        "prompt_version": prompt_version,
        "response": dict(response),
        "confidence": confidence,
        "status": status,
        "error": error,
        "backend": backend,
    }


def _is_subsequence(candidate: tuple[str, ...], source: tuple[str, ...]) -> bool:
    iterator = iter(source)
    return all(any(value == expected for value in iterator) for expected in candidate)
