"""Majority voting for independent stream-classification prompt variants."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from .base import SemanticAnalyzer, SemanticDecision
from .models import FunctionInfo, ParameterInfo, StructInfo
from .prompts import STREAM_PROMPT_VERSION, STREAM_VARIANTS, stream_prompt


@dataclass(frozen=True)
class StreamVoteResult:
    is_byte_stream: bool
    kind: str
    confidence: float
    reason: str
    positive_votes: int
    valid_votes: int
    decisions: tuple[SemanticDecision, ...]


def vote_stream_parameter(analyzer: SemanticAnalyzer, function: FunctionInfo,
                          parameter: ParameterInfo,
                          structs: tuple[StructInfo, ...]) -> StreamVoteResult:
    """Run distinct variants and conservatively require two positive votes."""
    decisions = tuple(
        _safe_stream_call(analyzer, function, parameter, structs, variant)
        for variant in STREAM_VARIANTS
    )
    valid = [decision for decision in decisions if decision.status == "ok"]
    positives = sum(decision.data.get("is_byte_stream") is True for decision in valid)
    kinds = [decision.data.get("kind", "other") for decision in valid
             if isinstance(decision.data.get("kind", "other"), str)]
    kind = Counter(kinds).most_common(1)[0][0] if kinds else "other"
    confidences = [decision.confidence for decision in valid
                   if isinstance(decision.confidence, (int, float))
                   and not isinstance(decision.confidence, bool)]
    confidence = sum(confidences) / len(confidences) if confidences else 0.0
    reasons = [decision.data.get("reason") for decision in valid
               if isinstance(decision.data.get("reason"), str)]
    reason = "; ".join(dict.fromkeys(filter(None, reasons)))
    return StreamVoteResult(
        positives >= 2,
        kind,
        confidence,
        reason or "semantic analysis unavailable",
        positives,
        len(valid),
        decisions,
    )


def _safe_stream_call(analyzer: SemanticAnalyzer, function: FunctionInfo,
                      parameter: ParameterInfo, structs: tuple[StructInfo, ...],
                      variant: str) -> SemanticDecision:
    try:
        decision = analyzer.classify_stream_parameter(function, parameter, structs, variant)
        if not isinstance(decision, SemanticDecision):
            raise TypeError("semantic analyzer returned an invalid decision")
        return decision
    except Exception as exc:
        fallback = {"is_byte_stream": False, "kind": "other", "confidence": 0.0,
                    "reason": "semantic analyzer failed"}
        return SemanticDecision(
            fallback,
            stream_prompt(function, parameter, structs, variant),
            STREAM_PROMPT_VERSION,
            {},
            0.0,
            "error",
            type(exc).__name__,
        )
