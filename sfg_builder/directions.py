"""Struct parameter direction and return-struct output candidate analysis."""

from __future__ import annotations

from dataclasses import replace

from .base import SemanticAnalyzer, SemanticDecision
from .models import (AccessHint, DecisionTrace, FunctionAnnotation, FunctionInfo,
                     ParameterInfo, StructDirection, StructInfo)
from .prompts import DIRECTION_PROMPT_VERSION, direction_prompt


DIRECTIONS = {"input", "output", "both", "unknown"}
STATIC_PROMPT_VERSION = "sfg-direction-static-v1"


class StructDirectionAnalyzer:
    """Augment role annotations without constructing FunctionFlow or graph edges."""

    def __init__(self, analyzer: SemanticAnalyzer):
        self.analyzer = analyzer

    def analyze(self, functions: tuple[FunctionInfo, ...],
                annotations: tuple[FunctionAnnotation, ...],
                structs: tuple[StructInfo, ...]) -> tuple[FunctionAnnotation, ...]:
        by_id = {function.id: function for function in functions}
        results = []
        for annotation in annotations:
            function = by_id[annotation.function_id]
            relevant_structs = _relevant_structs(function, structs)
            hints = {hint.parameter: hint for hint in function.access_hints}
            directions = []
            traces = []
            for parameter in function.parameters:
                if not parameter.is_struct_like:
                    continue
                hint = hints.get(parameter.name or "")
                if parameter.is_pointer:
                    decision = _safe_pointer_direction(
                        self.analyzer, function, parameter, hint, relevant_structs,
                    )
                else:
                    decision = _by_value_direction(function, parameter, hint, relevant_structs)
                directions.append(StructDirection(
                    parameter.name or "",
                    parameter.base_type,
                    str(decision.data["direction"]),
                    str(decision.data["reason"]),
                    decision.confidence,
                    hint,
                ))
                traces.append(_trace(function, decision))

            outputs = ((function.return_base_type,)
                       if function.return_is_struct_like else ())
            results.append(replace(
                annotation,
                struct_directions=tuple(directions),
                decisions=annotation.decisions + tuple(traces),
                output_struct_candidates=outputs,
            ))
        return tuple(results)


def _safe_pointer_direction(analyzer: SemanticAnalyzer, function: FunctionInfo,
                            parameter: ParameterInfo, hint: AccessHint | None,
                            structs: tuple[StructInfo, ...]) -> SemanticDecision:
    try:
        decision = analyzer.infer_struct_direction(function, parameter, hint, structs)
        _validate_direction(decision, parameter)
        return decision
    except Exception as exc:
        direction, reason, confidence = _static_fallback(parameter, hint)
        data = {"parameter": parameter.name, "struct_type": parameter.base_type,
                "direction": direction, "reason": reason, "confidence": confidence}
        return SemanticDecision(
            data,
            direction_prompt(function, parameter, hint, structs),
            DIRECTION_PROMPT_VERSION,
            {},
            confidence,
            "error",
            type(exc).__name__,
        )


def _by_value_direction(function: FunctionInfo, parameter: ParameterInfo,
                        hint: AccessHint | None,
                        structs: tuple[StructInfo, ...]) -> SemanticDecision:
    data = {
        "parameter": parameter.name,
        "struct_type": parameter.base_type,
        "direction": "input",
        "reason": "C passes a non-pointer struct parameter by value",
        "confidence": 1.0,
    }
    return SemanticDecision(
        data,
        direction_prompt(function, parameter, hint, structs),
        STATIC_PROMPT_VERSION,
        data,
        1.0,
    )


def _validate_direction(decision: SemanticDecision, parameter: ParameterInfo) -> None:
    if not isinstance(decision, SemanticDecision):
        raise TypeError("semantic analyzer returned an invalid decision")
    data = decision.data
    if (data.get("parameter") != parameter.name
            or data.get("struct_type") != parameter.base_type
            or data.get("direction") not in DIRECTIONS
            or not isinstance(data.get("reason"), str)
            or isinstance(decision.confidence, bool)
            or not isinstance(decision.confidence, (int, float))
            or not 0 <= decision.confidence <= 1):
        raise ValueError("direction decision does not match the required schema")


def _static_fallback(parameter: ParameterInfo,
                     hint: AccessHint | None) -> tuple[str, str, float]:
    if hint and hint.reads and hint.writes:
        return "both", "semantic analysis failed; AST reports member reads and writes", 0.8
    if hint and hint.writes:
        return "output", "semantic analysis failed; AST reports member writes", 0.8
    if hint and hint.reads:
        return "input", "semantic analysis failed; AST reports member reads", 0.8
    if parameter.is_const:
        return "input", "semantic analysis failed; const-qualified struct pointer", 0.8
    return "unknown", "semantic analysis failed; no decisive static evidence", 0.0


def _trace(function: FunctionInfo, decision: SemanticDecision) -> DecisionTrace:
    return DecisionTrace(
        function.name,
        function.id,
        function.file,
        function.start_line,
        "struct_direction",
        decision.prompt_version,
        decision.prompt,
        decision.response,
        decision.confidence,
        decision.status,
        decision.error,
    )


def _relevant_structs(function: FunctionInfo,
                      structs: tuple[StructInfo, ...]) -> tuple[StructInfo, ...]:
    names = {parameter.base_type for parameter in function.parameters
             if parameter.is_struct_like}
    if function.return_is_struct_like:
        names.add(function.return_base_type)
    return tuple(info for info in structs
                 if info.name in names or names.intersection(info.aliases))
