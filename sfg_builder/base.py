"""Core contracts for pluggable semantic analyzers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .models import AccessHint, FunctionInfo, ParameterInfo, StructInfo


class SemanticError(Exception):
    """Raised when a semantic provider violates its transport or JSON contract."""


@dataclass(frozen=True)
class SemanticDecision:
    data: dict[str, Any]
    prompt: str
    prompt_version: str
    response: dict[str, Any]
    confidence: float
    status: str = "ok"
    error: str | None = None


class SemanticAnalyzer(Protocol):
    def classify_stream_parameter(self, function: FunctionInfo, parameter: ParameterInfo,
                                  structs: tuple[StructInfo, ...], variant: str) -> SemanticDecision:
        ...

    def classify_function_role(self, function: FunctionInfo,
                               structs: tuple[StructInfo, ...]) -> SemanticDecision:
        ...

    def infer_struct_direction(self, function: FunctionInfo, parameter: ParameterInfo,
                               hint: AccessHint | None,
                               structs: tuple[StructInfo, ...]) -> SemanticDecision:
        ...
