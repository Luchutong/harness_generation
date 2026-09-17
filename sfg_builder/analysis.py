"""Compatibility orchestration for role and struct direction annotations."""

from __future__ import annotations

from .base import SemanticAnalyzer
from .directions import StructDirectionAnalyzer
from .models import (FunctionAnnotation, FunctionCandidate, FunctionInfo,
                     StructInfo)
from .roles import FunctionRoleAnnotator


class FunctionAnnotator:
    """Compose the independently testable role and direction analysis stages."""

    def __init__(self, analyzer: SemanticAnalyzer):
        self.roles = FunctionRoleAnnotator(analyzer)
        self.directions = StructDirectionAnalyzer(analyzer)

    def annotate(self, functions: tuple[FunctionInfo, ...],
                 candidates: tuple[FunctionCandidate, ...],
                 structs: tuple[StructInfo, ...]) -> tuple[FunctionAnnotation, ...]:
        roles = self.roles.annotate(functions, candidates, structs)
        return self.directions.analyze(functions, roles, structs)
