"""ISF/PRF/HPF role annotation without struct direction analysis."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

from .base import (SemanticAnalyzer, SemanticBudgetExceeded, SemanticDecision,
                   SemanticReplayMismatch)
from .models import (CandidateParameter, DecisionTrace, FunctionAnnotation,
                     FunctionCandidate, FunctionInfo, StreamParameterAnnotation,
                     StructInfo)
from .prompts import ROLE_PROMPT_VERSION, role_prompt
from .voting import vote_stream_parameter


LABEL_ORDER = ("ISF", "PRF", "HPF")


class FunctionRoleAnnotator:
    """Apply semantic decisions only to the corresponding static candidates."""

    def __init__(self, analyzer: SemanticAnalyzer):
        self.analyzer = analyzer

    def annotate(self, functions: tuple[FunctionInfo, ...],
                 candidates: tuple[FunctionCandidate, ...],
                 structs: tuple[StructInfo, ...]) -> tuple[FunctionAnnotation, ...]:
        by_id = {function.id: function for function in functions}
        annotations = []
        for candidate in candidates:
            function = by_id[candidate.function_id]
            relevant_structs = _relevant_structs(function, structs)
            streams = []
            traces = []

            if candidate.isf_candidate:
                for stream_candidate in candidate.stream_parameters:
                    parameter = _find_parameter(function, stream_candidate)
                    vote = vote_stream_parameter(
                        self.analyzer, function, parameter, relevant_structs,
                    )
                    traces.extend(
                        _trace(function, "stream_parameter", decision)
                        for decision in vote.decisions
                    )
                    streams.append(StreamParameterAnnotation(
                        parameter.name,
                        parameter.type,
                        vote.is_byte_stream,
                        vote.kind,
                        vote.confidence,
                        vote.reason,
                        vote.positive_votes,
                        vote.valid_votes,
                    ))

            role = None
            if candidate.struct_related_candidate:
                role = _safe_role_call(self.analyzer, function, relevant_structs)
                traces.append(_trace(function, "function_role", role))

            labels = []
            if any(stream.is_byte_stream for stream in streams):
                labels.append("ISF")
            if role is not None and role.data.get("is_prf") is True:
                labels.append("PRF")
            if role is not None and role.data.get("is_hpf") is True:
                labels.append("HPF")

            operation = str(role.data.get("operation", "other")) if role else "other"
            reason = (str(role.data.get("reason", "semantic analysis unavailable"))
                      if role else "not a struct-related candidate")
            annotations.append(FunctionAnnotation(
                function.id,
                function.name,
                function.file,
                function.start_line,
                tuple(label for label in LABEL_ORDER if label in labels),
                operation,
                tuple(streams),
                (),
                reason,
                tuple(traces),
            ))
        return tuple(annotations)


def _find_parameter(function: FunctionInfo, candidate: CandidateParameter):
    return next(
        parameter for parameter in function.parameters
        if (parameter.name, parameter.type, parameter.base_type)
        == (candidate.name, candidate.type, candidate.base_type)
    )


def _safe_role_call(analyzer: SemanticAnalyzer, function: FunctionInfo,
                    structs: tuple[StructInfo, ...]) -> SemanticDecision:
    try:
        decision = analyzer.classify_function_role(function, structs)
        if not isinstance(decision, SemanticDecision):
            raise TypeError("semantic analyzer returned an invalid decision")
        return decision
    except (SemanticBudgetExceeded, SemanticReplayMismatch):
        raise
    except Exception as exc:
        fallback = {"is_prf": False, "is_hpf": False, "operation": "other",
                    "reason": "semantic analyzer failed", "confidence": 0.0}
        return SemanticDecision(
            fallback,
            role_prompt(function, structs),
            ROLE_PROMPT_VERSION,
            {},
            0.0,
            "error",
            type(exc).__name__,
        )


def _trace(function: FunctionInfo, task: str, decision: SemanticDecision) -> DecisionTrace:
    return DecisionTrace(
        function.name,
        function.id,
        function.file,
        function.start_line,
        task,
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


def write_annotations_json(annotations: tuple[FunctionAnnotation, ...], path: Path,
                           *, semantic_backend: str | None = None,
                           semantic_source: str | None = None) -> Path:
    """Persist role annotations and their auditable semantic decisions."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = []
    for annotation in annotations:
        value = annotation.to_dict()
        value["is_prf"] = "PRF" in annotation.labels
        value["is_hpf"] = "HPF" in annotation.labels
        serialized.append(value)
    payload = {
        "schema_version": 1,
        "annotations": serialized,
    }
    if semantic_backend is not None:
        payload["semantic_backend"] = semantic_backend
    if semantic_source is not None:
        payload["semantic_source"] = semantic_source
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return path
