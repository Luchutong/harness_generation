"""High-recall static discovery of ISF and struct-related candidates."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile

from .models import CandidateParameter, FunctionCandidate, FunctionInfo


_BYTE_BASE_TYPES = {"void", "char", "signed char", "unsigned char", "uint8_t", "int8_t"}


class ISFCandidateDetector:
    """Select byte-compatible pointer parameters without assigning an ISF label."""

    def candidate_parameters(self, function: FunctionInfo) -> tuple[CandidateParameter, ...]:
        return tuple(
            CandidateParameter(parameter.name, parameter.type, parameter.base_type)
            for parameter in function.parameters
            if parameter.is_pointer and parameter.base_type in _BYTE_BASE_TYPES
        )

    def detect(self, functions: tuple[FunctionInfo, ...]) -> tuple[FunctionCandidate, ...]:
        result = []
        for function in functions:
            streams = self.candidate_parameters(function)
            if streams:
                result.append(_function_candidate(function, streams=streams))
        return tuple(result)


class StructCandidateDetector:
    """Select functions related to a resolved struct parameter or return type."""

    def candidate_parameters(self, function: FunctionInfo) -> tuple[CandidateParameter, ...]:
        return tuple(
            CandidateParameter(parameter.name, parameter.type, parameter.base_type)
            for parameter in function.parameters
            if parameter.is_struct_like
        )

    def return_struct(self, function: FunctionInfo) -> str | None:
        return function.return_base_type if function.return_is_struct_like else None

    def detect(self, functions: tuple[FunctionInfo, ...]) -> tuple[FunctionCandidate, ...]:
        result = []
        for function in functions:
            struct_parameters = self.candidate_parameters(function)
            return_struct = self.return_struct(function)
            if struct_parameters or return_struct:
                result.append(_function_candidate(
                    function,
                    struct_parameters=struct_parameters,
                    return_struct=return_struct,
                ))
        return tuple(result)


class PRFHPFCandidateDetector(StructCandidateDetector):
    """Named API for the shared PRF/HPF struct-related candidate pool."""


class CandidateDetector:
    """Combine independent static ISF and struct-related candidate discovery."""

    def __init__(self) -> None:
        self.isf = ISFCandidateDetector()
        self.structs = PRFHPFCandidateDetector()

    def detect(self, functions: tuple[FunctionInfo, ...]) -> tuple[FunctionCandidate, ...]:
        result = []
        for function in functions:
            streams = self.isf.candidate_parameters(function)
            struct_parameters = self.structs.candidate_parameters(function)
            return_struct = self.structs.return_struct(function)
            if streams or struct_parameters or return_struct:
                result.append(_function_candidate(
                    function,
                    streams=streams,
                    struct_parameters=struct_parameters,
                    return_struct=return_struct,
                ))
        return tuple(result)


def _function_candidate(
    function: FunctionInfo,
    *,
    streams: tuple[CandidateParameter, ...] = (),
    struct_parameters: tuple[CandidateParameter, ...] = (),
    return_struct: str | None = None,
) -> FunctionCandidate:
    struct_related = bool(struct_parameters or return_struct)
    return FunctionCandidate(
        function.id,
        function.name,
        function.file,
        function.start_line,
        bool(streams),
        streams,
        struct_related,
        struct_related,
        struct_related,
        struct_parameters,
        return_struct,
    )


def write_candidates_json(candidates: tuple[FunctionCandidate, ...], path: Path) -> Path:
    """Persist static candidates without invoking any semantic analyzer."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "isf": [item.function for item in candidates if item.isf_candidate],
        "prf": [item.function for item in candidates if item.prf_candidate],
        "hpf": [item.function for item in candidates if item.hpf_candidate],
        "candidates": [item.to_dict() for item in candidates],
    }
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
