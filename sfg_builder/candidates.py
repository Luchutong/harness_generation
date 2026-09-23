"""High-recall static discovery of ISF and struct-related candidates."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import tempfile

from .models import CandidateParameter, FunctionCandidate, FunctionInfo


_BYTE_BASE_TYPES = {"char", "signed char", "unsigned char", "uint8_t", "int8_t"}

# `void *` is deliberately absent from the set above.  A void pointer carries no
# element type, so it is indistinguishable from an opaque cookie -- the allocator
# callbacks `void * (*mem_alloc)(size_t, int, void * user_data)` and
# `void (*mem_free)(void *, void * user_data)` are the canonical examples, and
# admitting them costs two of the four FTs on a project with one real byte stream.
# It is admitted only with separate evidence that the callee treats it as a
# buffer: a scalar length argument paired with a plausible buffer parameter.
LENGTH_PARAMETER_NAMES = {
    "size", "len", "length", "n", "buffer_length", "buffer_size",
    "input_size", "input_len", "data_size", "data_len", "buf_size",
    "buf_len", "nbytes", "byte_count",
}
_BUFFER_NAME_TOKENS = frozenset({
    "data", "buffer", "buf", "bytes", "input", "memory", "payload", "stream", "src",
})
_OPAQUE_NAME_TOKENS = frozenset({
    "user", "userdata", "cookie", "context", "ctx", "opaque", "private",
})


def _identifier_tokens(name: str | None) -> frozenset[str]:
    words = re.findall(
        r"[A-Z]+(?=[A-Z][a-z]|\b)|[A-Z]?[a-z]+|[0-9]+",
        (name or "").replace("_", " "),
    )
    return frozenset(word.lower() for word in words)


def has_byte_buffer_length(function: FunctionInfo, index: int) -> bool:
    """Require a plausible scalar length and reject named opaque cookies."""
    parameter = function.parameters[index]
    tokens = _identifier_tokens(parameter.name)
    if tokens & _OPAQUE_NAME_TOKENS:
        return False
    for length_index, length in enumerate(function.parameters):
        if (length.is_pointer or length.is_struct_like
                or length.base_type in {"float", "double", "long double"}
                or (length.name or "").lower() not in LENGTH_PARAMETER_NAMES):
            continue
        if length_index == index + 1 or tokens & _BUFFER_NAME_TOKENS:
            return True
    return False


class ISFCandidateDetector:
    """Select byte-compatible pointer parameters without assigning an ISF label."""

    def candidate_parameters(self, function: FunctionInfo) -> tuple[CandidateParameter, ...]:
        selected = []
        for index, parameter in enumerate(function.parameters):
            if not parameter.is_pointer:
                continue
            if parameter.base_type in _BYTE_BASE_TYPES:
                selected.append(parameter)
            elif parameter.base_type == "void" and has_byte_buffer_length(function, index):
                selected.append(parameter)
        return tuple(
            CandidateParameter(parameter.name, parameter.type, parameter.base_type)
            for parameter in selected
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
