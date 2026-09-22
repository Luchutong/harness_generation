"""Deterministic semantic analyzer for tests and offline execution."""

from __future__ import annotations

from .base import SemanticDecision
from .models import AccessHint, FunctionInfo, ParameterInfo, StructInfo
from .prompts import (DIRECTION_PROMPT_VERSION, ROLE_PROMPT_VERSION,
                      STREAM_PROMPT_VERSION, direction_prompt, role_prompt,
                      stream_prompt)


class MockSemanticAnalyzer:
    """Return reproducible decisions without network or credentials."""

    def classify_stream_parameter(self, function: FunctionInfo, parameter: ParameterInfo,
                                  structs: tuple[StructInfo, ...], variant: str) -> SemanticDecision:
        prompt = stream_prompt(function, parameter, structs, variant)
        name = (parameter.name or "").lower()
        if "filename" in name or name in {"file", "path", "pathname"}:
            kind = "filename" if "file" in name else "pathname"
            accepted, reason = False, "path-like name"
        elif any(token in name for token in ("error", "message", "errmsg")):
            kind, accepted, reason = "other", False, "diagnostic output name"
        elif parameter.is_struct_like:
            kind, accepted, reason = "struct", False, "resolved struct-like type"
        else:
            kind = "text" if parameter.base_type == "char" else "binary"
            accepted = any(token in name for token in
                           ("data", "buffer", "buf", "bytes", "input", "memory",
                            "payload", "stream", "src"))
            if not accepted:
                accepted = parameter.base_type in {"uint8_t", "int8_t", "unsigned char"}
            if not accepted and _looks_like_parser_input(function, parameter):
                accepted = True
            reason = ("byte-compatible pointer and stream-like declaration"
                      if accepted else "ambiguous pointer")
        data = {"is_byte_stream": accepted, "kind": kind, "confidence": 0.95,
                "reason": reason}
        return SemanticDecision(data, prompt, STREAM_PROMPT_VERSION, data, data["confidence"])

    def classify_function_role(self, function: FunctionInfo,
                               structs: tuple[StructInfo, ...]) -> SemanticDecision:
        prompt = role_prompt(function, structs)
        name = function.name.lower()
        lifecycle = next((token for token in (
            "create", "alloc", "init", "initialize", "reset", "cleanup", "release",
            "destroy", "free", "from_memory",
        ) if token in name), None)
        if lifecycle in {"create", "alloc"}:
            operation = "allocate"
        elif lifecycle in {"cleanup", "release", "destroy", "free"}:
            operation = "free" if lifecycle == "free" else "cleanup"
        elif lifecycle:
            operation = "init"
        elif "read" in name or function.return_is_struct_like:
            operation = "read"
        elif any(token in name for token in ("convert", "transform")):
            operation = "transform"
        else:
            operation = "process"
        struct_related = (function.return_is_struct_like
                          or any(parameter.is_struct_like for parameter in function.parameters))
        data = {
            "is_prf": struct_related and lifecycle is None,
            "is_hpf": struct_related and lifecycle is not None,
            "operation": operation,
            "reason": "deterministic mock classification from function metadata",
            "confidence": 0.9,
        }
        return SemanticDecision(data, prompt, ROLE_PROMPT_VERSION, data, data["confidence"])

    def infer_struct_direction(self, function: FunctionInfo, parameter: ParameterInfo,
                               hint: AccessHint | None,
                               structs: tuple[StructInfo, ...]) -> SemanticDecision:
        prompt = direction_prompt(function, parameter, hint, structs)
        if hint and hint.reads and hint.writes:
            direction, reason = "both", "AST reports field reads and writes"
        elif hint and hint.writes:
            direction, reason = "output", "AST reports field writes"
        elif hint and hint.reads:
            direction, reason = "input", "AST reports field reads"
        elif any(token in function.name.lower()
                 for token in ("free", "destroy", "release", "cleanup")):
            direction, reason = "input", "lifecycle cleanup consumes an existing object"
        else:
            direction, reason = "unknown", "no decisive access evidence"
        confidence = 0.9 if direction != "unknown" else 0.2
        data = {"parameter": parameter.name, "struct_type": parameter.base_type,
                "direction": direction, "reason": reason, "confidence": confidence}
        return SemanticDecision(data, prompt, DIRECTION_PROMPT_VERSION, data, confidence)


def _looks_like_parser_input(function: FunctionInfo, parameter: ParameterInfo) -> bool:
    if parameter.pointer_depth != 1 or parameter.base_type not in {"char", "unsigned char"}:
        return False
    function_name = function.name.lower()
    if not any(token in function_name for token in (
        "parse", "decode", "deserialize", "load", "read", "scan"
    )):
        return False
    parameter_name = (parameter.name or "").lower()
    if any(token in parameter_name for token in ("end", "out", "result", "error")):
        return False
    has_length_parameter = any(
        not item.is_pointer and item.name and item.name.lower() in {
            "size", "len", "length", "n", "buffer_length", "input_size",
        }
        for item in function.parameters
    )
    return parameter.is_const or has_length_parameter or function.return_is_struct_like
