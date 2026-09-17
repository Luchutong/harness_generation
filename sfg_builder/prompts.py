"""Versioned prompt templates containing only function-local semantic context."""

from __future__ import annotations

import json

from .models import AccessHint, FunctionInfo, ParameterInfo, StructInfo


STREAM_PROMPT_VERSION = "sfg-stream-v1"
ROLE_PROMPT_VERSION = "sfg-role-v1"
DIRECTION_PROMPT_VERSION = "sfg-direction-v1"
STREAM_VARIANTS = ("direct", "yes_no", "multiple_choice")


def stream_prompt(function: FunctionInfo, parameter: ParameterInfo,
                  structs: tuple[StructInfo, ...], variant: str) -> str:
    questions = {
        "direct": "Directly determine whether the target is a contiguous byte/text stream.",
        "yes_no": "Answer yes or no internally: does the target point to contiguous byte/text data?",
        "multiple_choice": (
            "First choose exactly one kind: binary, text, filename, pathname, struct, or other; "
            "then decide whether that kind is a byte stream."
        ),
    }
    if variant not in questions:
        raise ValueError(f"unknown stream prompt variant: {variant}")
    return (
        _context(function, structs)
        + f"\nTarget parameter: {parameter.name}: {parameter.type}\n"
        + questions[variant]
        + "\nReturn only this JSON object: "
        + '{"is_byte_stream":bool,"kind":"binary|text|filename|pathname|struct|other",'
          '"confidence":0.0,"reason":"..."}'
    )


def role_prompt(function: FunctionInfo, structs: tuple[StructInfo, ...]) -> str:
    return (
        _context(function, structs)
        + "\nClassify PRF and HPF independently; both may be true. Return only this JSON object: "
        + '{"is_prf":bool,"is_hpf":bool,'
          '"operation":"process|read|transform|init|allocate|cleanup|free|other",'
          '"reason":"...","confidence":0.0}'
    )


def direction_prompt(function: FunctionInfo, parameter: ParameterInfo, hint: AccessHint | None,
                     structs: tuple[StructInfo, ...]) -> str:
    hint_json = json.dumps(hint.to_dict() if hint else {}, ensure_ascii=False)
    return (
        _context(function, structs)
        + f"\nTarget struct pointer: {parameter.name}: {parameter.type}"
        + f"\nAST access hints: {hint_json}\nReturn only this JSON object: "
        + '{"parameter":"...","struct_type":"...",'
          '"direction":"input|output|both|unknown","reason":"...","confidence":0.0}'
    )


def _context(function: FunctionInfo, structs: tuple[StructInfo, ...]) -> str:
    definitions = "\n".join(info.declaration for info in structs)
    return (
        f"Function signature: {function.signature}\n"
        f"Function body:\n{function.body}\n"
        f"Relevant type definitions:\n{definitions}"
    )
