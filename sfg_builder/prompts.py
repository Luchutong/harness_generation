"""Versioned prompt templates containing only function-local semantic context."""

from __future__ import annotations

import json
from typing import Any, Mapping

from .models import AccessHint, FunctionInfo, ParameterInfo, StructInfo


STREAM_PROMPT_VERSION = "sfg-stream-v1"
ROLE_PROMPT_VERSION = "sfg-role-v1"
DIRECTION_PROMPT_VERSION = "sfg-direction-v2"
USAGE_REVIEW_PROMPT_VERSION = "sfg-usage-review-v1"
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
        + f"\nAST access hints: {hint_json}"
        + f"\nSet parameter exactly to {parameter.name!r} and struct_type exactly "
          f"to the base type {parameter.base_type!r}, without pointer symbols."
          "\nReturn only this JSON object: "
        + '{"parameter":"...","struct_type":"...",'
          '"direction":"input|output|both|unknown","reason":"...","confidence":0.0}'
    )


def usage_review_prompt(
    patterns: tuple[Mapping[str, Any], ...],
    functions: tuple[FunctionInfo, ...],
) -> str:
    """Ask the model to review static candidates without granting invention authority."""
    function_names = {
        name
        for pattern in patterns
        for name in pattern.get("sequence", [])
        if isinstance(name, str)
    }
    context = [
        {
            "id": function.id,
            "name": function.name,
            "signature": function.signature,
            "documentation": function.documentation,
        }
        for function in functions if function.name in function_names
    ]
    payload = [
        {
            "pattern_id": pattern.get("id"),
            "lifecycle_kind": pattern.get("lifecycle_kind"),
            "resource_type": pattern.get("resource_type"),
            "producer_function": pattern.get("producer_function"),
            "producer_binding": pattern.get("producer_binding"),
            "producer_argument_index": pattern.get("producer_argument_index"),
            "consumers": pattern.get("consumers"),
            "consumer_argument_indices": pattern.get("consumer_argument_indices"),
            "cleanup_function": pattern.get("cleanup_function"),
            "cleanup_argument_index": pattern.get("cleanup_argument_index"),
            "sequence": pattern.get("sequence"),
            "conditions": pattern.get("conditions"),
            "path_kind": pattern.get("path_kind"),
            "support_total": pattern.get("support_total"),
            "support_by_source": pattern.get("support_by_source"),
        }
        for pattern in patterns
    ]
    return (
        "Review statically mined C API lifecycle patterns. Static same-variable dataflow "
        "and source locations are authoritative. Do not add or rename functions, change "
        "argument positions, or join different resources. Decide whether each candidate "
        "is a real lifecycle, which calls are required for one executable FT, and which "
        "patterns are semantically equivalent. required_sequence must be an ordered "
        "subsequence of sequence, preserve duplicate calls, start with the producer, end "
        "with cleanup, and retain every input-stream target call. Use the same merge_group "
        "only for interchangeable lifecycle modes; keep different producers, cleanup paths, "
        "reference-count behavior, and normal/error paths separate.\n"
        "Function metadata:\n" + json.dumps(context, ensure_ascii=False, sort_keys=True)
        + "\nPatterns:\n" + json.dumps(payload, ensure_ascii=False, sort_keys=True)
        + "\nReturn only one JSON object: "
        + '{"decisions":[{"pattern_id":"...","is_valid_lifecycle":true,'
          '"lifecycle_kind":"owned_resource|reference_count|not_lifecycle",'
          '"required_sequence":["..."],"optional_calls":["..."],'
          '"merge_group":"...","confidence":0.0,"reason":"..."}]}'
    )


def _context(function: FunctionInfo, structs: tuple[StructInfo, ...]) -> str:
    definitions = "\n".join(info.declaration for info in structs)
    return (
        f"Function signature: {function.signature}\n"
        f"Function body:\n{function.body}\n"
        f"Relevant type definitions:\n{definitions}"
    )
