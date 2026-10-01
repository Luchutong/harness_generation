"""Bounded request observations, with credential redaction before persistence."""
import hashlib
import json
import re
from copy import deepcopy

VERSION = "provider-request-diagnostics-v2"
ERROR_CATEGORIES = ("transport_error", "timeout", "http_400", "http_401", "http_403",
    "http_429", "http_5xx", "invalid_response", "tool_call_parse_error",
    "terminal_schema_error", "terminal_repair_error", "unknown_provider_error")


def normalize_tool_history(messages):
    """Make rejected historical arguments wire-valid without changing evidence.

    The loop has already rejected these calls. A provider may reject even a
    repair request when an earlier assistant tool call contains malformed JSON.
    Only the outbound copy is normalized; no tool is executed and no proposal
    is accepted here. Original model responses remain in the saved trace.
    """
    outbound = deepcopy(list(messages))
    changes = []
    def invalid_constant(value):
        raise ValueError(value)
    for index, message in enumerate(outbound):
        if not isinstance(message, dict) or message.get("role") != "assistant":
            continue
        for call in message.get("tool_calls") or []:
            if not isinstance(call, dict) or not isinstance(call.get("function"), dict):
                continue
            function = call["function"]
            arguments = function.get("arguments")
            if not isinstance(arguments, str):
                continue  # The loop rejects invalid call field types separately.
            try:
                json.loads(arguments, parse_constant=invalid_constant)
            except (TypeError, ValueError):
                changes.append({"message_index": index, "tool_call_id": call.get("id"),
                    "tool_name": function.get("name"), "original_arguments_chars": len(arguments),
                    "original_arguments_digest": hashlib.sha256(arguments.encode()).hexdigest(),
                    "reason": "malformed_historical_tool_arguments", "replacement": "{}"})
                function["arguments"] = "{}"
    return outbound, changes


def redact(value, secrets=(), depth=0):
    if depth > 8:
        return "[truncated]"
    if isinstance(value, dict):
        result = {}
        for key, item in list(value.items())[:64]:
            sensitive = (str(key).lower() in {'env','environ'} or
                re.search(r"authorization|api.?key|token|password|secret|cookie|environment|headers|credential", str(key), re.I))
            result[redact(str(key), secrets, depth + 1)[:128]] = "[redacted]" if sensitive else redact(item, secrets, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        return [redact(item, secrets, depth + 1) for item in value[:64]]
    if isinstance(value, str):
        # Replace before truncation so a credential crossing the limit cannot
        # leave a visible prefix. Neither request bodies nor headers are saved.
        for secret in secrets:
            if isinstance(secret, str) and secret:
                value = value.replace(secret, "[redacted]")
        value = re.sub(r"(?i)\bBearer\s+[^\s\"',;]+", "Bearer [redacted]", value)
        value = re.sub(r"(?i)(api[_-]?key|authorization|token|password|secret)(\s*[=:]\s*)[^\s\"',;&]+", r"\1\2[redacted]", value)
        return value[:4096]
    return value if value is None or type(value) in {int, float, bool} else "[unsupported]"


def request_observation(model, messages, tools):
    payload = {"model": model, "messages": list(messages), "tools": list(tools)}
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return {"diagnostics_version": VERSION, "model": model, "message_count": len(messages),
        "tool_count": len(tools), "schema_size": len(json.dumps(tools, ensure_ascii=False)),
        "prompt_chars": len(json.dumps(messages, ensure_ascii=False)),
        "request_payload_digest": hashlib.sha256(encoded.encode()).hexdigest()}


def classify_error(error):
    category = getattr(error, "error_category", None)
    if category in ERROR_CATEGORIES or category == "budget_exhausted":
        return category
    status = getattr(error, "http_status", getattr(error, "status_code", None))
    if status in {400, 401, 403, 429}:
        return f"http_{status}"
    if type(status) is int and status >= 500:
        return "http_5xx"
    name = type(error).__name__.lower()
    if isinstance(error, TimeoutError) or "timeout" in name:
        return "timeout"
    if isinstance(error, ConnectionError) or "connection" in name or "transport" in name:
        return "transport_error"
    return "unknown_provider_error"


def provider_error_observation(error, request, secrets=()):
    status = getattr(error, "status_code", None)
    response = getattr(error, "response", None)
    body = getattr(error, "body", None)
    if body is None and response is not None:
        try:
            body = response.json()
        except Exception:
            body = getattr(response, "text", None)
    if isinstance(body, str) and len(body) <= 65536:
        try:
            body = json.loads(body)
        except (TypeError, ValueError):
            pass
    safe = redact(body, secrets)
    inner = safe.get("error", safe) if isinstance(safe, dict) else {}
    inner = inner if isinstance(inner, dict) else {}
    request_id = getattr(error, "request_id", None)
    if request_id is None and response is not None:
        headers = getattr(response, "headers", {})
        request_id = headers.get("x-request-id") or headers.get("x-tt-logid")
    return {**request, "error_category": classify_error(error),
        "response_status": status if type(status) is int else None,
        "request_id": redact(request_id, secrets), "provider_error_code": inner.get("code"),
        "provider_error_message": inner.get("message"), "error_body": safe}
