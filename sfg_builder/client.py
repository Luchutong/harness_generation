"""Strict-JSON LLM semantic analyzer and injectable HTTPS transport."""

from __future__ import annotations

import http.client
import json
from typing import Any, Callable
from urllib.parse import urlparse

from .base import SemanticDecision, SemanticError
from .models import AccessHint, FunctionInfo, ParameterInfo, StructInfo
from .prompts import (DIRECTION_PROMPT_VERSION, ROLE_PROMPT_VERSION,
                      STREAM_PROMPT_VERSION, direction_prompt, role_prompt,
                      stream_prompt)


STREAM_KINDS = {"binary", "text", "filename", "pathname", "struct", "other"}
OPERATIONS = {"process", "read", "transform", "init", "allocate", "cleanup", "free", "other"}
DIRECTIONS = {"input", "output", "both", "unknown"}


class LLMSemanticAnalyzer:
    """Semantic provider whose transport is injected and whose schemas are validated."""

    def __init__(self, transport: Callable[[dict[str, Any]], dict[str, Any]], model: str):
        self.transport = transport
        self.model = model

    def classify_stream_parameter(self, function: FunctionInfo, parameter: ParameterInfo,
                                  structs: tuple[StructInfo, ...], variant: str) -> SemanticDecision:
        prompt = stream_prompt(function, parameter, structs, variant)
        data, _response = self._request(prompt)
        if (type(data.get("is_byte_stream")) is not bool
                or data.get("kind") not in STREAM_KINDS
                or not isinstance(data.get("reason"), str)
                or "confidence" not in data):
            raise SemanticError("stream response does not match the required schema")
        confidence = _confidence(data["confidence"])
        return SemanticDecision(data, prompt, STREAM_PROMPT_VERSION, data, confidence)

    def classify_function_role(self, function: FunctionInfo,
                               structs: tuple[StructInfo, ...]) -> SemanticDecision:
        prompt = role_prompt(function, structs)
        data, _response = self._request(prompt)
        if (type(data.get("is_prf")) is not bool
                or type(data.get("is_hpf")) is not bool
                or data.get("operation") not in OPERATIONS
                or not isinstance(data.get("reason"), str)
                or "confidence" not in data):
            raise SemanticError("role response does not match the required schema")
        confidence = _confidence(data["confidence"])
        return SemanticDecision(data, prompt, ROLE_PROMPT_VERSION, data, confidence)

    def infer_struct_direction(self, function: FunctionInfo, parameter: ParameterInfo,
                               hint: AccessHint | None,
                               structs: tuple[StructInfo, ...]) -> SemanticDecision:
        prompt = direction_prompt(function, parameter, hint, structs)
        data, _response = self._request(prompt)
        if (data.get("parameter") != parameter.name
                or data.get("struct_type") != parameter.base_type
                or data.get("direction") not in DIRECTIONS
                or not isinstance(data.get("reason"), str)
                or "confidence" not in data):
            raise SemanticError("direction response does not match the required schema")
        confidence = _confidence(data["confidence"])
        return SemanticDecision(data, prompt, DIRECTION_PROMPT_VERSION, data, confidence)

    def _request(self, prompt: str) -> tuple[dict[str, Any], dict[str, Any]]:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "Analyze C metadata. Return only a JSON object."},
                {"role": "user", "content": prompt},
            ],
            "stream": False,
            "temperature": 0,
            "max_tokens": 1024,
        }
        try:
            response = self.transport(payload)
        except SemanticError:
            raise
        except Exception as exc:
            raise SemanticError(f"LLM transport failed ({type(exc).__name__})") from None
        try:
            choice = response["choices"][0]
            if choice["finish_reason"] != "stop":
                raise KeyError
            content = choice["message"]["content"]
            if not isinstance(content, str):
                raise TypeError
            data = json.loads(content.strip())
        except (KeyError, IndexError, TypeError, ValueError, AttributeError, json.JSONDecodeError):
            raise SemanticError("LLM returned malformed completion JSON") from None
        if not isinstance(data, dict):
            raise SemanticError("LLM completion JSON must be an object")
        return data, response


class OpenAICompatibleTransport:
    def __init__(self, api_key: str, endpoint: str = "https://api.deepseek.com/chat/completions",
                 timeout: int = 120):
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("LLM endpoint must be an https URL")
        self.api_key = api_key
        self.host = parsed.hostname
        self.path = parsed.path or "/chat/completions"
        self.timeout = timeout

    def __call__(self, payload: dict[str, Any]) -> dict[str, Any]:
        connection = http.client.HTTPSConnection(self.host, timeout=self.timeout)
        try:
            connection.request("POST", self.path, json.dumps(payload).encode("utf-8"), {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            })
            response = connection.getresponse()
            raw = response.read().decode("utf-8", errors="replace")
            if response.status != 200:
                raise SemanticError(f"LLM HTTP {response.status}")
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError
            return value
        except SemanticError:
            raise
        except (OSError, http.client.HTTPException, ValueError, json.JSONDecodeError) as exc:
            raise SemanticError(f"LLM transport failed ({type(exc).__name__})") from None
        finally:
            connection.close()


def _confidence(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
        raise SemanticError("confidence must be a number in [0, 1]")
    return float(value)
