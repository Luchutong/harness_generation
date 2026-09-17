"""Provider-neutral LLM generation interface and implementations."""

from __future__ import annotations

import http.client
import json
import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence, runtime_checkable
from urllib.parse import urlparse

from .prompts import RenderedPrompt
from .records import write_json


class LLMError(RuntimeError):
    """A provider, transport, or recorded-response failure."""


@dataclass(frozen=True)
class LLMConfig:
    """Non-secret LLM configuration.

    ``api_key_env_name`` identifies an environment variable.  The secret value
    itself is intentionally not part of this object or its serialization.
    """

    model: str
    base_url: str
    api_key_env_name: str = "OPENAI_API_KEY"
    temperature: float = 0.2
    max_tokens: int = 4096
    timeout: float = 120.0
    thinking: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.model, str) or not self.model.strip():
            raise ValueError("model must not be empty")
        if not isinstance(self.base_url, str):
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        parsed = urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("base_url must be an absolute HTTP(S) URL")
        if (not isinstance(self.api_key_env_name, str)
                or not self.api_key_env_name.strip()):
            raise ValueError("api_key_env_name must not be empty")
        if (isinstance(self.temperature, bool)
                or not isinstance(self.temperature, (int, float))
                or not math.isfinite(self.temperature)
                or not 0.0 <= self.temperature <= 2.0):
            raise ValueError("temperature must be between 0 and 2")
        if (isinstance(self.max_tokens, bool)
                or not isinstance(self.max_tokens, int)
                or self.max_tokens <= 0):
            raise ValueError("max_tokens must be positive")
        if (isinstance(self.timeout, bool)
                or not isinstance(self.timeout, (int, float))
                or not math.isfinite(self.timeout)
                or self.timeout <= 0):
            raise ValueError("timeout must be positive")
        if self.thinking not in {None, "enabled", "disabled"}:
            raise ValueError("thinking must be enabled, disabled, or null")

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "base_url": self.base_url,
            "api_key_env_name": self.api_key_env_name,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
            "thinking": self.thinking,
        }


@dataclass(frozen=True)
class LLMGeneration:
    """Normalized text generation plus reproducibility metadata."""

    content: str
    model: str
    prompt_version: str
    provider: str
    response_id: str | None = None
    finish_reason: str | None = None
    usage: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.prompt_version.strip():
            raise ValueError("prompt_version must not be empty")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "content": self.content,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "provider": self.provider,
            "usage": dict(self.usage),
            "metadata": dict(self.metadata),
        }
        if self.response_id is not None:
            result["response_id"] = self.response_id
        if self.finish_reason is not None:
            result["finish_reason"] = self.finish_reason
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "LLMGeneration":
        required = ("content", "model", "prompt_version", "provider")
        missing = [key for key in required if not isinstance(value.get(key), str)]
        if missing:
            raise ValueError(f"invalid recorded response fields: {', '.join(missing)}")
        usage = value.get("usage", {})
        metadata = value.get("metadata", {})
        if not isinstance(usage, Mapping) or not isinstance(metadata, Mapping):
            raise ValueError("recorded usage and metadata must be objects")
        return cls(
            content=value["content"],
            model=value["model"],
            prompt_version=value["prompt_version"],
            provider=value["provider"],
            response_id=_optional_string(value, "response_id"),
            finish_reason=_optional_string(value, "finish_reason"),
            usage=dict(usage),
            metadata=dict(metadata),
        )


@runtime_checkable
class LLMClient(Protocol):
    """The only generation dependency needed by future Stage implementations."""

    def generate(self, prompt: RenderedPrompt | str, *,
                 prompt_version: str | None = None) -> LLMGeneration:
        ...


class MockLLM:
    """Deterministic in-memory client for unit tests and offline development."""

    def __init__(self, responses: Sequence[str | LLMGeneration], *,
                 model: str = "mock-model") -> None:
        self._responses = list(responses)
        self._position = 0
        self.model = model
        self.provider = "mock"
        self.calls: list[dict[str, str]] = []

    def generate(self, prompt: RenderedPrompt | str, *,
                 prompt_version: str | None = None) -> LLMGeneration:
        content, version, name = _prompt_parts(prompt, prompt_version)
        self.calls.append({
            "prompt": content,
            "prompt_version": version,
            "prompt_name": name,
        })
        if self._position >= len(self._responses):
            raise LLMError("mock response sequence exhausted")
        response = self._responses[self._position]
        if isinstance(response, LLMGeneration):
            if response.prompt_version != version:
                raise LLMError("mock response prompt version mismatch")
            self._position += 1
            return response
        self._position += 1
        return LLMGeneration(
            content=response,
            model=self.model,
            prompt_version=version,
            provider="mock",
            metadata={"prompt_name": name},
        )


class FakeLLM(MockLLM):
    """Semantic alias for tests that prefer a fake over mock vocabulary."""


class RecordedResponseLLM:
    """Replay previously serialized generations without network access."""

    def __init__(self, responses: Sequence[LLMGeneration]) -> None:
        self._responses = list(responses)
        self._position = 0
        self.calls: list[dict[str, str]] = []
        self.provider = "recorded-response"
        self.model = responses[0].model if responses else "recorded-model"

    @classmethod
    def from_file(cls, path: str | Path) -> "RecordedResponseLLM":
        try:
            document = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise LLMError(f"could not load recorded responses: {type(error).__name__}") from error
        if not isinstance(document, Mapping) or document.get("schema_version") != 1:
            raise LLMError("recorded responses require schema_version 1")
        responses = document.get("responses")
        if not isinstance(responses, list):
            raise LLMError("recorded responses must be a list")
        try:
            parsed = [LLMGeneration.from_dict(item) for item in responses
                      if isinstance(item, Mapping)]
        except ValueError as error:
            raise LLMError(str(error)) from error
        if len(parsed) != len(responses):
            raise LLMError("each recorded response must be an object")
        return cls(parsed)

    def generate(self, prompt: RenderedPrompt | str, *,
                 prompt_version: str | None = None) -> LLMGeneration:
        content, version, name = _prompt_parts(prompt, prompt_version)
        self.calls.append({
            "prompt": content,
            "prompt_version": version,
            "prompt_name": name,
        })
        if self._position >= len(self._responses):
            raise LLMError("recorded response sequence exhausted")
        response = self._responses[self._position]
        if response.prompt_version != version:
            raise LLMError("recorded response prompt version mismatch")
        self._position += 1
        return response


def write_recorded_responses(path: str | Path,
                             responses: Sequence[LLMGeneration]) -> None:
    """Persist replayable responses in a stable, secret-free JSON document."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    write_json(
        destination,
        {
            "schema_version": 1,
            "responses": [response.to_dict() for response in responses],
        },
        sort_keys=True,
        allow_nan=False,
    )


Transport = Callable[[str, Mapping[str, Any], Mapping[str, str], float], Mapping[str, Any]]


class OpenAICompatibleLLM:
    """Minimal Chat Completions client for OpenAI-compatible HTTP endpoints."""

    def __init__(self, config: LLMConfig, *, transport: Transport | None = None,
                 environ: Mapping[str, str] | None = None) -> None:
        self.config = config
        self.provider = "openai-compatible"
        self.model = config.model
        self._transport = transport or _post_json
        self._environ = environ if environ is not None else os.environ

    def generate(self, prompt: RenderedPrompt | str, *,
                 prompt_version: str | None = None) -> LLMGeneration:
        content, version, name = _prompt_parts(prompt, prompt_version)
        api_key = self._environ.get(self.config.api_key_env_name)
        if not api_key:
            raise LLMError(
                f"API key environment variable is not set: {self.config.api_key_env_name}"
            )
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": [{"role": "user", "content": content}],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": False,
        }
        if self.config.thinking is not None:
            payload["thinking"] = {"type": self.config.thinking}
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        try:
            response = self._transport(
                _chat_completions_url(self.config.base_url),
                payload,
                headers,
                self.config.timeout,
            )
            if not isinstance(response, Mapping):
                raise TypeError("response is not an object")
            choice = response["choices"][0]
            if not isinstance(choice, Mapping):
                raise TypeError("choice is not an object")
            generated = choice["message"]["content"]
            if not isinstance(generated, str):
                raise TypeError("message content is not text")
            generated = _redact_secret(generated, api_key)
            model = response.get("model", self.config.model)
            usage = response.get("usage", {})
        except LLMError:
            raise
        except TimeoutError as error:
            # A timeout says something about the clock, not about the payload.
            # Reporting it as an invalid response would send a reader looking
            # for a malformed body that does not exist, which is exactly the
            # misdiagnosis a short --llm-timeout is most likely to run into.
            # socket.timeout is an alias of TimeoutError on every supported
            # Python, so this one clause catches both spellings.
            raise LLMError(
                "OpenAI-compatible request timed out after "
                f"{self.config.timeout:g}s"
            ) from error
        except Exception as error:
            raise LLMError(f"invalid OpenAI-compatible response: {type(error).__name__}") from error

        return LLMGeneration(
            content=generated,
            model=(
                _redact_secret(model, api_key)
                if isinstance(model, str) else self.config.model
            ),
            prompt_version=version,
            provider="openai-compatible",
            response_id=(
                _redact_secret(response["id"], api_key)
                if isinstance(response.get("id"), str) else None
            ),
            finish_reason=(
                _redact_secret(choice["finish_reason"], api_key)
                if isinstance(choice.get("finish_reason"), str) else None
            ),
            usage=(
                _redact_secret(dict(usage), api_key)
                if isinstance(usage, Mapping) else {}
            ),
            metadata={
                "prompt_name": name,
                "temperature": self.config.temperature,
                "max_tokens": self.config.max_tokens,
                "thinking": self.config.thinking,
            },
        )


def _prompt_parts(prompt: RenderedPrompt | str,
                  prompt_version: str | None) -> tuple[str, str, str]:
    if isinstance(prompt, RenderedPrompt):
        if prompt_version is not None and prompt_version != prompt.prompt_version:
            raise ValueError("explicit prompt_version conflicts with rendered prompt")
        return prompt.content, prompt.prompt_version, prompt.name
    if not isinstance(prompt, str):
        raise TypeError("prompt must be RenderedPrompt or str")
    if prompt_version is None or not prompt_version.strip():
        raise ValueError("prompt_version is required for plain string prompts")
    return prompt, prompt_version, "unregistered"


def _chat_completions_url(base_url: str) -> str:
    normalized = base_url.rstrip("/")
    if normalized.endswith("/chat/completions"):
        return normalized
    return normalized + "/chat/completions"


def _post_json(url: str, payload: Mapping[str, Any], headers: Mapping[str, str],
               timeout: float) -> Mapping[str, Any]:
    parsed = urlparse(url)
    connection_type = (http.client.HTTPSConnection
                       if parsed.scheme == "https" else http.client.HTTPConnection)
    connection = connection_type(parsed.hostname, parsed.port, timeout=timeout)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        connection.request(
            "POST",
            path,
            body=json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8"),
            headers=dict(headers),
        )
        response = connection.getresponse()
        body = response.read()
        if not 200 <= response.status < 300:
            raise LLMError(f"OpenAI-compatible endpoint returned HTTP {response.status}")
        decoded = json.loads(body.decode("utf-8"))
        if not isinstance(decoded, Mapping):
            raise LLMError("OpenAI-compatible endpoint returned a non-object response")
        return decoded
    except LLMError:
        raise
    except TimeoutError as error:
        # This is where a silent endpoint actually surfaces: the default
        # transport wraps every failure below, so TimeoutError never reaches
        # OpenAICompatibleLLM.generate as itself.  Naming the timeout here is
        # what makes a short --llm-timeout legible in the error text.
        raise LLMError(
            f"OpenAI-compatible request timed out after {timeout:g}s"
        ) from error
    except Exception as error:
        raise LLMError(f"OpenAI-compatible request failed: {type(error).__name__}") from error
    finally:
        connection.close()


def _optional_string(value: Mapping[str, Any], key: str) -> str | None:
    item = value.get(key)
    if item is not None and not isinstance(item, str):
        raise ValueError(f"recorded {key} must be a string or null")
    return item


def _redact_secret(value: Any, secret: str) -> Any:
    """Remove a provider credential from every persisted response field."""

    if isinstance(value, str):
        return value.replace(secret, "[REDACTED]")
    if isinstance(value, Mapping):
        return {
            _redact_secret(key, secret): _redact_secret(item, secret)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_secret(item, secret) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_secret(item, secret) for item in value)
    return value
