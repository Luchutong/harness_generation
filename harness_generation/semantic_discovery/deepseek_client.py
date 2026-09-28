"""DeepSeek Chat Completions adapter, separate from Stage 1–4 text generation."""
from __future__ import annotations

from dataclasses import dataclass
import math
import os
from typing import Mapping
from urllib.parse import urlparse

from .models import AgentModelError, AgentModelResponse, AgentToolCall


@dataclass(frozen=True)
class DeepSeekConfig:
    model: str = "deepseek-flash"
    base_url: str = "https://api.deepseek.com"
    thinking: str = "disabled"
    timeout: float = 60.0
    max_tokens: int = 4096

    def __post_init__(self):
        if not isinstance(self.model, str) or not self.model.strip():
            raise ValueError("DeepSeek model must not be empty")
        parsed = urlparse(self.base_url)
        if (parsed.scheme not in {"https", "http"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("DeepSeek base URL must be an HTTP(S) URL without credentials or query")
        if self.thinking not in {"enabled", "disabled"}:
            raise ValueError("thinking must be enabled or disabled")
        if (isinstance(self.timeout, bool) or not isinstance(self.timeout, (int, float))
                or not math.isfinite(self.timeout) or self.timeout <= 0):
            raise ValueError("timeout must be positive and finite")
        if type(self.max_tokens) is not int or self.max_tokens < 1:
            raise ValueError("max_tokens must be a positive integer")

    @classmethod
    def from_environment(cls, *, model=None, environ: Mapping[str, str] | None = None,
                         **overrides):
        env = os.environ if environ is None else environ
        return cls(model=model or env.get("DEEPSEEK_MODEL", "").strip() or "deepseek-flash",
                   base_url=env.get("DEEPSEEK_BASE_URL", "").strip() or "https://api.deepseek.com",
                   **overrides)

    def to_dict(self):
        return {"provider": "deepseek", "model": self.model, "base_url": self.base_url,
                "thinking": self.thinking, "timeout": self.timeout, "max_tokens": self.max_tokens}


class DeepSeekAgentModel:
    provider = "deepseek"

    def __init__(self, config: DeepSeekConfig | None = None, *,
                 environ: Mapping[str, str] | None = None, client=None):
        self.config = config or DeepSeekConfig.from_environment(environ=environ)
        self.model = self.config.model
        env = os.environ if environ is None else environ
        if client is not None:  # Explicit transport injection for offline adapter tests.
            self._client = client
            return
        key = env.get("DEEPSEEK_API_KEY", "").strip()
        if not key:
            raise ValueError("missing DeepSeek configuration: DEEPSEEK_API_KEY")
        try:
            from openai import OpenAI
        except ImportError:
            raise ValueError("install the project's openai dependency to use DeepSeek") from None
        try:
            self._client = OpenAI(api_key=key, base_url=self.config.base_url,
                                  timeout=self.config.timeout, max_retries=0)
        except Exception:
            raise AgentModelError("DeepSeek client initialization failed") from None

    def complete(self, messages, tools) -> AgentModelResponse:
        try:
            response = self._client.chat.completions.create(
                model=self.model, messages=list(messages), tools=list(tools),
                max_tokens=self.config.max_tokens,
                extra_body={"thinking": {"type": self.config.thinking}},
            )
            choice = response.choices[0]
            message = choice.message
            calls = tuple(AgentToolCall(c.id, c.function.name, c.function.arguments)
                          for c in (message.tool_calls or []))
            usage = response.usage
            # Only numeric token counters and known response fields are persisted.
            counts = {name: getattr(usage, name) for name in
                      ("prompt_tokens", "completion_tokens", "total_tokens")
                      if usage is not None and type(getattr(usage, name, None)) is int}
            metadata = {"usage": counts, "response_id": response.id,
                        "finish_reason": choice.finish_reason, "served_model": response.model}
            return AgentModelResponse(message.content, calls,
                                      getattr(message, "reasoning_content", None), metadata)
        except Exception:
            # Never serialize provider exception strings, HTTP headers/bodies, or
            # SDK request objects: any of these can contain the API credential.
            raise AgentModelError("DeepSeek request or response failed") from None
