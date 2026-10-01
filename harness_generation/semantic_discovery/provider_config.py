"""Configure compatible native tool calling without duplicating the provider."""
from dataclasses import dataclass
import os
from pathlib import Path
import shlex

from .deepseek_client import DeepSeekConfig, DeepSeekAgentModel


def load_environment_file(path):
    allowed = {"LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL", "LLM_THINKING",
               "DEEPSEEK_API_KEY", "DEEPSEEK_BASE_URL", "DEEPSEEK_MODEL", "DEEPSEEK_THINKING"}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        name, separator, raw = line.strip().removeprefix("export ").partition("=")
        if separator and name.strip() in allowed:
            os.environ[name.strip()] = " ".join(shlex.split(raw, comments=True))


@dataclass(frozen=True)
class CompatibleAgentConfig(DeepSeekConfig):
    @classmethod
    def from_environment(cls, *, model=None, environ=None, **overrides):
        env = os.environ if environ is None else environ
        configured_model = model or env.get("LLM_MODEL", "").strip()
        if not configured_model:
            raise ValueError("compatible provider requires --model or LLM_MODEL")
        base = env.get("LLM_BASE_URL", "").strip().rstrip("/").removesuffix("/chat/completions")
        if not base:
            raise ValueError("compatible provider requires LLM_BASE_URL")
        overrides.setdefault("thinking", env.get("LLM_THINKING", "disabled"))
        return cls(model=configured_model, base_url=base, **overrides)

    def to_dict(self):
        return {**super().to_dict(), "provider": "openai-compatible"}


class CompatibleAgentModel(DeepSeekAgentModel):
    provider = "openai-compatible"
    api_key_env_name = "LLM_API_KEY"


class LazyAgentModel:
    def __init__(self, config):
        self.config, self.model, self._model = config, config.model, None
        self.provider = config.to_dict()["provider"]

    def complete(self, messages, tools):
        if self._model is None:
            self._model = native_agent_model(self.config)
        return self._model.complete(messages, tools)


def native_agent_model(config):
    adapter = CompatibleAgentModel if config.to_dict()["provider"] == "openai-compatible" else DeepSeekAgentModel
    return adapter(config)


def agent_configuration(provider, *, model=None, thinking=None):
    cls = CompatibleAgentConfig if provider == "openai-compatible" else DeepSeekConfig
    return cls.from_environment(model=model, **({"thinking": thinking} if thinking is not None else {}))
