"""Compatible native tools share the existing adapter and never persist keys."""
from types import SimpleNamespace

import pytest

from harness_generation.semantic_discovery.provider_config import (
    CompatibleAgentConfig, CompatibleAgentModel, LazyAgentModel, load_environment_file)
from harness_generation.semantic_discovery.models import AgentModelError


def test_configured_url_model_and_key_environment(tmp_path, monkeypatch):
    env = tmp_path / "provider.env"
    env.write_text('export LLM_API_KEY="test-key"\nLLM_BASE_URL=https://example.org/api/plan/v3/chat/completions\nLLM_MODEL=model-alias\nLLM_THINKING=disabled\nUNRELATED=value\n')
    for name in ("LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL", "LLM_THINKING", "UNRELATED"):
        monkeypatch.delenv(name, raising=False)
    load_environment_file(env)
    cfg = CompatibleAgentConfig.from_environment()
    assert cfg.base_url == "https://example.org/api/plan/v3"
    assert cfg.model == "model-alias" and cfg.to_dict()["provider"] == "openai-compatible"
    assert "test-key" not in str(cfg.to_dict())
    import os
    assert "UNRELATED" not in os.environ
    lazy = LazyAgentModel(cfg)
    assert lazy._model is None


def test_adapter_preserves_native_tools_and_actual_model_usage():
    calls = []
    def create(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(id="response_1",model="served-model",usage=SimpleNamespace(prompt_tokens=10,completion_tokens=20,total_tokens=30),
            choices=[SimpleNamespace(finish_reason="tool_calls",message=SimpleNamespace(content=None,tool_calls=[
                SimpleNamespace(id="call_1",function=SimpleNamespace(name="terminal",arguments='{"ok":true}'))]))])
    cfg = CompatibleAgentConfig(model="alias",base_url="https://example.org/v3")
    model = CompatibleAgentModel(cfg, client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
    result = model.complete([{"role":"user","content":"test"}],[{"type":"function","function":{"name":"terminal"}}])
    assert result.tool_calls[0].name == "terminal"
    assert result.metadata["served_model"] == "served-model" and result.metadata["usage"]["total_tokens"] == 30
    assert calls[0]["tools"][0]["function"]["name"] == "terminal"


def test_provider_errors_redact_exception_and_no_fallback():
    def create(**kwargs): raise RuntimeError("credential=test-secret")
    cfg = CompatibleAgentConfig(model="alias",base_url="https://example.org/v3")
    model = CompatibleAgentModel(cfg,client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
    with pytest.raises(AgentModelError) as error:
        model.complete([],[])
    assert "test-secret" not in str(error.value)
