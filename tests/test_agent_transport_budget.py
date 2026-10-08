"""Public transport deadlines and request timing, with no live provider calls."""
from copy import deepcopy
from datetime import datetime
import json
from types import SimpleNamespace

import pytest

from harness_generation.semantic_discovery import deepseek_client as adapter
from harness_generation.semantic_discovery.models import AgentModelError
from harness_generation.semantic_discovery.provider_config import (
    CompatibleAgentConfig, CompatibleAgentModel, agent_configuration)


def reply():
    return SimpleNamespace(id='offline-response', model='offline-served',
        usage=SimpleNamespace(prompt_tokens=10, completion_tokens=2, total_tokens=12),
        choices=[SimpleNamespace(finish_reason='tool_calls', message=SimpleNamespace(
            content=None, tool_calls=[SimpleNamespace(id='terminal', function=SimpleNamespace(
                name='terminal', arguments='{}'))]))])


@pytest.mark.parametrize('outcome', ['response', 'timeout', 'invalid_response'])
@pytest.mark.parametrize('deadline', [60.0, 120.0])
def test_request_duration_deadline_and_failure_are_observed_without_retry(monkeypatch, outcome, deadline):
    count = []
    ticks = iter([100.0, 101.25])
    monkeypatch.setattr(adapter, 'time', SimpleNamespace(monotonic=lambda: next(ticks)))
    def create(**kwargs):
        count.append(deepcopy(kwargs))
        if outcome == 'timeout':
            raise TimeoutError('offline timeout')
        return reply() if outcome == 'response' else SimpleNamespace(choices=[])
    model = CompatibleAgentModel(CompatibleAgentConfig(model='offline', timeout=deadline),
        environ={}, client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
    original = [{'role': 'user', 'content': 'source'}]
    if outcome == 'response':
        response = model.complete(original, [])
        diagnostic = response.metadata['request_diagnostics']
        assert response.metadata['usage']['total_tokens'] == 12
    else:
        with pytest.raises(AgentModelError) as caught:
            model.complete(original, [])
        diagnostic = caught.value.diagnostics
        assert caught.value.error_category == ('timeout' if outcome == 'timeout' else 'invalid_response')
        assert 'usage' not in diagnostic  # A failed response has unknown usage.
    assert len(count) == 1 and count[0]['max_tokens'] == 4096
    assert diagnostic['request_elapsed_seconds'] == 1.25
    assert diagnostic['request_timeout_seconds'] == deadline
    assert diagnostic['sdk_max_retries'] == 0
    assert datetime.fromisoformat(diagnostic['request_finished_utc']) >= datetime.fromisoformat(diagnostic['request_started_utc'])
    assert original == [{'role': 'user', 'content': 'source'}]
    assert 'source' not in json.dumps(diagnostic)


def test_public_deadline_reaches_sdk_with_zero_hidden_retries(monkeypatch):
    import openai
    options = []
    monkeypatch.setattr(openai, 'OpenAI', lambda **kwargs: options.append(kwargs) or object())
    CompatibleAgentModel(CompatibleAgentConfig(model='offline', timeout=120), environ={'LLM_API_KEY': 'offline-test-key'})
    assert len(options) == 1
    assert options[0]['timeout'] == 120 and options[0]['max_retries'] == 0


@pytest.mark.parametrize('provider', ['deepseek', 'openai-compatible'])
def test_transport_override_preserves_model_thinking_and_output_budget(monkeypatch, provider):
    monkeypatch.setenv('LLM_MODEL', 'offline-model')
    monkeypatch.setenv('LLM_BASE_URL', 'https://offline.invalid')
    original = agent_configuration(provider, model='offline-model', thinking='disabled').to_dict()
    changed = agent_configuration(provider, model='offline-model', thinking='disabled', timeout=120).to_dict()
    assert original['timeout'] == 60
    assert changed == {**original, 'timeout': 120}


@pytest.mark.parametrize('module', [
    'harness_generation.semantic_discovery.cli',
    'harness_generation.semantic_slicing.cli',
    'harness_generation.harness_context.cli'])
@pytest.mark.parametrize('deadline', ['0', '61', 'nan', 'inf'])
def test_stage_cli_rejects_unregistered_deadlines_before_loading_artifacts(module, deadline):
    from importlib import import_module
    with pytest.raises(SystemExit) as caught:
        import_module(module).main(['--artifacts', '/nonexistent/offline', '--agent-timeout', deadline])
    assert caught.value.code == 2


@pytest.mark.parametrize('module', [
    'harness_generation.semantic_discovery.cli',
    'harness_generation.semantic_slicing.cli',
    'harness_generation.harness_context.cli'])
def test_injected_transport_deadline_cannot_be_silently_overridden(module, tmp_path):
    from importlib import import_module
    class Injected:
        provider, model = 'offline', 'offline'
        def complete(self, *_):
            raise AssertionError('No model request is authorized before this configuration rejection')
    path = tmp_path / 'not-created'
    assert import_module(module).main(['--artifacts', str(path), '--agent-timeout', '120'], model=Injected()) == 1
    assert not path.exists()
