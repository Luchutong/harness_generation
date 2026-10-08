"""Strict native terminal JSON correction within registered recovery budgets."""
import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from harness_generation.semantic_discovery.models import (
    AgentModelError, AgentModelResponse, AgentToolCall, DecisionSchemaError, FakeAgentModel, ValidationBudget)
from harness_generation.semantic_discovery.tools import _schema

from harness_generation.semantic_discovery.loop import BoundedAgentLoop as Loop
TERMINAL = _schema('done', 'done', {}, [])

class Tools:
    schemas = [_schema('read_source', 'source', {}, [])]
    def execute(self, *args):
        raise AssertionError('No source tools may execute during correction')

class Responses(FakeAgentModel):
    def complete(self, messages, tools):
        self.calls.append({'messages': list(messages), 'tools': tools})
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result(messages, tools) if callable(result) else result

def native(payload, call_id='attempt', finish='tool_calls'):
    return AgentModelResponse(tool_calls=(AgentToolCall(call_id, 'done', payload),), metadata={
        'finish_reason': finish, 'response_id': call_id,
        'usage': {'prompt_tokens': 10, 'completion_tokens': 4096, 'total_tokens': 4106}})

def strict(text):
    data = json.loads(text)
    if data != {'choice_id': 'issued', 'open_questions': []}:
        raise ValueError('choice must be issued; no automatic role or fields')
    return data

GOOD = '{"choice_id":"issued","open_questions":[]}'

@pytest.mark.parametrize('malformed', ['{', '{"choice_id":"issu', '{"choice_id":"issued",}', '{"choice_id":"issued"', ''])
def test_native_invalid_json_with_tool_calls_finish_uses_one_existing_round(malformed):
    model = Responses([native(malformed), native(GOOD, 'explicit_correction')])
    result = Loop(model, ValidationBudget(max_rounds=3), TERMINAL, strict,
                  max_protocol_recoveries=1).run([], Tools())
    assert result.decision == json.loads(GOOD)
    assert result.rounds == result.model_calls == len(model.calls) == 2
    assert result.protocol_recoveries == 1 and result.tool_calls == 0
    assert model.calls[1]['tools'] == [TERMINAL]
    assert result.terminal_submission_attempts == 2
    assert any(e.get('error_category') == 'terminal_json_parse_error' for e in result.events)
    recovery = next(e for e in result.events if e['kind'] == 'protocol_recovery')
    assert recovery['reason'] == 'malformed_terminal_json' and recovery['within_existing_budget']
    assert result.messages[0]['tool_calls'][0]['function']['arguments'] == malformed
    assert sum(e['metadata']['usage']['completion_tokens'] for e in result.events if e['kind'] == 'model_response') == 8192

@pytest.mark.parametrize('rounds,recoveries', [(1, 1), (3, 0)])
def test_no_remaining_round_or_disabled_budget_never_recovers(rounds, recoveries):
    model = Responses([native('{'), native(GOOD, 'unused')])
    result = Loop(model, ValidationBudget(max_rounds=rounds), TERMINAL, strict,
                  max_protocol_recoveries=recoveries).run([], Tools())
    assert result.decision is None and len(model.calls) == 1 and result.protocol_recoveries == 0


def test_second_malformed_json_stops_with_remaining_rounds_unused():
    model = Responses([native('{'), native('{', 'second_bad'), native(GOOD, 'unused')])
    result = Loop(model, ValidationBudget(max_rounds=4), TERMINAL, strict,
                  max_protocol_recoveries=1).run([], Tools())
    assert result.decision is None and len(model.calls) == 2 and result.protocol_recoveries == 1
    assert result.rounds == 2 and result.tool_calls == 0

@pytest.mark.parametrize('payload', ['{}', '{"choice_id":"foreign","open_questions":[]}',
                                    '{"choice_id":"issued"}', '{"choice_id":"issued","open_questions":[],"role":"core"}'])
def test_well_formed_but_semantically_invalid_json_does_not_get_parse_recovery(payload):
    model = Responses([native(payload), native(GOOD, 'unused')])
    result = Loop(model, ValidationBudget(max_rounds=3), TERMINAL, strict,
                  max_protocol_recoveries=1).run([], Tools())
    assert result.decision is None and len(model.calls) == 1 and result.protocol_recoveries == 0
    assert result.events[-1]['error_category'] == 'terminal_validation_error'


def test_json_error_inside_validator_is_semantic_not_terminal_transport():
    def validator(text):
        json.loads(text)
        json.loads('{broken nested proof')
    model = Responses([native(GOOD), native(GOOD, 'unused')])
    result = Loop(model, ValidationBudget(max_rounds=3), TERMINAL, validator,
                  max_protocol_recoveries=1).run([], Tools())
    assert result.decision is None and result.protocol_recoveries == 0 and len(model.calls) == 1
    assert result.events[-1]['error_category'] == 'terminal_validation_error'

@pytest.mark.parametrize('damage', ['mixed_call', 'duplicate_id', 'oversize_id', 'oversize_payload'])
def test_invalid_terminal_envelope_never_triggers_json_recovery(damage):
    if damage == 'mixed_call':
        bad = AgentModelResponse(tool_calls=(AgentToolCall('bad', 'done', '{'), AgentToolCall('other', 'read_source', '{}')))
    elif damage == 'duplicate_id':
        bad = native('{', 'seen')
    elif damage == 'oversize_id':
        bad = native('{', 'x' * 513)
    else:
        bad = native('{' + 'x' * 64000)
    model = Responses([bad, native(GOOD, 'unused')])
    initial = ({'tool_call_id': 'seen', 'kind': 'already_seen'},) if damage == 'duplicate_id' else ()
    result = Loop(model, ValidationBudget(max_rounds=3), TERMINAL, strict,
                  max_protocol_recoveries=1).run([], Tools(), initial_events=initial)
    assert result.decision is None and result.protocol_recoveries == 0 and len(model.calls) == 1

@pytest.mark.parametrize('category', ['http_400', 'http_401', 'http_403', 'transport_error', 'unknown_provider_error', 'budget_exhausted', 'timeout'])
def test_provider_failure_during_terminal_only_correction_cannot_fallback(category):
    error = AgentModelError('recorded error'); error.error_category = category
    model = Responses([native('{'), error, native(GOOD, 'unused')])
    result = Loop(model, ValidationBudget(max_rounds=4), TERMINAL, strict,
                  max_protocol_recoveries=1, max_provider_recoveries=1).run([], Tools())
    assert result.decision is None and len(model.calls) == 2 and result.protocol_recoveries == 1
    assert result.provider_recoveries == 0
    assert any(e.get('error_category') == category and e['kind'] == 'model_error' for e in result.events)


def test_malformed_json_inside_extra_schema_repair_does_not_gain_ordinary_parse_recovery():
    def validator(text):
        if json.loads(text) == {}:
            raise DecisionSchemaError('$', {}, ['explicit choice_id'])
        return strict(text)
    model = Responses([native('{}'), native('{', 'extra_repair'), native(GOOD, 'unused')])
    result = Loop(model, ValidationBudget(max_rounds=4), TERMINAL, validator,
                  max_terminal_repairs=1, max_protocol_recoveries=1).run([], Tools())
    assert result.decision is None and len(model.calls) == 2
    assert result.schema_repair_attempted and result.protocol_recoveries == 0


def test_text_terminal_parse_error_does_not_use_native_protocol_branch():
    model = Responses([AgentModelResponse(content='{'), native(GOOD, 'unused')])
    result = Loop(model, ValidationBudget(max_rounds=3), TERMINAL, strict,
                  allow_text_terminal=True, max_protocol_recoveries=1).run([], Tools())
    assert result.decision is None and len(model.calls) == 1 and result.protocol_recoveries == 0
