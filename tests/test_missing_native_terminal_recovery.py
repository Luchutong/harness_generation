"""A registered last-round zero-call response permits one explicit submission."""
import json

import pytest

from harness_generation.semantic_discovery.models import AgentModelResponse, AgentToolCall, ValidationBudget
from harness_generation.semantic_discovery.loop import BoundedAgentLoop
from test_terminal_selection_recovery import run, response, GOOD, Responses, NoSource, TERMINAL, strict

CATEGORY = 'terminal_native_submission_missing'


def prose(finish='stop'):
    return AgentModelResponse(content='Unaccepted analysis; no semantic decision.',
        metadata={'finish_reason': finish, 'response_id': 'offline-prose',
                  'usage': {'prompt_tokens': 5, 'completion_tokens': 7, 'total_tokens': 12}})


@pytest.mark.parametrize('finish', ['stop', 'tool_calls'])
def test_missing_native_last_round_asks_once_preserves_prose_and_cost(finish):
    out, model = run([prose(finish), response(GOOD, 2)], categories=[CATEGORY], last_only=True)
    assert out.decision == json.loads(GOOD)
    assert out.model_calls == len(model.calls) == 2 and out.rounds == 1
    assert out.extra_terminal_repair_attempts == 1 and out.extra_terminal_repair_success
    assert out.tool_calls == 0 and not out.schema_repair_attempted
    assert out.messages[0]['content'] == prose().content
    assert model.calls[1]['tools'][0]['function']['name'] == 'submit_semantic_slice'
    assert len(model.calls[1]['tools']) == 1
    assert sum(e['metadata']['usage']['total_tokens'] for e in out.events if e['kind'] == 'model_response') == 52
    assert any(e.get('error_category') == CATEGORY for e in out.events)


@pytest.mark.parametrize('finish', ['length', None, 'content_filter', 'unknown'])
def test_truncated_or_unknown_completion_never_gets_missing_native_extra(finish):
    out, model = run([prose(finish), response(GOOD, 2)], categories=[CATEGORY])
    assert out.decision is None and len(model.calls) == 1 and out.extra_terminal_repair_attempts == 0


@pytest.mark.parametrize('extra,categories', [(0, [CATEGORY]), (1, ['terminal_schema_error'])])
def test_unregistered_or_disabled_missing_native_stops(extra, categories):
    out, model = run([prose(), response(GOOD, 2)], extra=extra, categories=categories)
    assert out.decision is None and len(model.calls) == 1 and out.extra_terminal_repair_attempts == 0


def test_remaining_ordinary_round_is_used_before_extra():
    out, model = run([prose(), response(GOOD, 2)], rounds=2, categories=[CATEGORY], protocol=1)
    assert out.decision == json.loads(GOOD) and len(model.calls) == 2
    assert out.extra_terminal_repair_attempts == 0 and out.protocol_recoveries == 1


@pytest.mark.parametrize('second', [prose(), response('{}', 2), response('{', 2),
                                 response('{"choice_id":"foreign","open_questions":[]}', 2)])
def test_second_response_never_creates_another_extra(second):
    out, model = run([prose(), second, response(GOOD, 3)], categories=[CATEGORY, 'terminal_schema_error'])
    assert out.decision is None and len(model.calls) == 2 and out.extra_terminal_repair_attempts == 1


def test_foreign_tool_is_not_missing_native_and_never_executes():
    malformed = AgentModelResponse(tool_calls=(AgentToolCall('foreign', 'outside_repository', '{}'),),
                                   metadata={'finish_reason': 'stop'})
    model = Responses([malformed, response(GOOD, 2)])
    out = BoundedAgentLoop(model, ValidationBudget(max_rounds=1), TERMINAL, strict,
        reserve_terminal_round=True, max_terminal_repairs=1, terminal_repair_categories=[CATEGORY]).run([], NoSource())
    assert out.decision is None and len(model.calls) == 1 and out.extra_terminal_repair_attempts == 0
