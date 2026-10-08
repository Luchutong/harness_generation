"""Optional transient recovery spends ordinary rounds and preserves failures."""
import json

import pytest

from harness_generation.semantic_discovery.loop import BoundedAgentLoop
from harness_generation.semantic_discovery.models import AgentModelError, AgentModelResponse, AgentToolCall, DecisionSchemaError, ValidationBudget
from harness_generation.semantic_discovery.tools import _schema


TERMINAL = _schema('done', 'done', {}, [])
SUCCESS = AgentModelResponse(tool_calls=(AgentToolCall('complete', 'done', '{}'),))


class NoTools:
    schemas = []
    def execute(self, *args):
        raise AssertionError('A provider recovery cannot fabricate a source read')


class Responses:
    model = 'offline_transient'
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []
    def complete(self, messages, schemas):
        self.calls.append((list(messages), schemas))
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def error(category):
    failure = AgentModelError('Recorded provider failure')
    failure.error_category = category
    return failure


@pytest.mark.parametrize('category', ['timeout', 'http_429', 'http_5xx'])
def test_transient_failure_uses_one_remaining_ordinary_round(category):
    model = Responses([error(category), SUCCESS])
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=2), TERMINAL, json.loads,
                              reserve_terminal_round=True, max_provider_recoveries=1).run([], NoTools())
    assert outcome.termination == 'final_decision' and outcome.decision == {}
    assert outcome.rounds == outcome.model_calls == len(model.calls) == 2
    assert outcome.tool_calls == 0 and outcome.provider_recoveries == 1
    assert len([e for e in outcome.events if e['kind'] == 'model_error']) == 1
    recovery = next(e for e in outcome.events if e['kind'] == 'provider_recovery')
    assert recovery['error_category'] == category and recovery['remaining_rounds'] == 1
    assert recovery['within_existing_budget'] is True


@pytest.mark.parametrize('category', ['http_400', 'http_401', 'http_403', 'transport_error', 'unknown_provider_error', 'budget_exhausted'])
def test_configuration_or_unclassified_failures_do_not_recover(category):
    model = Responses([error(category), SUCCESS])
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=3), TERMINAL, json.loads,
                              max_provider_recoveries=1).run([], NoTools())
    assert len(model.calls) == 1 and outcome.provider_recoveries == 0 and outcome.decision is None
    assert not any(e['kind'] == 'provider_recovery' for e in outcome.events)


def test_repeated_timeout_is_preserved_without_second_recovery():
    model = Responses([error('timeout'), error('timeout'), SUCCESS])
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=3), TERMINAL, json.loads,
                              max_provider_recoveries=1).run([], NoTools())
    assert len(model.calls) == 2 and outcome.termination == 'provider_error'
    assert outcome.provider_recoveries == 1 and outcome.decision is None
    assert len([e for e in outcome.events if e['kind'] == 'model_error']) == 2


@pytest.mark.parametrize('rounds,recoveries', [(1, 1), (3, 0)])
def test_no_remaining_budget_or_disabled_option_preserves_old_stop(rounds, recoveries):
    model = Responses([error('timeout'), SUCCESS])
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=rounds), TERMINAL, json.loads,
                              max_provider_recoveries=recoveries).run([], NoTools())
    assert len(model.calls) == 1 and outcome.provider_recoveries == 0


def test_extra_terminal_shape_repair_never_retries_provider_failure():
    malformed = AgentModelResponse(tool_calls=(AgentToolCall('bad', 'done', '{}'),))
    model = Responses([malformed, error('timeout'), SUCCESS])
    def validate(text):
        raise DecisionSchemaError('$', 'malformed', ['object'])
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=3), TERMINAL, validate,
                              max_terminal_repairs=1, max_provider_recoveries=1).run([], NoTools())
    assert len(model.calls) == 2 and outcome.schema_repair_attempted
    assert outcome.provider_recoveries == 0 and outcome.termination == 'provider_error'
    assert not any(e['kind'] == 'provider_recovery' for e in outcome.events)
