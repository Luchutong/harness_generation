"""Terminal corrections stay explicit, strict and within the ordinary budget."""
import json

import pytest

from harness_generation.semantic_discovery.loop import BoundedAgentLoop
from harness_generation.semantic_discovery.models import AgentModelResponse, AgentToolCall, DecisionSchemaError, ValidationBudget
from harness_generation.semantic_discovery.tools import _schema


TERMINAL = _schema('done', 'done', {}, [])


def submission(call_id, choice):
    return AgentModelResponse(tool_calls=(AgentToolCall(call_id, 'done', json.dumps({'choice': choice})),))


class Tools:
    schemas = [_schema('read_source', 'read_source', {}, [])]
    def execute(self, *args):
        raise AssertionError('A terminal correction must not execute repository tools')


class Model:
    model = 'offline_semantic_correction'
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []
    def complete(self, messages, schemas):
        self.calls.append((list(messages), schemas))
        return self.responses.pop(0)


def strict(text):
    value = json.loads(text)
    if value != {'choice': 'source-issued'}:
        raise ValueError('choice must be source-issued; foreign proof is rejected')
    return value


def test_explicit_corrected_submission_revalidates_and_uses_existing_round():
    model = Model([submission('invalid', 'invented'), submission('corrected', 'source-issued')])
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=3), TERMINAL, strict,
                              max_semantic_recoveries=1).run([], Tools())
    assert outcome.decision == {'choice': 'source-issued'} and outcome.termination == 'final_decision'
    assert outcome.rounds == outcome.model_calls == len(model.calls) == 2
    assert outcome.tool_calls == 0 and outcome.semantic_recoveries == 1
    assert model.calls[1][1] == [TERMINAL]
    assert any(e['error_category'] == 'terminal_validation_error' for e in outcome.events if 'error_category' in e)
    recovery = next(e for e in outcome.events if e['kind'] == 'semantic_recovery')
    assert recovery['remaining_rounds'] == 2 and recovery['within_existing_budget']
    feedback = [json.loads(m['content']) for m in model.calls[1][0] if m['role'] == 'tool']
    assert feedback == [{'error': 'terminal_validation_failed',
                         'detail': 'choice must be source-issued; foreign proof is rejected'}]
    assert outcome.repair_audit()['semantic_recoveries'] == 1


@pytest.mark.parametrize('rounds,recoveries', [(1, 1), (3, 0)])
def test_disabled_or_exhausted_correction_preserves_fail_closed(rounds, recoveries):
    model = Model([submission('invalid', 'invented'), submission('unused', 'source-issued')])
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=rounds), TERMINAL, strict,
                              max_semantic_recoveries=recoveries).run([], Tools())
    assert outcome.decision is None and len(model.calls) == 1 and outcome.semantic_recoveries == 0


def test_second_invalid_submission_is_not_accepted_or_retried():
    model = Model([submission('bad1', 'invented'), submission('bad2', 'invented'),
                   submission('unused', 'source-issued')])
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=4), TERMINAL, strict,
                              max_semantic_recoveries=1).run([], Tools())
    assert outcome.decision is None and outcome.termination == 'invalid_output'
    assert len(model.calls) == 2 and outcome.semantic_recoveries == 1 and outcome.tool_calls == 0
    assert len([e for e in outcome.events if e.get('error_category') == 'terminal_validation_error']) == 2


def test_aggregate_semantic_diagnostics_keep_every_error_row():
    errors = [{'row': i, 'reason': 'unissued source proof ' + ('x' * 700)} for i in range(4)]
    class Rejected(ValueError):
        def to_dict(self):
            return {'errors': errors}
    def reject(text):
        raise Rejected('all submitted rows failed')
    model = Model([submission('bad1', 'invented'), submission('bad2', 'invented')])
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=2), TERMINAL, reject,
                              max_semantic_recoveries=1).run([], Tools())
    feedback = next(json.loads(m['content']) for m in model.calls[1][0] if m['role'] == 'tool')
    assert feedback['validation_diagnostics']['errors'] == errors
    assert outcome.decision is None


def test_semantic_failure_inside_extra_schema_repair_does_not_extend_budget():
    model = Model([submission('shape', 'shape'), submission('semantic', 'invented'),
                   submission('unused', 'source-issued')])
    def validator(text):
        if json.loads(text)['choice'] == 'shape':
            raise DecisionSchemaError('choice', 'shape', ['source-issued'])
        return strict(text)
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=4), TERMINAL, validator,
                              max_terminal_repairs=1, max_semantic_recoveries=1).run([], Tools())
    assert outcome.decision is None and len(model.calls) == 2 and outcome.schema_repair_attempted
    assert outcome.semantic_recoveries == 0


def test_protocol_invalid_mixed_call_cannot_trigger_semantic_correction():
    mixed = AgentModelResponse(tool_calls=(AgentToolCall('a', 'done', '{}'),
                                          AgentToolCall('b', 'read_source', '{}')))
    model = Model([mixed, submission('unused', 'source-issued')])
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=4), TERMINAL, strict,
                              max_semantic_recoveries=1).run([], Tools())
    assert outcome.decision is None and len(model.calls) == 1 and outcome.semantic_recoveries == 0


@pytest.mark.parametrize('invalid', [True, -1, 2, '1'])
def test_semantic_recovery_option_is_strict(invalid):
    with pytest.raises(ValueError, match='max_semantic_recoveries'):
        BoundedAgentLoop(None, ValidationBudget(), TERMINAL, strict, max_semantic_recoveries=invalid)
