"""Transient Slice recovery retains failures and uses its ordinary-round budget."""
import pytest

from harness_generation.semantic_discovery.models import AgentModelError, ValidationBudget
from test_semantic_slicing import DIRECT, fixture, run, terminal


def failure(category):
    def respond(messages, schemas):
        error = AgentModelError('offline provider failure')
        error.error_category = category
        raise error
    return respond


@pytest.mark.parametrize('category', ['timeout', 'http_429', 'http_5xx'])
def test_slice_recovers_transient_once_and_revalidates_native_submission(tmp_path, category):
    sample = fixture(tmp_path, DIRECT)
    fid = sample[-1]['parse']
    result, model, tools = run(sample, [failure(category), terminal({fid: ('core', 'accepted_anchor')})],
                               ValidationBudget(max_rounds=2))
    assert result.result['run_status'] == 'completed'
    assert result.result['core_functions'] == [fid]
    assert result.metadata['canonical_is_fallback'] is False
    assert result.metadata['provider_recoveries'] == 1
    assert result.result['budget']['rounds'] == result.result['budget']['model_calls'] == len(model.calls) == 2
    assert result.result['budget']['tool_calls'] == 1  # Existing frontier bootstrap only.
    errors = [e for e in result.trace['events'] if e['kind'] == 'model_error']
    assert len(errors) == 1 and errors[0]['error_category'] == category
    assert not errors[0].get('usage')  # Failed-request cost remains unknown.
    assert set(result.evidence['records'][0]) >= {'evidence_id', 'tool'}


@pytest.mark.parametrize('category,rounds', [('http_401', 3), ('http_400', 3), ('timeout', 1)])
def test_slice_nonretryable_or_final_round_failure_remains_blocked(tmp_path, category, rounds):
    sample = fixture(tmp_path, DIRECT)
    fid = sample[-1]['parse']
    result, model, _ = run(sample, [failure(category), terminal({fid: ('core', 'accepted_anchor')})],
                           ValidationBudget(max_rounds=rounds))
    assert result.result['run_status'] == 'error' and result.metadata['canonical_is_fallback'] is True
    assert len(model.calls) == 1 and result.metadata['provider_recoveries'] == 0


def test_slice_second_timeout_is_preserved_without_another_recovery(tmp_path):
    sample = fixture(tmp_path, DIRECT)
    fid = sample[-1]['parse']
    result, model, _ = run(sample, [failure('timeout'), failure('timeout'),
        terminal({fid: ('core', 'accepted_anchor')})], ValidationBudget(max_rounds=4))
    assert result.result['run_status'] == 'error' and result.metadata['canonical_is_fallback'] is True
    assert len(model.calls) == 2 and result.metadata['provider_recoveries'] == 1
    assert len([e for e in result.trace['events'] if e['kind'] == 'model_error']) == 2
