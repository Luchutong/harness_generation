"""Preparation leaves exact cleanup source and a query for the native agent.

Authored during the test pause. These definitions have not been executed.
"""
import pytest

from harness_generation.harness_context import ContextBudget, HarnessRequirementBuilder
from harness_generation.harness_context.agent import HarnessContextAgent
from harness_generation.harness_context.construction import prepare_local_evidence
from harness_generation.harness_context.value_flow import complete_bodies
from harness_generation.semantic_discovery.models import FakeAgentModel
from harness_generation.semantic_discovery.tools import ToolBudgetExceeded
from test_context_investigation_frontier_memory import LATE_CLEANUP
from test_harness_context import setup


def prepared(tmp_path, *, cap=8, grouped=False):
    result = setup(tmp_path, LATE_CLEANUP, budget=ContextBudget(max_preparation_tool_calls=cap))
    tools, ids = result[5], result[0][-1]
    rows = [row for row in HarnessRequirementBuilder().build(result[1], result[3])['requirements']
        if row['subject_function_id'] == ids['parse']]
    lifecycle = next(row for row in rows if row['kind'] == 'lifecycle')
    selected = [next(row for row in rows if row['kind'] == 'input_binding'), lifecycle] if grouped else [lifecycle]
    tools.activate(selected[0], requirement_ids=[row['requirement_id'] for row in selected])
    tools.bootstrap()
    return result, selected


@pytest.mark.parametrize('grouped', [False, True])
def test_return_cleanup_source_precedes_generic_forwarded_helpers(tmp_path, grouped):
    result, rows = prepared(tmp_path, grouped=grouped)
    tools, state, ids = result[5], result[4], result[0][-1]
    before = state.tool_calls
    events = prepare_local_evidence(tools, requirements=rows)
    queries = [event for event in events if event['kind'] == 'tool_call']
    assert queries[0]['tool'] == 'get_call_sites'
    assert queries[0]['arguments'] == {'function': ids['parse'], 'callee': 'drop'}
    assert ids['drop'] in complete_bodies(result[3], {eid: tools.evidence[eid] for eid in tools.visible_ids})
    assert state.tool_calls - before <= state.budget.max_preparation_tool_calls
    assert state.model_calls == 0 and state.budget_stop is None


def test_zero_preparation_cap_keeps_seed_and_native_query_budget(tmp_path):
    result, rows = prepared(tmp_path, cap=0)
    tools, state = result[5], result[4]
    before = state.tool_calls, dict(state.evidence), set(tools.visible_ids)
    assert prepare_local_evidence(tools, requirements=rows) == []
    assert (state.tool_calls, state.evidence, tools.visible_ids) == before


def test_one_preparation_query_discovers_cleanup_without_claiming_its_body(tmp_path):
    result, rows = prepared(tmp_path, cap=1)
    tools, state, ids = result[5], result[4], result[0][-1]
    before = state.tool_calls
    events = prepare_local_evidence(tools, requirements=rows)
    assert state.tool_calls - before == 1
    assert ids['drop'] in tools.scope_ids
    assert ids['drop'] not in complete_bodies(result[3], state.evidence)
    assert events[-1]['kind'] == 'preparation_stop' and events[-1]['tool_executed'] is False
    assert state.budget_stop is None
    tools.execute('get_function', {'function': ids['drop']})
    assert ids['drop'] in complete_bodies(result[3], state.evidence)


@pytest.mark.parametrize('remaining', [0, 1])
def test_preparation_respects_explicit_optional_ceiling_and_leaves_one_read(tmp_path, remaining):
    result, rows = prepared(tmp_path)
    tools, state = result[5], result[4]
    before = state.tool_calls
    tools.investigation_tool_limit = 0 if remaining == 0 else before + remaining
    events = prepare_local_evidence(tools, requirements=rows)
    assert state.tool_calls == before and state.budget_stop is None
    assert events[-1]['kind'] == 'preparation_stop'
    assert events[-1]['limit'] == 0 and events[-1]['tool_executed'] is False


@pytest.mark.parametrize('failure,reason', [
    (ToolBudgetExceeded, 'max_source_chars'), (OSError, 'source_unavailable'),
])
def test_charged_source_failure_is_present_in_preparation_trace(tmp_path, monkeypatch, failure, reason):
    result, rows = prepared(tmp_path)
    tools, state = result[5], result[4]
    before = state.tool_calls, dict(state.evidence), state.source_chars

    def charged_failure(name, arguments):
        state.tool_calls += 1
        raise failure(reason)

    monkeypatch.setattr(tools, 'execute', charged_failure)
    events = prepare_local_evidence(tools, requirements=rows)
    assert state.tool_calls == before[0] + 1
    assert state.evidence == before[1] and state.source_chars == before[2]
    assert events[-1]['kind'] == 'tool_call' and events[-1]['tool_executed'] is True
    assert events[-1]['error'] == reason and events[-1]['result_evidence_ids'] == []


def test_authorized_cached_cleanup_body_is_reexposed_without_new_source_charge(tmp_path):
    result, rows = prepared(tmp_path, cap=1)
    tools, state, ids = result[5], result[4], result[0][-1]
    tools.execute('get_call_sites', {'function': ids['parse'], 'callee': 'drop'})
    body = tools.execute('get_function', {'function': ids['drop']})
    tools.visible_ids.difference_update(body['evidence_ids'])
    assert ids['drop'] not in complete_bodies(result[3], {eid: tools.evidence[eid] for eid in tools.visible_ids})
    events = prepare_local_evidence(tools, requirements=rows)
    reused = [event for event in events if event.get('tool') == 'get_function'
        and event['arguments']['function'] == ids['drop']]
    assert reused and reused[0]['evidence_reuse'] is True
    assert set(body['evidence_ids']) <= tools.visible_ids
    assert ids['drop'] in complete_bodies(result[3], {eid: tools.evidence[eid] for eid in tools.visible_ids})


@pytest.mark.parametrize('failure,reason', [
    (ToolBudgetExceeded, 'max_source_chars'), (OSError, 'source_unavailable'),
])
def test_bootstrap_failure_retains_real_tool_cost_without_a_provider_request(tmp_path, monkeypatch, failure, reason):
    result, rows = prepared(tmp_path, cap=0)
    tools, state = result[5], result[4]
    model = FakeAgentModel([])
    before = state.tool_calls

    def charged_failure():
        state.tool_calls += 1
        raise failure(reason)

    monkeypatch.setattr(tools, 'bootstrap', charged_failure)
    run = HarnessContextAgent(model, state).investigate(rows[0], tools)
    assert run.metadata['model_calls'] == 0 and run.metadata['tool_calls'] == 1
    assert state.tool_calls == before + 1
    assert run.trace['events'][0]['tool_executed'] is True
    assert run.trace['events'][0]['provider_request'] is False
    assert run.metadata['termination'] == reason
    assert run.result['facts'] == [] and run.result['status'] == 'unresolved'
