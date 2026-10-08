"""Directed checks for the failures in the json-parser native trajectory."""
from copy import deepcopy
import json

import pytest

from harness_generation.semantic_discovery.loop import BoundedAgentLoop
from harness_generation.semantic_discovery.models import AgentModelResponse, AgentToolCall, FakeAgentModel, ValidationBudget
from harness_generation.semantic_discovery.tools import _schema
from harness_generation.harness_context.construction import prepare_local_evidence
from harness_generation.semantic_slicing.core_proofs import source_evidence
from harness_generation.harness_context.native_diagnostics import native_diagnostics
from harness_generation.harness_context.proposals import registry
from harness_generation.harness_context.repairs import merge_resolution
from harness_generation.harness_context.value_flow import complete_bodies
from test_source_snapshot_closure import fragments


class NoRepositoryTools:
    schemas = []
    def execute(self, *args):
        raise AssertionError('Protocol recovery may not invoke repository tools')


def test_truncated_prose_recovers_native_submission_within_remaining_rounds():
    model = FakeAgentModel([AgentModelResponse('long text', metadata={'finish_reason': 'length'}),
        AgentModelResponse(tool_calls=(AgentToolCall('done_1', 'done', '{}'),))])
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=2), _schema('done', 'done', {}, []),
        json.loads, reserve_terminal_round=True, max_protocol_recoveries=1).run([], NoRepositoryTools())
    assert outcome.termination == 'final_decision' and outcome.protocol_recoveries == 1
    assert outcome.model_calls == 2 and outcome.tool_calls == 0


def test_truncated_terminal_arguments_are_not_executed_or_accepted():
    model = FakeAgentModel([AgentModelResponse(tool_calls=(AgentToolCall('cut', 'done', '{'),),
        metadata={'finish_reason': 'length'}),
        AgentModelResponse(tool_calls=(AgentToolCall('fixed', 'done', '{}'),))])
    seen = []
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=2), _schema('done', 'done', {}, []),
        lambda text: seen.append(text) or json.loads(text), max_protocol_recoveries=1).run([], NoRepositoryTools())
    assert outcome.termination == 'final_decision' and seen == ['{}']
    assert any(m.get('tool_call_id') == 'cut' for m in outcome.messages if m['role'] == 'tool')


def test_no_budget_left_does_not_add_a_recovery_call():
    model = FakeAgentModel([AgentModelResponse('text', metadata={'finish_reason': 'length'})])
    outcome = BoundedAgentLoop(model, ValidationBudget(max_rounds=1), _schema('done', 'done', {}, []),
        json.loads, max_protocol_recoveries=1).run([], NoRepositoryTools())
    assert outcome.termination == 'invalid_output' and len(model.calls) == 1


@pytest.mark.parametrize('corruption', ['gap', 'different_hash', 'changed_source'])
def test_slice_fragment_coverage_rejects_gaps_versions_and_content(tmp_path, corruption):
    snapshot, function, records = fragments(tmp_path)
    assert source_evidence(function['id'], snapshot.functions, records)
    changed = deepcopy(records)
    eid = list(changed)[1]
    if corruption == 'gap':
        changed.pop(eid)
    elif corruption == 'different_hash':
        changed[eid]['source_sha256'] = '0' * 64
    else:
        changed[eid]['content'] = changed[eid]['content'].replace('value +=', 'value -=')
    assert not source_evidence(function['id'], snapshot.functions, changed)


def test_source_details_use_byte_offsets_for_large_line_numbers(tmp_path):
    from test_source_detail_tools import SOURCE, active
    _, tools, ids = active(tmp_path, '\n' * 300 + SOURCE)
    rows = tools.execute('find_field_writes', {'function': ids['parse'], 'field': 'drop'})['evidence']
    assert rows[0]['line_start'] > 300
    assert ids['discard'] in rows[0]['possible_callee_ids']


def test_local_evidence_reads_exact_callback_helper_from_field_reference(tmp_path):
    from test_source_detail_tools import SOURCE, active
    prepared, tools, ids = active(tmp_path, SOURCE)
    events = prepare_local_evidence(tools)
    bodies = complete_bodies(prepared[3], prepared[4].evidence)
    assert ids['parse'] in bodies and ids['discard'] in bodies
    assert any(e['tool'] == 'find_field_writes' and e['arguments'] == {'function': ids['parse'], 'field': 'drop'}
               for e in events)


def test_native_diagnostics_records_last_checkpoint_and_python_exception(tmp_path):
    directory = tmp_path / 'diag'
    with pytest.raises(RuntimeError):
        with native_diagnostics(directory) as checkpoint:
            checkpoint('before_failure', requirement_id='req_demo')
            raise RuntimeError('boom')
    record = json.loads((directory / 'native_checkpoint.json').read_text())
    assert record['phase'] == 'python_exception'
    assert record['exception_type'] == 'RuntimeError'
    assert (directory / 'native_fault.log').exists()


def test_support_subject_reuses_exact_parent_body_without_new_reads(tmp_path):
    from test_cleanup_connection_smoke import prepared_case
    prepared, _ = prepared_case(tmp_path)
    ids, tools, state = prepared[0][-1], prepared[5], prepared[4]
    before = state.tool_calls, state.source_chars, len(state.discoveries)
    requirement = dict(requirement_id='cleanup_subject', kind='support_decision',
        subject_function_id=ids['node_free'], required_by=[ids['parse']])
    tools.activate(requirement)
    signed = registry(tools)
    assert ids['parse'] in signed['issued_function_ids']
    assert any(c['function_id'] == ids['node_free'] and c['required_by'] == ids['parse']
        and c['reason'] == 'cleanup' for c in signed['support_candidates'])
    assert before == (state.tool_calls, state.source_chars, len(state.discoveries))


def lifecycle_fixture(tmp_path):
    from test_cleanup_connection_smoke import prepared_case, specs_for
    from test_harness_context import mine
    from harness_generation.harness_context.persistence import context_directory
    from test_evidence_repairs import configure
    prepared, _ = prepared_case(tmp_path)
    run, _ = mine(prepared, specs_for(prepared), persist=True)
    assert run.completeness['generation_allowed']
    directory = context_directory(prepared[0][0], prepared[1]['ft_id'])
    rows = json.loads((directory / 'requirements.json').read_text())['requirements']
    resolutions = json.loads((directory / 'resolutions.json').read_text())['resolutions']
    fixture = prepared[1], prepared[3], rows, resolutions, prepared[4], run.completeness
    requirement = next(r for r in rows if r['kind'] == 'lifecycle'
        and r['subject_function_id'] == prepared[1]['anchor_function_id'])
    return requirement, deepcopy(resolutions[requirement['requirement_id']]), configure(fixture), fixture


def test_lifecycle_necessity_correction_keeps_cleanup_api_gap(tmp_path):
    from harness_generation.harness_context.models import fact_id
    req, incoming, evaluator, fixture = lifecycle_fixture(tmp_path)
    incoming['discovered_api_dependencies'] = []
    for fact in incoming['facts']:
        fact['value']['resources'][0]['cleanup']['api'] = None
        fact['fact_id'] = fact_id(fact)
    previous = deepcopy(incoming)
    previous['facts'][0]['value']['resources'][0]['cleanup']['mandatory'] = False
    previous['facts'][0]['fact_id'] = fact_id(previous['facts'][0])
    # This case starts without a selected cleanup API. Rebuild its requirement
    # universe, rather than keeping requirements activated by the removed API.
    from harness_generation.harness_context.api_closure import build_api_closure
    from harness_generation.harness_context.requirements import HarnessRequirementBuilder
    from harness_generation.harness_context.loop import expand_requirements
    from test_evidence_repairs import configure
    ft, snapshot, rows, resolutions, state, report = fixture
    resolutions[req['requirement_id']] = previous
    closure = build_api_closure(ft, rows, resolutions, snapshot, state)
    expected = HarnessRequirementBuilder().build(ft, snapshot)['requirements']
    expand_requirements(ft, snapshot, expected, closure)
    active = {r['requirement_id'] for r in expected}
    rows[:] = [r for r in rows if r['requirement_id'] in active]
    for rid in list(resolutions):
        if rid not in active:
            del resolutions[rid]
    evaluator = configure(fixture)
    merged, audit = merge_resolution(previous, incoming, req, proof_evaluator=evaluator)
    assert audit['withdrawals'] and not audit['conflicts']
    assert merged['facts'][0]['value']['resources'][0]['cleanup'] == dict(mandatory=True, api=None)
    assert not audit['withdrawals'][0]['replacement_proof']['cleanup_api_proved']


def test_lifecycle_other_property_conflict_is_not_silently_repaired(tmp_path):
    from harness_generation.harness_context.models import fact_id
    req, incoming, evaluator, _ = lifecycle_fixture(tmp_path)
    previous = deepcopy(incoming)
    previous['facts'][0]['value']['resources'][0].update(reuse='per_context')
    previous['facts'][0]['value']['resources'][0]['cleanup']['mandatory'] = False
    previous['facts'][0]['fact_id'] = fact_id(previous['facts'][0])
    _, audit = merge_resolution(previous, incoming, req, proof_evaluator=evaluator)
    assert not audit['withdrawals'] and audit['conflicts']
