"""Aggregate terminal feedback stays strict and repairs only within fixed rounds."""
from copy import deepcopy
import json

import pytest

from harness_generation.semantic_discovery.models import AgentModelResponse, AgentToolCall, ValidationBudget, canonical
from harness_generation.semantic_slicing.models import ClassificationSchemaError, validate_submission
from harness_generation.semantic_slicing.proposals import choices, terminal_schema
from test_candidate_identity_and_closure import slice_tools
from test_semantic_slicing import DIRECT, fixture, queries, run, tool


SOURCE = DIRECT + 'int other_wrapper(const unsigned char *data, size_t size) { return parse(data, size); }\n'


def selected(tools, fid, role, questions=()):
    choice = next(c for c in choices(tools) if c['function_id'] == fid and c['role'] == role)
    return {'choice_id': choice['choice_id'], 'open_questions': list(questions)}


def test_all_unresolved_questions_and_duplicate_functions_are_reported_together(tmp_path):
    sample = fixture(tmp_path, SOURCE)
    tools, ids = slice_tools(sample), sample[-1]
    tools.execute('get_function', {'function': ids['wrapper']})
    payload = {'classification': [selected(tools, ids['parse'], 'core'),
        selected(tools, ids['wrapper'], 'unresolved'),
        selected(tools, ids['other_wrapper'], 'unresolved'),
        selected(tools, ids['wrapper'], 'exclude')]}
    before = deepcopy(payload), deepcopy(tools.evidence), tools.source_chars
    with pytest.raises(ClassificationSchemaError) as captured:
        validate_submission(canonical(payload), tools)
    errors = captured.value.to_dict()['errors']
    assert [e['error'] for e in errors] == ['unresolved_question_missing', 'unresolved_question_missing', 'duplicate_function_identity']
    assert {e['function_id'] for e in errors} == {ids['wrapper'], ids['other_wrapper']}
    duplicate = errors[-1]
    assert duplicate['first_row'] == 1 and duplicate['duplicate_row'] == 3
    assert (payload, tools.evidence, tools.source_chars) == before


def test_partial_question_correction_still_reports_every_remaining_failure(tmp_path):
    sample = fixture(tmp_path, SOURCE)
    tools, ids = slice_tools(sample), sample[-1]
    rows = [selected(tools, ids['parse'], 'core'), selected(tools, ids['wrapper'], 'unresolved'),
            selected(tools, ids['other_wrapper'], 'unresolved')]
    with pytest.raises(ClassificationSchemaError) as first:
        validate_submission(canonical({'classification': rows}), tools)
    assert len(first.value.errors) == 2
    rows[1]['open_questions'] = ['Does wrapper have an independent processing result observed by parse?']
    with pytest.raises(ClassificationSchemaError) as second:
        validate_submission(canonical({'classification': rows}), tools)
    assert [e['function_id'] for e in second.value.errors] == [ids['other_wrapper']]
    rows[2]['open_questions'] = ['Does other_wrapper have an independent data or state effect consumed by parse?']
    accepted = validate_submission(canonical({'classification': rows}), tools)
    assert {r['function_id'] for r in accepted['classification'] if r['role'] == 'core'} == {ids['parse']}
    assert all(r['role'] == 'unresolved' for r in accepted['classification'] if r['function_id'] != ids['parse'])


@pytest.mark.parametrize('corruption', ['foreign_choice', 'unissued_evidence', 'blank_question', 'extra_role'])
def test_aggregate_feedback_does_not_accept_foreign_or_mutated_rows(tmp_path, corruption):
    sample = fixture(tmp_path, SOURCE)
    tools, ids = slice_tools(sample), sample[-1]
    rows = [selected(tools, ids['parse'], 'core'), selected(tools, ids['wrapper'], 'unresolved', ['Need independent dependence proof.'])]
    if corruption == 'foreign_choice':
        rows[1]['choice_id'] = 'slice_choice_' + '0' * 24
    elif corruption == 'unissued_evidence':
        rows[1]['evidence_ids'] = ['ev_foreign']
    elif corruption == 'blank_question':
        rows[1]['open_questions'] = ['  ']
    else:
        rows[1]['role'] = 'core'
    with pytest.raises(ValueError):
        validate_submission(canonical({'classification': rows}), tools)


def native_rows(messages, ids, *, complete=False, call_id='bad_terminal'):
    registry = next(json.loads(m['content'])['slice_role_choices'] for m in reversed(messages)
                    if m['role'] == 'tool' and 'slice_role_choices' in json.loads(m['content']))
    rows = []
    for name in ('parse', 'wrapper', 'other_wrapper'):
        role = 'core' if name == 'parse' else 'unresolved'
        choice = next(c for c in registry if c['function_id'] == ids[name] and c['role'] == role)
        rows.append({'choice_id': choice['choice_id'], 'open_questions':
                     [f'Is {name} an independently input-dependent processing operation of parse?'] if complete and role == 'unresolved' else []})
    return queries(tool('submit_semantic_slice', call_id, classification=rows))


def test_one_remaining_round_repairs_all_rows_with_complete_feedback_and_no_new_tools(tmp_path):
    sample = fixture(tmp_path, SOURCE)
    ids = sample[-1]
    def repair(messages, schemas):
        assert [s['function']['name'] for s in schemas] == ['submit_semantic_slice']
        feedback = next(json.loads(m['content']) for m in reversed(messages)
                        if m['role'] == 'tool' and 'errors' in json.loads(m['content']))
        assert {e['function_id'] for e in feedback['errors']} == {ids['wrapper'], ids['other_wrapper']}
        return native_rows(messages, ids, complete=True, call_id='fixed_terminal')
    result, model, tools = run(sample, [queries(tool('find_callers', 'discover', function=ids['parse'])),
        lambda messages, schemas: native_rows(messages, ids), repair], ValidationBudget(max_rounds=3))
    assert result.result['run_status'] == 'completed_with_unresolved'
    assert result.result['core_functions'] == [ids['parse']]
    assert len(model.calls) == result.result['budget']['model_calls'] == 3
    assert result.result['budget']['tool_calls'] == 2
    assert len(result.metadata['initial_schema_errors']) == 2
    assert result.metadata['protocol_recoveries'] == 1 and not result.metadata['schema_repair_attempted']
    assert all(r['open_questions'] for r in result.result['classification'] if r['role'] == 'unresolved')


def test_terminal_last_round_is_compact_and_does_not_autofill_questions(tmp_path):
    sample = fixture(tmp_path, SOURCE)
    ids = sample[-1]
    def bad(messages, schemas):
        guidance = next(json.loads(m['content'])['terminal_guidance'] for m in reversed(messages)
                        if m['role'] == 'user' and m.get('content', '').startswith('{') and 'terminal_guidance' in json.loads(m['content']))
        assert 'one_function_one_choice' in guidance and 'compact_submission' in guidance
        return native_rows(messages, ids)
    result, model, _ = run(sample, [queries(tool('find_callers', 'discover', function=ids['parse'])), bad,
        lambda messages, schemas: native_rows(messages, ids, call_id='still_missing_questions')], ValidationBudget(max_rounds=2))
    assert result.result['run_status'] == 'invalid' and result.metadata['canonical_is_fallback']
    assert result.result['core_functions'] == [ids['parse']]
    assert len(model.calls) == 3 and len(result.metadata['initial_schema_errors']) == 2
    assert result.metadata['protocol_recoveries'] == 0 and result.metadata['extra_terminal_repair_attempts'] == 1
    assert result.metadata['terminal_correction_attempts'] == 1
    assert result.metadata['schema_repair_attempted'] and not result.metadata['schema_repair_success']


def test_wire_schema_caps_rows_to_function_universe_and_forbids_identical_rows(tmp_path):
    tools = slice_tools(fixture(tmp_path, SOURCE))
    schema = terminal_schema(tools)['function']['parameters']['properties']['classification']
    assert schema['maxItems'] == len(tools.authorized_ids) and schema['uniqueItems'] is True


def test_competing_choices_require_explicit_model_selection_and_one_budgeted_repair(tmp_path):
    sample = fixture(tmp_path, SOURCE)
    ids = sample[-1]
    def submit(messages, schemas, *, duplicate):
        registry = next(json.loads(m['content'])['slice_role_choices'] for m in reversed(messages)
                        if m['role'] == 'tool' and 'slice_role_choices' in json.loads(m['content']))
        anchor = next(c for c in registry if c['function_id'] == ids['parse'] and c['role'] == 'core')
        unresolved = next(c for c in registry if c['function_id'] == ids['wrapper'] and c['role'] == 'unresolved')
        exclude = next(c for c in registry if c['function_id'] == ids['wrapper'] and c['role'] == 'exclude')
        rows = [{'choice_id': anchor['choice_id'], 'open_questions': []},
                {'choice_id': unresolved['choice_id'], 'open_questions': ['Does wrapper perform processing independent of its parse call?']}]
        if duplicate:
            rows.append({'choice_id': exclude['choice_id'], 'open_questions': []})
        return queries(tool('submit_semantic_slice', 'duplicate_terminal' if duplicate else 'chosen_terminal', classification=rows))
    result, model, _ = run(sample, [queries(tool('read_source_range', 'source', file='api.c', line_start=1, line_end=5)),
        lambda messages, schemas: submit(messages, schemas, duplicate=True),
        lambda messages, schemas: submit(messages, schemas, duplicate=False)], ValidationBudget(max_rounds=3))
    assert len(model.calls) == 3 and result.metadata['protocol_recoveries'] == 1
    assert result.result['run_status'] == 'completed_with_unresolved'
    row = next(r for r in result.result['classification'] if r['function_id'] == ids['wrapper'])
    assert row['role'] == 'unresolved' and row['open_questions']
    assert result.result['excluded_functions'] == []  # No implicit last-row-wins role selection.


def test_semantic_evidence_failure_has_actionable_feedback_without_shape_repair(tmp_path):
    sample = fixture(tmp_path, SOURCE)
    ids = sample[-1]
    def forged(messages, schemas):
        return queries(tool('submit_semantic_slice', 'forged_terminal', classification=[{
            'function_id': ids['parse'], 'role': 'core', 'reason_codes': ['accepted_anchor'],
            'evidence_ids': ['ev_previous_run'], 'open_questions': []}]))
    result, model, _ = run(sample, [forged], ValidationBudget(max_rounds=3))
    assert result.result['run_status'] == 'invalid' and len(model.calls) == 1
    assert not result.metadata['initial_schema_errors'] and result.metadata['protocol_recoveries'] == 0
    feedback = json.loads(result.trace['messages'][-1]['content'])
    assert feedback == {'error': 'terminal_validation_failed', 'detail': 'evidence was not issued in this run'}
