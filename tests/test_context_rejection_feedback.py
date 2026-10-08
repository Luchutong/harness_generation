"""Read-only feedback retains linked conflicts and rolled-back submissions."""
from copy import deepcopy

from harness_generation.harness_context.closure_feedback import (
    attach_closure_feedback, attach_rejected_candidates, build_closure_feedback)
from harness_generation.harness_context.obligations import close_obligations
from test_closure_feedback import fact, node
from test_context_input_feedback import disputed_origin


def test_concrete_flag_conflict_is_named_alongside_the_reported_unknown_field():
    graph, rows, facts, signed, evidence = disputed_origin(construction='input', source='fuzz_data')
    binding = deepcopy(facts[1]['value']['bindings'][0])
    facts[1] = fact('input', 'input_binding', {**binding, 'binary_zero_allowed': True})
    facts.append(fact('input', 'input_binding', {**binding, 'binary_zero_allowed': False}))
    gap = node('input_flags', 'input', 'input_binding', 'src', diagnostics=[
        {'code': 'input_constraints_unresolved', 'detail': {'unknown_fields': ['alignment']}}])
    graph.update(close_obligations([gap], ['input_flags']))
    before = deepcopy((graph, rows, facts, signed, evidence))
    feedback = build_closure_feedback(graph, rows, facts, signed=signed, evidence=evidence)
    item, = feedback['items']
    assert len(item['correction_targets']) == 2
    assert {target['observed_values']['binary_zero_allowed'] for target in item['correction_targets']} == {True, False}
    assert all(target['field_paths'] == ['value.bindings[0].alignment',
        'value.bindings[0].binary_zero_allowed'] for target in item['correction_targets'])
    assert (graph, rows, facts, signed, evidence) == before


def test_group_preservation_never_reprotects_another_items_targeted_claim():
    graph, rows, facts, signed, evidence = disputed_origin()
    input_gap = node('input_gap', 'input', 'input_binding', 'src', diagnostics=[
        {'code': 'input_constraints_unresolved', 'detail': {'unknown_fields': ['alignment']}}])
    argument_gap = next(row for row in graph['nodes'] if row['obligation_id'] == 'src_recipe')
    graph.update(close_obligations([argument_gap, input_gap], ['src_recipe', 'input_gap']))
    feedback = build_closure_feedback(graph, rows, facts, signed=signed, evidence=evidence)
    targets = {target['fact_id'] for item in feedback['items'] for target in item['correction_targets']}
    assert facts[0]['fact_id'] in targets and facts[1]['fact_id'] in targets
    assert all(not targets.intersection(item['preserve_fact_ids']) for item in feedback['items'])
    assert all(facts[2]['fact_id'] in item['preserve_fact_ids'] for item in feedback['items'])
    group, = feedback['transaction_groups']
    assert group['requirement_ids'] == ['arg', 'input']
    assert any(row['value']['parameter'] == 'independent'
        for item in feedback['items'] for row in item['preserve_rows'])


def test_rolled_back_proposal_survives_the_agents_second_feedback_projection():
    graph, rows, facts, signed, evidence = disputed_origin()
    feedback = build_closure_feedback(graph, rows, facts, signed=signed, evidence=evidence)
    rejected = {'transaction_id': 'rejected_transaction', 'submitted_requirement_ids': ['arg', 'input'],
        'round': 2, 'native_submissions': {'input': {'value': 'uncommitted_native_proposal'}},
        'rejection_diagnostics': [{'code': 'linked_contract_still_unproved'}], 'correction_allowed': True}
    before = deepcopy((feedback, rejected))
    annotated = attach_rejected_candidates(feedback, [rejected])
    tasks = attach_closure_feedback([{'requirement_id': 'input'}], annotated)
    # Agent investigation recomputes its source view; the diagnostic from the
    # scheduler must remain visible without being promoted into current facts.
    tasks = attach_closure_feedback(tasks, feedback)
    item, = tasks[0]['closure_feedback']['items']
    assert item['rejected_candidates'] == [rejected]
    assert item['current_facts'] == feedback['items'][0]['current_facts']
    assert (feedback, rejected) == before
