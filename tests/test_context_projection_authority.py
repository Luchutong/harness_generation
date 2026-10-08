"""Transport keeps observed claims and issued options distinct from proof."""
from copy import deepcopy
import json

from harness_generation.harness_context.models import resource_id
from harness_generation.harness_context.prompt_projection import (
    feedback_view, proposal_view, resource_identity_view, terminal_guidance)


FID, OTHER = 'api.c:6:open_memory', 'api.c:7:read_memory'
FUNCTION = {'id': FID, 'parameters': [{'name': 'data'}, {'name': 'size'}]}


def fact(kind, value, *, fid=FID, label='a', requirement=None):
    return {'fact_id': 'fact_' + label, 'requirement_id': requirement or 'req_' + kind,
            'function_id': fid, 'predicate': kind, 'value': deepcopy(value),
            'evidence_ids': ['ev_body']}


def lifecycle(rid, *, fid=FID, parameter=None, label='a', creator=FID):
    return fact('lifecycle', {'resources': [{'resource_id': rid, 'type': 'Stream',
        'subject_parameter': parameter, 'return_value': parameter is None,
        'creation': {'kind': 'creator_api', 'api': creator},
        'initialization': {'api': None, 'mandatory': False},
        'cleanup': {'api': 'api.c:9:close_memory', 'mandatory': True}, 'reuse': 'per_input'}]},
        fid=fid, label=label)


def catalog():
    return {resource_id(FID): {'value_type': 'Resource', 'evidence_ids': ['ev_body'],
                              'origin': {'function_id': FID, 'parameter': None, 'kind': 'return',
                                         'type': 'Stream', 'pointer_depth': 1}},
            resource_id(OTHER, 's'): {'value_type': 'StateObject', 'evidence_ids': ['ev_read'],
                                     'origin': {'function_id': OTHER, 'parameter': 's', 'kind': 'parameter',
                                                'type': 'Stream', 'pointer_depth': 1}},
            'resource_caller_return': {'value_type': 'Resource', 'evidence_ids': ['ev_example'],
                                       'origin': {'function_id': FID, 'parameter': None, 'kind': 'return',
                                                  'caller_id': 'api.c:10:example', 'call_offset': 34,
                                                  'type': 'Stream', 'pointer_depth': 1}}}


def binding(rid, *, parameter=None, fid=FID, reason='source_value_flow'):
    return {'function_id': fid, 'parameter': parameter, 'return_value': parameter is None,
            'resource_id': rid, 'reason': reason, 'evidence_ids': ['ev_example']}


def preview(*bindings, canonical=()):
    return {'resource_identity': {'bindings': list(bindings)},
            'canonical_construction': {'parameters': list(canonical)}}


def subject(view, parameter=None, returned=True):
    return next(s for s in view['subjects'] if s['subject_parameter'] == parameter
                and s['return_value'] == returned)


def test_observed_lifecycle_cannot_override_issued_default_or_creator_return():
    foreign = resource_id(OTHER, 's')
    facts = [lifecycle(foreign), lifecycle(foreign, fid=OTHER, parameter='s', label='b')]
    before = deepcopy(facts)
    view = resource_identity_view(FUNCTION, facts, preview(), catalog())
    assert view['resource_ids']['return_value'] == resource_id(FID)
    assert subject(view)['selection_status'] == 'issued_default'
    assert {r['resource_id'] for r in view['observed_resource_choices']} == {foreign}
    assert all(r['proof_status'] == 'unverified' for r in view['observed_resource_choices'])
    assert all(r['source_issued_origin']['origin']['function_id'] == OTHER
               for r in view['observed_resource_choices'])
    assert facts == before


def test_distinct_unproved_lifecycle_choices_are_ambiguous_independent_of_order():
    facts = [lifecycle(resource_id(OTHER, 's')), lifecycle('resource_caller_return', label='b')]
    first = resource_identity_view(FUNCTION, facts, preview(), catalog())
    reverse = resource_identity_view(FUNCTION, facts[::-1], preview(), catalog())
    assert first == reverse
    assert first['resource_ids']['return_value'] is None
    assert subject(first)['selection_status'] == 'ambiguous_observed_proposals'
    assert subject(first)['observed_conflict']
    origins = {r['resource_id']: r['origin'] for r in subject(first)['issued_options']}
    assert origins[resource_id(OTHER, 's')] != origins['resource_caller_return']


def test_exact_source_endpoint_certificate_can_disambiguate_its_own_subject():
    facts = [lifecycle(resource_id(OTHER, 's')), lifecycle('resource_caller_return', label='b')]
    p = preview(binding('resource_caller_return'))
    before = deepcopy((facts, p))
    view = resource_identity_view(FUNCTION, facts, p, catalog())
    assert view['resource_ids']['return_value'] == 'resource_caller_return'
    assert subject(view)['selection_status'] == 'certified_endpoint'
    assert subject(view)['observed_conflict']
    read = {'id': OTHER, 'parameters': [{'name': 's'}]}
    other = resource_identity_view(read, facts, p, catalog())
    assert other['resource_ids']['s'] == resource_id(OTHER, 's')
    assert subject(other, 's', False)['selection_status'] == 'issued_default'
    assert (facts, p) == before


def test_competing_certified_origins_never_select_first_last_or_default():
    p = preview(binding(resource_id(FID)), binding('resource_caller_return'))
    view = resource_identity_view(FUNCTION, [], p, catalog())
    assert view['resource_ids']['return_value'] is None
    assert subject(view)['selection_status'] == 'ambiguous_certificates'
    assert len(subject(view)['certificates']) == 2


def test_model_based_unique_creator_and_unissued_certificate_have_no_authority():
    p = preview(binding('resource_caller_return', reason='unique_harness_creator_binding'),
                binding('resource_unissued'), binding('resource_caller_return', fid=OTHER))
    view = resource_identity_view(FUNCTION, [], p, catalog())
    assert view['resource_ids']['return_value'] == resource_id(FID)
    assert subject(view)['certificates'] == []


def test_only_resolved_source_issued_canonical_with_proof_digest_selects_parameter():
    function = {'id': OTHER, 'parameters': [{'name': 's'}]}
    canonical = {'function_id': OTHER, 'parameter': 's', 'status': 'resolved',
                 'recipe': {'resource_id': 'resource_caller_return'}, 'proof_digest': 'digest',
                 'reason': 'graph_proof', 'evidence_ids': ['ev_example']}
    view = resource_identity_view(function, [], preview(canonical=[canonical]), catalog())
    assert view['resource_ids']['s'] == 'resource_caller_return'
    for bad in [dict(canonical, status='unknown'), dict(canonical, proof_digest=None),
                dict(canonical, evidence_ids=[]), dict(canonical, recipe={'resource_id': 'unissued'})]:
        view = resource_identity_view(function, [], preview(canonical=[bad]), catalog())
        assert view['resource_ids']['s'] == resource_id(OTHER, 's')


def argument_fact():
    return fact('argument_construction', {'arguments': [
        {'parameter': 'data', 'construction': 'input', 'api': None, 'resource_id': None, 'constant': None},
        {'parameter': 'size', 'construction': 'derived', 'api': None, 'resource_id': None, 'constant': None}]})


def recipe_node(f, parameter='data', *, status='proved', source='canonical_construction', reason='graph_semantic_agreement'):
    return {'obligation_id': 'obligation_' + parameter, 'requirement_id': f['requirement_id'],
            'subject_function_id': f['function_id'], 'subject_parameter': parameter, 'subject_field': None,
            'predicate': 'parameter_recipe', 'proof_status': status, 'fact_ids': [f['fact_id']],
            'evidence_ids': ['ev_body'], 'local_proof': {'status': status, 'sources': [
                {'kind': source, 'reason': reason, 'proof_digest': 'digest'}]}}


def projected_arguments(f):
    return {'argument_contract': {'arguments': [dict(r, fact_id=f['fact_id'], function_id=FID)
                                               for r in f['value']['arguments']]}}


def test_proved_sibling_covers_only_exact_argument_row_and_keeps_whole_fact_partial():
    f = argument_fact()
    graph = {'nodes': [recipe_node(f), recipe_node(f, 'size', status='missing')]}
    p = projected_arguments(f)
    before = deepcopy((f, graph, p))
    result = proposal_view([f], graph, p)[0]
    assert result['proof_status'] == 'partial'
    assert [c['proof_status'] for c in result['claim_proofs']] == ['proved', 'unverified']
    assert result['claim_proofs'][0]['covered_fields'] == sorted(f['value']['arguments'][0])
    assert result['claim_proofs'][1]['obligation_ids'] == []
    assert (f, graph, p) == before


def test_proved_aggregate_or_changed_projection_does_not_cover_original_claim():
    f = argument_fact()
    aggregate = recipe_node(f, source='validated_semantic_proposal')
    aggregate['predicate'] = 'argument_construction'
    assert proposal_view([f], {'nodes': [aggregate]}, projected_arguments(f))[0]['proof_status'] == 'unverified'
    p = projected_arguments(f)
    p['argument_contract']['arguments'][0]['construction'] = 'derived'
    result = proposal_view([f], {'nodes': [recipe_node(f)]}, p)[0]
    assert result['proof_status'] == 'unverified'
    assert result['graph_obligations'][0]['proof_status'] == 'proved'
    assert result['claim_proofs'][0]['covered_fields'] == []


def test_exact_closed_ownership_node_cannot_authorize_source_projected_lifetime():
    row = {'parameter': 'data', 'return_value': False, 'field': None, 'resource_id': None,
           'ownership': 'borrowed', 'release_api': None, 'lifetime': 'during_call'}
    f = fact('ownership', {'entries': [row]})
    n = recipe_node(f)
    n.update(predicate='ownership_subject', local_proof={'status': 'proved', 'sources': [
        {'kind': 'source_checked_ownership_projection', 'semantic_fact_ids': [f['fact_id']]}]})
    p = {'ownership_contract': {'entries': [dict(row, fact_id=f['fact_id'])]}}
    assert proposal_view([f], {'nodes': [n]}, p)[0]['proof_status'] == 'proved'
    p['ownership_contract']['entries'][0]['lifetime'] = 'until_release'
    assert proposal_view([f], {'nodes': [n]}, p)[0]['proof_status'] == 'unverified'


def test_linked_feedback_keeps_exact_old_conflicting_fields_across_projection():
    old = fact('input_binding', {'bindings': [{'parameter': 'data', 'source': 'derived',
        'via_function_id': None, 'binary_zero_allowed': True}]})
    new = deepcopy(old)
    new['fact_id'] = 'fact_new'
    new['value']['bindings'][0]['binary_zero_allowed'] = None
    unrelated = fact('return_semantics', {'success': 'always'}, label='unrelated')
    feedback = {'items': [{'current_facts': [old, new, unrelated], 'preserve_fact_ids': ['fact_unrelated'],
                          'correction_targets': [{'fact_id': old['fact_id'], 'field_paths': ['value.bindings[0].source']},
                                                 {'fact_id': new['fact_id'], 'field_paths': ['value.bindings[0].source']}]}]}
    before = deepcopy(feedback)
    reduced = feedback_view(feedback)
    assert reduced['items'][0]['current_facts'] == [old, new]
    assert reduced['items'][0]['current_facts'][1]['value']['bindings'][0]['binary_zero_allowed'] is None
    assert feedback == before


def test_native_agent_payload_names_observations_and_preserves_budget(tmp_path):
    from harness_generation.harness_context.agent import HarnessContextAgent
    from harness_generation.harness_context import ContextBudget
    from harness_generation.harness_context.models import fact_id
    from harness_generation.harness_context.requirements import HarnessRequirementBuilder
    from test_harness_context import setup, ScriptedModel, direct_specs, argument

    budget = ContextBudget()
    prepared = setup(tmp_path, budget=budget)
    fid = prepared[0][-1]['parse']
    req = next(r for r in HarnessRequirementBuilder().build(prepared[1], prepared[3])['requirements']
               if r['kind'] == 'argument_construction')
    old = fact('argument_construction', {'arguments': [argument('data', 'derived')]},
               fid=fid, requirement=req['requirement_id'])
    old['fact_id'] = fact_id(old)
    model = ScriptedModel(direct_specs(fid))
    run = HarnessContextAgent(model, prepared[4]).investigate(req, prepared[5], facts=[old])
    request = json.loads(next(m['content'] for m in model.calls[0]['messages'] if m['role'] == 'user'))
    assert 'confirmed_facts' not in request
    assert request['observed_proposals'][0]['fact_id'] == old['fact_id']
    assert request['observed_proposals'][0]['proof_status'] == 'unverified'
    assert 'resource_identity_options' in request
    assert request['budgets'] == budget.to_dict() == ContextBudget().to_dict()
    assert 'alias' in request['resource_identity_options']['rule']
    assert 'budget' not in terminal_guidance([req])
    from harness_generation.semantic_discovery.models import digest
    submission = run.metadata['native_submission']
    assert submission['origin'] == 'validated_native_terminal'
    assert submission['requirement_id'] == req['requirement_id']
    assert submission['resolution_digest'] == digest(submission['resolution'])
    assert old['fact_id'] not in {f['fact_id'] for f in submission['resolution']['facts']}
    assert any(a['parameter'] == 'data' and a['construction'] == 'input'
               for f in submission['resolution']['facts'] for a in f['value']['arguments'])
    before = deepcopy(submission)
    run.result['facts'].clear()
    assert run.metadata['native_submission'] == before


def test_group_native_capture_marks_rejected_slot_and_valid_partial_siblings(tmp_path):
    from harness_generation.harness_context.agent import HarnessContextAgent
    from harness_generation.harness_context.requirements import HarnessRequirementBuilder
    from harness_generation.semantic_discovery.models import digest
    from test_harness_context import setup, direct_specs
    from test_context_grouping import GroupedFixtureModel

    prepared = setup(tmp_path)
    rows = HarnessRequirementBuilder().build(prepared[1], prepared[3])['requirements']
    def invalid_ownership(requirement, result):
        if requirement['kind'] == 'ownership':
            result['facts'][0]['evidence_ids'] = []
    model = GroupedFixtureModel(direct_specs(prepared[0][-1]['parse']), mutate=invalid_ownership)
    runs = HarnessContextAgent(model, prepared[4]).investigate_group(rows, prepared[5])
    by_id = {r['requirement_id']: r for r in rows}
    for run in runs:
        submission = run.metadata['native_submission']
        req = by_id[submission['requirement_id']]
        if req['kind'] == 'ownership':
            assert submission['origin'] == 'semantic_validation_rejected'
            assert submission['resolution'] is None and submission['resolution_digest'] is None
            assert submission['semantic_validation_errors']
        else:
            assert submission['origin'] == 'conservative_group_parse_partial'
            assert submission['resolution']['requirement_id'] == req['requirement_id']
            assert submission['resolution_digest'] == digest(submission['resolution'])
    assert prepared[4].model_calls <= prepared[4].budget.max_total_model_calls


def test_budget_fallback_never_calls_merged_result_a_native_submission(tmp_path):
    from harness_generation.harness_context.agent import HarnessContextAgent
    from harness_generation.harness_context import ContextBudget
    from harness_generation.harness_context.requirements import HarnessRequirementBuilder
    from test_harness_context import setup

    prepared = setup(tmp_path, budget=ContextBudget())
    row = HarnessRequirementBuilder().build(prepared[1], prepared[3])['requirements'][0]
    prepared[4].model_calls = prepared[4].budget.max_total_model_calls
    run = HarnessContextAgent(None, prepared[4]).investigate(row, prepared[5])
    assert run.metadata['native_submission'] == {
        'version': 'native-typed-submission-v1', 'requirement_id': row['requirement_id'],
        'origin': 'no_validated_native_submission', 'resolution': None,
        'resolution_digest': None, 'semantic_validation_errors': []}
