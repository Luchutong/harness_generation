"""Library result fields do not become caller initialization obligations."""
import pytest

from harness_generation.harness_context.proof_grounding import field_proofs
from test_context_generation import ready
from test_harness_context import lifecycle_value, owner
from test_owned_traversal_proofs import SOURCE
from test_proof_reliability import analysis_fixture


def tree_source():
    return SOURCE.replace('finish', 'node_free').replace('bytes', 'data').replace('extent', 'size') + '''
void example(const unsigned char *data,unsigned size){
 if(!size)return;
 Node *result=parse(data,size);if(!result)return;node_free(result);
}
'''


def test_owned_core_result_gate_and_plan_close_without_initializing_target_fields(tmp_path):
    _, frozen, plan = ready(tmp_path, 'owned', source_override=tree_source())
    context, report = frozen[1], frozen[4]
    graph = report['semantic_obligation_graph']
    nodes = {n['obligation_id']: n for n in graph['nodes']}
    binding, = [n for n in nodes.values() if n['predicate'] == 'cleanup_return_input_valid']
    assert binding['proof_status'] == 'proved' and not graph['open_roots']
    assert binding['local_proof']['sources'][0]['proof_scope'] == 'harness_cleanup_input_binding'
    assert binding['local_proof']['sources'][0]['internal_target_fields']
    deps = {d['relation']: nodes[d['obligation_id']] for d in binding['dependencies']}
    assert deps['owned_result_producer_invocation']['predicate'] == 'api_invocation_proved'
    assert deps['owned_result_lifetime']['predicate'] == 'ownership_subject'
    assert deps['owned_result_lifetime']['subject_parameter'] is None
    assert deps['owned_result_lifetime']['subject_function_id'] == plan['call_sequence'][0]['function_id']
    assert deps['owned_result_lifetime']['fact_ids']
    assert len(plan['call_sequence']) == len(plan['cleanup_sequence']) == 1
    assert plan['call_sequence'][0]['return_resource'] == plan['cleanup_sequence'][0]['arguments'][0]['resource_id']
    assert context['core_apis'] == [plan['call_sequence'][0]['function_id']]


def binding_case(tmp_path, source=None):
    snapshot, ids, records, _ = analysis_fixture(tmp_path, source or tree_source())
    core, cleanup, rid = ids['parse'], ids['node_free'], 'one_result'
    context = {'core_apis': [core], 'state_contract': {'preconditions': []},
        'canonical_construction': {'parameters': [dict(function_id=cleanup, parameter='node', status='resolved',
            recipe=dict(kind='resource_reference', producer_api=core, resource_id=rid))]},
        'construction_contract': {'sources': [dict(construction_id='observed_cleanup', kind='cleanup_consumption',
            verified=True, function_id=cleanup, parameter='node', creator_api=core, resource_id=rid,
            observed_pair_origins=['example_result'], evidence_ids=['ev_parse', 'ev_node_free'])]},
        'lifecycle_contract': lifecycle_value(core, rid, 'Node', None, core, cleanup),
        'ownership_contract': {'entries': [dict(function_id=core, evidence_ids=['ev_parse'],
            **owner(returned=True, ownership='owned', release=cleanup, resource=rid))]}}
    context['lifecycle_contract']['resources'][0]['function_id'] = core
    return context, snapshot, records, {'required_support_apis': [{'function_id': cleanup}]}, ids


@pytest.mark.parametrize('missing', ['source_pair', 'verified', 'same_object', 'resolved_recipe',
    'core_producer', 'owned', 'release_api', 'lifetime', 'mandatory_init', 'explicit_state', 'full_body'])
def test_scope_requires_exact_observed_owned_result_and_all_preconditions(tmp_path, missing):
    context, snapshot, records, closure, ids = binding_case(tmp_path)
    rows = field_proofs(context, snapshot, records, closure)
    assert len(rows) == 1 and rows[0]['code'] == 'source_observed_core_return_cleanup'
    source = context['construction_contract']['sources'][0]
    selection = context['canonical_construction']['parameters'][0]
    ownership = context['ownership_contract']['entries'][0]
    if missing == 'source_pair': source['observed_pair_origins'] = []
    elif missing == 'verified': source['verified'] = False
    elif missing == 'same_object': selection['recipe']['resource_id'] = 'different_result'
    elif missing == 'resolved_recipe': selection['status'] = 'unresolved'
    elif missing == 'core_producer': context['core_apis'] = []
    elif missing == 'owned': ownership['ownership'] = 'borrowed'
    elif missing == 'release_api': ownership['release_api'] = ids['walk']
    elif missing == 'lifetime': ownership['lifetime'] = 'during_call'
    elif missing == 'mandatory_init': context['lifecycle_contract']['resources'][0]['initialization'] = dict(api=ids['walk'], mandatory=True)
    elif missing == 'explicit_state': context['state_contract']['preconditions'] = [dict(function_id=ids['node_free'], parameter='node', kind='initialized', api=None)]
    elif missing == 'full_body': del records['ev_parse']
    rows = field_proofs(context, snapshot, records, closure)
    assert rows and not any(r['code'] == 'source_observed_core_return_cleanup' for r in rows)
    assert any(r['status'] != 'proved' for r in rows)


def test_explicit_cleanup_field_guard_remains_a_caller_precondition(tmp_path):
    source = tree_source().replace('void node_free(Node *node){',
        'void node_free(Node *node){if(node->tag!=2)__builtin_trap();')
    context, snapshot, records, closure, _ = binding_case(tmp_path, source)
    rows = field_proofs(context, snapshot, records, closure)
    assert any(r['field'] == 'tag' and r['status'] != 'proved' for r in rows)
    assert not any(r['code'] == 'source_observed_core_return_cleanup' for r in rows)
