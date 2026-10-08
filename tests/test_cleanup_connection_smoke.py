"""Small directed checks for source reuse and canonical cleanup integration."""
import json

import pytest

from harness_generation.harness_context.requirements import HarnessRequirementBuilder
from harness_generation.harness_context.proposals import registry
from harness_generation.harness_context.value_flow import complete_bodies
from harness_generation.harness_context.models import resource_id, ContextBudget
from harness_generation.context_generation import HarnessPlanBuilder
from harness_generation.context_generation.cli import main
from harness_generation.context_generation.persistence import load_frozen_inputs
from harness_generation.llm import FakeLLM
from test_harness_context import setup, mine, direct_specs, owner, argument, order, lifecycle_value


SOURCE = '''#include <stdlib.h>
#include <stddef.h>
typedef struct Node { unsigned value; } Node;
typedef struct Hooks { void (*dispose)(void *,void *); void *cookie; } Hooks;
static void release_storage(void *p,void *cookie){free(p);}
static void invoke(Hooks *table,Node *node){table->dispose(node,table->cookie);}
static void unrelated(void *p){free(p);}
void node_free(Node *node){Hooks setting={0};setting.dispose=release_storage;invoke(&setting,node);}
Node *parse(const unsigned char *data,size_t size){Node *node=calloc(1,sizeof(Node));if(node)node->value=size?data[0]:0;return node;}
'''


def prepared_case(tmp_path, source=SOURCE):
    prepared = setup(tmp_path, source=source, budget=ContextBudget())
    ids, tools = prepared[0][-1], prepared[5]
    requirements = HarnessRequirementBuilder().build(prepared[1], prepared[3])['requirements']
    req = next(r for r in requirements if r['kind'] == 'ownership' and r['subject_function_id'] == ids['parse'])
    tools.activate(req)
    tools.bootstrap()
    queries = [('find_type_usages', {'type': 'Node'}),
        ('get_function', {'function': ids['node_free']}),
        ('find_field_writes', {'function': ids['node_free'], 'field': 'dispose'}),
        ('get_function', {'function': ids['release_storage']}),
        ('get_call_sites', {'function': ids['node_free'], 'callee': 'invoke'}),
        ('get_function', {'function': ids['invoke']})]
    for name, args in queries:
        result = tools.execute(name, args)
        assert not result.get('error'), result
    return prepared, requirements


def specs_for(prepared):
    ids = prepared[0][-1]
    fid, cleanup = ids['parse'], ids['node_free']
    rid = resource_id(fid)
    specs = direct_specs(fid)
    specs[fid, 'return_semantics']['value'] = dict(success='nonnull', nullable=True, owned=True, error_cleanup=False)
    specs[fid, 'ownership']['value']['entries'].append(owner(returned=True, ownership='owned', release=cleanup, resource=rid))
    specs[fid, 'lifecycle'] = {'value': lifecycle_value(fid, rid, 'Node', None, fid, cleanup),
        'dependencies': [dict(function_id=cleanup, necessity='required', reason='cleanup')]}
    specs[fid, 'call_order'] = {'value': {'constraints': [order(fid, cleanup)]}}
    specs[cleanup, 'argument_construction'] = {'value': {'arguments': [argument('node', 'derived')]}}
    specs[cleanup, 'ownership'] = {'value': {'entries': [owner('node', ownership='transferred')]}}
    return specs


def test_source_chain_survives_obligation_switch_without_new_reads(tmp_path):
    prepared, requirements = prepared_case(tmp_path)
    ids, tools, state = prepared[0][-1], prepared[5], prepared[4]
    fid, cleanup = ids['parse'], ids['node_free']
    before = state.tool_calls, state.source_chars, len(state.discoveries)
    fact = dict(function_id=fid, predicate='ownership', value={'entries': [
        owner(returned=True, ownership='owned', release=cleanup)]}, evidence_ids=[])
    for kind, subject in [('lifecycle', fid), ('ownership', cleanup), ('argument_construction', cleanup)]:
        req = next(r for r in requirements if r['kind'] == kind and r['subject_function_id'] == subject) if subject == fid else dict(
            requirement_id='followup_' + kind, subject_function_id=subject, required_by=[fid], kind=kind)
        tools.activate(req, [fact])
        visible = {eid: tools.evidence[eid] for eid in tools.visible_ids}
        assert {cleanup, ids['invoke'], ids['release_storage']} <= complete_bodies(prepared[3], visible).keys()
        assert ids['unrelated'] not in tools.scope_ids
        if subject == fid:
            assert any(c['function_id'] == cleanup and c['reason'] == 'cleanup' for c in registry(tools)['support_candidates'])
    assert before == (state.tool_calls, state.source_chars, len(state.discoveries))


def test_changed_source_cannot_reuse_helper_or_cached_body(tmp_path):
    prepared, requirements = prepared_case(tmp_path)
    tools, ids = prepared[5], prepared[0][-1]
    file = tools.index.owned_path(prepared[3].functions[ids['release_storage']]['file'])
    file.write_text(file.read_text().replace('free(p);', '(void)p;'))
    tools.activate(next(r for r in requirements if r['kind'] == 'ownership'))
    assert not tools.visible_ids and not tools.query_cache


def test_excluded_helper_does_not_reenter_source_scope(tmp_path):
    prepared, requirements = prepared_case(tmp_path)
    tools, ids = prepared[5], prepared[0][-1]
    tools.excluded.add(ids['release_storage'])
    for kind in ['ownership', 'lifecycle']:
        tools.activate(next(r for r in requirements if r['kind'] == kind))
        assert ids['release_storage'] not in tools.scope_ids
        assert not any(c['function_id'] == ids['node_free'] and c['reason'] == 'cleanup'
            for c in registry(tools)['support_candidates'])


def test_null_userdata_cannot_be_assumed_nonnull_inside_callback(tmp_path):
    from harness_generation.harness_context.resource_identity import parameter_release_proof
    from test_proof_reliability import analysis_fixture
    source = SOURCE.replace('free(p);}', 'if(!cookie)return;free(p);}', 1)
    snapshot, ids, _, bodies = analysis_fixture(tmp_path, source)
    assert parameter_release_proof(snapshot.functions[ids['node_free']], 'node', snapshot, bodies) is None


@pytest.mark.parametrize('body', ['if(node->value)free(node);', 'free(&node);', 'free(node);free(node);',
    'free(node);node->value=1;'])
def test_conditional_wrong_object_and_double_release_do_not_get_binding(tmp_path, body):
    from harness_generation.harness_context.construction import project_cleanup_consumption
    from test_proof_reliability import analysis_fixture
    source = SOURCE.replace('Hooks setting={0};setting.dispose=release_storage;invoke(&setting,node);', body)
    snapshot, ids, records, _ = analysis_fixture(tmp_path, source)
    context = dict(core_apis=[ids['parse']], lifecycle_contract={'resources': [dict(
        function_id=ids['parse'], return_value=True, type='Node', evidence_ids=['ev_parse'],
        cleanup=dict(mandatory=True, api=ids['node_free']))]}, ownership_contract={'entries': [dict(
        function_id=ids['parse'], return_value=True, ownership='owned', release_api=ids['node_free'])]},
        argument_contract={'arguments': []})
    assert not project_cleanup_consumption(context, snapshot, records, set(ids.values()))
    assert not context['argument_contract']['arguments']


def test_extra_cleanup_argument_remains_an_independent_obligation(tmp_path):
    from harness_generation.harness_context.construction import project_cleanup_consumption
    from test_proof_reliability import analysis_fixture
    source = SOURCE.replace('node_free(Node *node)', 'node_free(Node *node, unsigned flags)')
    snapshot, ids, records, _ = analysis_fixture(tmp_path, source)
    flag = dict(function_id=ids['node_free'], **argument('flags', 'unknown'))
    context = dict(core_apis=[ids['parse']], lifecycle_contract={'resources': [dict(
        function_id=ids['parse'], return_value=True, type='Node', evidence_ids=['ev_parse'],
        cleanup=dict(mandatory=True, api=ids['node_free']))]}, ownership_contract={'entries': [dict(
        function_id=ids['parse'], return_value=True, ownership='owned', release_api=ids['node_free'])]},
        argument_contract={'arguments': [flag]})
    proof, = project_cleanup_consumption(context, snapshot, records, set(ids.values()))
    assert proof['parameter'] == 'node'
    assert flag['construction'] == 'unknown' and flag['resource_id'] is None


def test_same_type_producers_cannot_guess_cleanup_instance(tmp_path):
    from harness_generation.harness_context.construction import project_cleanup_consumption
    from test_proof_reliability import analysis_fixture
    snapshot, ids, records, _ = analysis_fixture(tmp_path, SOURCE + '\nNode *another(void){return calloc(1,sizeof(Node));}\n')
    producers = [ids['parse'], ids['another']]
    context = dict(core_apis=producers, lifecycle_contract={'resources': [dict(
        function_id=fid, return_value=True, type='Node', evidence_ids=['ev_parse' if fid == ids['parse'] else 'ev_another'],
        cleanup=dict(mandatory=True, api=ids['node_free'])) for fid in producers]},
        ownership_contract={'entries': [dict(function_id=fid, return_value=True, ownership='owned',
            release_api=ids['node_free']) for fid in producers]}, argument_contract={'arguments': []})
    assert not project_cleanup_consumption(context, snapshot, records, set(ids.values()))


def test_two_released_formals_cannot_bind_to_one_resource(tmp_path):
    from harness_generation.harness_context.construction import project_cleanup_consumption
    from test_proof_reliability import analysis_fixture
    source = SOURCE.replace('node_free(Node *node)', 'node_free(Node *node, Node *other)').replace(
        'invoke(&setting,node);', 'invoke(&setting,node);free(other);')
    snapshot, ids, records, _ = analysis_fixture(tmp_path, source)
    context = dict(core_apis=[ids['parse']], lifecycle_contract={'resources': [dict(
        function_id=ids['parse'], return_value=True, type='Node', evidence_ids=['ev_parse'],
        cleanup=dict(mandatory=True, api=ids['node_free']))]}, ownership_contract={'entries': [dict(
        function_id=ids['parse'], return_value=True, ownership='owned', release_api=ids['node_free'])]},
        argument_contract={'arguments': []})
    assert not project_cleanup_consumption(context, snapshot, records, set(ids.values()))


def test_callback_cleanup_closes_context_and_references_same_plan_resource(tmp_path):
    prepared, _ = prepared_case(tmp_path)
    run, _ = mine(prepared, specs_for(prepared), query_type='Node', persist=True)
    assert run.completeness['generation_allowed'], run.completeness
    frozen = load_frozen_inputs(prepared[0][0], prepared[1]['ft_id'])
    plan = HarnessPlanBuilder().build(*frozen[:5])
    producer, = plan['call_sequence']
    cleanup, = plan['cleanup_sequence']
    arg, = cleanup['arguments']
    assert cleanup['function_id'] == prepared[0][-1]['node_free']
    assert arg['canonical_recipe']['kind'] == 'resource_reference'
    assert arg['resource_id'] == producer['return_resource'] == cleanup['resource_instance']
    assert all(c['function_id'] not in {prepared[0][-1]['invoke'], prepared[0][-1]['release_storage']}
        for c in plan['call_sequence'] + plan['cleanup_sequence'])
    variable = arg['binding_expression']
    code = '''#include <stdint.h>
#include <stddef.h>
typedef struct Node { unsigned value; } Node;
extern "C" Node *parse(const unsigned char *,size_t);
extern "C" void node_free(Node *);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size){
 if(size>1048576)return 0;
 Node *VARIABLE=parse(data,size);
 if(VARIABLE)node_free(VARIABLE);
 return 0;
}
'''.replace('VARIABLE', variable)
    store = prepared[0][0]
    assert main(['--artifacts', str(store.root), '--build', '--runtime'], llm=FakeLLM([code])) == 0
    directory = next((store.root / 'context_generations').glob('*/*/*/metadata.json')).parent
    build = json.loads((directory / 'build/build.json').read_text())
    runtime = json.loads((directory / 'build/runtime.json').read_text())
    assert build['success'], build
    assert runtime['status'] == 'passed', runtime
