"""Resource identity, invocation scope, input roles and semantic selection."""
from copy import deepcopy
import json
import shutil

import pytest

from harness_generation.cli import main
from harness_generation.llm import FakeLLM
from harness_generation.context_generation import HarnessPlanBuilder
from harness_generation.harness_context.evidence import parse_resolution
from harness_generation.harness_context.models import resource_id
from harness_generation.harness_context.parameter_semantics import project_parameter_relations, mandatory_upper_bounds
from harness_generation.harness_context.argument_graph import build_argument_graph
from harness_generation.harness_context.reconciliation import GraphContractReconciler
from harness_generation.harness_context.value_roles import origin_catalog
from harness_generation.harness_context.requirements import HarnessRequirementBuilder
from harness_generation.semantic_discovery.models import canonical
from test_argument_graph import graph_fixture
from test_harness_context import setup, mine, direct_specs, context_specs, argument, owner, assert_gate
from test_context_semantics import SHARED, indirect


def invocation_fixture(tmp_path, *, wrong_cleanup=False, self_init=False):
    roles={'parse':('core','accepted_anchor'),
        'feed':('core','external_input_injection'),'create':('support','resource_creation'),
        'destroy':('support','resource_cleanup')}
    source=SHARED
    if wrong_cleanup:
        source+='void alternative_destroy(Context *ctx){free(ctx);}\n'
        roles['alternative_destroy']=('support','resource_cleanup')
    prepared=setup(tmp_path,source,roles=roles)
    ids=prepared[0][-1];parse,feed=ids['parse'],ids['feed']
    specs=context_specs(ids);rid=resource_id(parse,'ctx')
    specs[parse,'input_binding']={'value':{'bindings':[indirect('ctx',feed)]}}
    specs[parse,'argument_construction']={'value':{'arguments':[argument('ctx','creator_api',ids['create'],rid)]}}
    specs[parse,'ownership']={'value':{'entries':[owner('ctx',resource=rid)]}}
    specs[parse,'lifecycle']['value']['resources'][0]['initialization']={'mandatory':True,'api':parse if self_init else feed}
    if wrong_cleanup:
        other=ids['alternative_destroy']
        specs[parse,'lifecycle']['value']['resources'][0]['cleanup']={'mandatory':True,'api':other}
        specs[parse,'lifecycle']['dependencies'][1]['function_id']=other
        specs[other,'support_decision']={'value':{'decision':'required','reason':'cleanup','required_by':[parse]},
            'dependencies':[{'function_id':other,'required_by':parse,'necessity':'required','reason':'cleanup'}]}
        specs[other,'argument_construction']={'value':{'arguments':[argument('ctx','derived',resource=rid)]}}
        specs[other,'ownership']={'value':{'entries':[owner('ctx',ownership='transferred')]}}
    specs[parse,'state']={'value':{'preconditions':[{'parameter':'ctx','kind':'initialized','api':feed}]}}
    specs.update(direct_specs(feed))
    specs[feed,'argument_construction']['value']['arguments'].insert(0,argument('ctx','derived',resource=rid))
    specs[feed,'ownership']['value']['entries'].append(owner('ctx',resource=rid))
    specs[feed,'lifecycle']=deepcopy(specs[parse,'lifecycle'])
    specs[feed,'lifecycle']['value']['resources'][0]['initialization']={'mandatory':False,'api':None}
    specs[feed,'lifecycle']['value']['resources'][0]['cleanup']={'mandatory':True,'api':ids['destroy']}
    specs[feed,'lifecycle']['dependencies'][1]['function_id']=ids['destroy']
    specs[feed,'state']={'value':{'preconditions':[{'parameter':'ctx','kind':'initialized','api':ids['create']}]}}
    specs[feed,'call_order']={'value':{'constraints':[]}}
    run,_=mine(prepared,specs,query_type='Context',persist=True)
    return prepared,run


def test_call_scoped_initialization_does_not_change_resource_identity_and_replays(tmp_path):
    prepared,run=invocation_fixture(tmp_path)
    assert_gate(run)
    context=run.context;ids=prepared[0][-1]
    resources=context['resource_contract']['resources']
    assert len(resources)==1 and 'initialization' not in resources[0]
    raw={r['function_id']:r['initialization'] for r in context['lifecycle_contract']['resources']}
    assert raw[ids['parse']]=={'mandatory':True,'api':ids['feed']}
    assert raw[ids['create']]==raw[ids['feed']]=={'mandatory':False,'api':None}
    plan=HarnessPlanBuilder().build(prepared[1],context,run.closure,prepared[3],run.completeness)
    parse=next(c for c in plan['call_sequence'] if c['function_id']==ids['parse'])
    assert any(p['api']==ids['feed'] and p['phase']=='before_call' for p in parse['preconditions'] if p['source']=='lifecycle_initialization')
    assert not any(p['source']=='lifecycle_initialization' for c in plan['call_sequence'] if c['function_id']==ids['create'] for p in c['preconditions'])
    if shutil.which('clang') and shutil.which('clang++'):
        code='''#include <stdint.h>
#include <stddef.h>
typedef struct Context {const unsigned char *data;size_t size;} Context;
extern "C" Context *create(void);
extern "C" void feed(Context *ctx,const unsigned char *data,size_t size);
extern "C" int parse(Context *ctx);
extern "C" void destroy(Context *ctx);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size) {
if(size>1048576)return 0;Context *ctx=create();if(ctx){feed(ctx,data,size);parse(ctx);destroy(ctx);}return 0;}
'''
        assert main(['context-generate','--artifacts',str(prepared[0][0].root),'--build','--runtime'],llm=FakeLLM([code]))==0


def test_real_lifetime_definition_conflict_still_blocks(tmp_path):
    _,run=invocation_fixture(tmp_path,wrong_cleanup=True)
    assert not run.completeness['generation_allowed']
    assert {'code':'conflicting_resource_identity'} in run.completeness['validation_errors']


def test_same_call_cannot_satisfy_its_own_initialization_precondition(tmp_path):
    _,run=invocation_fixture(tmp_path,self_init=True)
    assert not run.completeness['generation_allowed']
    assert 'self_initialization_obligation_unresolved' in {r['code'] for r in run.completeness['hard_missing']}


def test_pointer_input_cannot_create_resource_origin_or_submit_phantom_fact(tmp_path):
    prepared=setup(tmp_path);ids=prepared[0][-1];fid=ids['parse'];tools=prepared[5]
    req=next(r for r in HarnessRequirementBuilder().build(prepared[1],prepared[3])['requirements'] if r['kind']=='argument_construction')
    tools.activate(req);seed=tools.bootstrap()
    catalog=origin_catalog(prepared[3],tools.evidence,tools.scope_ids)
    assert resource_id(fid,'data') not in catalog
    value=direct_specs(fid)[fid,'argument_construction']['value']
    value['arguments'][0]['resource_id']=resource_id(fid,'data')
    proposal={'requirement_id':req['requirement_id'],'status':'resolved',
        'facts':[{'function_id':fid,'predicate':req['kind'],'value':value,'evidence_ids':seed['evidence_ids']}],
        'discovered_api_dependencies':[],'open_questions':[]}
    with pytest.raises(ValueError,match='value_role_resource_id_forbidden'):
        parse_resolution(canonical(proposal),tools)


@pytest.mark.parametrize('guard,selected',[
    ('if(n>16) abort();',True),('if(n>16) return 0;',False),
    ('if(n>16) unknown();',False),('if(n>16) {abort();} else {}',False)])
def test_semantic_bound_selects_bounded_recipe_without_name_rules(tmp_path,guard,selected):
    source='typedef unsigned long size_t;int parse(const unsigned char *src,size_t n){'+guard+'return n?src[n-1]:0;} '
    source+='void usage(const unsigned char *raw,size_t extent){size_t prefix=extent<16?extent:16;parse(raw,prefix);}'
    fixture=graph_fixture(tmp_path,source,bindings=[('usage','raw','extent'),('parse','src','n')])
    context,ft,reqs,snapshot,records,ids=fixture
    context['buffer_length_contract']['links'].append({'function_id':ids['parse'],'buffer_parameter':'src',
        'length_parameter':'n','relation':'bytes','evidence_ids':[e for e,r in records.items() if r['function_id']==ids['parse']]})
    context['argument_contract']['arguments'].append({'function_id':ids['parse'],'parameter':'n','construction':'derived',
        'resource_id':None,'api':None,'constant':None,'fact_id':'fact_explicit_length_proposal',
        'evidence_ids':[e for e,r in records.items() if r['function_id']==ids['parse']]})
    project_parameter_relations(context,snapshot,records)
    graph=build_argument_graph(context,ft,reqs,snapshot,records)
    contract=GraphContractReconciler().reconcile(context,graph,reqs,snapshot)
    row=next(p for p in contract['parameters'] if p['function_id']==ids['parse'] and p['parameter']=='n')
    assert (row['status']=='resolved')==selected
    if selected:
        assert row['recipe']['kind']=='derived_scalar' and row['recipe']['bounds']==[0,16]
        assert any(d['code']=='construction_candidate_semantic_relation_mismatch' for d in contract['diagnostics'])


def test_external_input_flow_contains_no_resource_nodes_and_keeps_input_root(tmp_path):
    prepared,run=invocation_fixture(tmp_path)
    assert_gate(run)
    flow=run.context['external_input_flow']
    assert flow['roots'] and flow['indirect_invocation_paths']
    assert set(run.context['core_apis'])<=set(flow['reachable_functions'])
    assert all(n['node_type']!='Resource' for n in flow['nodes'])
    assert not any(e.get('resource_id') for e in flow['edges'])
    changed=deepcopy(run.context);changed['external_input_flow']['reachable_functions']=[]
    from harness_generation.harness_context.evidence import HarnessContextValidator
    errors=HarnessContextValidator().validate(changed,prepared[1],prepared[3],run.requirements['requirements'],
        prepared[4].evidence,prepared[5].initial_ids|set(prepared[4].discoveries))
    assert {'code':'context_changed_canonical_projection'} in errors


@pytest.mark.parametrize('shadowed', ['abort', '__builtin_trap'])
def test_function_pointer_parameter_is_not_a_nonreturning_intrinsic(tmp_path,shadowed):
    source=('typedef unsigned long size_t; '
        f'int parse(const unsigned char *src,size_t n,void (*{shadowed})(void))'
        f'{{if(n>16) {shadowed}();return n?src[n-1]:0;}}')
    fixture=graph_fixture(tmp_path,source)
    snapshot,ids=fixture[3],fixture[-1]
    assert mandatory_upper_bounds(snapshot.functions[ids['parse']],snapshot)==[]
