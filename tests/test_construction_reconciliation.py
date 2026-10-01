"""Canonical selection, conflict gates and executable recipe regressions."""
from copy import deepcopy
import json

import pytest

from harness_generation.harness_context.argument_graph import build_argument_graph, parameter_id
from harness_generation.harness_context.reconciliation import GraphContractReconciler, project_canonical_construction
from harness_generation.harness_context.evidence import HarnessContextValidator
from harness_generation.context_generation.recipes import lower_recipes, scalar_expression
from harness_generation.context_generation.validation import validate_code
from test_argument_graph import graph_fixture, BASE
from test_context_generation import ready, DIRECT_CODE
from test_harness_context import setup, mine, direct_specs, argument, resource_id


def proposal(fixture, function, parameter, kind, *, api=None, rid=None, constant=None):
    context,_,_,_,records,ids=fixture
    fid=ids[function]
    context['argument_contract']['arguments'].append({'function_id':fid,'parameter':parameter,
        'construction':kind,'api':ids[api] if api else None,'resource_id':rid,'constant':constant,
        'fact_id':'fact_offline_proposal','evidence_ids':[e for e,r in records.items() if r['function_id']==fid]})


def reconcile(fixture):
    graph=build_argument_graph(*fixture[:5])
    return GraphContractReconciler().reconcile(fixture[0],graph,fixture[2],fixture[3]),graph


def selection(contract, fixture, function, index):
    return next(p for p in contract['parameters'] if p['parameter_id']==parameter_id(fixture[-1][function],index))


def test_equivalent_zero_recipes_close_creator_dependencies_without_merging_resources(tmp_path):
    fixture=graph_fixture(tmp_path,BASE+'void usage(void) { C c={0}; A a={0}; P *p=supply(&c,&a); parse(p); retire(p); }')
    proposal(fixture,'supply','config','zero_init');proposal(fixture,'supply','allocator','zero_init')
    contract,graph=reconcile(fixture)
    assert selection(contract,fixture,'parse',0)['status']=='resolved'
    assert selection(contract,fixture,'supply',0)['reason']=='graph_semantic_agreement'
    assert selection(contract,fixture,'supply',0)['recipe']['kind']=='stack_zero_init'
    assert graph['unresolved_ownership']  # Construction does not discharge ownership.
    assert contract==reconcile(fixture)[0]


def test_multiple_equal_mechanisms_form_one_equivalence_class(tmp_path):
    source=BASE+'void usage(void) { C c={0}; A a={0}; supply(&c,&a); } void other(void) { C c={0}; A a={0}; supply(&c,&a); }'
    fixture=graph_fixture(tmp_path,source);contract,_=reconcile(fixture)
    row=selection(contract,fixture,'supply',0)
    classes=[r for r in contract['equivalence_classes'] if r['parameter_id']==row['parameter_id']]
    assert row['status']=='resolved' and len(classes)==1 and len(classes[0]['candidate_ids'])==2


def test_conflicting_semantic_recipe_cannot_override_mechanical_origin(tmp_path):
    fixture=graph_fixture(tmp_path,BASE+'void usage(void) { C c={0}; A a={0}; P *p=supply(&c,&a); parse(p); }')
    proposal(fixture,'parse','p','zero_init')
    contract,_=reconcile(fixture)
    assert selection(contract,fixture,'parse',0)['status']=='conflict'
    assert selection(contract,fixture,'parse',0)['reason']=='graph_semantic_contradiction'


def test_proposal_without_mechanical_proof_has_explicit_diagnostic(tmp_path):
    fixture=graph_fixture(tmp_path,'typedef struct P {int n;} P; int parse(P *p) { return p->n; }')
    proposal(fixture,'parse','p','zero_init');contract,_=reconcile(fixture)
    assert selection(contract,fixture,'parse',0)['reason']=='semantic_only_not_reproduced'
    assert contract['diagnostics'][0]['code']=='semantic_recipe_not_reproduced'


def test_exact_resource_identity_selects_one_proven_origin_but_type_does_not(tmp_path):
    fixture=graph_fixture(tmp_path,'''typedef struct P {int n;} P; P *make(void) {static P p;return &p;}
int parse(P *p) {return p->n;} void usage(void) {P *a=make();P *b=make();parse(a);parse(b);}''')
    contract,graph=reconcile(fixture);assert selection(contract,fixture,'parse',0)['status']=='unknown'
    proposal(fixture,'parse','p','creator_api',api='make')
    contract,_=reconcile(fixture);assert selection(contract,fixture,'parse',0)['status']=='conflict'
    fixture[0]['argument_contract']['arguments'][0]['resource_id']=graph['resource_origins'][0]['resource_id']
    contract,_=reconcile(fixture)
    assert selection(contract,fixture,'parse',0)['reason']=='semantic_selects_proven_origin'
    assert len(graph['resource_origins'])==2


def test_creator_unknown_argument_is_precise_and_not_a_resolved_contract(tmp_path):
    fixture=graph_fixture(tmp_path,BASE+'void usage(C *c,A *a) {P *p=supply(c,a);parse(p);}')
    contract,_=reconcile(fixture);row=selection(contract,fixture,'parse',0)
    assert row['status']=='unknown' and row['reason']=='creator_argument_missing'
    assert set(row['missing_dependencies'])=={parameter_id(fixture[-1]['supply'],0),parameter_id(fixture[-1]['supply'],1)}


def test_out_storage_and_resource_remain_separate_recipes(tmp_path):
    fixture=graph_fixture(tmp_path,'''typedef struct P {int n;} P; typedef struct C {int f;} C;
int fill(P **out,C *c) {*out=calloc(1,sizeof(P));return 1;} int parse(P *p){return p->n;}
void usage(void){C c={0};P *p;fill(&p,&c);parse(p);}''')
    proposal(fixture,'fill','out','zero_init');contract,graph=reconcile(fixture)
    out=selection(contract,fixture,'fill',0);consumer=selection(contract,fixture,'parse',0)
    assert out['recipe']['kind']=='out_parameter_storage' and consumer['recipe']['kind']=='out_parameter_call'
    assert out['recipe']['resource_id']==consumer['recipe']['resource_id']
    context=fixture[0];context['canonical_construction']=contract
    recipes=lower_recipes(context,set(fixture[-1].values()),fixture[3])
    assert next(r for r in recipes if r['kind']=='out_parameter_storage')['binding_expression'].startswith('&hg_resource_')


@pytest.mark.parametrize('expression,accepted',[('(n<4096?n:4096)+4',True),('n-1',False),('n+4',False),('arbitrary(n)',False)])
def test_bounded_scalar_is_plan_data_without_arbitrary_expression_execution(tmp_path,expression,accepted):
    fixture=graph_fixture(tmp_path,'typedef unsigned long size_t; int parse(const unsigned char *b,size_t n){return n?b[0]:0;} '
        'void usage(const unsigned char *x,size_t n){parse(x,'+expression+');}',bindings=[('usage','x','n')])
    contract,_=reconcile(fixture);row=selection(contract,fixture,'parse',1)
    assert (row['status']=='resolved')==accepted
    if accepted:
        assert row['recipe']['bounds']==[4,4100]
        assert '4096' in scalar_expression(row['recipe']['expression'])


def test_narrow_scalar_target_is_not_assumed_safe(tmp_path):
    fixture=graph_fixture(tmp_path,'typedef unsigned long size_t; int parse(const unsigned char *b,unsigned char n){return n?b[0]:0;} '
        'void usage(const unsigned char *x,size_t n){parse(x,(n<4096?n:4096));}',bindings=[('usage','x','n')])
    contract,_=reconcile(fixture);assert selection(contract,fixture,'parse',1)['status']=='unknown'


def test_canonical_artifact_tampering_is_recomputed_and_rejected(tmp_path):
    prepared=setup(tmp_path);run,_=mine(prepared,direct_specs(prepared[0][-1]['parse']))
    changed=deepcopy(run.context);changed['canonical_construction']['parameters'][0]['recipe']['kind']='constant'
    errors=HarnessContextValidator().validate(changed,prepared[1],prepared[3],run.requirements['requirements'],prepared[4].evidence,prepared[5].initial_ids)
    assert {'code':'context_changed_canonical_projection'} in errors


def test_mandatory_graph_contract_conflict_blocks_generation(tmp_path):
    prepared=setup(tmp_path);fid=prepared[0][-1]['parse'];specs=direct_specs(fid)
    specs[fid,'argument_construction']['value']['arguments'][0]={**argument('data','constant'),'constant':0}
    run,_=mine(prepared,specs)
    assert not run.completeness['generation_allowed'] and not run.context['frozen']
    assert 'construction_contract_conflict' in {h['code'] for h in run.completeness['hard_missing']}


def test_existing_complete_plan_contains_only_canonical_argument_recipes(tmp_path):
    _,frozen,plan=ready(tmp_path,'context')
    assert plan['schema_version']==2 and plan['construction_recipes']
    assert all(a['recipe_id']==a['canonical_recipe']['recipe_id'] for c in plan['call_sequence']+plan['cleanup_sequence'] for a in c['arguments'])
    (tmp_path/'other').mkdir()
    assert validate_code(DIRECT_CODE,ready(tmp_path/'other')[2])['status']=='valid'


def test_generated_scalar_must_match_canonical_ir(tmp_path):
    _,_,plan=ready(tmp_path)
    argument=plan['call_sequence'][0]['arguments'][1]
    argument['canonical_recipe']={'kind':'derived_scalar','expression':{'op':'min','left':{'op':'fuzz_size'},'right':{'op':'constant','value':16}}}
    assert 'canonical_scalar_recipe_mismatch' in validate_code(DIRECT_CODE,plan)['errors']
    bounded=DIRECT_CODE.replace('parse(data, size)','parse(data, (size < 16 ? size : 16))')
    assert validate_code(bounded,plan)['status']=='valid'
    overwritten=bounded.replace('(void)parse','size = 100; (void)parse')
    assert 'canonical_scalar_recipe_mismatch' in validate_code(overwritten,plan)['errors']


@pytest.mark.parametrize('declaration,consume,accepted',[
    ('P *p = NULL;','p',True),('P *p;','p',False),('P *p = NULL; P *wrong = NULL;','wrong',False)])
def test_generated_out_call_requires_initialized_cell_and_same_pointee(declaration,consume,accepted):
    rid='resource_offline_origin'
    out={'parameter':'out','canonical_recipe':{'kind':'out_parameter_storage','resource_id':rid}}
    use={'parameter':'p','canonical_recipe':{'kind':'out_parameter_call','resource_id':rid}}
    plan={'language':'c++','entrypoint':'LLVMFuzzerTestOneInput','headers':[],
        'api_declarations':[{'function_id':'fill','symbol':'fill','signature':'int fill(P **out);','parameters':[{}]},
                            {'function_id':'parse','symbol':'parse','signature':'int parse(P *p);','parameters':[{}]}],
        'contracts':{'callback_contract':{'callbacks':[]}},'type_declarations':['typedef struct P {int n;} P;'],
        'call_sequence':[{'symbol':'fill','arguments':[out],'return_resource':None},
                         {'symbol':'parse','arguments':[use],'return_resource':None}],
        'cleanup_sequence':[],'ordering_edges':[['fill','parse']],'construction_recipes':[out['canonical_recipe'],use['canonical_recipe']]}
    code='''#include <stddef.h>
#include <stdint.h>
typedef struct P {int n;} P;
extern "C" int fill(P **out);
extern "C" int parse(P *p);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size) {
'''+declaration+'fill(&p);parse('+consume+'); return 0;}'
    result=validate_code(code,plan)
    assert (result['status']=='valid')==accepted,result
