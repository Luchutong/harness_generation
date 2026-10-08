"""Callback execution and semantic-only admission use source, not role labels."""
from copy import deepcopy
import shutil

import pytest

from harness_generation.context_generation import HarnessPlanBuilder
from harness_generation.context_generation.persistence import load_frozen_inputs
from harness_generation.context_generation.validation import validate_code
from harness_generation.harness_context.models import resource_id
from test_argument_graph import graph_fixture
from test_construction_reconciliation import reconcile, selection, proposal
from test_harness_context import (mine, direct_specs, argument, owner, order, lifecycle_value, assert_gate)


SOURCE = '''#include <stdlib.h>
#include <stddef.h>
typedef struct User { unsigned bias; } User;
typedef int (*Handler)(void *user,const unsigned char *src,size_t cb);
User *acquire(unsigned bias) { User *u=malloc(sizeof(User)); if(u) u->bias=bias; return u; }
void dispose(User *u) { free(u); }
int handle(void *user,const unsigned char *src,size_t cb) { User *u=user; return cb ? src[0]^u->bias : u->bias; }
int parse(const unsigned char *src,size_t cb,Handler handler,void *user) { return handler(user,src,cb); }
void usage(const unsigned char *raw,size_t extent) { User *u=acquire(0); parse(raw,extent,handle,u); dispose(u); }
'''


@pytest.mark.parametrize('rename', [False, True])
def test_callback_binding_forwarding_closes_exact_origin(tmp_path, rename):
    source = SOURCE
    if rename:
        for a,b in [('acquire','new_resource'),('dispose','finish'),('handle','visitor'),('handler','callback'),('user','opaque'),('src','bytes'),('cb','length')]:
            source = source.replace(a,b)
    f=graph_fixture(tmp_path, source, bindings=[('parse','bytes' if rename else 'src','length' if rename else 'cb')])
    contract,graph=reconcile(f)
    target='visitor' if rename else 'handle'
    dispatcher=graph['callback_dispatches'][0]
    assert dispatcher['function_id']==f[-1][target] and dispatcher['calls_per_invocation']==1
    assert selection(contract,f,'parse',2)['recipe']['producer_api']==f[-1][target]
    assert selection(contract,f,target,0)['recipe']['resource_id']==selection(contract,f,'parse',3)['recipe']['resource_id']
    assert all(selection(contract,f,target,i)['status']=='resolved' for i in range(3))


@pytest.mark.parametrize('replacement', [
    'return cb ? handler(user,src,cb) : 0;',
    'handler(user,src,cb); return handler(user,src,cb);',
    'user = NULL; return handler(user,src,cb);',
    'return 0; handler(user,src,cb);',
    'saved_user = user; return handler(user,src,cb);',
])
def test_callback_schedule_requires_one_unmodified_synchronous_forward(tmp_path,replacement):
    f=graph_fixture(tmp_path,SOURCE.replace('return handler(user,src,cb);',replacement),bindings=[('parse','src','cb')])
    assert not reconcile(f)[1]['callback_dispatches']


def test_callback_shadow_and_wrong_abi_do_not_issue_function_binding(tmp_path):
    for suffix,source in [('shadow',SOURCE.replace('void usage(const unsigned char *raw,size_t extent)',
            'void usage(const unsigned char *raw,size_t extent,Handler handle)')),
            ('abi',SOURCE.replace('int handle(void *user','long handle(void *user'))]:
        directory=tmp_path/suffix;directory.mkdir()
        f=graph_fixture(directory,source,bindings=[('parse','src','cb')]);contract,graph=reconcile(f)
        assert not graph['callback_dispatches']
        assert selection(contract,f,'parse',2)['status']=='unknown'


@pytest.mark.parametrize('construction', ['zero_init','stack','constant','callback'])
def test_semantic_labels_alone_cannot_certify_argument(tmp_path,construction):
    f=graph_fixture(tmp_path,'typedef struct P {int n;} P; int parse(P *p) {return p->n;}')
    proposal(f,'parse','p',construction,constant=0 if construction=='constant' else None)
    row=selection(reconcile(f)[0],f,'parse',0)
    assert row['status']=='unknown' and row['recipe'] is None


def callback_plan(tmp_path, *, prepared_only=False, budget=None):
    from test_semantic_slicing import fixture, run, queries, tool, terminal
    from test_minimal_ft import inputs, build
    from harness_generation.semantic_slicing.persistence import save_run, run_configuration
    from harness_generation.minimal_ft.persistence import save_build
    from harness_generation.harness_context.persistence import load_minimal_ft
    from harness_generation.harness_context import ContextBudget, MiningState
    from harness_generation.harness_context.tools import HarnessContextTools
    from harness_generation.entry_candidates import CandidateCatalog
    from harness_generation.semantic_discovery.tools import RepositoryIndex
    from harness_generation.semantic_discovery.models import candidate_id
    sample=fixture(tmp_path,SOURCE,'parse');store,_,_,_,_,ids=sample
    roles={'parse':('core','accepted_anchor'),'handle':('core','core_processing'),
           'acquire':('support','resource_creation'),'dispose':('support','resource_cleanup'),
           'usage':('exclude','diagnostic_only')}
    sliced,model,tools=run(sample,[queries(tool('find_callers','caller',function=ids['parse'])),
        queries(tool('read_source_range','issued_bodies',file='api.c',line_start=1,line_end=9)),
        queries(*(tool('get_function','body_'+n,function=ids[n]) for n in roles)),
        terminal({ids[n]:role for n,role in roles.items()})])
    assert sliced.result['run_status']=='completed'
    save_run(store,sliced,run_configuration(sample[2],tools.frontier,tools.budget,model,32))
    sample=(store,candidate_id(ids['parse']),ids)
    _,snapshot,configuration=inputs(sample);built=build(sample);save_build(store,built,configuration)
    ft,metadata=load_minimal_ft(store,built.minimal_ft['ft_id'],snapshot)
    catalog=CandidateCatalog((),snapshot.source_fingerprint)
    state=MiningState(budget or ContextBudget(max_total_model_calls=80,max_tool_calls=200,max_source_chars=300000))
    context_tools=HarnessContextTools(snapshot,catalog,ft,state,index=RepositoryIndex(snapshot.artifacts,catalog,functions_path=store.functions))
    prepared=(sample,ft,metadata,snapshot,state,context_tools)
    ids=prepared[0][-1];fid=ids['parse'];creator=ids['acquire'];cleanup=ids['dispose'];rid=resource_id(creator)
    specs=direct_specs(fid,data='src',size='cb')
    specs[fid,'argument_construction']['value']['arguments'] += [argument('handler','callback',ids['handle']),argument('user','creator_api',creator,rid)]
    specs[fid,'ownership']['value']['entries'].append(owner('user',resource=rid))
    specs[fid,'callback']={'value':{'callbacks':[dict(parameter='handler',signature='int (*handler)(void *user,const unsigned char *src,size_t cb)',
        mandatory=True,setup_api=ids['handle'],userdata='user',lifetime='during_call',null_allowed=False)]}}
    specs.update(direct_specs(ids['handle'],data='src',size='cb'))
    # Input and length come from the dispatcher proof, not duplicate proposals.
    del specs[ids['handle'],'input_binding']
    del specs[ids['handle'],'buffer_length']
    specs[ids['handle'],'argument_construction']['value']['arguments'].insert(0,argument('user','creator_api',creator,rid))
    specs[ids['handle'],'ownership']['value']['entries'].append(owner('user',resource=rid))
    specs[creator,'lifecycle']={'value':lifecycle_value(creator,rid,'User',None,creator,cleanup),
        'dependencies':[dict(function_id=cleanup,necessity='required',reason='cleanup')]}
    specs[creator,'ownership']={'value':{'entries':[owner(returned=True,ownership='owned',release=cleanup,resource=rid)]}}
    specs[creator,'return_semantics']={'value':dict(success='nonnull',nullable=True,owned=True,error_cleanup=False)}
    specs[creator,'call_order']={'value':{'constraints':[order(creator,cleanup)]}}
    for parent in [fid,ids['handle']]:
        specs[parent,'argument_construction']['dependencies']=[dict(function_id=creator,necessity='required',reason='creation')]
        specs[parent,'call_order']={'value':{'constraints':[order(creator,parent),order(parent,cleanup)]}}
    specs[creator,'support_decision']={'value':dict(decision='required',reason='creation',required_by=[fid,ids['handle']])}
    specs[cleanup,'support_decision']={'value':dict(decision='required',reason='cleanup',required_by=[creator])}
    if prepared_only:
        return prepared,specs
    run,_=mine(prepared,specs,query_type='User',persist=True)
    assert_gate(run)
    assert ids['usage'] not in prepared[4].discoveries
    assert ids['usage'] not in {r['function_id'] for r in run.closure['required_support_apis']}
    frozen=load_frozen_inputs(prepared[0][0],prepared[1]['ft_id'])
    return prepared[0][0],HarnessPlanBuilder().build(*frozen[:5])


CODE='''#include <stdint.h>
#include <stddef.h>
typedef struct User { unsigned bias; } User;
typedef int (*Handler)(void *user,const unsigned char *src,size_t cb);
extern "C" User *acquire(unsigned bias);
extern "C" void dispose(User *u);
extern "C" int handle(void *user,const unsigned char *src,size_t cb);
extern "C" int parse(const unsigned char *src,size_t cb,Handler handler,void *user);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size) {
 if(size>1048576) return 0;
 User *u=acquire(0);
 if(u) { (void)parse(data,size,handle,u); dispose(u); }
 return 0;
}
'''


def test_plan_preserves_core_callback_without_extra_direct_call(tmp_path):
    _,plan=callback_plan(tmp_path)
    callback=next(c for c in plan['call_sequence'] if c['symbol']=='handle')
    assert callback['invocation_kind']=='callback'
    assert callback['via_function_id']==next(c['function_id'] for c in plan['call_sequence'] if c['symbol']=='parse')
    assert validate_code(CODE,plan)['status']=='valid'
    inherited=next(b for b in plan['contracts']['input_contract']['bindings'] if b['function_id']==callback['function_id'])
    assert inherited['source']=='derived' and inherited['via_function_id']==callback['via_function_id']
    stub=CODE.replace('extern "C" int handle(void *user,const unsigned char *src,size_t cb);',
        'extern "C" int handle(void *user,const unsigned char *src,size_t cb);\nstatic int empty(void *user,const unsigned char *src,size_t cb) { return 0; }').replace('parse(data,size,handle,u)','parse(data,size,empty,u)')
    assert 'canonical_callback_binding_mismatch' in validate_code(stub,plan)['errors']
    double=CODE.replace('(void)parse','(void)handle(u,data,size); (void)parse')
    assert validate_code(double,plan)['status']=='invalid'
    swapped=CODE.replace('parse(data,size,handle,u)','parse(data,size,handle,NULL)')
    assert 'canonical_resource_binding_mismatch' in validate_code(swapped,plan)['errors']


def test_bound_callback_harness_compiles_and_runs_under_sanitizers(tmp_path):
    if not shutil.which('clang') or not shutil.which('clang++'):
        pytest.skip('clang toolchain unavailable')
    from harness_generation.cli import main
    from harness_generation.llm import FakeLLM
    import json
    store,_=callback_plan(tmp_path)
    assert main(['context-generate','--artifacts',str(store.root),'--build','--runtime'],llm=FakeLLM([CODE]))==0
    runtime=next((store.root/'context_generations').glob('**/runtime.json'))
    replay=json.loads(runtime.read_text())
    assert replay['status']=='passed' and len(replay['cases'])==6


def test_planned_creator_requires_body_effect_issued_identity_and_recursive_arguments(tmp_path):
    source='typedef struct P {int n;} P; P *make(unsigned mode) {static P p;return &p;} int parse(P *p){return p->n;}'
    f=graph_fixture(tmp_path,source)
    proposal(f,'parse','p','creator_api',api='make',rid=resource_id(f[-1]['make']))
    row=selection(reconcile(f)[0],f,'parse',0)
    assert row['status']=='unknown' and row['reason']=='creator_argument_missing'
    proposal(f,'make','mode','constant',constant=0)
    assert selection(reconcile(f)[0],f,'parse',0)['status']=='unknown'  # A proposed zero is not source evidence.
    clone=lambda:[deepcopy(f[0]),deepcopy(f[1]),deepcopy(f[2]),f[3],deepcopy(f[4]),dict(f[5])]
    bare=clone()
    bare[0]['argument_contract']['arguments'][0]['resource_id']='resource_unissued'
    assert selection(reconcile(bare)[0],bare,'parse',0)['recipe'] is None
    no_body=clone()
    no_body[4].clear()
    assert selection(reconcile(no_body)[0],no_body,'parse',0)['recipe'] is None
    excluded=clone();excluded[1]['excluded_functions']=[f[-1]['make']]
    assert selection(reconcile(excluded)[0],excluded,'parse',0)['recipe'] is None
