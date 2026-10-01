"""Offline signed-source Context → Plan → real compiler/runtime for new recipes.

Semantic facts here are explicit regression fixtures, never native evaluation
results. Real source parsing, gates, Plan lowering and local compilation run.
"""
import shutil

import pytest

from harness_generation.cli import main
from harness_generation.llm import FakeLLM
from harness_generation.context_generation import HarnessPlanBuilder
from harness_generation.harness_context.requirements import HarnessRequirementBuilder
from test_harness_context import setup, mine, context_specs, direct_specs, owner, argument, resource_id, assert_gate, order


def fixture(tmp_path,out):
    creator=('int create(Context **out,const Config *cfg) { (void)cfg; *out=calloc(1,sizeof(Context)); return *out!=NULL; }'
        if out else 'Context *create(const Config *cfg) { (void)cfg; return calloc(1,sizeof(Context)); }')
    call='Context *ctx; create(&ctx,&cfg);' if out else 'Context *ctx=create(&cfg);'
    source='''#include <stdlib.h>
#include <stddef.h>
typedef struct Config {unsigned flags;} Config;
typedef struct Context {int ready;int calls;} Context;
'''+creator+'''
void destroy(Context *ctx) {free(ctx);}
int parse(Context *ctx,const unsigned char *data,size_t size) {ctx->calls++;return size?data[0]:0;}
void usage(const unsigned char *data,size_t size) {Config cfg={0};'''+call+'parse(ctx,data,size);destroy(ctx);}'
    prepared=setup(tmp_path,source)
    store,_,ids=prepared[0]
    # Preload exact signed bodies with the existing tool; no graph is fabricated.
    req=HarnessRequirementBuilder().build(prepared[1],prepared[3])['requirements'][0]
    prepared[5].activate(req)
    for fid in ids.values():prepared[5].execute('get_function',{'function':fid})
    specs=context_specs(ids);create=ids['create'];rid=resource_id(ids['parse'],'ctx')
    specs[create,'argument_construction']={'value':{'arguments':[argument('cfg','zero_init')]}}
    specs[create,'ownership']={'value':{'entries':[owner('cfg')]}}
    specs[create,'lifecycle']['value']['resources'].append({'resource_id':resource_id(create,'cfg'),
        'type':'Config','subject_parameter':'cfg','return_value':False,
        'creation':{'kind':'stack','api':None},'initialization':{'api':None,'mandatory':False},
        'cleanup':{'api':None,'mandatory':False},'reuse':'per_input'})
    if out:
        specs[create,'argument_construction']['value']['arguments'].insert(0,argument('out','zero_init'))
        specs[create,'ownership']['value']['entries'].insert(0,owner('out'))
        specs[create,'ownership']['value']['entries'].append({**owner('out',ownership='owned',release=ids['destroy'],resource=rid),
            'subject_kind':'OutParameterPointee'})
        specs[create,'return_semantics']={'value':{'success':'nonzero','nullable':None,'owned':None,'error_cleanup':False}}
        output=specs[create,'lifecycle']['value']['resources'][0]
        output.update(subject_parameter='out',return_value=False,resource_id=rid)
    else:
        specs[create,'ownership']['value']['entries'].append(owner(returned=True,ownership='owned',release=ids['destroy'],resource=rid))
    run,_=mine(prepared,specs,query_type='Context',persist=True)
    assert_gate(run)
    plan=HarnessPlanBuilder().build(prepared[1],run.context,run.closure,prepared[3],run.completeness)
    return store,plan


@pytest.mark.parametrize('out',[False,True])
def test_creator_parameters_and_out_storage_compile_and_replay(tmp_path,out):
    if not shutil.which('clang') or not shutil.which('clang++'):
        pytest.skip('clang toolchain unavailable')
    store,plan=fixture(tmp_path,out)
    kinds={r['kind'] for r in plan['construction_recipes']}
    assert 'stack_zero_init' in kinds
    assert ('out_parameter_storage' in kinds)==out
    prototype='int create(Context **out,const Config *cfg);' if out else 'Context *create(const Config *cfg);'
    construct='Context *ctx=NULL; int ok=create(&ctx,&cfg);' if out else 'Context *ctx=create(&cfg);'
    guard='ok && ctx' if out else 'ctx'
    code='''#include <stdint.h>
#include <stddef.h>
typedef struct Config {unsigned flags;} Config;
typedef struct Context {int ready;int calls;} Context;
extern "C" '''+prototype+'''
extern "C" int parse(Context *ctx,const unsigned char *data,size_t size);
extern "C" void destroy(Context *ctx);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size) {
if(size>1048576) return 0; Config cfg={}; '''+construct+' if('+guard+') {parse(ctx,data,size);destroy(ctx);} return 0;}'
    assert main(['context-generate','--artifacts',str(store.root),'--build','--runtime'],llm=FakeLLM([code]))==0


def test_bounded_scalar_contract_lowers_compiles_and_replays(tmp_path):
    if not shutil.which('clang') or not shutil.which('clang++'):
        pytest.skip('clang toolchain unavailable')
    source='''#include <stdlib.h>
#include <stddef.h>
int parse(const unsigned char *data,size_t size) {if(size>16) abort();return size?data[size-1]:0;}
int usage(const unsigned char *data,size_t size) {size_t prefix=size<16?size:16;return parse(data,prefix);}
'''
    # A wrapper explicitly accepted as the anchor is retained. It cannot enter
    # another target's CORE merely because it supplies that target's arguments.
    prepared=setup(tmp_path,source,anchor='usage',roles={'parse':('core','core_processing'),
        'usage':('core','accepted_anchor')},discover_callers=True)
    store,_,ids=prepared[0]
    requirement=HarnessRequirementBuilder().build(prepared[1],prepared[3])['requirements'][0]
    prepared[5].activate(requirement)
    for fid in ids.values():
        prepared[5].execute('get_function',{'function':fid})
    specs=direct_specs(ids['parse'])
    specs[ids['parse'],'buffer_length']['value']['links'][0]['relation']='derived'
    specs.update(direct_specs(ids['usage']))
    for fid in ids.values():
        specs[fid,'call_order']={'value':{'constraints':[order(ids['usage'],ids['parse'])]}}
    run,_=mine(prepared,specs,persist=True)
    assert_gate(run)
    plan=HarnessPlanBuilder().build(prepared[1],run.context,run.closure,prepared[3],run.completeness)
    scalar=next(r for r in plan['construction_recipes'] if r['kind']=='derived_scalar')
    assert scalar['bounds']==[0,16]
    code='''#include <stdint.h>
#include <stddef.h>
extern "C" int parse(const unsigned char *data,size_t size);
extern "C" int usage(const unsigned char *data,size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size) {
if(size>1048576) return 0;usage(data,size);size_t prefix=size<16?size:16;parse(data,prefix);return 0;}
'''
    assert main(['context-generate','--artifacts',str(store.root),'--build','--runtime'],llm=FakeLLM([code]))==0
