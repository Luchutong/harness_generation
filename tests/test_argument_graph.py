"""Source-backed dependency regressions; no API/project-name heuristics."""
from copy import deepcopy
import json

import pytest

from harness_generation.artifacts import ArtifactStore
from harness_generation.minimal_ft.models import ProjectSnapshot
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.records import write_json
from sfg_builder.parser import CProjectParser, write_functions_json
from harness_generation.semantic_discovery.models import digest
from harness_generation.harness_context.argument_graph import build_argument_graph, parameter_id
from harness_generation.harness_context.requirements import HarnessRequirementBuilder
from harness_generation.harness_context.evidence import CONTRACT_FIELDS, HarnessContextValidator
from test_harness_context import setup, mine, direct_specs, context_specs


def graph_fixture(tmp_path, source, *, anchor='parse', bindings=(), owners=()):
    project = tmp_path / 'source'
    project.mkdir()
    (project / 'unit.c').write_text(source)
    store = ArtifactStore(tmp_path / 'artifacts')
    write_functions_json(CProjectParser().parse(project), store.functions, project=project)
    for path, key in ((store.annotations,'annotations'), (store.flows,'flows')):
        write_json(path, {'schema_version':1, key:[]})
    write_json(store.sfg, {'schema_version':1,'nodes':[],'edges':[],'functions':[]})
    snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(store.root))
    ids = {f['name']:fid for fid,f in snapshot.functions.items()}
    ft = {'ft_id':'ft_offline_graph', 'anchor_function_id':ids[anchor], 'source_slice':{},
        'core_functions':[{'function_id':ids[anchor], 'evidence_ids':[]}],
        'support_candidates':[{'function_id':fid, 'evidence_ids':[]} for name,fid in ids.items() if name!=anchor],
        'excluded_functions':[], 'unresolved_dependencies':[], 'relations':[]}
    requirements = HarnessRequirementBuilder().build(ft,snapshot)['requirements']
    context = {'core_apis':[ids[anchor]], 'facts':[]}
    for _,(section,field) in CONTRACT_FIELDS.items():
        context[section] = {field:[]}
    evidence = {}
    for fid,function in snapshot.functions.items():
        record = {'function_id':fid,'tool':'get_function','content':function['body'],
                  'source':function['file'],'truncated':False}
        eid = 'ev_' + digest({'snapshot':snapshot.source_fingerprint,'record':record})[:32]
        evidence[eid] = {**record,'evidence_id':eid}
    def eids(fid):
        return [eid for eid,r in evidence.items() if r['function_id']==fid]
    for function,parameter,length in bindings:
        fid = ids[function]
        context['input_contract']['bindings'].append({'function_id':fid,'parameter':parameter,'size_parameter':length,
            'source':'fuzz_data','transform':'direct','evidence_ids':eids(fid)})
    for function,parameter,returned,ownership in owners:
        fid=ids[function]
        context['ownership_contract']['entries'].append({'function_id':fid,'parameter':parameter,
            'return_value':returned,'ownership':ownership,'release_api':None,'evidence_ids':eids(fid)})
    return context,ft,requirements,snapshot,evidence,ids


def inspect(fixture):
    return build_argument_graph(*fixture[:5])


def construction(graph, fid, index):
    return next((p for p in graph['dependency_graph']['resolved_parameters']
                 if p['target_parameter']==parameter_id(fid,index)),None)


def hole(graph, fid, index):
    return next(p for p in graph['dependency_graph']['unresolved_parameters']
                if p['parameter_id']==parameter_id(fid,index))


@pytest.mark.parametrize('names',[('data','size'),('src','cb')])
def test_direct_and_nonstandard_names_need_binding_evidence(tmp_path,names):
    data,size=names
    source=f'typedef unsigned long size_t; int parse(const unsigned char *{data},size_t {size}) {{ return {size} ? {data}[0] : 0; }}'
    fixture=graph_fixture(tmp_path,source,bindings=[('parse',data,size)])
    graph=inspect(fixture);fid=fixture[-1]['parse']
    assert construction(graph,fid,0)['source_kind']=='fuzz_bytes'
    assert construction(graph,fid,1)['source_kind']=='fuzz_size'
    bare=deepcopy(fixture[0]);bare['input_contract']['bindings']=[]
    graph=build_argument_graph(bare,*fixture[1:5])
    assert construction(graph,fid,1) is None  # size_t/name alone proves nothing.


BASE='''typedef struct P { const unsigned char *b; unsigned long n; } P;
typedef struct C { unsigned flags; } C;
typedef struct A { int mode; } A;
P *supply(C *config,A *allocator) { static P p; return &p; }
void retire(P *p) { free(p); }
int parse(P *p) { return p->n ? p->b[0] : 0; }
'''


def test_creator_arguments_form_recursive_holes_then_close(tmp_path):
    source=BASE+'void usage(C *c,A *a) { P *p=supply(c,a); parse(p); retire(p); }'
    fixture=graph_fixture(tmp_path,source);graph=inspect(fixture);ids=fixture[-1]
    missing=hole(graph,ids['parse'],0)
    assert missing['code']=='creator_argument_missing'
    assert set(missing['missing_dependencies'])=={parameter_id(ids['supply'],0),parameter_id(ids['supply'],1)}
    candidates=[c for c in graph['construction_candidates'] if c['target_parameter']==parameter_id(ids['parse'],0)]
    assert candidates[0]['source_kind']=='creator_return' and candidates[0]['proof_status']=='proven'
    assert graph['resource_origins'][0]['ownership']=='unresolved'


def test_creator_accepts_local_config_and_allocator_without_ownership_inference(tmp_path):
    fixture=graph_fixture(tmp_path,BASE+'void usage(void) { C c={0}; A a={0}; P *p=supply(&c,&a); parse(p); retire(p); }')
    graph=inspect(fixture);ids=fixture[-1]
    assert construction(graph,ids['parse'],0)['source_kind']=='creator_return'
    assert construction(graph,ids['supply'],0)['source_kind']=='zero_initialized_object'
    assert construction(graph,ids['supply'],1)['source_kind']=='zero_initialized_object'
    assert graph['unresolved_ownership']
    assert any(e['kind']=='released_by' for e in graph['edges'])
    assert {e['reason'] for e in graph['state_dependencies']} >= {'graph_proven_runtime_origin','graph_same_origin_release'}


def test_out_parameter_has_its_own_storage_and_resource(tmp_path):
    source=BASE+'''int fill(P **out,C *opts) { *out=supply(opts,0); return 0; }
void usage(void) { C cfg={0}; P *p; fill(&p,&cfg); parse(p); retire(p); }'''
    fixture=graph_fixture(tmp_path,source);graph=inspect(fixture);ids=fixture[-1]
    proof=construction(graph,ids['parse'],0)
    assert proof and proof['source_kind']=='out_parameter'
    assert construction(graph,ids['fill'],0)['source_kind']=='local_stack_object'
    assert any(n['node_type']=='OutParameter' for n in graph['nodes'])
    origin=next(n for n in graph['resource_origins'] if n['resource_id']==proof['resource_id'])
    assert origin['origin']['kind']=='out_parameter' and origin['ownership']=='unresolved'


def test_multiple_same_type_resources_keep_call_instances(tmp_path):
    source='''typedef struct P { int v; } P;
P *supply(void) { static P p; return &p; }
int parse(P *a,P *b) { return a->v+b->v; }
void usage(void) { P *a=supply(); P *b=supply(); parse(a,b); }'''
    fixture=graph_fixture(tmp_path,source);graph=inspect(fixture);fid=fixture[-1]['parse']
    assert construction(graph,fid,0)['resource_id']!=construction(graph,fid,1)['resource_id']
    assert len(graph['resource_origins'])==2


@pytest.mark.parametrize('usage',[
    'P *a=supply(); P *b=a; parse(b); retire(a);',
    'Holder holder; holder.ctx=supply(); parse(holder.ctx); retire(holder.ctx);'])
def test_alias_and_struct_field_preserve_origin(tmp_path,usage):
    source='''typedef struct P { int v; } P; typedef struct Holder { P *ctx; } Holder;
P *supply(void) { static P p; return &p; }
int parse(P *p) { return p->v; } void retire(P *p) { free(p); }
void usage(void) { '''+usage+' }'
    fixture=graph_fixture(tmp_path,source);graph=inspect(fixture);ids=fixture[-1]
    assert construction(graph,ids['parse'],0)['resource_id']==construction(graph,ids['retire'],0)['resource_id']
    assert any(e['kind']=='aliases' for e in graph['edges'])


@pytest.mark.parametrize('usage',[
    'P *p=supply(); p=other; parse(p);',
    'P *p=condition?supply():alternate(); parse(p);',
    'P *p; if(condition) p=supply(); else p=alternate(); parse(p);',
    'P *p=supply(); while(condition) p=alternate(); parse(p);'])
def test_reassignment_branch_and_loop_are_unresolved(tmp_path,usage):
    source='''typedef struct P { int v; } P;
P *supply(void) { static P p; return &p; } P *alternate(void) { static P p; return &p; }
int parse(P *p) { return p->v; }
void usage(P *other,int condition) { '''+usage+' }'
    fixture=graph_fixture(tmp_path,source);graph=inspect(fixture);fid=fixture[-1]['parse']
    assert construction(graph,fid,0) is None
    assert hole(graph,fid,0)['code'] in {'resource_alias_ambiguous','argument_origin_missing'}


@pytest.mark.parametrize('expression,accepted',[
    ('n',True),('n-1',False),('n+4',False),('(n<4096?n:4096)',True),('(n<4096?n:4096)+4',True),('arbitrary(n)',False)])
def test_scalar_ir_has_bounds_and_never_executes_c(tmp_path,expression,accepted):
    source='''typedef unsigned long size_t;
int parse(const unsigned char *b,size_t count) { return count ? b[0] : 0; }
void usage(const unsigned char *x,size_t n) { parse(x,'''+expression+'); }'
    fixture=graph_fixture(tmp_path,source,bindings=[('usage','x','n')]);graph=inspect(fixture);fid=fixture[-1]['parse']
    proof=construction(graph,fid,1)
    assert (proof is not None)==accepted
    if accepted:
        assert isinstance(proof['expression'],dict) and proof['expression']['op'] in {'fuzz_size','min','add'}


@pytest.mark.parametrize('writes,expected',[('p->b=b; p->n=n;',True),('(void)b; (void)n;',False)])
def test_feed_order_requires_same_origin_writer_reader(tmp_path,writes,expected):
    source='''typedef struct P { const unsigned char *b; unsigned long n; } P;
P *supply(void) { static P p; return &p; }
void feed(P *p,const unsigned char *b,unsigned long n) { '''+writes+''' }
int parse(P *p) { return p->n ? p->b[0] : 0; }
void usage(const unsigned char *b,unsigned long n) { P *p=supply(); feed(p,b,n); parse(p); }'''
    fixture=graph_fixture(tmp_path,source);graph=inspect(fixture);ids=fixture[-1]
    assert any(e['before']==ids['feed'] and e['after']==ids['parse'] and e['reason']=='graph_same_origin_field_write_read'
               for e in graph['state_dependencies'])==expected


def test_owned_return_uses_independent_ownership_evidence(tmp_path):
    source='''typedef struct P { int v; } P;
P *parse(void) { static P p; return &p; } void retire(P *p) { free(p); }
void usage(void) { P *p=parse(); retire(p); }'''
    fixture=graph_fixture(tmp_path,source);graph=inspect(fixture)
    assert graph['unresolved_ownership']
    fixture=(*fixture[:5],fixture[-1])
    fid=fixture[-1]['parse']; eid=next(e for e,r in fixture[4].items() if r['function_id']==fid)
    context=deepcopy(fixture[0]);context['ownership_contract']['entries']=[{'function_id':fid,'parameter':None,
        'return_value':True,'ownership':'owned','evidence_ids':[eid]}]
    graph=build_argument_graph(context,*fixture[1:5])
    assert not graph['unresolved_ownership']
    assert graph['resource_origins'][0]['ownership_evidence'][0]['ownership']=='owned'


def test_proof_ids_are_stable_and_modified_source_evidence_is_ignored(tmp_path):
    fixture=graph_fixture(tmp_path,'int parse(int flags) { return flags; } void usage(void) { parse(3); }')
    graph=inspect(fixture);fid=fixture[-1]['parse']; assert construction(graph,fid,0)['constant']==3
    assert inspect(fixture)==graph
    evidence=deepcopy(fixture[4])
    for record in evidence.values():
        if record['function_id']==fixture[-1]['usage']:
            record['content']=record['content'].replace('3','9')
    tampered=build_argument_graph(*fixture[:4],evidence)
    assert construction(tampered,fid,0) is None


def test_wrapper_diagnostic_does_not_reclassify_core(tmp_path):
    fixture=graph_fixture(tmp_path,'int inner(int value) { return value; } int parse(int flags) { return inner(flags); }')
    graph=inspect(fixture)
    assert graph['wrapper_diagnostics'][0]['role']=='delegation_wrapper'
    assert graph['wrapper_diagnostics'][0]['changes_core_classification'] is False


def test_dependency_cycle_is_observed_without_recursion_failure(tmp_path):
    source='''void second(int value); void first(int value) { second(value); }
void second(int value) { first(value); } int parse(int flags) { return flags; }'''
    fixture=graph_fixture(tmp_path,source);graph=inspect(fixture)
    assert graph['dependency_graph']['cycles']
    assert any(d['code']=='dependency_cycle' for d in graph['diagnostics'])


def test_release_before_consumer_is_not_a_constructed_live_resource(tmp_path):
    source='''typedef struct P { int v; } P; P *supply(void) { static P p; return &p; }
void retire(P *p) { free(p); } int parse(P *p) { return p->v; }
void usage(void) { P *p=supply(); retire(p); parse(p); }'''
    fixture=graph_fixture(tmp_path,source);graph=inspect(fixture)
    assert construction(graph,fixture[-1]['parse'],0) is None
    assert hole(graph,fixture[-1]['parse'],0)['code']=='resource_alias_ambiguous'


def test_conditional_out_write_is_a_specific_hole(tmp_path):
    source='''typedef struct P { int v; } P; P *supply(void) { static P p; return &p; }
int fill(P **out,int choice) { if(choice) *out=supply(); return 0; }
int parse(P *p) { return p->v; } void usage(void) { P *p; fill(&p,1); parse(p); }'''
    fixture=graph_fixture(tmp_path,source);graph=inspect(fixture)
    assert construction(graph,fixture[-1]['parse'],0) is None
    assert hole(graph,fixture[-1]['parse'],0)['code']=='out_parameter_origin_unknown'


def test_gate_recomputes_graph_and_rejects_tampered_artifact(tmp_path):
    prepared=setup(tmp_path)
    run,_=mine(prepared,direct_specs(prepared[0][-1]['parse']),persist=True)
    assert run.completeness['generation_allowed']
    directory=prepared[0][0].root/'harness_contexts'/run.context['ft_id']
    assert json.loads((directory/'argument_graph.json').read_text())==run.context['argument_graph']
    mutated=deepcopy(run.context); mutated['argument_graph']['dependency_graph']['unresolved_parameters']=[]
    mutated['argument_graph']['version']='fabricated'
    errors=HarnessContextValidator().validate(mutated,prepared[1],prepared[3],run.requirements['requirements'],prepared[4].evidence,prepared[5].initial_ids)
    assert errors and errors[0]['code']=='context_changed_canonical_projection'


def test_graph_origin_resolution_does_not_discharge_ownership_requirement(tmp_path):
    source='''typedef struct P { int v; } P; P *supply(void) { static P p; return &p; }
int parse(P *p) { return p->v; } void usage(void) { P *p=supply(); parse(p); }'''
    prepared=setup(tmp_path,source,roles={'parse':('core','accepted_anchor'),'supply':('support','resource_creation')})
    run,_=mine(prepared,{})
    assert run.context['argument_graph']['dependency_graph']['resolved_parameters']
    assert not run.completeness['generation_allowed']
    assert any(row['kind']=='ownership' for row in run.completeness['hard_missing'])
    assert not any(row.get('proof_kind')=='argument-construction-graph-v1' and
        next(r for r in run.requirements['requirements'] if r['requirement_id']==row['requirement_id'])['kind']=='ownership'
        for row in run.context['framework_satisfied_requirements'])


def test_parameter_ids_and_resource_registry_are_not_model_labels(tmp_path):
    from harness_generation.harness_context.argument_graph import issued_resource_ids
    fixture=graph_fixture(tmp_path,'typedef struct P { int v; } P; P *parse(void) { return 0; }')
    catalog=issued_resource_ids(fixture[3],fixture[4],set(fixture[-1].values()))
    assert catalog and 'resource_invented_by_model' not in catalog
    assert all(r.startswith('resource_') for r in catalog)
