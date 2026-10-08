"""Source counterexamples, coverage and monotone exact-subject repair."""
from copy import deepcopy

import pytest

from harness_generation.harness_context.proof_grounding import analyze, field_proofs, contradictions
from harness_generation.harness_context.repairs import merge_resolution, fact_conflicts
from test_harness_context import setup, owner


def analysis_fixture(tmp_path, source):
    prepared = setup(tmp_path, source)
    snapshot, ids = prepared[3], prepared[0][-1]
    records = {"ev_" + name: {"evidence_id": "ev_" + name, "tool": "get_function", "function_id": fid,
        "content": snapshot.functions[fid]["body"], "truncated": False} for name, fid in ids.items()}
    issued = {fid: {"ev_" + name} for name, fid in ids.items()}
    return snapshot, ids, records, issued


BASE = '''typedef unsigned long size_t;
typedef struct Context { unsigned ready; unsigned other; } Context;
Context *create(void) { return calloc(1,sizeof(Context)); }
void prime(Context *ctx) { BODY }
int parse(Context *ctx,const unsigned char *data,size_t size) { if(ctx->ready!=1) __builtin_trap(); return size?data[0]^ctx->other:ctx->other; }
'''


def field_case(tmp_path, body, *, condition=True):
    snapshot, ids, records, issued = analysis_fixture(tmp_path, BASE.replace('BODY', body))
    context = {"core_apis": [ids['parse']], "canonical_construction": {"parameters": [
        dict(function_id=ids['parse'],parameter='ctx',recipe=dict(kind='creator_call',producer_api=ids['create'],resource_id='resource_one')),
        dict(function_id=ids['prime'],parameter='ctx',recipe=dict(kind='resource_reference',resource_id='resource_one'))]},
        "state_contract": {"preconditions": [dict(function_id=ids['parse'],parameter='ctx',kind='initialized',api=ids['prime'])] if condition else []}}
    rows = field_proofs(context, snapshot, records, {"required_support_apis": []})
    return rows, context, snapshot, ids, records


@pytest.mark.parametrize('body,expected', [
    ('ctx->other=1;', 'initializer_field_or_object_mismatch'),
    ('if(ctx->other) ctx->ready=1;', 'initializer_conditional_or_unreproduced_write'),
    ('Context other={0}; other.ready=1;', 'initializer_field_or_object_mismatch'),
    ('Context *other=create(); other->ready=1;', 'initializer_field_or_object_mismatch'),
    ('ctx->ready=0;', 'initializer_field_value_mismatch'),
    ('return; ctx->ready=1;', 'initializer_field_or_object_mismatch'),
    ('ctx->ready+=1;', 'initializer_conditional_or_unreproduced_write'),
])
def test_wrong_field_conditional_other_object_value_and_unreachable_write_do_not_prove(tmp_path, body, expected):
    rows, *_ = field_case(tmp_path, body)
    ready = next(r for r in rows if r['field']=='ready')
    assert ready['status'] != 'proved' and ready['code'] == expected
    assert ready['evidence_ids']


@pytest.mark.parametrize('body', ['ctx->ready=1;ctx->other=0;',
    'Context *alias=ctx;alias->ready=1;alias->other=0;',
    'if(!ctx) return; ctx->ready=1;ctx->other=0;',
    'if(ctx->other) ctx->ready=1;else ctx->ready=1;ctx->other=0;'])
def test_definite_same_object_write_alias_and_both_branches_are_positive(tmp_path, body):
    rows, *_ = field_case(tmp_path, body)
    assert all(r['status']=='proved' for r in rows)


def test_parameter_reassignment_to_another_object_is_not_same_object_proof(tmp_path):
    rows, *_ = field_case(tmp_path, 'Context *other=create();ctx=other;ctx->ready=1;')
    assert next(r for r in rows if r['field']=='ready')['status']=='contradicted'


def test_omitted_state_proposal_does_not_omit_required_guard_or_field(tmp_path):
    rows, *_ = field_case(tmp_path, 'ctx->other=1;', condition=False)
    assert {r['field'] for r in rows} == {'ready','other'}
    assert next(r for r in rows if r['field']=='ready')['status'] != 'proved'


def test_callback_retention_contradicts_during_call_lifetime(tmp_path):
    source='''typedef unsigned long size_t;
typedef int (*Callback)(void *user,const unsigned char *data,size_t size);
static void *saved;
int parse(void *user,Callback cb,const unsigned char *data,size_t size) { saved=user;return cb(user,data,size); }
'''
    snapshot, ids, records, _ = analysis_fixture(tmp_path, source)
    common={'function_id':ids['parse'],'fact_id':'fact_owned','evidence_ids':['ev_parse']}
    context={'ownership_contract':{'entries':[{**common,**owner('user')}]},
        'callback_contract':{'callbacks':[{**common,'userdata':'user','lifetime':'during_call'}]}}
    rows=contradictions(context,snapshot,records)
    assert {r['code'] for r in rows} == {'ownership_escape_lifetime_conflict','callback_userdata_escape_lifetime_conflict'}
    context['ownership_contract']['entries'][0]['lifetime']='until_context_cleanup'
    context['callback_contract']['callbacks'][0]['lifetime']='per_context'
    assert not contradictions(context,snapshot,records)


def test_cleanup_reassigning_parameter_and_freeing_wrong_object_is_rejected(tmp_path):
    source='''typedef unsigned long size_t;
typedef struct Node {int n;} Node;
static Node *saved;
Node *parse(const unsigned char *data,size_t size) { Node *p=malloc(sizeof(Node));return p; }
void finish(Node *p) {p=saved;free(p);}
'''
    snapshot,ids,records,issued=analysis_fixture(tmp_path,source)
    context={'ownership_contract':{'entries':[dict(function_id=ids['parse'],fact_id='fact_return',evidence_ids=['ev_parse','ev_finish'],
        **owner(returned=True,ownership='owned',release=ids['finish']))]},'callback_contract':{'callbacks':[]}}
    assert {r['code'] for r in contradictions(context,snapshot,records)} == {'cleanup_object_or_path_conflict'}
    summary=analyze(snapshot.functions[ids['finish']],snapshot,issued)
    assert all('parameter:p' not in p['released'] for p in summary['paths'])


def repair_input(entries, *, kind='ownership'):
    field={'ownership':'entries','argument_construction':'arguments'}[kind]
    req={'requirement_id':'req_one','subject_function_id':'api:parse','kind':kind}
    result={'requirement_id':'req_one','status':'resolved','facts':[dict(requirement_id='req_one',function_id='api:parse',predicate=kind,
        value={field:entries},evidence_ids=['ev_subject'])], 'discovered_api_dependencies':[], 'open_questions':[]}
    return req,result


def test_patch_one_subject_preserves_other_subject_and_old_evidence():
    req,previous=repair_input([owner('data'),{**owner('ctx',ownership='unknown'),'lifetime':'unknown'}])
    previous['facts'][0]['evidence_ids'].append('ev_old')
    _,incoming=repair_input([owner('ctx')]);incoming['facts'][0]['evidence_ids'].append('ev_new')
    merged,audit=merge_resolution(previous,incoming,req)
    rows={r['parameter']:(r,f['evidence_ids']) for f in merged['facts'] for r in f['value']['entries']}
    assert set(rows)=={'data','ctx'} and rows['data'][0]==owner('data')
    assert rows['data'][1]==['ev_old','ev_subject']
    assert set(rows['ctx'][1])=={'ev_old','ev_new','ev_subject'}
    assert not audit['conflicts'] and not fact_conflicts(merged['facts'])


def test_same_subject_conflict_is_explicit_not_last_write_wins():
    req,previous=repair_input([owner('data'),owner('ctx')])
    _,incoming=repair_input([owner('ctx',ownership='transferred')])
    merged,audit=merge_resolution(previous,incoming,req)
    assert audit['conflicts'] and fact_conflicts(merged['facts'])
    assert len([r for f in merged['facts'] for r in f['value']['entries'] if r['parameter']=='ctx'])==2
    assert next(r for f in merged['facts'] for r in f['value']['entries'] if r['parameter']=='data')==owner('data')
    again,_=merge_resolution(merged,incoming,req)
    assert again==merged


def test_unknown_followup_cannot_retract_resolved_subject():
    req,previous=repair_input([owner('data')])
    _,incoming=repair_input([{**owner('data',ownership='unknown'),'lifetime':'unknown'}])
    merged,_=merge_resolution(previous,incoming,req)
    assert merged['facts'][0]['value']['entries']==[owner('data')]


def test_repair_distinguishes_boolean_and_integer_constants():
    from test_harness_context import argument
    req,previous=repair_input([{**argument('n','constant'),'constant':True}],kind='argument_construction')
    _,incoming=repair_input([{**argument('n','constant'),'constant':1}],kind='argument_construction')
    merged,audit=merge_resolution(previous,incoming,req)
    assert audit['conflicts'] and fact_conflicts(merged['facts'])


def test_conflicting_collection_metadata_blocks_even_with_no_rows():
    req={'requirement_id':'req_length','subject_function_id':'api:parse','kind':'buffer_length'}
    def proposal(applicable):
        return dict(requirement_id='req_length',status='resolved',facts=[dict(requirement_id='req_length',
            function_id='api:parse',predicate='buffer_length',value=dict(applicable=applicable,links=[]),evidence_ids=['ev_subject'])],
            discovered_api_dependencies=[],open_questions=[])
    merged,_=merge_resolution(proposal(True),proposal(False),req)
    assert fact_conflicts(merged['facts'])


def test_uninterpreted_bulk_write_is_missing_not_positive_proof(tmp_path):
    rows,*_=field_case(tmp_path,'memset(ctx,1,sizeof(*ctx));')
    assert all(r['status']=='missing' for r in rows)


@pytest.mark.parametrize('conditional',[False,True])
def test_out_parameter_export_needs_same_object_on_every_path(tmp_path,conditional):
    body='Context *p=calloc(1,sizeof(Context));' + ('if(flag) *out=p;' if conditional else '*out=p;')
    source='typedef struct Context {int ready;} Context;int create(Context **out,int flag){'+body+'return 1;}int parse(Context *ctx){return ctx->ready;}'
    snapshot,ids,records,_=analysis_fixture(tmp_path,source)
    context={'core_apis':[ids['parse']],'state_contract':{'preconditions':[]},'canonical_construction':{'parameters':[
        dict(function_id=ids['parse'],parameter='ctx',recipe=dict(kind='out_parameter_call',producer_api=ids['create'],out_parameter='out',resource_id='resource_one'))]}}
    rows=field_proofs(context,snapshot,records,{'required_support_apis':[]})
    assert (rows[0]['status']=='proved') != conditional


@pytest.mark.parametrize('shadowed',['calloc','free','abort'])
def test_function_pointer_parameters_do_not_acquire_intrinsic_proofs(tmp_path,shadowed):
    definitions={
        'calloc':'Context *parse(void *(*calloc)(int,int)){return calloc(1,sizeof(Context));}',
        'free':'void parse(Context *ctx,void (*free)(void *)){free(ctx);}',
        'abort':'int parse(Context *ctx,void (*abort)(void)){if(ctx->ready!=1)abort();return ctx->ready;}',
    }
    source='typedef struct Context {int ready;} Context;'+definitions[shadowed]
    snapshot,ids,records,issued=analysis_fixture(tmp_path,source)
    result=analyze(snapshot.functions[ids['parse']],snapshot,issued)
    assert all(not p['zero'] and not p['released'] for p in result['paths'])
    assert not result['guards'] and any(p['uncertain'] for p in result['paths'])


def test_uninitialized_local_function_pointer_is_not_a_free_intrinsic(tmp_path):
    source='typedef struct Context {int ready;} Context;void parse(Context *ctx){void (*free)(void *);free(ctx);}'
    snapshot,ids,_,issued=analysis_fixture(tmp_path,source)
    result=analyze(snapshot.functions[ids['parse']],snapshot,issued)
    assert all(not p['released'] for p in result['paths']) and any(p['uncertain'] for p in result['paths'])


def coherent_context(tmp_path):
    import json
    from test_context_generation import ready
    from harness_generation.harness_context.persistence import context_directory
    from harness_generation.harness_context import MiningState, ContextBudget
    store,frozen,_=ready(tmp_path,'context')
    ft,context,closure,snapshot,report=frozen[:5]
    directory=context_directory(store,ft['ft_id'])
    requirements=json.loads((directory/'requirements.json').read_text())['requirements']
    resolutions=json.loads((directory/'resolutions.json').read_text())['resolutions']
    state=MiningState(ContextBudget())
    state.evidence={r['evidence_id']:r for r in json.loads((directory/'evidence.json').read_text())['records']}
    state.discoveries=json.loads((directory/'metadata.json').read_text())['discoveries']
    return ft,snapshot,requirements,resolutions,state,report


def rebuild(prepared):
    from harness_generation.harness_context.api_closure import build_api_closure
    from harness_generation.harness_context.evidence import build_context
    from harness_generation.harness_context import HarnessContextCompletenessValidator
    ft,snapshot,requirements,resolutions,state,_=prepared
    facts=[]
    for r in requirements:
        result=resolutions.get(r['requirement_id'])
        if result:
            r['status']=result['status'];r['evidence_ids']=sorted({e for f in result['facts'] for e in f['evidence_ids']})
            facts+=result['facts']
    closure=build_api_closure(ft,requirements,resolutions,snapshot,state)
    context=build_context(ft,requirements,facts,snapshot,state.evidence)
    context['dependencies']=closure['unresolved_api_dependencies']
    return HarnessContextCompletenessValidator().validate(context,closure,ft,snapshot,requirements,resolutions,state)


def test_one_gap_patch_closes_without_new_unrelated_gap_and_retains_proved_node(tmp_path):
    from harness_generation.harness_context.models import fact_id
    prepared=coherent_context(tmp_path);reqs,resolutions=prepared[2:4]
    req=next(r for r in reqs if r['kind']=='ownership' and prepared[1].functions[r['subject_function_id']]['name']=='parse')
    original=deepcopy(resolutions[req['requirement_id']])
    missing=deepcopy(original)
    target=next(f for f in missing['facts'] if f['value']['entries'][0]['parameter']=='ctx')
    target['value']['entries'][0].update(ownership='unknown',lifetime='unknown');target['fact_id']=fact_id(target)
    missing['facts'].sort(key=lambda fact: fact['fact_id'])
    missing.update(status='unresolved',open_questions=['ctx ownership is missing'])
    resolutions[req['requirement_id']]=missing
    before=rebuild(prepared)
    data=next(n for n in before['semantic_obligation_graph']['nodes'] if n['predicate']=='ownership_subject'
        and n['subject_function_id']==req['subject_function_id'] and n['subject_parameter']=='data')
    assert before['status']=='incomplete' and data['proof_status']=='proved'
    patch=deepcopy(original);patch['facts']=[f for f in patch['facts'] if f['value']['entries'][0]['parameter']=='ctx']
    merged,audit=merge_resolution(missing,patch,req);resolutions[req['requirement_id']]=merged
    after=rebuild(prepared)
    assert after['status']=='complete' and not audit['conflicts']
    retained=next(n for n in after['semantic_obligation_graph']['nodes'] if n['obligation_id']==data['obligation_id'])
    assert retained['proof_status']=='proved' and retained['evidence_ids']==data['evidence_ids']
    assert not after['semantic_obligation_graph']['open_roots']


def test_conflicting_subject_retracts_its_proof_not_other_pointer(tmp_path):
    prepared=coherent_context(tmp_path);reqs,resolutions=prepared[2:4]
    req=next(r for r in reqs if r['kind']=='ownership' and prepared[1].functions[r['subject_function_id']]['name']=='parse')
    original=resolutions[req['requirement_id']]
    patch=deepcopy(original);patch['facts']=[f for f in patch['facts'] if f['value']['entries'][0]['parameter']=='ctx']
    patch['facts'][0]['value']['entries'][0]['ownership']='transferred'
    merged,audit=merge_resolution(original,patch,req);resolutions[req['requirement_id']]=merged
    after=rebuild(prepared)
    assert not after['generation_allowed'] and audit['conflicts']
    subjects={n['subject_parameter']:n for n in after['semantic_obligation_graph']['nodes'] if n['predicate']=='ownership_subject'
        and n['subject_function_id']==req['subject_function_id']}
    assert subjects['ctx']['proof_status']=='contradicted' and subjects['data']['proof_status']=='proved'


def test_coverage_rejects_closed_graph_that_drops_required_field_node(tmp_path):
    from harness_generation.harness_context.completeness import HarnessContextCompletenessValidator
    from harness_generation.harness_context.obligations import close_obligations
    from harness_generation.semantic_discovery.models import digest
    prepared=coherent_context(tmp_path);graph=deepcopy(prepared[-1]['semantic_obligation_graph'])
    field=next(n for n in graph['nodes'] if n['predicate']=='incoming_field_initialized')
    nid=field['obligation_id'];graph['nodes']=[n for n in graph['nodes'] if n['obligation_id']!=nid]
    for n in graph['nodes']:n['dependencies']=[d for d in n['dependencies'] if d['obligation_id']!=nid]
    roots=[r for r in graph['mandatory_roots'] if r!=nid]
    graph.update(close_obligations(graph['nodes'],roots))
    assert not graph['open_roots']
    graph['graph_digest']=digest({k:v for k,v in graph.items() if k!='graph_digest'})
    report=HarnessContextCompletenessValidator().validate_graph(graph,prepared[2])
    assert not report['generation_allowed'] and 'semantic_obligation_coverage_gap' in {e['code'] for e in report['validation_errors']}


def test_first_round_graph_skips_proved_construction_and_prioritizes_frontier(tmp_path):
    from test_context_semantics import shared_ready
    prepared,run,model=shared_ready(tmp_path)
    assert run.completeness['generation_allowed']
    assert run.metadata['metrics']['proved_investigation_skips']>0
    import json
    first=json.loads(next(m['content'] for m in model.calls[0]['messages'] if m['role']=='user'))
    assert first['missing_tasks'] and first['semantic_obligations']['targets']
    assert run.metadata['investigation_schedule'][0]['missing_obligations']
    assert run.metadata['metrics']['bootstrap_source_reads']<=len(prepared[3].functions)


def test_parameter_diagnostic_blocks_only_its_exact_recipe(tmp_path,monkeypatch):
    from harness_generation.harness_context.semantic_proofs import SemanticProofEvaluator
    prepared=coherent_context(tmp_path)
    req=next(r for r in prepared[2] if r['kind']=='argument_construction' and prepared[1].functions[r['subject_function_id']]['name']=='parse')
    original=SemanticProofEvaluator.evaluate
    def contradictory(self,*args,**kwargs):
        audit=original(self,*args,**kwargs)
        audit['failures'].append(dict(requirement_id=req['requirement_id'],subject_function_id=req['subject_function_id'],
            kind='argument_construction',subject_parameter='ctx',code='subject_repair_conflict',question='Conflicting ctx recipe'))
        return audit
    monkeypatch.setattr(SemanticProofEvaluator,'evaluate',contradictory)
    report=rebuild(prepared)
    nodes=[n for n in report['semantic_obligation_graph']['nodes'] if n['subject_function_id']==req['subject_function_id'] and n['predicate']=='parameter_recipe']
    assert not report['generation_allowed']
    assert next(n for n in nodes if n['subject_parameter']=='ctx')['proof_status']=='contradicted'
    assert next(n for n in nodes if n['subject_parameter']=='data')['proof_status']=='proved'
