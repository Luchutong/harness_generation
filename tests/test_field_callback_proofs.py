"""Invocation-specific field bindings and unknown-versus-disproof boundaries."""
from copy import deepcopy

import pytest

from harness_generation.harness_context.proof_grounding import analyze, cleanup_checks, contradictions
from harness_generation.harness_context.proposals import registry
from harness_generation.harness_context.value_flow import complete_bodies
from harness_generation.semantic_slicing.support_effects import bindings
from test_proof_reliability import analysis_fixture
from test_source_detail_tools import active
from test_harness_context import owner


SOURCE = '''typedef unsigned long size_t;
typedef struct Node { int value; } Node;
typedef struct Options { void (*drop)(void *, void *); void (*other)(void *, void *); void *user; } Options;
static void discard(void *p, void *user) { free(p); }
static void alternative(void *p, void *user) { (void)p; }
void worker(Options *opts, Node *p) { opts->drop(p, opts->user); }
void configure(Options *opts) { opts->drop=discard; opts->user=0; }
void finish(Node *p, int flag) { BODY }
Node *parse(const unsigned char *data, size_t size) { return calloc(1,sizeof(Node)); }
'''


def fixture(tmp_path, body, *, source=SOURCE, rename=False):
    source = source.replace('BODY', body)
    if rename:
        for old, new in [('Options','Hooks'), ('drop','dispose'), ('discard','release_storage'),
                         ('worker','invoke'), ('opts','table'), ('user','cookie')]:
            source = source.replace(old, new)
    snapshot, ids, records, issued = analysis_fixture(tmp_path, source)
    summary = analyze(snapshot.functions[ids['finish']], snapshot, issued)
    return snapshot, ids, records, issued, summary


@pytest.mark.parametrize('rename',[False,True])
@pytest.mark.parametrize('body',[
    'Options a={0};a.drop=discard;worker(&a,p);',
    'Options a={0};Options *alias=&a;alias->drop=&discard;worker(alias,p);',
    'Options a={.drop=&discard,.user=0};worker(&a,p);',
    'Options a={0};if(flag)a.drop=discard;else a.drop=discard;worker(&a,p);',
    'Options a={0};configure(&a);worker(&a,p);',
])
def test_exact_object_all_paths_address_and_formal_forwarding(tmp_path,body,rename):
    snapshot, ids, _, issued, summary = fixture(tmp_path,body,rename=rename)
    proof, = summary['callback_bindings']
    target = ids['release_storage' if rename else 'discard']
    assert proof['status']=='proved' and proof['target_function_ids']==[target]
    assert proof['argument_origins']==['parameter:p','literal:0']
    assert all('parameter:p' in p['released'] and not p['uncertain'] for p in summary['paths'])
    effects = bindings(snapshot.functions[ids['parse']],snapshot.functions[ids['finish']],snapshot.functions,issued,
        release_summary=summary)
    assert effects['cleanup'][0]['api_parameter']=='p'


@pytest.mark.parametrize('body',[
    'Options a={0},b={0};a.drop=discard;worker(&b,p);',
    'Options a={0};a.other=discard;worker(&a,p);',
    'Options a={0};if(flag)a.drop=discard;worker(&a,p);',
    'Options a={0};if(flag)a.drop=discard;else a.drop=alternative;worker(&a,p);',
    'Options a={0};a.drop=discard;a.drop=alternative;worker(&a,p);',
    'Options a={0},b={0};Options *alias=&a;a.drop=discard;alias=&b;worker(alias,p);',
    'Options a={0};a.drop=discard;unknown(&a);worker(&a,p);',
    'Options a={0};a.drop=discard;flag && (a.drop=alternative);worker(&a,p);',
    'Options a={0};a.drop=discard;Options b=a;worker(&b,p);',
    'void (*discard)(void*,void*)=0;Options a={0};a.drop=discard;worker(&a,p);',
    'Options a={0};a.drop=(void (*)(void*,void*))alternative;worker(&a,p);',
    'Options *a;a->drop=discard;worker(a,p);',
    'Options a={0};a.drop=discard;a.drop(p,(a.drop=alternative,0));',
    'Options a={0};a.drop=discard;a.drop(&p,0);',
    'Options a={0};a.drop=discard;a.drop=&a.other;worker(&a,p);',
])
def test_reassignment_condition_other_object_shadow_escape_and_copy_do_not_release(tmp_path,body):
    snapshot,ids,_,issued,summary = fixture(tmp_path,body)
    effects=bindings(snapshot.functions[ids['parse']],snapshot.functions[ids['finish']],snapshot.functions,issued,
        release_summary=summary)
    assert 'cleanup' not in effects
    assert not all(not p['uncertain'] and 'parameter:p' in p['released'] for p in summary['paths'])


def test_abi_mismatch_is_not_a_function_binding(tmp_path):
    source=SOURCE.replace('static void discard(void *p, void *user)', 'static int discard(void *p, void *user)')
    _,_,_,_,summary=fixture(tmp_path,'Options a={0};a.drop=discard;worker(&a,p);',source=source)
    assert all(r['status']=='missing' and not r['target_function_ids'] for r in summary['callback_bindings'])
    assert not any('parameter:p' in p['released'] for p in summary['paths'])


@pytest.mark.parametrize('missing',['discard','worker'])
def test_unissued_complete_helper_cannot_prove_binding(tmp_path,missing):
    snapshot,ids,_,issued,_=fixture(tmp_path,'Options a={0};a.drop=discard;worker(&a,p);')
    del issued[ids[missing]]
    result=analyze(snapshot.functions[ids['finish']],snapshot,issued)
    assert not any('parameter:p' in p['released'] for p in result['paths'])
    assert not any(r['status']=='proved' for r in result['callback_bindings'])


def test_two_invocations_keep_separate_callback_table_identities(tmp_path):
    body='Options a={0},b={0};a.drop=discard;b.drop=alternative;worker(&a,p);worker(&b,p);'
    _,ids,_,_,summary=fixture(tmp_path,body)
    assert len(summary['callback_bindings'])==2
    assert {tuple(r['target_function_ids']) for r in summary['callback_bindings']}=={(ids['discard'],),(ids['alternative'],)}
    assert len({tuple(r['invocation_sites']) for r in summary['callback_bindings']})==2
    assert len({r['owner_origin'] for r in summary['callback_bindings']})==2


def test_by_value_table_copy_is_not_formal_pointer_identity(tmp_path):
    source=SOURCE.replace('worker(Options *opts, Node *p) { opts->drop(p, opts->user); }',
        'worker(Options opts, Node *p) { opts.drop(p, opts.user); }')
    _,_,_,_,summary=fixture(tmp_path,'Options a={0};a.drop=discard;worker(a,p);',source=source)
    assert not any('parameter:p' in p['released'] for p in summary['paths'])


def test_bound_callback_releasing_userdata_is_not_resource_release(tmp_path):
    source=SOURCE.replace('{ free(p); }','{ free(user); }')
    snapshot,ids,records,_,summary=fixture(tmp_path,'Options a={0};a.drop=discard;worker(&a,p);',source=source)
    assert summary['callback_bindings'][0]['status']=='proved'
    assert all('parameter:p' not in p['released'] for p in summary['paths'])
    assert cleanup_checks(claim(ids),snapshot,records)[0]['status']=='contradicted'


def test_address_of_pointer_storage_is_not_a_pointee_release(tmp_path):
    snapshot,ids,records,_,summary=fixture(tmp_path,'free(&p);')
    assert all('parameter:p' not in p['released'] for p in summary['paths'])
    assert cleanup_checks(claim(ids),snapshot,records)[0]['status']=='contradicted'


def test_ambiguous_project_free_symbol_is_not_a_libc_release(tmp_path):
    from types import SimpleNamespace
    snapshot,ids,_,issued,_=fixture(tmp_path,'Options a={0};a.drop=discard;worker(&a,p);')
    # Model an index with two project definitions and no same-file resolution.
    # Neither target has an issued body; absence of a unique target is unknown.
    functions=dict(snapshot.functions)
    for name in ['unit_a.c','unit_b.c']:
        row=deepcopy(snapshot.functions[ids['alternative']])
        row.update(id=name+':1:free',file=name,name='free')
        functions[row['id']]=row
    index=SimpleNamespace(functions=functions,artifacts=snapshot.artifacts)
    summary=analyze(index.functions[ids['finish']],index,issued)
    assert not any('parameter:p' in p['released'] for p in summary['paths'])
    assert all(r['status']=='missing' for r in summary['callback_bindings'])


def test_registry_binding_refresh_replaces_old_missing_diagnostic(tmp_path):
    from harness_generation.harness_context.proposals import merge_registry
    _,tools,ids=active(tmp_path,SOURCE.replace('BODY','Options a={0};a.drop=discard;worker(&a,p);'))
    signed=merge_registry({},tools.bootstrap())
    for name,args in [('find_cleanup_candidates',{'type':'Node'}),('get_function',{'function':ids['finish']}),
            ('find_field_writes',{'function':ids['finish'],'field':'drop'}),('get_function',{'function':ids['discard']}),
            ('get_call_sites',{'function':ids['finish'],'callee':'worker'}),('get_function',{'function':ids['worker']})]:
        signed=merge_registry(signed,tools.execute(name,args))
    roots=[r for r in signed['source_callback_bindings'] if r['root_function_id']==ids['finish']]
    assert len(roots)==1 and roots[0]['status']=='proved'


def test_detail_fragment_and_function_reference_need_complete_definitions_for_registry(tmp_path):
    prepared,tools,ids=active(tmp_path,SOURCE.replace('BODY','Options a={0};a.drop=discard;worker(&a,p);'))
    tools.bootstrap()
    tools.execute('find_cleanup_candidates',{'type':'Node'})
    tools.execute('get_function',{'function':ids['finish']})
    tools.execute('find_field_writes',{'function':ids['finish'],'field':'drop'})
    assert not any(c['function_id']==ids['finish'] and c['reason']=='cleanup' for c in registry(tools)['support_candidates'])
    tools.execute('get_function',{'function':ids['discard']})
    tools.execute('get_call_sites',{'function':ids['finish'],'callee':'worker'})
    tools.execute('get_function',{'function':ids['worker']})
    signed=registry(tools)
    candidate,= [c for c in signed['support_candidates'] if c['function_id']==ids['finish'] and c['reason']=='cleanup']
    assert not candidate['necessity_proven']
    bodies=complete_bodies(prepared[3],prepared[4].evidence)
    assert set().union(*(bodies[ids[n]] for n in ['finish','worker','discard']))<=set(candidate['evidence_ids'])
    assert any(r['root_function_id']==ids['finish'] and r['status']=='proved' for r in signed['source_callback_bindings'])


def claim(ids):
    return {'ownership_contract':{'entries':[dict(function_id=ids['parse'],fact_id='fact_return',
        evidence_ids=['ev_parse','ev_finish'],**owner(returned=True,ownership='owned',release=ids['finish']))]},
        'callback_contract':{'callbacks':[]}}


@pytest.mark.parametrize('body,status',[
    ('Options a={0};a.drop=discard;worker(&a,p);','proved'),
    ('Options a={0};a.drop=alternative;worker(&a,p);','contradicted'),
    ('if(flag)free(p);','contradicted'),
    ('unknown(p);','missing'),
    ('while(p){free(p);p=0;}','missing'),
    ('Options a={0};worker(&a,p);','missing'),
    ('free(*(Node**)p);','missing'),
    ('p=flag?p:0;free(p);','missing'),
])
def test_uninterpreted_control_flow_is_unknown_but_real_counterexample_stays_false(tmp_path,body,status):
    snapshot,ids,records,_,_=fixture(tmp_path,body)
    checks=cleanup_checks(claim(ids),snapshot,records)
    assert checks[0]['status']==status
    negatives=contradictions(claim(ids),snapshot,records)
    assert bool(negatives)==(status=='contradicted')


def test_excluded_or_truncated_target_stays_unavailable(tmp_path):
    snapshot,ids,records,_,_=fixture(tmp_path,'Options a={0};a.drop=discard;worker(&a,p);')
    records['ev_discard']['truncated']=True
    records['ev_discard']['content']=records['ev_discard']['content'][:-4]
    assert ids['discard'] not in complete_bodies(snapshot,records)
    summary=analyze(snapshot.functions[ids['finish']],snapshot,complete_bodies(snapshot,records))
    assert not any('parameter:p' in p['released'] for p in summary['paths'])


def test_missing_cleanup_effect_is_a_gate_gap_not_a_repair_disproof(tmp_path,monkeypatch):
    from test_proof_reliability import coherent_context,rebuild
    from harness_generation.harness_context import proof_grounding
    prepared=coherent_context(tmp_path)
    fid=next(fid for fid,f in prepared[1].functions.items() if f['name']=='parse')
    monkeypatch.setattr(proof_grounding,'cleanup_checks',lambda *args:[dict(function_id=fid,kind='ownership',
        parameter='ctx',status='missing',code='cleanup_effect_unproven')])
    report=rebuild(prepared)
    assert not report['generation_allowed']
    node=next(n for n in report['semantic_obligation_graph']['nodes'] if n['subject_function_id']==fid
        and n['predicate']=='ownership_subject' and n['subject_parameter']=='ctx')
    assert node['proof_status']=='missing'
