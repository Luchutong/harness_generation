"""Reuse reconciliation needs a whole fresh, nonescaping source lifetime."""
from copy import deepcopy

import pytest

from harness_generation.harness_context.invocation_scope import prove_finite_resource_scope
from harness_generation.harness_context.invocations import project_invocations
from harness_generation.harness_context.value_flow import body_tree, complete_bodies
from harness_generation.semantic_discovery.models import digest
from harness_generation.semantic_discovery.tools import _walk
from test_internal_stream_invocations import SOURCE, fixture, graph_and_contract, stream_context, STREAM_HARNESS
from test_harness_context import assert_gate, lifecycle_value


def scope_fixture(tmp_path, source=SOURCE):
    f = fixture(tmp_path, source)
    context, _, _, snapshot, records, ids = f
    graph, _ = graph_and_contract(f)
    context['argument_graph'] = graph
    # Rebuild the source call identity even if other conservative graph checks
    # reject it, so negatives also exercise the scope proof's own boundary.
    caller = snapshot.functions[ids['example']]
    _, body = body_tree(caller)
    call = next(n for n in _walk(body) if n.type == 'call_expression')
    origin = {'function_id': ids['open_bytes'], 'kind': 'return', 'parameter': None,
        'type': 'Reader', 'pointer_depth': 1, 'caller_id': caller['id'], 'call_offset': call.start_byte}
    rid = 'resource_' + digest(origin)[:24]
    graph['resource_origins'] = [{'resource_id': rid, 'origin': origin}]
    rows = []
    for name in ('open_bytes', 'parse', 'take'):
        resource, = lifecycle_value(ids[name], rid, 'Reader', None if name == 'open_bytes' else 'r',
                                   ids['open_bytes'], ids['release'])['resources']
        rows.append({**resource, 'function_id': ids[name], 'reuse': 'per_context' if name == 'take' else 'per_input',
                     'fact_id': 'fact_' + name, 'evidence_ids': sorted(records)})
    context['lifecycle_contract']['resources'] = rows
    return context, snapshot, records, rid


def prove(f):
    context, snapshot, records, rid = f
    return prove_finite_resource_scope(context, rid, context['lifecycle_contract']['resources'],
                                       snapshot, complete_bodies(snapshot, records))


def test_fresh_scope_reconciles_only_derived_definition_and_is_rebuildable(tmp_path):
    context, snapshot, records, rid = f = scope_fixture(tmp_path)
    before = deepcopy(context['lifecycle_contract'])
    proof = prove(f)
    assert proof['scope'] == 'fresh_create_use_cleanup_within_one_invocation'
    assert proof['effective_reuse'] == 'per_input'
    assert proof['source_fingerprint'] == snapshot.source_fingerprint
    assert set(proof['source_evidence']) == set(snapshot.functions)
    rebuilt = prove_finite_resource_scope(context, rid, before['resources'], snapshot,
                                         {fid: set(eids) for fid, eids in proof['source_evidence'].items()})
    assert rebuilt == proof
    project_invocations(context, snapshot, records)
    assert context['lifecycle_contract'] == before
    assert context['resource_contract']['diagnostics'] == []
    resource, = context['resource_contract']['resources']
    assert resource['reuse'] == 'per_input' and resource['invocation_scope_proof'] == proof
    assert {r['reuse'] for r in resource['observed_reuse']} == {'per_input', 'per_context'}
    # Removing authenticated source cannot retain yesterday's successful proof.
    project_invocations(context, snapshot, {})
    assert context['resource_contract']['diagnostics'][0]['code'] == 'conflicting_resource_identity'
    assert 'invocation_scope_proof' not in context['resource_contract']['resources'][0]


@pytest.mark.parametrize('before,after', [
    ('Reader *r = malloc(sizeof(*r));', 'static Reader object; Reader *r = &object;'),
    ('Reader *r = malloc(sizeof(*r));', 'Reader *r = malloc(sizeof(*r)); global=r;'),
    ('Reader *r = malloc(sizeof(*r));', 'Reader *r = malloc(sizeof(*r)); saved[0]=r;'),
    ('Reader *r = malloc(sizeof(*r));', 'Reader *r = malloc(sizeof(*r)); *output=r;'),
    ('Reader *r = malloc(sizeof(*r));', 'Reader *r = malloc(sizeof(*r)); save(r);'),
    ('return r;\n}', 'unknown(r); return r;\n}'),
    ('Reader *r=open_bytes(data,size);', 'static Reader *r; r=open_bytes(data,size);'),
    ('if(r){parse(r);release(r);}', 'if(size){parse(r);release(r);}'),
    ('if(r){parse(r);release(r);}', 'if(r){parse(r);if(size)release(r);}'),
    ('if(r){parse(r);release(r);}', 'if(r){parse(r);release(r);release(r);}'),
    ('if(r){parse(r);release(r);}', 'if(r){release(r);parse(r);release(r);}'),
    ('if(r){parse(r);release(r);}', 'if(r){global=r;parse(r);release(r);}'),
    ('if(r){parse(r);release(r);}', 'if(r){save(r);parse(r);release(r);}'),
    ('if(r){parse(r);release(r);}', 'if(r){unknown(&r);parse(r);release(r);}'),
    ('if(r){parse(r);release(r);}', 'if(r){r=0;parse(r);release(r);}'),
    ('if(r){parse(r);release(r);}', 'if(r){parse(r);release(0);}'),
    ('if(r){parse(r);release(r);}', 'if(r){parse(r);release(r);}else{parse(r);}'),
    ('void release(Reader *r) { free(r); }', 'void release(Reader *r) { if(r->extent)free(r); }'),
    ('void release(Reader *r) { free(r); }', 'void release(Reader *r) { free(r);free(r); }'),
    ('void release(Reader *r) { free(r); }', 'void release(Reader *r) { global=r;free(r); }'),
    ('if(n)memcpy(destination,r->bytes+r->cursor,n);', 'global=r;if(n)memcpy(destination,r->bytes+r->cursor,n);'),
    ('if(n)memcpy(destination,r->bytes+r->cursor,n);', 'save(r);if(n)memcpy(destination,r->bytes+r->cursor,n);'),
    ('if(n)memcpy(destination,r->bytes+r->cursor,n);', 'if(n)free(r);if(n)memcpy(destination,r->bytes+r->cursor,n);'),
    ('size_t n=r->extent-r->cursor;', 'void (*memcpy)(void*,const void*,size_t)=save;size_t n=r->extent-r->cursor;'),
    ('size_t n=r->extent-r->cursor;', 'r++;size_t n=r->extent-r->cursor;'),
    ('size_t n=r->extent-r->cursor;', '++r;size_t n=r->extent-r->cursor;'),
    ('size_t n=r->extent-r->cursor;', '(r)++;size_t n=r->extent-r->cursor;'),
    ('size_t n=r->extent-r->cursor;', '(r)+=1;size_t n=r->extent-r->cursor;'),
    ('while((n=take(r,temporary,sizeof(temporary))))', 'global=r;while((n=take(r,temporary,sizeof(temporary))))'),
])
def test_static_escape_ambiguous_control_and_may_release_never_reconcile(tmp_path, before, after):
    source = SOURCE.replace(before, after)
    # A known project callee that retains the exact pointer is as unsafe as an
    # unknown call. Its body must not make the caller certificate permissive.
    source += '\nvoid save(Reader *r) { global=r; }\n'
    f = scope_fixture(tmp_path, source)
    assert prove(f) is None
    project_invocations(*f[:3])
    assert f[0]['resource_contract']['diagnostics'][0]['code'] == 'conflicting_resource_identity'


@pytest.mark.parametrize('field,value', [('reuse','unknown'), ('reuse','static'),
    ('creation', {'kind':'borrowed','api':None}), ('cleanup', {'mandatory':False,'api':None}),
    ('type','OtherResource'), ('subject_parameter','other')])
def test_other_identity_or_reuse_disagreements_remain_hard(tmp_path, field, value):
    f = scope_fixture(tmp_path)
    f[0]['lifecycle_contract']['resources'][0][field] = value
    assert prove(f) is None
    project_invocations(*f[:3])
    assert f[0]['resource_contract']['diagnostics']


@pytest.mark.parametrize('change', ['missing_caller', 'missing_cleanup', 'missing_creator', 'modified_content'])
def test_scope_requires_complete_authentic_source_for_whole_chain(tmp_path, change):
    f = scope_fixture(tmp_path)
    function = {'missing_caller':'example','missing_cleanup':'release','missing_creator':'open_bytes',
                'modified_content':'parse'}[change]
    eid = next(eid for eid,r in f[2].items() if r['function_id'].endswith(':'+function))
    if change == 'modified_content':
        f[2][eid]['content'] = 'invented source'
    else:
        del f[2][eid]
    assert prove(f) is None


@pytest.mark.parametrize('mutation', ['', 'r++;', '++r;', '(r)++;', 'r=r+1;', 'r+=1;', '(r)+=1;', '(r)=r+1;'])
def test_ordinary_consumer_keeps_the_exact_resource_parameter(tmp_path, mutation):
    start = SOURCE.index('int parse(Reader *r) {')
    end = SOURCE.index('void release(Reader *r)')
    source = SOURCE[:start] + 'int parse(Reader *r) {' + mutation + 'return r->cursor;}\n' + SOURCE[end:]
    f = scope_fixture(tmp_path, source)
    f[0]['lifecycle_contract']['resources'] = [r for r in f[0]['lifecycle_contract']['resources']
                                             if not r['function_id'].endswith(':take')]
    next(r for r in f[0]['lifecycle_contract']['resources'] if r['function_id'].endswith(':parse'))['reuse'] = 'per_context'
    assert bool(prove(f)) == (not mutation)


def mixed_reuse(specs, ids):
    specs[ids['take'], 'lifecycle']['value']['resources'][0]['reuse'] = 'per_context'


def test_real_context_and_plan_keep_atomic_facts_and_internal_execution_scope(tmp_path):
    from harness_generation.context_generation import HarnessPlanBuilder, PlanError
    from harness_generation.context_generation.validation import validate_code
    prepared, run = stream_context(tmp_path, grouped=True, change_specs=mixed_reuse)
    assert_gate(run)
    original = [f for f in run.context['facts'] if f['predicate'] == 'lifecycle'
                and f['function_id'] == prepared[0][-1]['take']]
    assert original[0]['value']['resources'][0]['reuse'] == 'per_context'
    raw = [r for r in run.context['lifecycle_contract']['resources'] if r['function_id'] == prepared[0][-1]['take']]
    assert raw[0]['reuse'] == 'per_context'
    resource, = run.context['resource_contract']['resources']
    assert resource['reuse'] == 'per_input' and resource['invocation_scope_proof']['proof_status'] == 'proven'
    plan = HarnessPlanBuilder().build(prepared[1], run.context, run.closure, prepared[3], run.completeness)
    assert validate_code(STREAM_HARNESS, plan)['status'] == 'valid'
    assert [c for c in plan['call_sequence'] if c['function_id'] == prepared[0][-1]['take']][0]['calls_per_input'] is None
    changed = deepcopy(run.context)
    changed['resource_contract']['resources'][0]['invocation_scope_proof']['effective_reuse'] = 'static'
    with pytest.raises(PlanError):
        HarnessPlanBuilder().build(prepared[1], changed, run.closure, prepared[3], run.completeness)
    for field, value in [
        ('cleanup', {'api': prepared[0][-1]['parse'], 'mandatory': True}),
        ('creation', {'api': prepared[0][-1]['release'], 'kind': 'creator_api'}),
        ('type', 'DifferentResource'),
        ('bindings', [{'function_id': prepared[0][-1]['parse'], 'parameter': 'other', 'return_value': False}]),
        ('observed_reuse', [{'function_id': prepared[0][-1]['take'], 'parameter': 'r',
                            'return_value': False, 'reuse': 'static', 'fact_id': 'forged'}]),
    ]:
        changed = deepcopy(run.context)
        changed['resource_contract']['resources'][0][field] = value
        with pytest.raises(PlanError, match='resource invocation scope'):
            HarnessPlanBuilder().build(prepared[1], changed, run.closure, prepared[3], run.completeness)


@pytest.mark.parametrize('missing', [('take','ownership'), ('parse','lifecycle'), ('open_bytes','ownership')])
def test_finite_scope_never_supplies_missing_ownership_or_lifecycle(tmp_path, missing):
    _, run = stream_context(tmp_path, grouped=True, omit=missing, change_specs=mixed_reuse)
    assert run.completeness['generation_allowed'] is False
    assert run.completeness['hard_missing'] or run.completeness['validation_errors']
