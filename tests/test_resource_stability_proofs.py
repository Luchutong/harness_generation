"""Frozen-cohort failures repaired through exact source certificates."""
from copy import deepcopy

import pytest

from harness_generation.harness_context.resource_identity import (
    allocated_export_proof, exclusive_return_export_proof, exclusive_parameter_use_proof, exact_cleanup_connection,
    project_callback_identities, resolve_resources)
from harness_generation.harness_context.construction import (
    project_allocated_return_creation, project_owned_return_cleanup, project_out_cleanup_consumption)
from harness_generation.harness_context.argument_graph import build_argument_graph
from harness_generation.harness_context.reconciliation import GraphContractReconciler
from harness_generation.harness_context.models import fact_id
from harness_generation.harness_context.repairs import merge_resolution
from test_argument_graph import graph_fixture
from test_callback_boundaries import SOURCE
from test_construction_reconciliation import proposal, selection
from test_proof_reliability import analysis_fixture


def callback_context(tmp_path, source=SOURCE):
    f = graph_fixture(tmp_path, source, bindings=[('parse', 'src', 'cb')])
    proposal(f, 'handle', 'user', 'creator_api', api='acquire', rid='resource_model_label')
    f[0]['resource_identity'] = resolve_resources(f[0], f[3], f[4])
    graph = build_argument_graph(*f[:5])
    return f, graph


def test_callback_exact_forwarding_normalizes_semantic_identity_without_mutating_fact(tmp_path):
    f, graph = callback_context(tmp_path)
    before = deepcopy(f[0]['argument_contract']['arguments'][0])
    baseline = GraphContractReconciler().reconcile(f[0], graph, f[2], f[3])
    assert selection(baseline, f, 'handle', 0)['status'] == 'conflict'
    project_callback_identities(f[0], graph, f[3])
    projected = deepcopy(f[0])
    project_callback_identities(f[0], graph, f[3])
    assert f[0] == projected
    result = GraphContractReconciler().reconcile(f[0], graph, f[2], f[3])
    assert selection(result, f, 'handle', 0)['status'] == 'resolved'
    assert selection(result, f, 'handle', 0)['recipe']['resource_id'] == selection(result, f, 'parse', 3)['recipe']['resource_id']
    assert before['resource_id'] == 'resource_model_label'
    assert before['fact_id'] == f[0]['argument_contract']['arguments'][0]['fact_id']


@pytest.mark.parametrize('replacement', [
    'return cb ? handler(user,src,cb) : 0;',
    'user=NULL; return handler(user,src,cb);',
    'saved=user; return handler(user,src,cb);',
    'handler(user,src,cb);return handler(user,src,cb);',
])
def test_unproved_callback_forwarding_preserves_unknown_identity(tmp_path, replacement):
    f, graph = callback_context(tmp_path, SOURCE.replace('return handler(user,src,cb);', replacement))
    project_callback_identities(f[0], graph, f[3])
    assert f[0]['argument_contract']['arguments'][0]['resource_id'] == 'resource_model_label'
    assert not any(b['reason'] == 'source_callback_parameter_forwarding' for b in f[0]['resource_identity']['bindings'])


def test_multiple_dispatcher_origins_do_not_collapse_callback_userdata(tmp_path):
    source = SOURCE.replace('parse(raw,extent,handle,u);',
        'User *v=acquire(1);parse(raw,extent,handle,u);parse(raw,extent,handle,v);dispose(v);')
    f, graph = callback_context(tmp_path, source)
    project_callback_identities(f[0], graph, f[3])
    assert f[0]['argument_contract']['arguments'][0]['resource_id'] == 'resource_model_label'


def test_callback_origin_normalization_cannot_prove_a_different_creator(tmp_path):
    f, graph = callback_context(tmp_path, SOURCE + '\nUser *other(void){return calloc(1,sizeof(User));}')
    f[0]['argument_contract']['arguments'][0]['api'] = f[-1]['other']
    project_callback_identities(f[0], graph, f[3])
    result = GraphContractReconciler().reconcile(f[0], graph, f[2], f[3])
    assert selection(result, f, 'handle', 0)['status'] != 'resolved'


def test_erased_callback_cleanup_uses_exact_origin_without_changing_ownership(tmp_path):
    from harness_generation.harness_context.proof_grounding import cleanup_checks
    f, _ = callback_context(tmp_path)
    c, _, _, snapshot, records, ids = f
    row = dict(function_id=ids['handle'], parameter='user', return_value=False, field=None,
        ownership='owned', lifetime='until_release', release_api=ids['dispose'],
        resource_id='resource_not_a_proof', fact_id='fact_claim', evidence_ids=list(records))
    c['ownership_contract']['entries'] = [row]
    before = deepcopy(row)
    checks = cleanup_checks(c, snapshot, records)
    assert len(checks) == 1 and checks[0]['status'] == 'proved'
    proof = checks[0]['source_witness']
    assert proof['cleanup_parameter'] == 'u'
    assert proof['resource_id'] != row['resource_id']
    assert row == before  # The check validates the connection, never owns it.


@pytest.mark.parametrize('old,new', [
    ('if(u) u->bias=bias; return u;', 'if(u) u->bias=bias; saved=u; return u;'),
    ('return cb ? src[0]^u->bias : u->bias;', 'free(u); return 0;'),
    ('return cb ? src[0]^u->bias : u->bias;', 'if(cb) free(u); return 0;'),
    ('return cb ? src[0]^u->bias : u->bias;', 'saved=u; return 0;'),
    ('return cb ? src[0]^u->bias : u->bias;', 'saved_array[0]=u; return 0;'),
    ('return cb ? src[0]^u->bias : u->bias;', 'retain_user(u); return 0;'),
    ('return cb ? src[0]^u->bias : u->bias;', 'u++; return 0;'),
    ('return handler(user,src,cb);', 'return cb ? handler(user,src,cb) : 0;'),
    ('return handler(user,src,cb);', 'handler(user,src,cb); return handler(user,src,cb);'),
    ('parse(raw,extent,handle,u);', 'escape(u); parse(raw,extent,handle,u);'),
    ('parse(raw,extent,handle,u);', 'parse(raw,extent,handle,u); escape(u);'),
    ('parse(raw,extent,handle,u);', 'maybe_release(u); parse(raw,extent,handle,u);'),
    ('parse(raw,extent,handle,u);', 'parse(raw,extent,handle,u); kill_saved();'),
    ('User *u=acquire(0);', 'User *u=acquire(0); User *alias=u;'),
    ('User *u=acquire(0);', 'User *u=acquire(0); User *v=acquire(1);'),
    ('dispose(u);', 'dispose(shared);'),
    ('free(u);', 'if(u->bias) free(u);'),
    ('free(u);', 'free(u); free(u);'),
])
def test_callback_cleanup_connection_rejects_unproved_or_consumed_origins(tmp_path, old, new):
    from harness_generation.harness_context.proof_grounding import cleanup_checks
    source = SOURCE.replace(old, new) + '\nUser *saved,*shared,*saved_array[1];\n' \
        'void retain_user(User *p){saved_array[0]=p;}\n' \
        'void escape(User *p){saved=p;}\n' \
        'void maybe_release(User *p){if(p->bias)free(p);}\n' \
        'void kill_saved(void){free(saved);}\n'
    c, _, _, snapshot, records, ids = graph_fixture(tmp_path, source)
    c['ownership_contract']['entries'] = [dict(function_id=ids['handle'], parameter='user',
        return_value=False, field=None, ownership='owned', lifetime='until_release',
        release_api=ids['dispose'], resource_id='resource_forged_same_label', evidence_ids=list(records))]
    assert exact_cleanup_connection(c, snapshot, records, ids['handle'], 'user', False, ids['dispose']) is None
    assert cleanup_checks(c, snapshot, records)[0]['status'] != 'proved'
    assert exact_cleanup_connection(c, snapshot, records, ids['acquire'], None, True, ids['dispose']) is None


def test_cleanup_connection_requires_authentic_complete_source_evidence(tmp_path):
    c, _, _, snapshot, records, ids = graph_fixture(tmp_path, SOURCE)
    for fid in (ids['acquire'], ids['handle'], ids['parse'], ids['dispose'], ids['usage']):
        missing = {eid: r for eid, r in records.items() if r['function_id'] != fid}
        assert exact_cleanup_connection(c, snapshot, missing, ids['handle'], 'user', False, ids['dispose']) is None
    forged = {'ev_wrong_' + eid: {**r, 'evidence_id': 'ev_wrong_' + eid} for eid, r in records.items()}
    assert exact_cleanup_connection(c, snapshot, forged, ids['handle'], 'user', False, ids['dispose']) is None


def test_return_cleanup_connection_can_prove_two_call_sequence(tmp_path):
    c, _, _, snapshot, records, ids = graph_fixture(tmp_path,
        SOURCE.replace('parse(raw,extent,handle,u); ', ''))
    proof = exact_cleanup_connection(c, snapshot, records, ids['acquire'], None, True, ids['dispose'])
    assert proof and proof['creator_api'] == ids['acquire']


@pytest.mark.parametrize('parameters,statements,proved', [
    ('void', '', True),
    ('void', 'P *alias=p;', True),
    ('const unsigned char *input', 'p->bytes=input;', True),
    ('void', 'saved=p;', False),
    ('void', 'slots[0]=p;', False),
    ('P **out', '*out=p;', False),
    ('P *holder', 'holder->next=p;', False),
    ('void', 'P *alias=p; slots[0]=alias;', False),
    ('void', 'retain(p);', False),
    ('void', 'P *local[1]={p};', False),
    ('void', 'p++;', False),
    ('void', '++p;', False),
    ('void', 'p+=1;', False),
    ('void', '--p;', False),
    ('void', 'p-=1;', False),
    ('void', 'P *alias=p; alias++;', False),
    ('void', 'static P *held; held=p;', False),
    ('void', 'extern P *saved; saved=p;', False),
    ('void', '{P *saved;} saved=p;', False),
])
def test_exclusive_return_certificate_blocks_stored_fresh_aliases_only(tmp_path, parameters, statements, proved):
    source = '#include <stdlib.h>\ntypedef struct P {struct P *next;const unsigned char *bytes;} P;\n' \
        'P *saved; P *slots[1];void retain(P *p){slots[0]=p;}\n' \
        f'P *create({parameters}){{P *p=calloc(1,sizeof(P));{statements}return p;}}\n' \
        'int parse(P *p){return p->bytes != 0;}'
    snapshot, ids, records, issued = analysis_fixture(tmp_path, source)
    # The general allocation analysis may already reject an altered return;
    # the stronger certificate must reject every pointer mutation regardless.
    if not any(token in statements for token in ('++', '--', '+=', '-=')):
        assert allocated_export_proof(snapshot.functions[ids['create']], snapshot, issued)
    assert bool(exclusive_return_export_proof(snapshot.functions[ids['create']], snapshot, issued)) == proved


@pytest.mark.parametrize('statements,proved', [
    ('', True), ('P *alias=p;', True), ('P *alias=p;alias->n=1;', True),
    ('P *alias=p; safe(alias);', True),
    ('P *alias=p; saved=alias;', False), ('P *alias=p; slots[0]=alias;', False),
    ('P *alias=p; *out=alias;', False), ('P *alias=p; holder->next=alias;', False),
    ('P *alias=p; static P *held;held=alias;', False),
    ('P *alias=p; extern P *saved;saved=alias;', False),
    ('P *alias=p;alias++;', False), ('P *alias=p;++alias;', False),
    ('P *alias=p;alias+=1;', False), ('P *alias=p;alias=NULL;', False),
    ('P *alias=(P*)((char*)p+1);', False),
    ('P *alias=p;alias=(P*)((char*)alias+1);', False),
    ('P *alias=p; retain(alias);', False), ('P *alias=p; unknown(alias);', False),
    ('P *alias=p; interior=&alias->n;', False),
    ('P *alias=p; retain_interior(&alias->n);', False),
    ('P *alias=p; return alias;', False),
    ('void (*safe)(P *)=retain;safe(p);', False),
    ('{P *saved;} saved=p;', False),
])
def test_protected_parameter_and_local_alias_stores_cannot_prove_nonretention(tmp_path, statements, proved):
    source = '#include <stdlib.h>\ntypedef struct P {struct P *next;int n;} P;\n' \
        'P *saved,*slots[1];int *interior;void safe(P *p){p->n=1;}' \
        'void retain(P *p){slots[0]=p;}void retain_interior(int *p){interior=p;}\n' \
        f'int parse(P *p,P **out,P *holder){{{statements}return p->n;}}'
    snapshot, ids, records, issued = analysis_fixture(tmp_path, source)
    assert bool(exclusive_parameter_use_proof(snapshot.functions[ids['parse']], 'p', snapshot, issued)) == proved


def owned_return_projection_fixture(tmp_path, source=SOURCE):
    f = graph_fixture(tmp_path, source)
    c, _, _, _, records, ids = f
    c['ownership_contract']['entries'] = [dict(function_id=ids['acquire'], parameter=None,
        return_value=True, field=None, subject_kind='PointerReturn', ownership='owned',
        lifetime='until_release', release_api=None, resource_id='resource_claim', fact_id='fact_owner', evidence_ids=list(records))]
    c['lifecycle_contract']['resources'] = [dict(function_id=ids['acquire'], subject_parameter=None,
        return_value=True, creation={'kind': 'creator_api', 'api': ids['acquire']},
        cleanup={'mandatory': True, 'api': ids['dispose']}, type='User', resource_id='resource_claim', evidence_ids=list(records))]
    return f


def test_owned_return_cleanup_projection_changes_only_missing_release_api(tmp_path):
    f = owned_return_projection_fixture(tmp_path)
    c, _, _, snapshot, records, ids = f
    before = deepcopy(c['ownership_contract']['entries'][0])
    raw_fact = dict(fact_id='fact_owner', value={'entries': [deepcopy(before)]})
    c['facts'] = [raw_fact]
    certificates = project_owned_return_cleanup(c, snapshot, records, set(ids.values()))
    assert len(certificates) == 1 and certificates[0]['proof_scope'] == ['release_api']
    projected = c['ownership_contract']['entries'][0]
    assert projected['release_api'] == ids['dispose']
    assert {k: v for k, v in projected.items() if k not in {'release_api', 'construction_source'}} == \
        {k: v for k, v in before.items() if k != 'release_api'}
    assert raw_fact['value']['entries'][0] == before
    assert not project_owned_return_cleanup(c, snapshot, records, set(ids.values()))


@pytest.mark.parametrize('changes', [
    {'ownership': 'borrowed'}, {'ownership': 'transferred'}, {'ownership': 'unknown'},
    {'lifetime': 'during_call'}, {'release_api': 'handle'},
    {'return_value': False, 'parameter': 'user', 'subject_kind': 'PointerParameter'},
])
def test_owned_return_projection_preserves_explicit_nonmatching_subject_or_contract(tmp_path, changes):
    f = owned_return_projection_fixture(tmp_path)
    c, _, _, snapshot, records, ids = f
    changes = dict(changes)
    if isinstance(changes.get('release_api'), str):
        changes['release_api'] = ids[changes['release_api']]
    c['ownership_contract']['entries'][0].update(changes)
    before = deepcopy(c)
    assert not project_owned_return_cleanup(c, snapshot, records, set(ids.values()))
    assert c == before


@pytest.mark.parametrize('damage', ['no_cleanup', 'not_mandatory', 'second_resource', 'missing_caller', 'excluded_cleanup'])
def test_owned_return_projection_requires_unique_selected_lifecycle_and_exact_source(tmp_path, damage):
    f = owned_return_projection_fixture(tmp_path)
    c, _, _, snapshot, records, ids = f
    allowed = set(ids.values())
    if damage == 'no_cleanup':
        c['lifecycle_contract']['resources'][0]['cleanup']['api'] = None
    elif damage == 'not_mandatory':
        c['lifecycle_contract']['resources'][0]['cleanup']['mandatory'] = False
    elif damage == 'second_resource':
        c['lifecycle_contract']['resources'].append(deepcopy(c['lifecycle_contract']['resources'][0]))
    elif damage == 'missing_caller':
        records = {e: r for e, r in records.items() if r['function_id'] != ids['usage']}
    elif damage == 'excluded_cleanup':
        allowed.remove(ids['dispose'])
    before = deepcopy(c)
    assert not project_owned_return_cleanup(c, snapshot, records, allowed)
    assert c == before


def callback_retirement_fixture(tmp_path):
    import json
    from harness_generation.sfg_adapter import load_sfg_artifacts
    from harness_generation.minimal_ft.models import ProjectSnapshot
    from harness_generation.harness_context.models import ContextBudget, MiningState
    from test_callback_boundaries import callback_plan
    store, plan = callback_plan(tmp_path)
    directory = store.root / 'harness_contexts' / plan['ft_id']
    read = lambda path: json.loads(path.read_text())
    ft = read(store.root / 'minimal_fts' / plan['ft_id'] / 'minimal_ft.json')
    snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(store.root))
    reqs = read(directory / 'requirements.json')['requirements']
    resolutions = read(directory / 'resolutions.json')['resolutions']
    metadata = read(directory / 'metadata.json')
    state = MiningState(ContextBudget(**metadata['configuration']['budget']))
    state.evidence = {r['evidence_id']: r for r in read(directory / 'evidence.json')['records']}
    state.discoveries = metadata['discoveries']
    creator = next(fid for fid, f in snapshot.functions.items() if f['name'] == 'acquire')
    ownership_req = next(r for r in reqs if r['kind'] == 'ownership' and r['subject_function_id'] == creator)
    for fact in resolutions[ownership_req['requirement_id']]['facts']:
        if fact['value']['entries'][0]['return_value']:
            fact['value']['entries'][0]['release_api'] = None
            fact['fact_id'] = fact_id(fact)
    ownership_req['evidence_ids'] = sorted({e for f in resolutions[ownership_req['requirement_id']]['facts'] for e in f['evidence_ids']})
    req = next(r for r in reqs if r['kind'] == 'lifecycle' and r['subject_function_id'] == creator)
    incoming = deepcopy(resolutions[req['requirement_id']])
    previous = deepcopy(incoming)
    previous['facts'][0]['value']['resources'][0]['cleanup'] = {'mandatory': False, 'api': None}
    previous['facts'][0]['fact_id'] = fact_id(previous['facts'][0])
    previous['discovered_api_dependencies'] = []
    resolutions[req['requirement_id']] = previous
    fixture = ft, snapshot, reqs, resolutions, state, read(directory / 'completeness.json')
    return req, previous, incoming, fixture


def test_missing_return_owner_cleanup_api_can_retire_lifecycle_only_after_exact_connection(tmp_path):
    from test_evidence_repairs import configure
    req, previous, incoming, fixture = callback_retirement_fixture(tmp_path)
    owners = deepcopy([f for r in fixture[3].values() for f in r['facts'] if f['predicate'] == 'ownership'])
    merged, audit = merge_resolution(previous, incoming, req, proof_evaluator=configure(fixture))
    assert audit['withdrawals'] and not audit['conflicts']
    assert merged['facts'] == incoming['facts']
    witness = audit['withdrawals'][0]['replacement_proof']['source_witness']
    assert witness['kind'] == 'source_exact_cleanup_connection'
    assert owners == [f for r in fixture[3].values() for f in r['facts'] if f['predicate'] == 'ownership']
    # Without the caller chain, no type/semantic-label fallback may retire it.
    usage = next(fid for fid, f in fixture[1].functions.items() if f['name'] == 'usage')
    fixture[4].evidence = {e: r for e, r in fixture[4].evidence.items() if r.get('function_id') != usage}
    _, blocked = merge_resolution(previous, incoming, req, proof_evaluator=configure(fixture))
    assert not blocked['withdrawals'] and blocked['conflicts']


@pytest.mark.parametrize('ownership,lifetime,release', [
    ('borrowed', 'until_release', None),
    ('transferred', 'until_release', None),
    ('owned', 'during_call', None),
    ('owned', 'until_release', 'handle'),
])
def test_lifecycle_cleanup_proof_does_not_correct_an_explicit_owner_claim(tmp_path, ownership, lifetime, release):
    from test_evidence_repairs import configure
    req, previous, incoming, fixture = callback_retirement_fixture(tmp_path)
    owner_req = next(r for r in fixture[2] if r['kind'] == 'ownership' and r['subject_function_id'] == req['subject_function_id'])
    for fact in fixture[3][owner_req['requirement_id']]['facts']:
        if not fact['value']['entries'][0]['return_value']:
            continue
        row = fact['value']['entries'][0]
        row.update(ownership=ownership, lifetime=lifetime,
            release_api=next((fid for fid, f in fixture[1].functions.items() if f['name'] == release), None))
        fact['fact_id'] = fact_id(fact)
    _, blocked = merge_resolution(previous, incoming, req, proof_evaluator=configure(fixture))
    assert not blocked['withdrawals'] and blocked['conflicts']


def test_combined_cleanup_api_and_necessity_retirement_requires_exact_release(tmp_path):
    from test_known_issue_repair_smoke import lifecycle_fixture
    req, incoming, evaluator, fixture = lifecycle_fixture(tmp_path)
    previous = deepcopy(incoming)
    previous['facts'][0]['value']['resources'][0]['cleanup'] = {'mandatory': False, 'api': None}
    previous['facts'][0]['fact_id'] = fact_id(previous['facts'][0])
    previous['discovered_api_dependencies'] = []
    merged, audit = merge_resolution(previous, incoming, req, proof_evaluator=evaluator)
    assert audit['withdrawals'] and not audit['conflicts']
    proof = audit['withdrawals'][0]['replacement_proof']
    assert proof['cleanup_api_proved'] and set(proof['proof_scope']) == {'cleanup.api', 'cleanup.mandatory'}
    assert merged['facts'] == incoming['facts']
    # Removing one transitive release body cannot retire an unresolved API.
    from test_evidence_repairs import configure
    state = fixture[4]
    helper = next(fid for fid, function in fixture[1].functions.items() if function['name'] == 'release_storage')
    state.evidence = {eid: r for eid, r in state.evidence.items() if r.get('function_id') != helper}
    _, blocked = merge_resolution(previous, incoming, req, proof_evaluator=configure(fixture))
    assert not blocked['withdrawals'] and blocked['conflicts']


def test_a_second_concrete_cleanup_api_is_not_disproved_by_one_release(tmp_path):
    from test_known_issue_repair_smoke import lifecycle_fixture
    req, incoming, evaluator, fixture = lifecycle_fixture(tmp_path)
    previous = deepcopy(incoming)
    other = next(fid for fid, f in fixture[1].functions.items() if f['name'] == 'unrelated')
    previous['facts'][0]['value']['resources'][0]['cleanup'] = {'mandatory': True, 'api': other}
    previous['facts'][0]['fact_id'] = fact_id(previous['facts'][0])
    _, audit = merge_resolution(previous, incoming, req, proof_evaluator=evaluator)
    assert not audit['withdrawals'] and audit['conflicts']


def test_omitted_return_creator_is_retired_only_in_that_field(tmp_path):
    from test_known_issue_repair_smoke import lifecycle_fixture
    req, incoming, evaluator, fixture = lifecycle_fixture(tmp_path)
    previous = deepcopy(incoming)
    previous['facts'][0]['value']['resources'][0]['creation']['api'] = None
    previous['facts'][0]['fact_id'] = fact_id(previous['facts'][0])
    _, audit = merge_resolution(previous, incoming, req, proof_evaluator=evaluator)
    assert not audit['conflicts']
    # An omitted nullable field is filled by the existing monotone merge;
    # source projection handles a standalone producer omission separately.
    previous['facts'][0]['value']['resources'][0]['reuse'] = 'per_context'
    previous['facts'][0]['fact_id'] = fact_id(previous['facts'][0])
    _, blocked = merge_resolution(previous, incoming, req, proof_evaluator=evaluator)
    assert not blocked['withdrawals'] and blocked['conflicts']


def test_source_projected_cleanup_does_not_protect_the_old_owned_claim(tmp_path):
    from test_known_issue_repair_smoke import lifecycle_fixture
    from test_evidence_repairs import configure
    from test_harness_context import owner
    from harness_generation.harness_context.proposals import ownership_subject
    from harness_generation.harness_context.evidence import build_context
    _, _, _, fixture = lifecycle_fixture(tmp_path)
    fid = next(fid for fid, function in fixture[1].functions.items() if function['name'] == 'node_free')
    req = next(r for r in fixture[2] if r['kind'] == 'ownership' and r['subject_function_id'] == fid)
    row = owner('node', ownership='owned')
    row.update(ownership_subject(row, fid, fixture[1]))
    row.pop('function_id')
    fact = dict(requirement_id=req['requirement_id'], function_id=fid, predicate='ownership',
        value={'entries': [row]}, evidence_ids=sorted(fixture[4].evidence))
    fact['fact_id'] = fact_id(fact)
    previous = dict(requirement_id=req['requirement_id'], status='resolved', facts=[fact],
        discovered_api_dependencies=[], open_questions=[])
    fixture[3][req['requirement_id']] = previous
    evaluator = configure(fixture)
    context = build_context(fixture[0], fixture[2], evaluator.facts, fixture[1], fixture[4].evidence)
    _, _, graph = evaluator._projection(previous, req)
    evaluator.remember(context, graph)
    incoming = deepcopy(previous)
    incoming['facts'][0]['value']['entries'][0]['ownership'] = 'transferred'
    incoming['facts'][0]['fact_id'] = fact_id(incoming['facts'][0])
    _, audit = merge_resolution(previous, incoming, req, proof_evaluator=evaluator)
    assert audit['withdrawals'] and not audit['conflicts']
    assert audit['withdrawals'][0]['replacement_proof']['source_witness']['kind'] == 'source_exact_cleanup_consumption'


@pytest.mark.parametrize('body,proved', [
    ('P *p=calloc(1,sizeof(P));return p;', True),
    ('P *p=calloc(1,sizeof(P));if(!p)return NULL;return p;', True),
    ('static P p;return &p;', False),
    ('P *p=calloc(1,sizeof(P));free(p);return p;', False),
    ('if(flag)return shared;return calloc(1,sizeof(P));', False),
    ('return unknown();', False),
])
def test_nullable_self_creator_projection_requires_all_exported_values_allocated(tmp_path, body, proved):
    source = 'typedef struct P {int n;} P; P *shared;P *create(int flag){' + body + '}int parse(P *p){return p->n;}'
    snapshot, ids, records, issued = analysis_fixture(tmp_path, source)
    context = {'lifecycle_contract': {'resources': [dict(function_id=ids['create'], return_value=True,
        resource_id='resource_label', creation={'kind': 'creator_api', 'api': None})]}}
    certificates = project_allocated_return_creation(context, snapshot, records, set(ids.values()))
    assert bool(certificates) == proved
    assert context['lifecycle_contract']['resources'][0]['creation']['api'] == (ids['create'] if proved else None)


OUT = '''#include <stdlib.h>
typedef struct P {int n;} P;
int fill(P **out) {*out=calloc(1,sizeof(P));return 1;}
void dispose(P *p) {free(p);}
int parse(P *p) {return p->n;}
void usage(void) {P *p;fill(&p);parse(p);dispose(p);}
'''


def out_context(tmp_path, source=OUT):
    f = graph_fixture(tmp_path, source)
    context, _, _, snapshot, records, ids = f
    observations = resolve_resources(context, snapshot, records)['value_flow']['observations']
    rid = next((o['resource_id'] for o in observations if o['function_id'] == ids['parse']), 'resource_unknown')
    common = dict(field=None, return_value=False, evidence_ids=list(records), fact_id='fact_pointee', resource_id=rid)
    context['ownership_contract']['entries'] = [dict(common, function_id=ids['fill'], parameter='out',
        subject_kind='OutParameterPointee', ownership='owned', release_api=ids['dispose'], lifetime='until_release'),
        dict(common, function_id=ids['fill'], parameter='out', subject_kind='PointerParameter', ownership='borrowed',
            release_api=None, lifetime='during_call', resource_id='storage_distinct'),
        dict(common, function_id=ids['dispose'], parameter='p', subject_kind='PointerParameter', ownership='owned',
            release_api=None, lifetime='during_call')]
    context['lifecycle_contract']['resources'] = [dict(function_id=ids['parse'], subject_parameter='p',
        return_value=False, resource_id=rid, type='P', creation=dict(kind='creator_api', api=ids['fill']),
        cleanup=dict(mandatory=True, api=ids['dispose']), evidence_ids=list(records))]
    proposal(f, 'dispose', 'p', 'derived', rid=rid)
    return f


def test_out_pointee_cleanup_consumption_does_not_change_creator_ownership_or_storage(tmp_path):
    f = out_context(tmp_path)
    owners = f[0]['ownership_contract']['entries']
    producer, storage = deepcopy(owners[0]), deepcopy(owners[1])
    owners[2]['ownership'] = 'unknown'
    certificates = project_out_cleanup_consumption(f[0], f[3], f[4], set(f[-1].values()))
    assert len(certificates) == 1 and certificates[0]['producer_subject_kind'] == 'OutParameterPointee'
    assert owners[0] == producer and owners[1] == storage
    assert owners[2]['ownership'] == 'transferred'
    assert certificates[0]['resource_id'] != storage['resource_id']


def test_out_pointee_cleanup_preserves_an_explicit_wrong_owned_claim(tmp_path):
    f = out_context(tmp_path)
    assert not project_out_cleanup_consumption(f[0], f[3], f[4], set(f[-1].values()))
    assert f[0]['ownership_contract']['entries'][2]['ownership'] == 'owned'


@pytest.mark.parametrize('source', [
    OUT.replace('*out=calloc(1,sizeof(P));', 'if(flag)*out=calloc(1,sizeof(P));').replace('fill(P **out)', 'fill(P **out,int flag)').replace('fill(&p)', 'fill(&p,0)'),
    OUT.replace('*out=calloc(1,sizeof(P));', '*out=shared;').replace('int fill(', 'static P *shared;int fill('),
    OUT.replace('free(p);', 'if(p->n)free(p);'),
    OUT.replace('free(p);', 'free(p);free(p);'),
    OUT.replace('free(p);', 'p=calloc(1,sizeof(P));free(p);'),
])
def test_out_pointee_unknown_allocation_or_partial_wrong_release_cannot_project(tmp_path, source):
    f = out_context(tmp_path, source)
    assert not project_out_cleanup_consumption(f[0], f[3], f[4], set(f[-1].values()))
    assert f[0]['ownership_contract']['entries'][2]['ownership'] == 'owned'
