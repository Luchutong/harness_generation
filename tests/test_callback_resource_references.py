"""Erased callback resource references need a fresh authenticated owner chain."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from harness_generation.context_generation import HarnessPlanBuilder
from harness_generation.context_generation.builder import PlanError
from harness_generation.harness_context import ContextBudget, MiningState, HarnessContextCompletenessValidator
from harness_generation.harness_context.api_closure import build_api_closure
from harness_generation.harness_context.callback_resources import prove_callback_resource_reference, VERSION
from harness_generation.harness_context.evidence import build_context
from harness_generation.harness_context.models import fact_id
from harness_generation.harness_context.persistence import load_context_documents
from harness_generation.minimal_ft.models import ProjectSnapshot
from harness_generation.semantic_discovery.models import digest
from harness_generation.sfg_adapter import load_sfg_artifacts
from test_callback_boundaries import callback_plan, SOURCE
from test_argument_graph import graph_fixture


def load_prepared(root):
    directory = next((root / 'harness_contexts').iterdir())
    read = lambda p: json.loads(p.read_text())
    ft = read(root / 'minimal_fts' / directory.name / 'minimal_ft.json')
    snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(root))
    metadata = read(directory / 'metadata.json')
    state = MiningState(ContextBudget(**metadata['configuration']['budget']))
    state.evidence = {row['evidence_id']: row for row in read(directory / 'evidence.json')['records']}
    state.discoveries = metadata['discoveries']
    return [ft, snapshot, read(directory / 'requirements.json')['requirements'],
            read(directory / 'resolutions.json')['resolutions'], state]


def rebuild(prepared):
    ft, snapshot, requirements, resolutions, state = prepared
    facts = []
    for req in requirements:
        result = resolutions.get(req['requirement_id'])
        if result:
            req['status'] = result['status']
            req['evidence_ids'] = sorted({eid for fact in result['facts'] for eid in fact['evidence_ids']})
            facts += result['facts']
    closure = build_api_closure(ft, requirements, resolutions, snapshot, state)
    context = build_context(ft, requirements, facts, snapshot, state.evidence)
    context['dependencies'] = closure['unresolved_api_dependencies']
    report = gate(context, closure, prepared)
    context['frozen'] = report['generation_allowed']
    return context, closure, report


def gate(context, closure, prepared):
    ft, snapshot, requirements, resolutions, state = prepared
    return HarnessContextCompletenessValidator().validate(
        context, closure, ft, snapshot, requirements, resolutions, state)


@pytest.fixture(scope='module')
def baseline(tmp_path_factory):
    store, _ = callback_plan(tmp_path_factory.mktemp('callback_resource'))
    prepared = load_prepared(store.root)
    _, snapshot, requirements, resolutions, state = prepared
    ids = {fn['name']: fid for fid, fn in snapshot.functions.items()}
    req = next(r for r in requirements if r['subject_function_id'] == ids['handle'] and r['kind'] == 'input_binding')
    binding = dict(parameter='user', source='context', transform='none', via_function_id=ids['acquire'],
                   size_parameter=None, size_relation='none', mutable=False, nul_terminated=False,
                   binary_zero_allowed=None, alignment='none')
    evidence = sorted(eid for eid, row in state.evidence.items()
                      if row.get('function_id') == ids['handle'] and row['tool'] == 'get_function')
    fact = dict(requirement_id=req['requirement_id'], function_id=ids['handle'], predicate='input_binding',
                value={'bindings': [binding]}, evidence_ids=evidence)
    fact['fact_id'] = fact_id(fact)
    result = resolutions[req['requirement_id']]
    result.update(status='resolved', open_questions=[])
    result['facts'] = sorted(result['facts'] + [fact], key=lambda f: f['fact_id'])
    context, closure, report = rebuild(prepared)
    assert report['generation_allowed'], report
    binding = next(b for b in context['input_contract']['bindings'] if b['parameter'] == 'user')
    return prepared, context, closure, report, binding, ids, store


def test_bridge_closes_gate_plan_without_new_lifecycle_facts_or_fuzz_roots(baseline):
    prepared, context, closure, report, binding, ids, _ = baseline
    proof = prove_callback_resource_reference(context, binding, prepared[1], prepared[4].evidence)
    assert context['callback_resource_references'] == [proof]
    assert proof['version'] == VERSION and proof['source_records']
    assert not any(r['function_id'] == ids['handle'] and r['subject_parameter'] == 'user'
                   for r in context['lifecycle_contract']['resources'])
    assert not any(f['predicate'] == 'lifecycle' and f['function_id'] == ids['handle'] for f in context['facts'])
    assert all('callback_resource' not in f for f in context['facts'])
    plan = HarnessPlanBuilder().build(prepared[0], context, closure, prepared[1], report)
    assert plan['callback_resource_references'] == [{k: v for k, v in proof.items() if k != 'source_records'}]
    callback = next(row for row in plan['call_sequence'] if row['function_id'] == ids['handle'])
    assert callback['invocation_kind'] == 'callback' and callback['via_function_id'] == ids['parse']
    assert not any(root.get('parameter') == 'user' for root in context['external_input_flow']['roots'])
    assert context['facts'] == sorted([fact for result in prepared[3].values() for fact in result['facts']], key=lambda f: f['fact_id'])


@pytest.mark.parametrize('change', ['delete', 'rid', 'producer', 'source_record', 'inner_eid', 'missing_body', 'duplicate_record', 'dispatch'])
def test_certificate_deletion_and_tampering_rejected_by_gate_and_independent_plan(baseline, change):
    prepared, context, closure, report, _, ids, _ = baseline
    context = deepcopy(context)
    proof = context['callback_resource_references'][0]
    if change == 'delete':
        context['callback_resource_references'] = []
    elif change == 'rid':
        proof['resource_id'] = 'resource_unissued'
    elif change == 'producer':
        proof['producer_api'] = ids['parse']
    elif change == 'source_record':
        proof['source_records'][0]['content'] += ' /* tampered */'
    elif change == 'inner_eid':
        proof['source_records'][0]['evidence_id'] = 'ev_tampered'
    elif change == 'missing_body':
        proof['source_records'] = []
    elif change == 'duplicate_record':
        proof['source_records'].append(deepcopy(proof['source_records'][0]))
    elif change == 'dispatch':
        proof['callback_dispatch']['calls_per_invocation'] = 2
    actual = gate(context, closure, prepared)
    assert actual['generation_allowed'] is False
    assert any(e['code'] == 'context_changed_canonical_projection' for e in actual['validation_errors'])
    with pytest.raises(PlanError):
        HarnessPlanBuilder().build(prepared[0], context, closure, prepared[1], report)


@pytest.mark.parametrize('change', ['via', 'fuzz_data', 'derived', 'transform', 'rid', 'owned', 'lifetime', 'release', 'missing_owner', 'missing_lifecycle', 'mandatory', 'reuse', 'cleanup', 'explicit_consumer_lifecycle'])
def test_concrete_wrong_or_missing_semantics_never_gain_reference(baseline, change):
    prepared, original, _, _, original_binding, ids, _ = baseline
    context, binding = deepcopy(original), deepcopy(original_binding)
    producer = next(r for r in context['lifecycle_contract']['resources'] if r['function_id'] == ids['acquire'])
    owner = next(r for r in context['ownership_contract']['entries'] if r['function_id'] == ids['acquire'])
    if change == 'via': binding['via_function_id'] = ids['parse']
    elif change in {'fuzz_data', 'derived'}: binding['source'] = change
    elif change == 'transform': binding['transform'] = 'direct'
    elif change == 'rid': producer['resource_id'] = 'resource_wrong'
    elif change == 'owned': owner['ownership'] = 'borrowed'
    elif change == 'lifetime': owner['lifetime'] = 'during_call'
    elif change == 'release': owner['release_api'] = ids['parse']
    elif change == 'missing_owner': context['ownership_contract']['entries'].remove(owner)
    elif change == 'missing_lifecycle': context['lifecycle_contract']['resources'].remove(producer)
    elif change == 'mandatory': producer['cleanup']['mandatory'] = False
    elif change == 'reuse': producer['reuse'] = 'unknown'
    elif change == 'cleanup': producer['cleanup']['api'] = ids['parse']
    elif change == 'explicit_consumer_lifecycle':
        context['lifecycle_contract']['resources'].append({**deepcopy(producer), 'function_id': ids['handle'],
            'subject_parameter': 'user', 'return_value': False, 'resource_id': 'resource_wrong'})
    assert prove_callback_resource_reference(context, binding, prepared[1], prepared[4].evidence) is None


def test_bad_source_record_inner_identity_rejected_even_with_signed_dictionary_key(baseline):
    prepared, context, _, _, binding, _, _ = baseline
    records = deepcopy(prepared[4].evidence)
    next(iter(records.values()))['evidence_id'] = 'ev_wrong_inner'
    assert prove_callback_resource_reference(context, binding, prepared[1], records) is None


def test_wrong_via_projects_exact_input_binding_gap_with_original_owner_untouched(baseline):
    original, _, _, _, _, ids, _ = baseline
    prepared = [deepcopy(original[0]), original[1], deepcopy(original[2]), deepcopy(original[3]), original[4]]
    req = next(r for r in prepared[2] if r['kind'] == 'input_binding' and r['subject_function_id'] == ids['handle'])
    result = prepared[3][req['requirement_id']]
    fact = next(f for f in result['facts'] if any(b['parameter'] == 'user' for b in f['value']['bindings']))
    next(b for b in fact['value']['bindings'] if b['parameter'] == 'user')['via_function_id'] = ids['parse']
    fact['fact_id'] = fact_id(fact)
    result['facts'].sort(key=lambda f: f['fact_id'])
    _, _, report = rebuild(prepared)
    gaps = [r for r in report['hard_missing'] if r['code'] == 'shared_resource_identity_unresolved']
    assert gaps and all(r['kind'] == 'input_binding' and r['subject_parameter'] == 'user' for r in gaps)
    assert all(r['requirement_id'] == req['requirement_id'] for r in gaps)


@pytest.mark.parametrize('change', ['policy', 'proof_version'])
def test_old_successful_context_policy_cannot_be_reused(baseline, change):
    _, _, _, _, _, _, store = baseline
    root = next((store.root/'harness_contexts').iterdir())
    config = json.loads((root/'metadata.json').read_text())['configuration']
    assert config['callback_resource_reference_version'] == VERSION
    before = digest(config)
    if change == 'policy': config['policy_version'] = 'source-grounded-harness-context-v8'
    else: config.pop('callback_resource_reference_version')
    assert digest(config) != before
    assert load_context_documents(store, root.name, config, None) is None


@pytest.mark.parametrize('source,accepted', [
    (SOURCE, True),
    (SOURCE.replace('User *u=user; return', 'User *u=user; saved[0]=u; return'), False),
    (SOURCE.replace('User *u=user; return', 'User *u=user; *out=u; return'), False),
    (SOURCE.replace('User *u=user; return', 'User *u=user; holder.ptr=u; return'), False),
    (SOURCE.replace('User *u=user; return', 'User *u=user; stash(u); return'), False),
    (SOURCE.replace('User *u=user; return', 'User *u=user; saved[0]=&u->bias; return'), False),
    (SOURCE.replace('User *u=user; return', 'User *u=user; ++u; return'), False),
    (SOURCE.replace('return handler(user,src,cb);', 'return cb ? handler(user,src,cb) : 0;'), False),
    (SOURCE.replace('void *user', 'User *user'), False),
    (SOURCE + 'void again(const unsigned char *raw,size_t extent) { User *u=acquire(1); parse(raw,extent,handle,u); dispose(u); }\n', False),
])
def test_source_control_retention_interior_pointer_unknown_call_and_competing_origins(baseline, tmp_path, source, accepted):
    from harness_generation.harness_context.resource_identity import _cleanup_source_view
    prepared, original, _, _, original_binding, old_ids, _ = baseline
    fixture = graph_fixture(tmp_path, source)
    snapshot, records, ids = fixture[3:6]
    replacements = {old_ids[name]: ids[name] for name in old_ids}

    def replace(value):
        if isinstance(value, dict): return {k: replace(v) for k, v in value.items()}
        if isinstance(value, list): return [replace(v) for v in value]
        if isinstance(value, str): return replacements.get(value, value)
        return value

    context = replace(original)
    _, graph = _cleanup_source_view(context, snapshot, records)
    origins = [row for row in graph['resource_origins']
               if row['origin']['function_id'] == ids['acquire'] and row['origin']['kind'] == 'return']
    assert origins, 'counterexample must retain the same explicit creator source'
    old_rid = original['callback_resource_references'][0]['resource_id']
    replacements[old_rid] = origins[0]['resource_id']
    context, binding = replace(original), replace(original_binding)
    context['argument_graph']['callback_dispatches'] = graph['callback_dispatches']
    assert (prove_callback_resource_reference(context, binding, snapshot, records) is not None) is accepted
