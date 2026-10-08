"""Native contract revisions commit together or preserve the active baseline.

Uses the existing issued-source extent fixture and real closure projections.
These tests are written while execution is paused; no provider is involved.
"""
from copy import deepcopy

import pytest

from harness_generation.harness_context.api_closure import build_api_closure
from harness_generation.harness_context.closure_feedback import build_closure_feedback
from harness_generation.harness_context.completeness import HarnessContextCompletenessValidator
from harness_generation.harness_context.evidence import build_context
from harness_generation.harness_context.input_pairs import buffer_pairs
from harness_generation.harness_context.models import fact_id
from harness_generation.harness_context.repair_transactions import evaluate_revision, semantic_signature
from harness_generation.semantic_discovery.models import canonical
from test_context_revision_proofs import extent_fixture, extent_patch
from test_evidence_repairs import configure, target


def facts_of(resolutions):
    return [fact for resolution in resolutions.values() for fact in resolution['facts']]


def project(fixture, *, requirements=None, resolutions=None):
    ft, snapshot, rows, active, state, _ = fixture
    rows = deepcopy(rows if requirements is None else requirements)
    active = deepcopy(active if resolutions is None else resolutions)
    for row in rows:
        resolution = active.get(row['requirement_id'])
        if resolution:
            row['status'] = resolution['status']
            row['evidence_ids'] = sorted({eid for fact in resolution['facts'] for eid in fact['evidence_ids']})
    closure = build_api_closure(ft, rows, active, snapshot, state)
    context = build_context(ft, rows, facts_of(active), snapshot, state.evidence)
    context['dependencies'] = deepcopy(closure['unresolved_api_dependencies'])
    report = HarnessContextCompletenessValidator().validate(context, closure, ft, snapshot, rows, active, state)
    return rows, context, closure, report


def prepare_revision(fixture):
    """Both omitted links were actually submitted; proposals contain new rows only."""
    proposals = {}
    old_fact_ids = set()
    for kind, collection, slot in (
            ('input_binding', 'bindings', 'size_parameter'),
            ('buffer_length', 'links', 'length_parameter')):
        row = target(fixture, 'parse', kind)
        rid = row['requirement_id']
        original = deepcopy(fixture[3][rid])
        # Retain other buffers and other subjects in the active resolution.
        missing = deepcopy(original)
        old = next(f for f in missing['facts'] if f['value'][collection][0].get(
            'parameter', f['value'][collection][0].get('buffer_parameter')) == 'data')
        old['value'][collection][0][slot] = None
        old['fact_id'] = fact_id(old)
        missing['facts'].sort(key=lambda f: f['fact_id'])
        fixture[3][rid] = missing
        old_fact_ids.add(old['fact_id'])
        proposals[rid] = extent_patch(original, kind, 'size')
    _, context, _, report = project(fixture)
    assert not report['generation_allowed']
    snapshot = fixture[1]
    signed = {'input_length_choices': [dict(pair, function_id=fid)
        for fid in context['core_apis'] for pair in buffer_pairs(snapshot.functions[fid])]}
    feedback = build_closure_feedback(report, fixture[2], facts_of(fixture[3]),
        signed=signed, evidence=fixture[4].evidence,
        canonical_construction=context.get('canonical_construction'))
    return proposals, old_fact_ids, feedback, report


def immutable_inputs(fixture, incoming, feedback, protected):
    return deepcopy({'ft': fixture[0], 'requirements': fixture[2], 'resolutions': fixture[3],
        # The snapshot's read-only index is a MappingProxyType. Copy its
        # underlying records for the immutability assertion, not the proxy.
        'snapshot_functions': dict(fixture[1].functions),
        'source_fingerprint': fixture[1].source_fingerprint,
        'state': vars(fixture[4]), 'incoming': incoming, 'feedback': feedback, 'protected': protected})


def evaluate(fixture, incoming, feedback, *, protected=None, execution_failures=None):
    protected = {} if protected is None else protected
    before = immutable_inputs(fixture, incoming, feedback, protected)
    failures_before = deepcopy(execution_failures)
    outcome = evaluate_revision(fixture[0], fixture[1], fixture[4], fixture[2], fixture[3],
        incoming, feedback=feedback, protected=protected, execution_failures=execution_failures)
    assert immutable_inputs(fixture, incoming, feedback, protected) == before
    assert execution_failures == failures_before
    assert isinstance(outcome.audit['transaction_id'], str) and outcome.audit['transaction_id']
    return outcome


def assert_active_baseline(outcome, fixture, baseline):
    assert outcome.resolutions == fixture[3]
    assert {f['fact_id']: f for f in outcome.facts} == {
        f['fact_id']: f for f in facts_of(fixture[3])}
    assert outcome.report['generation_allowed'] == baseline['generation_allowed']
    assert outcome.report['semantic_obligation_graph_digest'] == baseline['semantic_obligation_graph_digest']


@pytest.mark.parametrize('reverse_submission_order', [False, True])
def test_two_native_extent_submissions_commit_together(tmp_path, reverse_submission_order):
    fixture = extent_fixture(tmp_path)
    incoming, missing_ids, feedback, _ = prepare_revision(fixture)
    if reverse_submission_order:
        incoming = dict(reversed(list(incoming.items())))
    outcome = evaluate(fixture, incoming, feedback)
    assert outcome.audit['status'] == 'committed'
    assert outcome.report['status'] == 'complete'
    assert outcome.report['generation_allowed']
    assert outcome.report['hard_missing'] == []
    assert missing_ids.isdisjoint(f['fact_id'] for f in outcome.facts)
    for kind, collection, slot in (
            ('input_binding', 'bindings', 'size_parameter'),
            ('buffer_length', 'links', 'length_parameter')):
        rid = target(fixture, 'parse', kind)['requirement_id']
        assert outcome.resolutions[rid]['facts'][0]['value'][collection][0][slot] == 'size'
    parse = target(fixture, 'parse', 'input_binding')['subject_function_id']
    recipes = {p['parameter']: p for p in outcome.context['canonical_construction']['parameters']
        if p['function_id'] == parse}
    assert recipes['data']['status'] == recipes['size']['status'] == 'resolved'
    assert recipes['data']['recipe']['kind'] == 'fuzz_bytes'
    assert recipes['size']['recipe']['kind'] == 'fuzz_size'


@pytest.mark.parametrize('submitted_kind', ['input_binding', 'buffer_length'])
def test_one_extent_side_is_rejected_and_does_not_publish_half_a_revision(tmp_path, submitted_kind):
    fixture = extent_fixture(tmp_path)
    incoming, missing_ids, feedback, baseline = prepare_revision(fixture)
    rid = target(fixture, 'parse', submitted_kind)['requirement_id']
    outcome = evaluate(fixture, {rid: incoming[rid]}, feedback)
    assert outcome.audit['status'] == 'rejected'
    assert outcome.audit['rejection_diagnostics']
    assert_active_baseline(outcome, fixture, baseline)
    assert missing_ids <= {f['fact_id'] for f in outcome.facts}


@pytest.mark.parametrize('conflict', ['input_boolean', 'buffer_metadata'])
def test_a_complete_extent_answer_cannot_override_competing_boolean_or_metadata(tmp_path, conflict):
    fixture = extent_fixture(tmp_path)
    incoming, _, feedback, baseline = prepare_revision(fixture)
    kind = 'input_binding' if conflict == 'input_boolean' else 'buffer_length'
    rid = target(fixture, 'parse', kind)['requirement_id']
    fact = incoming[rid]['facts'][0]
    if conflict == 'input_boolean':
        fact['value']['bindings'][0]['binary_zero_allowed'] = False
    else:
        fact['value']['applicable'] = False
    fact['fact_id'] = fact_id(fact)
    outcome = evaluate(fixture, incoming, feedback)
    assert outcome.audit['status'] == 'rejected'
    assert outcome.audit['rejection_diagnostics']
    assert_active_baseline(outcome, fixture, baseline)


def test_proved_scalar_recipe_is_preserved_when_a_linked_revision_changes_it(tmp_path):
    fixture = extent_fixture(tmp_path)
    evaluator = configure(fixture)
    _, context, _, complete = project(fixture)
    evaluator.remember(context, complete['semantic_obligation_graph'])
    protected = deepcopy(evaluator.protected)
    assert protected
    incoming, _, feedback, baseline = prepare_revision(fixture)
    rid = target(fixture, 'parse', 'argument_construction')['requirement_id']
    proposal = deepcopy(fixture[3][rid])
    scalar = next(f for f in proposal['facts'] if f['value']['arguments'][0]['parameter'] == 'size')
    scalar['value']['arguments'][0].update(construction='constant', constant=0)
    scalar['fact_id'] = fact_id(scalar)
    proposal['facts'] = [scalar]
    incoming[rid] = proposal
    outcome = evaluate(fixture, incoming, feedback, protected=protected)
    assert outcome.audit['status'] == 'rejected'
    assert_active_baseline(outcome, fixture, baseline)


def test_another_proved_buffer_is_retained_by_a_subject_local_transaction(tmp_path):
    source = '''typedef unsigned long size_t;
int parse(const unsigned char *data,size_t size,const unsigned char *other,size_t count){
    return (size?data[0]:0)+(count?other[0]:0);
}
'''
    fixture = extent_fixture(tmp_path, source=source, extra_buffer=('other', 'count'))
    incoming, _, feedback, _ = prepare_revision(fixture)
    independent = [deepcopy(f) for f in facts_of(fixture[3]) if any(
        row.get('parameter', row.get('buffer_parameter')) == 'other'
        for key in ('bindings', 'links', 'arguments', 'entries') for row in f['value'].get(key, []))]
    assert independent
    outcome = evaluate(fixture, incoming, feedback)
    assert outcome.audit['status'] == 'committed'
    assert outcome.report['generation_allowed']
    assert all(f in outcome.facts for f in independent)


def test_repeating_an_accepted_native_answer_is_no_progress(tmp_path):
    fixture = extent_fixture(tmp_path)
    incoming, _, feedback, _ = prepare_revision(fixture)
    committed = evaluate(fixture, incoming, feedback)
    assert committed.audit['status'] == 'committed'
    active = (fixture[0], fixture[1], deepcopy(committed.requirements),
        deepcopy(committed.resolutions), fixture[4], committed.report)
    fresh_feedback = build_closure_feedback(committed.report, active[2], facts_of(active[3]),
        evidence=active[4].evidence, canonical_construction=committed.context.get('canonical_construction'))
    duplicate = evaluate(active, incoming, fresh_feedback)
    assert duplicate.audit['status'] == 'no_progress'
    assert_active_baseline(duplicate, active, committed.report)


def test_evaluation_keeps_the_already_charged_ledger_and_issued_discoveries(tmp_path):
    fixture = extent_fixture(tmp_path)
    incoming, _, feedback, _ = prepare_revision(fixture)
    state = fixture[4]
    # The pure validator sees a continuation's existing ledger. It cannot
    # refund the calls or replace already-issued discoveries on rejection.
    state.model_calls = state.budget.max_total_model_calls
    state.tool_calls = 12
    state.source_chars = 8367
    state.tokens = {'prompt_tokens': 270000, 'completion_tokens': 9211, 'total_tokens': 279211}
    state.budget_stop = 'max_total_model_calls'
    before = deepcopy(vars(state))
    rid = target(fixture, 'parse', 'input_binding')['requirement_id']
    outcome = evaluate(fixture, {rid: incoming[rid]}, feedback)
    assert outcome.audit['status'] == 'rejected'
    assert vars(state) == before
    assert state.evidence and state.discoveries == before['discoveries']


@pytest.mark.parametrize('has_valid_sibling_submission', [False, True])
def test_provider_failure_preserves_baseline_instead_of_becoming_a_semantic_rejection(
        tmp_path, has_valid_sibling_submission):
    fixture = extent_fixture(tmp_path)
    incoming, _, feedback, baseline = prepare_revision(fixture)
    rid = target(fixture, 'parse', 'input_binding')['requirement_id']
    failures = {rid: {'requirement_id': rid, 'execution_status': 'provider_error',
        'errors': [{'kind': 'model_error', 'detail': 'offline provider-error diagnostic'}]}}
    submitted = incoming if has_valid_sibling_submission else {}
    outcome = evaluate(fixture, submitted, feedback, execution_failures=failures)
    assert outcome.audit['status'] == 'execution_failure'
    assert outcome.audit['rejection_diagnostics'] == [
        {'code': 'revision_execution_failure', 'failures': failures}]
    assert not outcome.audits
    assert_active_baseline(outcome, fixture, baseline)


def dependency_fixture(tmp_path):
    import json

    from harness_generation.harness_context.agent import HarnessContextAgent
    from harness_generation.harness_context.evidence import validate_resolution_record
    from harness_generation.harness_context.persistence import context_directory
    from test_harness_context import CONTEXT, ScriptedModel, context_specs, mine, setup

    prepared = setup(tmp_path, CONTEXT)
    specs = context_specs(prepared[0][-1])
    run, _ = mine(prepared, specs, query_type='Context', persist=True)
    directory = context_directory(prepared[0][0], prepared[1]['ft_id'])
    rows = json.loads((directory / 'requirements.json').read_text())['requirements']
    resolutions = json.loads((directory / 'resolutions.json').read_text())['resolutions']
    fixture = prepared[1], prepared[3], rows, resolutions, prepared[4], run.completeness
    row = target(fixture, 'parse', 'lifecycle')
    # Framework source reconciliation may close this slot without a native
    # selection. Explicitly investigate the existing Context fixture so these
    # reference-only tests receive a real parsed dependency with issued body
    # evidence and signed subject/effect bindings.
    model = ScriptedModel(specs, query_type='Context', initial_ids=prepared[-1].initial_ids)
    native_run = HarnessContextAgent(model, prepared[4]).investigate(
        row, prepared[-1], facts_of(resolutions),
        obligation_graph=run.completeness['semantic_obligation_graph'])
    native = native_run.metadata['native_submission']['resolution']
    assert native is not None and native['discovered_api_dependencies'], native_run.metadata
    validate_resolution_record(native, row, prepared[3], prepared[4],
        prepared[-1].initial_ids, prepared[-1].excluded)
    resolutions[row['requirement_id']] = deepcopy(native)
    return fixture


def test_only_referenced_evidence_ids_change_is_no_progress(tmp_path):
    fixture = dependency_fixture(tmp_path)
    rid, original = next((rid, result) for rid, result in fixture[3].items()
        if result['discovered_api_dependencies'])
    incoming = deepcopy(original)
    dependency = incoming['discovered_api_dependencies'][0]
    # Keep the real API body certificate. Add another already-issued record;
    # neither a new source claim nor a fresh discovery is being submitted.
    additional = next(eid for eid in fixture[4].evidence if eid not in dependency['evidence_ids'])
    dependency['evidence_ids'] = sorted({*dependency['evidence_ids'], additional})
    incoming['discovered_api_dependencies'].sort(key=canonical)
    fact = incoming['facts'][0]
    fact['evidence_ids'] = sorted({*fact['evidence_ids'], additional})
    fact['fact_id'] = fact_id(fact)
    incoming['facts'].sort(key=lambda f: f['fact_id'])
    _, context, _, baseline = project(fixture)
    feedback = build_closure_feedback(baseline, fixture[2], facts_of(fixture[3]),
        evidence=fixture[4].evidence, canonical_construction=context.get('canonical_construction'))
    assert incoming != original
    assert semantic_signature({rid: incoming}) == semantic_signature({rid: original})
    outcome = evaluate(fixture, {rid: incoming}, feedback)
    assert outcome.audit['status'] == 'no_progress'
    assert not outcome.audits
    assert_active_baseline(outcome, fixture, baseline)


def test_dependency_references_do_not_multiply_semantic_progress(tmp_path):
    fixture = dependency_fixture(tmp_path)
    original = fixture[3]
    identities_only = deepcopy(original)
    result = next(result for result in identities_only.values() if result['discovered_api_dependencies'])
    duplicate = deepcopy(result['discovered_api_dependencies'][0])
    additional = next(eid for eid in fixture[4].evidence if eid not in duplicate['evidence_ids'])
    duplicate['evidence_ids'] = sorted({*duplicate['evidence_ids'], additional})
    result['discovered_api_dependencies'].append(duplicate)
    # This signature test does not submit an invalid duplicate native terminal.
    # It verifies that evidence-union projections cannot buy semantic retries.
    assert semantic_signature(identities_only) == semantic_signature(original)
