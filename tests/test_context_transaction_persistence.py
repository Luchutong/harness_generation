"""Archive actual Agent attempts, then publish a checked candidate as one group.

All models below are the existing offline fixture adapter. Tests are authored
while execution is paused; no fixture, model, import or test is run at authoring.
"""
from copy import deepcopy
import json

import pytest

from harness_generation.harness_context import ContextBudget, HarnessRequirementBuilder
from harness_generation.harness_context.agent import HarnessContextAgent
from harness_generation.harness_context.closure_feedback import build_closure_feedback
from harness_generation.harness_context.input_pairs import buffer_pairs
from harness_generation.harness_context.models import ContextRun
from harness_generation.harness_context.persistence import (
    context_directory, load_context_documents, load_requirement,
    requirement_configuration, run_configuration, save_context, save_requirement,
    save_reconciled_requirement, save_revision_transaction,
)
from harness_generation.harness_context.repair_transactions import evaluate_revision
from harness_generation.records import write_json
from harness_generation.semantic_discovery.agent import ValidationRun
from harness_generation.semantic_discovery.models import FakeAgentModel, digest
from harness_generation.semantic_discovery.persistence import load_run_documents
from test_context_grouping import GroupedFixtureModel
from test_context_repair_transactions import facts_of, project
from test_harness_context import direct_specs, setup


DOCUMENT_NAMES = ('result', 'trace', 'evidence', 'metadata')


def read_document(path):
    return json.loads(path.read_text(encoding='utf-8'))


def document_bytes(directory):
    return {name: (directory / (name + '.json')).read_bytes() for name in DOCUMENT_NAMES}


def persisted_extent_baseline(tmp_path, *, input_status='resolved'):
    """Use the same issued-source extent contracts and actual grouped Agent runs.

    Missing links are submitted by the fixture model itself. We do not clone a
    previously paid run to manufacture an extra model response or attempt.
    """
    prepared = setup(tmp_path, budget=ContextBudget())
    sample, ft, metadata, snapshot, state, tools = prepared
    rows = HarnessRequirementBuilder().build(ft, snapshot)['requirements']
    fid = sample[-1]['parse']
    specs = direct_specs(fid)
    specs[fid, 'input_binding']['status'] = input_status
    specs[fid, 'input_binding']['value']['bindings'][0]['size_parameter'] = None
    specs[fid, 'buffer_length']['value']['links'][0]['length_parameter'] = None
    def keep_unresolved_question(requirement, result):
        if result['status'] == 'unresolved':
            result['open_questions'] = ['The source-backed input contract still needs its explicit length link.']

    model = GroupedFixtureModel(specs, mutate=keep_unresolved_question)
    calls_before = state.model_calls
    initial_runs = HarnessContextAgent(model, state).investigate_group(rows, tools)
    assert all(isinstance(run, ValidationRun) for run in initial_runs)
    assert sum(run.metadata['model_calls'] for run in initial_runs) == state.model_calls - calls_before
    assert sum(run.metadata['group_cost_owner'] for run in initial_runs) == 1
    resolutions = {}
    for run in initial_runs:
        native = run.metadata['native_submission']
        assert native['origin'] == 'validated_native_terminal'
        assert native['resolution_digest'] == digest(native['resolution'])
        assert any(event['kind'] == 'model_response' for event in run.trace['events'])
        # The Agent may split one native collection into independent subjects.
        # Use its actual projection as baseline, without rewriting its terminal.
        resolutions[run.result['requirement_id']] = deepcopy(run.result)
    fixture = ft, snapshot, rows, resolutions, state, None
    rows, context, closure, report = project(fixture)
    fixture = ft, snapshot, rows, resolutions, state, report
    assert not report['generation_allowed']
    configuration = run_configuration(ft, metadata, snapshot, state.budget, model,
        requirement_mode='grouped')
    configurations = {row['requirement_id']: requirement_configuration(configuration, row) for row in rows}
    by_id = {run.result['requirement_id']: run for run in initial_runs}
    for rid, run in by_id.items():
        assert run.result == resolutions[rid]
        archived = deepcopy(run)
        archived.result = deepcopy(run.metadata['native_submission']['resolution'])
        archived.metadata['result_origin'] = 'native_submission'
        save_requirement(sample[0], ft['ft_id'], archived, configurations[rid])
        if archived.result != run.result:
            row = next(row for row in rows if row['requirement_id'] == rid)
            save_reconciled_requirement(sample[0], ft['ft_id'], row, configurations[rid], run.result,
                run.metadata['subject_local_repairs'][rid], round_number=1)
    root = context_directory(sample[0], ft['ft_id'])
    for row in rows:
        rid = row['requirement_id']
        assert load_run_documents(root / 'agent_runs' / rid, configurations[rid], tools.index)
        if row['status'] == 'unresolved':
            assert resolutions[rid]['facts']
            assert load_requirement(sample[0], ft['ft_id'], row, configurations[rid], tools.index) is None
        else:
            assert load_requirement(sample[0], ft['ft_id'], row, configurations[rid], tools.index)
    return {'prepared': prepared, 'fixture': fixture, 'configuration': configuration,
        'configurations': configurations, 'root': root, 'baseline_runs': by_id,
        'baseline_context': context, 'baseline_closure': closure}


def native_revision(prepared, mode):
    fixture = prepared['fixture']
    ft, snapshot, rows, resolutions, state, baseline = fixture
    tools = prepared['prepared'][5]
    selected = [row for row in rows if row['kind'] in {'input_binding', 'buffer_length'}]
    specs = direct_specs(selected[0]['subject_function_id'])
    if mode in {'rejected', 'no_progress'}:
        fid = selected[0]['subject_function_id']
        specs[fid, 'buffer_length']['value']['links'][0]['length_parameter'] = None
        if mode == 'no_progress':
            specs[fid, 'input_binding']['value']['bindings'][0]['size_parameter'] = None
    model = GroupedFixtureModel(specs)
    calls_before = state.model_calls
    native_runs = HarnessContextAgent(model, state).investigate_group(selected, tools,
        facts_of(resolutions), obligation_graph=baseline['semantic_obligation_graph'])
    assert sum(run.metadata['model_calls'] for run in native_runs) == state.model_calls - calls_before
    assert sum(run.metadata['group_cost_owner'] for run in native_runs) == 1
    assert state.model_calls <= state.budget.max_total_model_calls
    runs = {run.result['requirement_id']: run for run in native_runs}
    incoming = {rid: deepcopy(run.metadata['native_submission']['resolution']) for rid, run in runs.items()}
    assert all(result is not None for result in incoming.values())
    signed = {'input_length_choices': [dict(pair, function_id=fid)
        for fid in prepared['baseline_context']['core_apis'] for pair in buffer_pairs(snapshot.functions[fid])]}
    feedback = build_closure_feedback(baseline, rows, facts_of(resolutions), signed=signed,
        evidence=state.evidence, canonical_construction=prepared['baseline_context']['canonical_construction'])
    before = deepcopy({'state': vars(state), 'rows': rows, 'resolutions': resolutions,
        'ft': ft, 'runs': runs, 'feedback': feedback})
    outcome = evaluate_revision(ft, snapshot, state, rows, resolutions, incoming,
        feedback=feedback, protected={})
    assert outcome.audit['status'] == mode
    assert {'state': vars(state), 'rows': rows, 'resolutions': resolutions,
        'ft': ft, 'runs': runs, 'feedback': feedback} == before
    return runs, outcome


def load_active(prepared, row, configuration=None):
    store, ft = prepared['prepared'][0][0], prepared['fixture'][0]
    return load_requirement(store, ft['ft_id'], row,
        prepared['configurations'][row['requirement_id']] if configuration is None else configuration,
        prepared['prepared'][5].index)


def publish(prepared, runs, outcome):
    store, ft = prepared['prepared'][0][0], prepared['fixture'][0]
    state_before = deepcopy(vars(prepared['fixture'][4]))
    run_before = deepcopy(runs)
    marker = save_revision_transaction(store, ft['ft_id'], runs, prepared['configurations'],
        outcome, round_number=2)
    assert vars(prepared['fixture'][4]) == state_before
    assert runs == run_before
    assert marker['status'] == outcome.audit['status']
    assert marker['decision'] == outcome.audit
    assert marker['decision_digest'] == digest(outcome.audit)
    return marker


def test_commit_keeps_native_terminals_and_their_real_cost_owner_separate_from_projection(tmp_path):
    prepared = persisted_extent_baseline(tmp_path)
    runs, outcome = native_revision(prepared, 'committed')
    prior_attempts = {rid: document_bytes(prepared['root'] / 'agent_runs' / rid / 'attempt_0001')
        for rid in runs}
    marker = publish(prepared, runs, outcome)
    assert outcome.report['generation_allowed']
    assert set(marker['member_projections']) == set(runs)
    assert set(marker['native_attempts']) == set(runs)
    model_calls = 0
    for rid, run in runs.items():
        attempt = prepared['root'] / marker['native_attempts'][rid]['path']
        archive = {name: read_document(attempt / (name + '.json')) for name in DOCUMENT_NAMES}
        assert archive['result'] == run.metadata['native_submission']['resolution']
        assert archive['trace'] == run.trace
        assert archive['evidence'] == run.evidence
        assert archive['metadata']['result_origin'] == 'native_submission'
        assert archive['metadata']['native_submission'] == run.metadata['native_submission']
        assert 'framework_reconciliations' not in archive['metadata']
        assert any(event['kind'] == 'model_response' for event in archive['trace']['events'])
        model_calls += archive['metadata']['model_calls']
        assert document_bytes(prepared['root'] / 'agent_runs' / rid / 'attempt_0001') == prior_attempts[rid]
        row = next(row for row in outcome.requirements if row['requirement_id'] == rid)
        latest = load_active(prepared, row)
        assert latest['result'] == outcome.resolutions[rid]
        assert latest['trace'] == archive['trace'] and latest['evidence'] == archive['evidence']
        assert latest['metadata']['result_origin'] == 'framework_committed_candidate'
        reconciliation = latest['metadata']['framework_reconciliations'][-1]
        assert reconciliation['model_calls_delta'] == reconciliation['tool_calls_delta'] == 0
        projection = prepared['root'] / marker['member_projections'][rid]['projection_path']
        assert document_bytes(projection) == document_bytes(prepared['root'] / 'agent_runs' / rid)
    assert model_calls == sum(run.metadata['model_calls'] for run in runs.values()) > 0
    # Each split run retains the authentic shared trace, while just one owns
    # the group model cost. Do not count identical sibling trace copies twice.
    owners = [run for run in runs.values() if run.metadata['group_cost_owner']]
    assert len(owners) == 1
    assert len([e for e in owners[0].trace['events'] if e['kind'] == 'model_response']) == model_calls


@pytest.mark.parametrize('mode', ['rejected', 'no_progress'])
def test_noncommitting_transaction_archives_attempts_and_keeps_latest_bytes(tmp_path, mode):
    prepared = persisted_extent_baseline(tmp_path)
    runs, outcome = native_revision(prepared, mode)
    baseline = {rid: document_bytes(prepared['root'] / 'agent_runs' / rid) for rid in runs}
    prior_attempts = {rid: document_bytes(prepared['root'] / 'agent_runs' / rid / 'attempt_0001')
        for rid in runs}
    marker = publish(prepared, runs, outcome)
    assert marker['member_projections'] == {}
    for rid, run in runs.items():
        assert document_bytes(prepared['root'] / 'agent_runs' / rid) == baseline[rid]
        assert document_bytes(prepared['root'] / 'agent_runs' / rid / 'attempt_0001') == prior_attempts[rid]
        archived = prepared['root'] / marker['native_attempts'][rid]['path']
        assert read_document(archived / 'result.json') == run.metadata['native_submission']['resolution']
        assert read_document(archived / 'trace.json') == run.trace
        row = next(row for row in prepared['fixture'][2] if row['requirement_id'] == rid)
        assert load_active(prepared, row)['result'] == prepared['fixture'][3][rid]
    assert outcome.resolutions == prepared['fixture'][3]


def test_provider_failed_attempts_are_archived_without_replacing_valid_active_contracts(tmp_path):
    prepared = persisted_extent_baseline(tmp_path)
    ft, snapshot, rows, resolutions, state, baseline = prepared['fixture']
    selected = [row for row in rows if row['kind'] in {'input_binding', 'buffer_length'}]
    latest_before = {row['requirement_id']: document_bytes(
        prepared['root'] / 'agent_runs' / row['requirement_id']) for row in selected}
    calls_before = state.model_calls
    # The exhausted offline model produces an actual Agent provider-error
    # attempt. It supplies neither a native terminal nor invented paid events.
    attempted = HarnessContextAgent(FakeAgentModel([]), state).investigate_group(selected,
        prepared['prepared'][5], facts_of(resolutions),
        obligation_graph=baseline['semantic_obligation_graph'])
    runs = {run.result['requirement_id']: run for run in attempted}
    failures = {rid: {'requirement_id': rid, 'execution_status': run.metadata['resolution_attempt_failed'],
        'errors': deepcopy(run.metadata['execution_errors'])} for rid, run in runs.items()}
    assert all(failure['execution_status'] == 'provider_error' for failure in failures.values())
    assert sum(run.metadata['model_calls'] for run in runs.values()) == state.model_calls - calls_before > 0
    before = deepcopy({'rows': rows, 'resolutions': resolutions, 'state': vars(state), 'ft': ft})
    outcome = evaluate_revision(ft, snapshot, state, rows, resolutions, {},
        feedback={}, protected={}, execution_failures=failures)
    assert outcome.audit['status'] == 'execution_failure'
    assert outcome.resolutions == resolutions
    assert {'rows': rows, 'resolutions': resolutions, 'state': vars(state), 'ft': ft} == before
    marker = publish(prepared, runs, outcome)
    assert marker['member_projections'] == {}
    for row in selected:
        rid = row['requirement_id']
        assert document_bytes(prepared['root'] / 'agent_runs' / rid) == latest_before[rid]
        attempt = prepared['root'] / marker['native_attempts'][rid]['path']
        metadata = read_document(attempt / 'metadata.json')
        assert metadata['result_origin'] == 'agent_fallback'
        assert metadata['native_submission']['resolution'] is None
        assert metadata['resolution_attempt_failed'] == 'provider_error'
        assert read_document(attempt / 'trace.json') == runs[rid].trace
        assert load_active(prepared, row)['result'] == resolutions[rid]


def test_group_members_remain_unloadable_until_shared_final_marker(tmp_path, monkeypatch):
    import harness_generation.harness_context.persistence as persistence
    prepared = persisted_extent_baseline(tmp_path)
    runs, outcome = native_revision(prepared, 'committed')
    marker_path = prepared['root'] / 'revision_transactions' / outcome.audit['transaction_id'] / 'metadata.json'
    original_write = persistence.write_json
    observed = []

    def observe_marker(path, document, **kwargs):
        if path == marker_path and document.get('status') == 'committed':
            assert read_document(marker_path)['status'] == 'pending'
            for rid in runs:
                row = next(row for row in outcome.requirements if row['requirement_id'] == rid)
                assert load_active(prepared, row) is None
                projection = prepared['root'] / document['member_projections'][rid]['projection_path']
                assert all((projection / (name + '.json')).is_file() for name in DOCUMENT_NAMES)
            observed.append(document['transaction_id'])
        return original_write(path, document, **kwargs)

    monkeypatch.setattr(persistence, 'write_json', observe_marker)
    publish(prepared, runs, outcome)
    assert observed == [outcome.audit['transaction_id']]
    assert all(load_active(prepared, row) for row in outcome.requirements if row['requirement_id'] in runs)


@pytest.mark.parametrize('tamper', [
    'pending_marker', 'decision', 'missing_marker', 'missing_projection',
    'projection_result', 'projection_trace', 'projection_evidence', 'projection_metadata',
    'archive_result', 'archive_trace', 'archive_evidence', 'archive_metadata',
])
def test_any_shared_projection_or_native_archive_tamper_invalidates_every_member(tmp_path, tamper):
    prepared = persisted_extent_baseline(tmp_path)
    runs, outcome = native_revision(prepared, 'committed')
    marker = publish(prepared, runs, outcome)
    rows = [row for row in outcome.requirements if row['requirement_id'] in runs]
    rid = rows[0]['requirement_id']
    marker_path = prepared['root'] / 'revision_transactions' / marker['transaction_id'] / 'metadata.json'
    if tamper in {'pending_marker', 'decision', 'missing_marker'}:
        path = marker_path
    elif tamper == 'missing_projection' or tamper.startswith('projection_'):
        name = 'metadata' if tamper == 'missing_projection' else tamper.removeprefix('projection_')
        path = prepared['root'] / marker['member_projections'][rid]['projection_path'] / (name + '.json')
    else:
        name = tamper.removeprefix('archive_')
        path = prepared['root'] / marker['native_attempts'][rid]['path'] / (name + '.json')
    original = path.read_bytes()
    if tamper in {'missing_marker', 'missing_projection'}:
        path.unlink()
    else:
        changed = json.loads(original)
        if tamper == 'pending_marker':
            changed['status'] = 'pending'
        elif tamper == 'decision':
            changed['decision']['status'] = 'rejected'
        else:
            changed['_tampered'] = True
        write_json(path, changed, sort_keys=True, allow_nan=False)
    assert all(load_active(prepared, row) is None for row in rows)
    path.write_bytes(original)
    assert all(load_active(prepared, row) is not None for row in rows)


@pytest.mark.parametrize('version', [
    'context_revision_transaction_version', 'native_submission_version',
    'max_rejected_revision_corrections_per_requirement', 'agent_prompt_version',
])
def test_transaction_resume_rejects_a_different_policy_or_native_format(tmp_path, version):
    prepared = persisted_extent_baseline(tmp_path)
    runs, outcome = native_revision(prepared, 'committed')
    publish(prepared, runs, outcome)
    for row in outcome.requirements:
        if row['requirement_id'] not in runs:
            continue
        changed = deepcopy(prepared['configurations'][row['requirement_id']])
        changed[version] = 'incompatible-previous-value'
        assert load_active(prepared, row, changed) is None


@pytest.mark.parametrize('old_input_status', ['resolved', 'unresolved'])
def test_authentic_old_context_cannot_resume_with_newer_authentic_latest_results(tmp_path, old_input_status):
    prepared = persisted_extent_baseline(tmp_path, input_status=old_input_status)
    ft, _, rows, resolutions, state, report = prepared['fixture']
    store = prepared['prepared'][0][0]
    context = deepcopy(prepared['baseline_context'])
    context['frozen'] = False
    baseline_run = ContextRun({'schema_version': 1, 'requirements': deepcopy(rows)},
        context, deepcopy(prepared['baseline_closure']), deepcopy(report), {'schema_version': 1})
    save_context(store, baseline_run, prepared['configuration'], state, resolutions)
    context_files = {path.name: path.read_bytes() for path in prepared['root'].glob('*.json')}
    assert load_context_documents(store, ft['ft_id'], prepared['configuration'], prepared['prepared'][5].index)
    runs, outcome = native_revision(prepared, 'committed')
    publish(prepared, runs, outcome)
    assert all(load_active(prepared, row) for row in outcome.requirements if row['requirement_id'] in runs)
    assert {path.name: path.read_bytes() for path in prepared['root'].glob('*.json')} == context_files
    assert load_context_documents(store, ft['ft_id'], prepared['configuration'], prepared['prepared'][5].index) is None
    current = deepcopy(outcome.context)
    current['frozen'] = outcome.report['generation_allowed']
    current_run = ContextRun({'schema_version': 1, 'requirements': deepcopy(outcome.requirements)},
        current, deepcopy(outcome.closure), deepcopy(outcome.report),
        {'schema_version': 1, 'context_revision_transactions': [deepcopy(outcome.audit)]})
    save_context(store, current_run, prepared['configuration'], state, outcome.resolutions)
    restored = load_context_documents(store, ft['ft_id'], prepared['configuration'], prepared['prepared'][5].index)
    assert restored['resolutions']['resolutions'] == outcome.resolutions
    assert restored['context_revision_transactions']['transactions'] == [outcome.audit]


@pytest.mark.parametrize('version', ['context_revision_transaction_version', 'native_submission_version'])
def test_top_context_cache_requires_the_current_transaction_and_native_version(tmp_path, version):
    prepared = persisted_extent_baseline(tmp_path)
    ft, _, rows, resolutions, state, report = prepared['fixture']
    store = prepared['prepared'][0][0]
    run = ContextRun({'schema_version': 1, 'requirements': deepcopy(rows)},
        deepcopy(prepared['baseline_context']), deepcopy(prepared['baseline_closure']), deepcopy(report),
        {'schema_version': 1})
    save_context(store, run, prepared['configuration'], state, resolutions)
    incompatible = deepcopy(prepared['configuration'])
    incompatible[version] = 'incompatible-previous-version'
    assert load_context_documents(store, ft['ft_id'], incompatible, prepared['prepared'][5].index) is None
    assert load_context_documents(store, ft['ft_id'], prepared['configuration'], prepared['prepared'][5].index)


def test_missing_source_carrier_records_publication_rejection_without_touching_latest(tmp_path, monkeypatch):
    import harness_generation.harness_context.transaction_support as support
    prepared = persisted_extent_baseline(tmp_path)
    runs, outcome = native_revision(prepared, 'committed')
    before = {rid: document_bytes(prepared['root'] / 'agent_runs' / rid) for rid in runs}
    before_calls = prepared['fixture'][4].model_calls

    def missing_carrier(*args, **kwargs):
        raise ValueError('source_support_origin_not_found:ev_missing_carrier')

    monkeypatch.setattr(support, 'save_source_support', missing_carrier)
    marker = save_revision_transaction(prepared['prepared'][0][0], prepared['fixture'][0]['ft_id'],
        runs, prepared['configurations'], outcome, round_number=2)
    assert marker['status'] == 'rejected'
    assert marker['decision']['status'] == 'committed', 'Source validation and publication decisions remain distinguishable'
    assert marker['publication_rejection']['code'] == 'candidate_source_witness_not_archived'
    assert marker['member_projections'] == {}
    assert marker['native_attempts']
    assert prepared['fixture'][4].model_calls == before_calls
    assert {rid: document_bytes(prepared['root'] / 'agent_runs' / rid) for rid in runs} == before
