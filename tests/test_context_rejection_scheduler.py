"""A partial native correction rolls back before one bounded linked retry.

Written during the test pause; these use explicit offline native terminals.
"""
from copy import deepcopy
import json

import pytest

from harness_generation.context_generation import HarnessPlanBuilder
from harness_generation.harness_context import ContextBudget, HarnessContextMiningLoop
from harness_generation.harness_context.persistence import run_configuration
from harness_generation.semantic_discovery.models import AgentModelError
from test_context_feedback_scheduler import FeedbackExtentModel, SOURCE, owned_specs
from test_harness_context import setup, assert_gate, ScriptedModel


class PartialThenCorrectModel(FeedbackExtentModel):
    def __init__(self, *args, repair_rejection=True, fail_rejection=False, **kwargs):
        self.repair_rejection = repair_rejection
        self.fail_rejection = fail_rejection
        self.current_rejection = False
        self.rejection_requests = []
        super().__init__(*args, **kwargs)

    def complete(self, messages, schemas):
        request = json.loads(next(m['content'] for m in messages if m['role'] == 'user'))
        packets = [packet for task in request.get('missing_tasks', [])
            for item in task.get('closure_feedback', {}).get('items', [])
            for packet in item.get('rejected_candidates', [])]
        self.current_rejection = bool(packets)
        if packets:
            self.rejection_requests.append(deepcopy(request))
            if self.fail_rejection:
                error = AgentModelError('Offline provider failure during rejected candidate correction')
                error.category = 'transient_error'
                raise error
        if 'requirements' not in request:
            # Preserve ordinary single-mode native terminals until the loop
            # deliberately switches a linked repair to a grouped terminal.
            self.requests.append(deepcopy(request))
            items = [item for task in request.get('missing_tasks', [])
                for item in task.get('closure_feedback', {}).get('items', [])]
            self.current_feedback = any(item['category'] == 'contract_correction' and
                any(path.endswith(('.size_parameter', '.length_parameter'))
                    for target in item['correction_targets'] for path in target['field_paths'])
                for item in items)
            if self.current_feedback:
                self.feedback_requests.append(deepcopy(request))
            return ScriptedModel.complete(self, messages, schemas)
        return super().complete(messages, schemas)

    def mutate_extent(self, requirement, result):
        if requirement['subject_function_id'] == self.fid:
            complete = self.current_rejection and self.repair_rejection
            for proposal in result['facts']:
                for binding in proposal['value'].get('bindings', []):
                    if binding['parameter'] == 'src' and not self.current_feedback:
                        binding['size_parameter'] = None
                for link in proposal['value'].get('links', []):
                    if link['buffer_parameter'] == 'src' and not complete:
                        link['length_parameter'] = None
        self.submissions.append(deepcopy(result))


def run_partial_fixture(tmp_path, *, grouped=True, repair_rejection=True, fail_rejection=False):
    prepared = setup(tmp_path, SOURCE, budget=ContextBudget())
    model = PartialThenCorrectModel(owned_specs(prepared[0][-1]), prepared[0][-1]['parse'],
        repair_rejection=repair_rejection, fail_rejection=fail_rejection,
        query_type='Node', initial_ids=prepared[5].initial_ids)
    snapshots = []
    before_ft = deepcopy(prepared[1])
    configuration = run_configuration(prepared[1], prepared[2], prepared[3], prepared[4].budget,
        model, requirement_mode='grouped' if grouped else 'single')
    run = HarnessContextMiningLoop(model, prepared[4], group_requirements=grouped).run(
        prepared[1], prepared[3], prepared[5], store=prepared[0][0], configuration=configuration,
        on_requirement=lambda row, result, resumed, state: snapshots.append(
            (deepcopy(row), deepcopy(result), state.model_calls)))
    assert prepared[1] == before_ft
    assert prepared[4].model_calls <= 24 and prepared[4].tool_calls <= 64
    assert prepared[4].source_chars <= 96000
    assert run.metadata['metrics']['completeness_rounds'] <= 3
    return prepared, run, model, snapshots


@pytest.mark.parametrize('grouped', [True, False])
def test_partial_revision_rolls_back_then_reopens_the_linked_slots_together(tmp_path, grouped):
    prepared, run, model, snapshots = run_partial_fixture(tmp_path, grouped=grouped)
    assert_gate(run)
    transactions = run.metadata['context_revision_transactions']
    rejected = [transaction for transaction in transactions if transaction['status'] == 'rejected']
    assert len(rejected) == 1 and any(transaction['status'] == 'committed' for transaction in transactions)
    rejected, = rejected
    assert rejected['active_graph_digest'] == rejected['before_graph_digest']
    assert rejected['candidate_graph_digest'] != rejected['active_graph_digest']
    assert rejected['rejection_diagnostics'] and model.rejection_requests
    parse = prepared[0][-1]['parse']
    linked = {row['requirement_id'] for row in run.requirements['requirements']
        if row['subject_function_id'] == parse and row['kind'] in {'input_binding', 'buffer_length'}}
    assert len(linked) == 2
    assert linked <= set(rejected['submitted_requirement_ids'])
    correction = next(transaction for transaction in transactions
        if transaction['rejection_correction_requirement_ids'])
    assert linked <= set(correction['submitted_requirement_ids'])
    assert correction['round'] > rejected['round']
    assert all(count == 1 for count in run.metadata['rejected_revision_corrections'].values())
    # Published callbacks at the paid first revision still expose the baseline.
    after_first_revision = [result for row, result, calls in snapshots
        if row['requirement_id'] in linked and calls == rejected['budget_after']['model_calls']]
    assert after_first_revision
    for result in after_first_revision:
        for fact in result['facts']:
            assert all(row['size_parameter'] is None for row in fact['value'].get('bindings', [])
                if row['parameter'] == 'src')
            assert all(row['length_parameter'] is None for row in fact['value'].get('links', [])
                if row['buffer_parameter'] == 'src')
    plan = HarnessPlanBuilder().build(prepared[1], run.context, run.closure, prepared[3], run.completeness)
    assert plan['frozen']


def test_repeated_partial_candidate_is_bounded_and_never_publishes_half_a_contract(tmp_path):
    _, run, model, _ = run_partial_fixture(tmp_path, repair_rejection=False)
    assert_gate(run, 'incomplete')
    transactions = run.metadata['context_revision_transactions']
    assert len([transaction for transaction in transactions if transaction['status'] == 'rejected']) == 2
    assert not any(transaction['status'] == 'committed' for transaction in transactions)
    assert model.rejection_requests
    assert all(count == 1 for count in run.metadata['rejected_revision_corrections'].values())
    assert any(not packet['correction_allowed'] for packet in run.metadata['candidate_rejection_feedback'])
    assert all(binding['size_parameter'] is None for binding in run.context['input_contract']['bindings']
        if binding['parameter'] == 'src')


def test_provider_failure_in_a_rejection_correction_keeps_baseline_and_paid_attempts(tmp_path):
    _, run, model, _ = run_partial_fixture(tmp_path, fail_rejection=True)
    assert_gate(run, 'incomplete')
    transactions = run.metadata['context_revision_transactions']
    assert any(transaction['status'] == 'execution_failure' for transaction in transactions)
    assert len(run.metadata['candidate_rejection_feedback']) == 1
    assert all(count == 1 for count in run.metadata['rejected_revision_corrections'].values())
    assert model.rejection_requests and run.metadata['execution_failures']
    assert not any(transaction['status'] == 'committed' for transaction in transactions)


def test_missing_publication_witness_is_feedback_instead_of_exiting_the_mining_loop(tmp_path, monkeypatch):
    import harness_generation.harness_context.transaction_support as support
    original = support.save_source_support

    def missing_nonempty_carrier(store, ft_id, destination, witnesses, attempts):
        if witnesses:
            raise ValueError('source_support_origin_not_found:' + next(iter(witnesses)))
        return original(store, ft_id, destination, witnesses, attempts)

    monkeypatch.setattr(support, 'save_source_support', missing_nonempty_carrier)
    _, run, _, _ = run_partial_fixture(tmp_path)
    assert_gate(run, 'incomplete')
    assert any(transaction.get('candidate_validation_status') == 'committed'
        and transaction['status'] == 'rejected' for transaction in run.metadata['context_revision_transactions'])
    assert any(diagnostic['code'] == 'candidate_source_witness_not_archived'
        for packet in run.metadata['candidate_rejection_feedback'] for diagnostic in packet['rejection_diagnostics'])
    assert all(binding['size_parameter'] is None for binding in run.context['input_contract']['bindings']
        if binding['parameter'] == 'src')
