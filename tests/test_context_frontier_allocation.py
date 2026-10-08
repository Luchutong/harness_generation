"""Protected calls remain available to mandatory work; no budget is reset."""
from types import SimpleNamespace

import pytest

from harness_generation.harness_context.agent import BudgetedModel
from harness_generation.harness_context.models import ContextBudget, MiningState
from harness_generation.harness_context.scheduling import (optional_allocation,
    repair_routes, revisable_requirements)
from harness_generation.semantic_discovery.loop import BoundedAgentLoop
from harness_generation.semantic_discovery.models import (AgentModelError,
    AgentModelResponse, AgentToolCall, FakeAgentModel, ValidationBudget, canonical)
from harness_generation.semantic_discovery.tools import ToolBudgetExceeded
from test_harness_context import setup


@pytest.mark.parametrize("models,tools,passes,expected", [
    (24, 64, 3, (20, 56)),
    (3, 6, 3, (2, 4)),
    (1, 1, 3, (1, 1)),
    (24, 64, 1, (24, 64)),
])
def test_optional_ceiling_uses_original_budget_and_clamps_small_allocations(models, tools, passes, expected):
    budget = ContextBudget(max_total_model_calls=models, max_tool_calls=tools,
                           max_completeness_rounds=passes)
    state = MiningState(budget)
    state.model_calls, state.tool_calls = 1, 1
    allocation = optional_allocation(state)
    assert (allocation["model_limit"], allocation["tool_limit"]) == expected
    assert allocation["remaining_optional_model_calls"] == expected[0] - 1
    assert allocation["remaining_optional_tool_calls"] == expected[1] - 1
    assert state.budget is budget and (state.model_calls, state.tool_calls) == (1, 1)


def test_zero_reserve_is_an_explicit_configuration_choice():
    state = MiningState(ContextBudget(repair_reserve_model_calls=0, repair_reserve_tool_calls=0))
    allocation = optional_allocation(state)
    assert allocation["reserved_model_calls"] == allocation["reserved_tool_calls"] == 0
    assert allocation["model_limit"] == 24 and allocation["tool_limit"] == 64


class RecordedModel:
    provider, model = "fake", "recorded"

    def __init__(self):
        self.requests = []

    def complete(self, messages, tools):
        self.requests.append((messages, tools))
        return AgentModelResponse(metadata={"usage": {"prompt_tokens": 2,
            "completion_tokens": 1, "total_tokens": 3}})


def test_optional_model_guard_leaves_reserved_calls_and_does_not_record_a_provider_request():
    state = MiningState(ContextBudget())
    state.model_calls = 20
    model = RecordedModel()
    limited = BudgetedModel(model, state, max_model_calls=20)
    with pytest.raises(AgentModelError) as caught:
        limited.complete([], [])
    assert caught.value.model_call is False
    assert caught.value.budget_stop_reason == "optional_model_reserve"
    assert state.model_calls == 20 and state.budget_stop is None and not model.requests
    BudgetedModel(model, state).complete([], [])
    assert state.model_calls == 21 and len(model.requests) == 1
    assert state.tokens["total_tokens"] == 3


def test_pretransport_guard_is_a_budget_event_in_the_shared_loop():
    state = MiningState(ContextBudget())
    state.model_calls = 20
    model = RecordedModel()
    schema = {"type": "function", "function": {"name": "submit", "description": "terminal",
              "parameters": {"type": "object", "properties": {}, "required": []}}}
    outcome = BoundedAgentLoop(BudgetedModel(model, state, max_model_calls=20),
        ValidationBudget(max_rounds=1), schema, lambda _: {}, reserve_terminal_round=True
    ).run([], SimpleNamespace(schemas=[]))
    assert outcome.exhausted and outcome.termination == "optional_model_reserve"
    assert outcome.model_calls == 0 and not model.requests
    assert len(outcome.events) == 1 and outcome.events[0]["kind"] == "budget_stop"
    assert outcome.events[0]["provider_request"] is False
    assert state.budget_stop is None and state.model_calls == 20


def test_optional_tool_guard_preserves_global_ledger_for_the_next_required_batch(tmp_path):
    prepared = setup(tmp_path)
    tools, state = prepared[5], prepared[4]
    from harness_generation.harness_context.requirements import HarnessRequirementBuilder
    row = HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"][0]
    tools.activate(row)
    state.tool_calls = 56
    tools.investigation_tool_limit = 56
    source_before, evidence_before = state.source_chars, dict(state.evidence)
    with pytest.raises(ToolBudgetExceeded, match="optional_tool_reserve"):
        tools.execute("get_function", {"function": row["subject_function_id"]})
    assert state.tool_calls == 56 and state.budget_stop is None
    assert state.source_chars == source_before and state.evidence == evidence_before
    tools.investigation_tool_limit = None
    result = tools.execute("get_function", {"function": row["subject_function_id"]})
    assert result["evidence_ids"] and state.tool_calls == 57


def test_trace_distinguishes_a_guarded_tool_request_from_an_executed_tool(tmp_path):
    prepared = setup(tmp_path)
    tools, state = prepared[5], prepared[4]
    from harness_generation.harness_context.requirements import HarnessRequirementBuilder
    row = HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"][0]
    tools.activate(row)
    state.tool_calls = 56
    tools.investigation_tool_limit = 56
    model = FakeAgentModel([AgentModelResponse(tool_calls=(AgentToolCall("read", "get_function",
        canonical({"function": row["subject_function_id"]})),))])
    terminal = {"type": "function", "function": {"name": "submit", "description": "terminal",
        "parameters": {"type": "object", "properties": {}, "required": []}}}
    outcome = BoundedAgentLoop(BudgetedModel(model, state), ValidationBudget(max_rounds=2),
        terminal, lambda _: {}).run([], tools)
    event, = [event for event in outcome.events if event["kind"] == "tool_call"]
    assert event["tool_executed"] is False and event["result_evidence_ids"] == []
    assert outcome.tool_calls == 1 and state.tool_calls == 56
    assert state.model_calls == outcome.model_calls == 1 and state.budget_stop is None


def test_only_prior_native_contract_corrections_are_ready_for_early_revision():
    feedback = {"items": [
        {"category": "contract_correction", "correction_targets": [
             {"requirement_id": rid, "fact_id": "fact_" + rid}
             for rid in ["old", "new", "failed", "already_revised"]],
         "repair_requirement_ids": ["old", "new", "failed", "already_revised", "empty_fallback"]},
        {"category": "unsupported", "correction_targets": [{"requirement_id": "unsupported", "fact_id": "old_fact"}],
         "repair_requirement_ids": ["unsupported"]},
    ]}
    attempted = {rid: "input_digest" for rid in ["old", "failed", "already_revised", "unsupported", "empty_fallback"]}
    assert revisable_requirements(feedback, attempted, {"failed": {}}, {"already_revised": 1}) == {"old"}


def test_missing_helper_can_reopen_an_existing_contract_without_waiting_for_unrelated_evidence():
    feedback = {"items": [{"category": "missing_evidence", "correction_targets": [
        {"requirement_id": rid, "fact_id": "fact_" + rid} for rid in ["lifecycle", "ownership"]],
        "repair_requirement_ids": ["lifecycle", "ownership"],
        "evidence_state": {"complete_body_evidence_ids": ["issued_subject_body"],
                           "missing_source_roles": ["cleanup"]}}]}
    attempts = {"lifecycle": "same_source", "ownership": "same_source"}
    assert revisable_requirements(feedback, attempts, {}, {}) == {"lifecycle", "ownership"}
    assert not revisable_requirements(feedback, attempts, {}, {"lifecycle": 1, "ownership": 1})
    feedback["items"][0]["evidence_state"]["complete_body_evidence_ids"] = []
    assert not revisable_requirements(feedback, attempts, {}, {})


def test_explicit_nonbudget_pretransport_failure_does_not_become_a_provider_request():
    class UnissuedModel:
        def complete(self, messages, tools):
            error = AgentModelError('local request could not be constructed')
            error.model_call = False
            raise error

    state = MiningState(ContextBudget())
    terminal = {"type": "function", "function": {"name": "submit", "description": "terminal",
        "parameters": {"type": "object", "properties": {}, "required": []}}}
    outcome = BoundedAgentLoop(BudgetedModel(UnissuedModel(), state), ValidationBudget(max_rounds=1),
        terminal, lambda _: {}).run([], SimpleNamespace(schemas=[]))
    assert outcome.model_calls == state.model_calls == 0
    assert outcome.termination == 'invalid_output'
    assert outcome.events[0]['kind'] == 'execution_error'
    assert outcome.events[0]['provider_request'] is False
    assert not any(event['kind'] in {'model_error', 'model_response'} for event in outcome.events)


def test_routes_distinguish_proof_capability_and_upstream_scope_without_permitting_rollback():
    items = [{"feedback_id": category, "category": category,
              "repair_requirement_ids": ["rid"], "subject_function_id": "fid"}
             for category in ["missing_evidence", "contract_correction", "unsupported", "upstream_blocker"]]
    routes = {row["feedback_id"]: row for row in repair_routes({"items": items})}
    assert routes["missing_evidence"]["action"] == "obtain_exact_missing_evidence"
    assert routes["contract_correction"]["action"] == "revise_linked_typed_slots"
    assert routes["unsupported"]["recommended_stage"] == "framework_source_proof"
    assert routes["upstream_blocker"]["recommended_stage"] == "semantic_slice"
    assert all(row["automatically_executed"] is False for row in routes.values())


def test_compatible_cached_contracts_keep_their_one_targeted_revision_opportunity(tmp_path):
    from copy import deepcopy
    from harness_generation.entry_candidates import CandidateCatalog
    from harness_generation.harness_context.loop import HarnessContextMiningLoop
    from harness_generation.harness_context.persistence import run_configuration
    from harness_generation.harness_context.tools import HarnessContextTools
    from test_context_feedback_scheduler import FeedbackExtentModel, owned_specs, run_fixture

    original, old_run, _, _ = run_fixture(tmp_path, correct=False, persist=True)
    assert old_run.completeness['status'] == 'incomplete'
    before_ft = deepcopy(original[1])
    state = MiningState(ContextBudget())
    catalog = CandidateCatalog((), original[3].source_fingerprint)
    tools = HarnessContextTools(original[3], catalog, original[1], state, index=original[5].index)
    model = FeedbackExtentModel(owned_specs(original[0][-1]), original[0][-1]['parse'],
        correct=True, query_type='Node', initial_ids=tools.initial_ids)
    configuration = run_configuration(original[1], original[2], original[3], state.budget, model,
        requirement_mode='grouped')
    resumed = HarnessContextMiningLoop(model, state, group_requirements=True).run(
        original[1], original[3], tools, store=original[0][0], configuration=configuration, resume=True)
    assert resumed.metadata['metrics']['resumed_requirements'] > 0
    assert model.feedback_requests and resumed.metadata['context_revision_history']
    assert resumed.completeness['generation_allowed']
    assert original[1] == before_ft
    revised = [rid for batch in resumed.metadata['context_revision_history'] for rid in batch['requirement_ids']]
    assert len(revised) == len(set(revised))
    assert state.model_calls <= 24 and state.tool_calls <= 64


def test_framework_prelude_reads_are_charged_once_to_the_persisted_group_owner(tmp_path):
    import json
    from harness_generation.harness_context.persistence import context_directory
    from test_context_feedback_scheduler import run_fixture

    original, _, _, _ = run_fixture(tmp_path, persist=True)
    directory = context_directory(original[0][0], original[1]['ft_id'])
    metadata = [json.loads(path.read_text()) for path in (directory / 'agent_runs').glob('*/attempt_*/metadata.json')]
    assert metadata and sum(item['tool_calls'] for item in metadata) == original[4].tool_calls
    assert any(item.get('framework_prelude_tool_calls', 0) for item in metadata)
    assert all(item.get('tool_calls', 0) == 0 for item in metadata if item.get('group_cost_owner') is False)
    traces = [json.loads(path.read_text()) for path in (directory / 'agent_runs').glob('*/attempt_*/trace.json')]
    assert any(event.get('framework_prelude') and event.get('tool_executed')
        for trace in traces for event in trace['events'])
