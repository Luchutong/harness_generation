"""Offline definitions for Context candidate revocation and commit barriers.

The driver below uses only the Python policy. It starts no external runtime and
keeps the actual model/source ledger under the framework's existing wrappers.
"""
from copy import deepcopy
import json

import pytest

from harness_generation.harness_context import ContextBudget, HarnessRequirementBuilder, HarnessContextMiningLoop
from harness_generation.harness_context.agent import BudgetedModel, HarnessContextAgent
from harness_generation.harness_context.dsh_policy import DSHContextPolicy
from harness_generation.harness_context.models import MiningState
from harness_generation.semantic_discovery.loop import LoopOutcome
from harness_generation.semantic_discovery.models import AgentModelResponse, AgentToolCall, ValidationBudget
from test_context_grouping import GroupedFixtureModel
from test_harness_context import direct_specs, setup


class PolicyBackend:
    def __init__(self, *, abort_reason=None):
        self.abort_reason, self.outcomes, self.before_abort = abort_reason, [], []

    def descriptor(self):
        return {"name": "offline-policy-driver", "version": 1}

    def run(self, **request):
        current = DSHContextPolicy(**request)
        while not current.done:
            response = current.complete()
            if response is not None:
                for call in response.tool_calls:
                    current.execute(call)
        self.before_abort.append(deepcopy(current.outcome))
        if self.abort_reason:
            current.abort(self.abort_reason)
        self.outcomes.append(current.outcome)
        return current.outcome


def requirements(prepared):
    return HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"]


def grouped_agent(prepared, backend, *, mutate=None):
    model = GroupedFixtureModel(direct_specs(prepared[0][-1]["parse"]), mutate=mutate)
    runs = HarnessContextAgent(model, prepared[4], investigation_backend=backend).investigate_group(
        requirements(prepared), prepared[5])
    return runs, model


def test_abort_marker_revokes_final_decision_without_refunding_paid_history():
    class Model:
        def complete(self, messages, tools):
            return AgentModelResponse(tool_calls=(AgentToolCall("submitted", "submit_context", '{"accepted":true}'),),
                metadata={"usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}})

    class Tools:
        schemas = []

    state = MiningState(ContextBudget())
    current = DSHContextPolicy(model=BudgetedModel(Model(), state),
        budget=ValidationBudget(max_rounds=1), tools=Tools(),
        terminal={"type": "function", "function": {"name": "submit_context", "parameters": {"type": "object"}}},
        validator=json.loads, messages=[{"role": "user", "content": "Submit"}])
    response = current.complete()
    current.execute(response.tool_calls[0])
    messages = deepcopy(current.outcome.messages)
    ledger = (state.model_calls, state.tool_calls, deepcopy(state.tokens))

    current.abort("dsh_shutdown_error")

    assert current.outcome.submission_revoked is True
    assert current.outcome.submission_revocation_reason == "dsh_shutdown_error"
    assert current.outcome.decision is None and current.done
    assert current.outcome.messages == messages
    assert (state.model_calls, state.tool_calls, state.tokens) == ledger
    assert state.model_calls == current.outcome.model_calls == 1
    assert state.tokens["total_tokens"] == 12


def test_revocation_fields_do_not_change_native_repair_audit_shape():
    outcome = LoopOutcome()
    assert outcome.submission_revoked is False and outcome.submission_revocation_reason is None
    baseline = outcome.repair_audit()
    outcome.submission_revoked = True
    outcome.submission_revocation_reason = "dsh_runtime_error"
    assert outcome.repair_audit() == baseline
    assert "submission_revoked" not in baseline and "submission_revocation_reason" not in baseline


def test_group_abort_withdraws_native_candidates_and_local_audits_from_active_metadata(tmp_path):
    prepared = setup(tmp_path)
    backend = PolicyBackend(abort_reason="dsh_turn_failed")
    runs, _model = grouped_agent(prepared, backend)

    assert backend.before_abort[0].decision is not None
    assert backend.outcomes[0].decision is None
    assert backend.outcomes[0].submission_revoked
    assert all(run.result["status"] == "unresolved" and run.result["facts"] == [] for run in runs)
    assert all(run.metadata["submission_revoked"] for run in runs)
    assert all(run.metadata["resolution_attempt_failed"] == "protocol_error" for run in runs)
    assert all(run.metadata["native_submission"]["resolution"] is None for run in runs)
    assert all(run.metadata["subject_local_repairs"] == {} for run in runs)
    history = next(event for event in runs[0].trace["events"] if event["kind"] == "submission_revocation")
    assert history["reason"] == "dsh_turn_failed"
    assert history["candidate_history"]["native_submissions"]
    assert history["candidate_history"]["subject_local_repairs"]
    assert all(row["resolution"] is not None
               for row in history["candidate_history"]["native_submissions"].values())
    assert any(event["kind"] == "decision_submission" for event in runs[0].trace["events"])
    assert sum(run.metadata["model_calls"] for run in runs) == prepared[4].model_calls == 1


def test_single_abort_withdraws_previously_validated_native_result(tmp_path):
    prepared = setup(tmp_path)
    from test_harness_context import ScriptedModel
    model = ScriptedModel(direct_specs(prepared[0][-1]["parse"]))
    backend = PolicyBackend(abort_reason="dsh_runtime_error")
    requirement = next(row for row in requirements(prepared) if row["kind"] == "input_binding")
    run = HarnessContextAgent(model, prepared[4], investigation_backend=backend).investigate(
        requirement, prepared[5])

    assert backend.before_abort[0].decision is not None
    assert run.result["facts"] == [] and run.result["status"] == "unresolved"
    assert run.metadata["native_submission"]["resolution"] is None
    assert run.metadata["subject_local_repairs"] == {}
    assert run.metadata["submission_revocation_reason"] == "dsh_runtime_error"


def test_abort_cannot_reactivate_an_earlier_conservative_group_fallback(tmp_path):
    prepared = setup(tmp_path)
    def mutate(requirement, result):
        if requirement["kind"] == "ownership":
            result["facts"][0]["evidence_ids"] = []
    backend = PolicyBackend(abort_reason="dsh_deadline_exceeded")
    runs, _model = grouped_agent(prepared, backend, mutate=mutate)

    history = next(event for event in runs[0].trace["events"] if event["kind"] == "submission_revocation")
    partial = history["candidate_history"]["semantic_fallback"]
    assert partial and any(row["facts"] for row in partial["resolutions"])
    assert all(run.result["facts"] == [] for run in runs)
    assert all(run.metadata["native_submission"]["resolution"] is None for run in runs)
    assert all(run.metadata["execution_status"] == "protocol_error" for run in runs)
    assert all(run.metadata["resolution_attempt_failed"] == "protocol_error" for run in runs)
    assert prepared[4].model_calls == backend.outcomes[0].model_calls
    assert prepared[4].model_calls == backend.before_abort[0].model_calls


def test_conservative_independent_group_siblings_survive_without_executor_revocation(tmp_path):
    prepared = setup(tmp_path)
    def mutate(requirement, result):
        if requirement["kind"] == "ownership":
            result["facts"][0]["evidence_ids"] = []
    backend = PolicyBackend()
    runs, _model = grouped_agent(prepared, backend, mutate=mutate)

    assert not backend.outcomes[0].submission_revoked
    assert {row["kind"] for row, run in zip(requirements(prepared), runs)
            if run.result["facts"]} == {"input_binding", "argument_construction", "buffer_length", "return_semantics"}
    assert all(run.metadata["execution_status"] == "conservative_partial_resolution" for run in runs)
    assert all("resolution_attempt_failed" not in run.metadata for run in runs)
    assert any(run.metadata["native_submission"]["resolution"] is not None for run in runs)


@pytest.mark.parametrize("failure", [
    {"submission_revoked": True, "submission_revocation_reason": "dsh_shutdown_error"},
    {"resolution_attempt_failed": "protocol_error"},
    {"execution_status": "provider_error"},
])
def test_first_commit_rejects_both_failed_native_metadata_and_failed_run_result(tmp_path, monkeypatch, failure):
    prepared = setup(tmp_path, budget=ContextBudget(max_completeness_rounds=1,
        max_total_model_calls=80, max_tool_calls=200, max_source_chars=300000))
    model = GroupedFixtureModel(direct_specs(prepared[0][-1]["parse"]))
    original = HarnessContextAgent.investigate_group
    submitted = []

    def failed_group(self, *args, **kwargs):
        runs = original(self, *args, **kwargs)
        assert any(run.result["facts"] for run in runs)
        assert any(run.metadata["native_submission"]["resolution"] is not None for run in runs)
        submitted.extend(deepcopy(runs))
        for run in runs:
            run.metadata.update(failure)
        return runs

    monkeypatch.setattr(HarnessContextAgent, "investigate_group", failed_group)
    run = HarnessContextMiningLoop(model, prepared[4], group_requirements=True).run(
        prepared[1], prepared[3], prepared[5])

    assert submitted
    assert run.context["facts"] == []
    assert not run.completeness["generation_allowed"]
    assert run.completeness["execution_failed_requirements"]
    assert run.metadata["metrics"]["model_calls"] == prepared[4].model_calls == 1


def test_answered_submission_with_recovered_error_history_is_not_revoked_or_rejected(tmp_path):
    class RecoveredModel(GroupedFixtureModel):
        def __init__(self, specs):
            super().__init__(specs)
            self.first = True

        def complete(self, messages, schemas):
            if self.first:
                self.first = False
                return AgentModelResponse(tool_calls=(AgentToolCall("unknown", "invented_reader", '{}'),))
            return super().complete(messages, schemas)

    prepared = setup(tmp_path)
    backend = PolicyBackend()
    model = RecoveredModel(direct_specs(prepared[0][-1]["parse"]))
    run = HarnessContextMiningLoop(model, prepared[4], group_requirements=True,
        investigation_backend=backend).run(prepared[1], prepared[3], prepared[5])

    assert backend.outcomes[0].decision is not None and not backend.outcomes[0].submission_revoked
    assert any(event["kind"] == "execution_error" for event in backend.outcomes[0].events)
    assert run.completeness["generation_allowed"]
    assert run.context["facts"]
    assert run.completeness["execution_failed_requirements"] == []
    assert prepared[4].model_calls == 2
