"""Investigation runner injection preserves typed validation and shared budgets.

These are offline seam tests; the forwarding fixture is not the DSH SDK and
does not establish provider or end-to-end stability.
"""
from copy import deepcopy

import pytest

from harness_generation.harness_context import ContextBudget, HarnessRequirementBuilder
from harness_generation.harness_context.agent import BudgetedModel, HarnessContextAgent
from harness_generation.semantic_discovery.loop import BoundedAgentLoop, LoopOutcome
from harness_generation.semantic_discovery.models import AgentModelError, FakeAgentModel
from test_context_grouping import GroupedFixtureModel
from test_harness_context import direct_specs, setup


class ForwardingBackend:
    """Record the adapter boundary while preserving the known offline loop."""
    def __init__(self):
        self.requests = []

    def descriptor(self):
        return {"name": "test-forwarding", "version": 1}

    def run(self, **request):
        self.requests.append(request)
        options = dict(request)
        model, budget = options.pop("model"), options.pop("budget")
        terminal, validator = options.pop("terminal"), options.pop("validator")
        messages, tools = options.pop("messages"), options.pop("tools")
        prelude_calls = options.pop("initial_tool_calls")
        prelude_events = options.pop("initial_events")
        return BoundedAgentLoop(model, budget, terminal, validator, **options).run(
            messages, tools, initial_tool_calls=prelude_calls, initial_events=prelude_events)


def rows(prepared):
    return HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"]


def test_backend_injection_replaces_native_loop_and_retains_group_cost_owner(tmp_path, monkeypatch):
    prepared = setup(tmp_path)
    model = GroupedFixtureModel(direct_specs(prepared[0][-1]["parse"]))
    backend = ForwardingBackend()

    def native_loop_forbidden(*args, **kwargs):
        raise AssertionError("the caller must select only one investigation loop")

    monkeypatch.setattr("harness_generation.harness_context.agent.BoundedAgentLoop", native_loop_forbidden)
    runs = HarnessContextAgent(model, prepared[4], investigation_backend=backend).investigate_group(
        rows(prepared), prepared[5])
    assert len(backend.requests) == 1
    request = backend.requests[0]
    assert isinstance(request["model"], BudgetedModel)
    assert request["tools"] is prepared[5]
    assert request["reserve_terminal_round"] is True
    assert callable(request["terminal_schema_factory"])
    assert callable(request["terminal_guidance_factory"])
    assert request["terminal"]["function"]["name"] == "submit_requirement_resolutions"
    assert request["initial_tool_calls"] == sum(
        bool(event.get("tool_executed", True)) for event in request["initial_events"])
    assert all(run.result["status"] == "resolved" for run in runs)
    assert all(run.metadata["agent_backend"] == backend.descriptor() for run in runs)
    assert sum(run.metadata["model_calls"] for run in runs) == prepared[4].model_calls == 1
    assert sum(run.metadata["tool_calls"] for run in runs) == prepared[4].tool_calls
    assert [run.metadata["group_cost_owner"] for run in runs] == [True] + [False] * (len(runs) - 1)


def test_preinvestigation_global_stop_issues_no_backend_call(tmp_path):
    prepared = setup(tmp_path, budget=ContextBudget(max_total_model_calls=1))
    prepared[4].model_calls = 1
    backend = ForwardingBackend()
    requirement = rows(prepared)[0]
    run = HarnessContextAgent(FakeAgentModel([]), prepared[4], investigation_backend=backend).investigate(
        requirement, prepared[5])
    assert backend.requests == []
    assert run.metadata["model_calls"] == run.metadata["tool_calls"] == 0
    assert run.metadata["termination"] == "max_total_model_calls"
    assert run.metadata["agent_backend"] == backend.descriptor()


def test_injected_backend_cannot_reset_optional_model_guard(tmp_path):
    prepared = setup(tmp_path)
    prepared[5].investigation_model_limit = 1
    state = prepared[4]

    class CountingGroupedFixtureModel(GroupedFixtureModel):
        def __init__(self, specs):
            super().__init__(specs)
            self.group_calls = 0

        def complete(self, messages, schemas):
            self.group_calls += 1
            return super().complete(messages, schemas)

    model = CountingGroupedFixtureModel(direct_specs(prepared[0][-1]["parse"]))

    class GuardProbeBackend(ForwardingBackend):
        def run(self, **request):
            self.requests.append(request)
            request["model"].complete(request["messages"], request["tools"].schemas + [request["terminal"]])
            with pytest.raises(AgentModelError) as failure:
                request["model"].complete(request["messages"], [request["terminal"]])
            assert failure.value.model_call is False
            assert failure.value.budget_stop_reason == "optional_model_reserve"
            return LoopOutcome(termination="max_rounds", exhausted=True, rounds=1,
                model_calls=1, tool_calls=request["initial_tool_calls"],
                events=deepcopy(request["initial_events"]), messages=list(request["messages"]))

    backend = GuardProbeBackend()
    runs = HarnessContextAgent(model, state, investigation_backend=backend).investigate_group(
        rows(prepared), prepared[5])
    assert state.model_calls == model.group_calls == 1
    # The grouped fixture synthesizes one result for each requirement within
    # that single model response; those internal records are not provider calls.
    assert len(model.calls) == len(rows(prepared))
    assert state.budget_stop is None
    assert runs[0].metadata["termination"] == "optional_model_reserve"
    assert sum(run.metadata["model_calls"] for run in runs) == 1


def test_backend_requires_execution_and_fingerprint_interface():
    with pytest.raises(TypeError, match="run and descriptor"):
        HarnessContextAgent(None, None, investigation_backend=object())
