"""A durable failed planner result is replayable without selecting an API plan."""
import json
import shutil

import pytest

from harness_generation.harness_strategy.models import StrategyBudget
from harness_generation.harness_strategy.planner import StrategyPlanner
from harness_generation.lightweight_context import LightweightContextStore
from harness_generation.lightweight_context.persistence import (load_strategy_inputs, replay_strategy_run,
    save_strategy_run, strategy_run_configuration)
from harness_generation.semantic_discovery.models import AgentModelResponse, AgentToolCall, FakeAgentModel, canonical
from v05_fixtures import lightweight_sample as sample, context_for

pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="small real Clang fixture required")


def test_failed_planning_replays_full_ledger_without_a_selected_candidate(sample, tmp_path):
    context = context_for(sample)
    budget = StrategyBudget()

    def invalid_submit(messages, schemas):
        replies = [json.loads(message["content"]) for message in messages if message["role"] == "tool"]
        body = next(response for response in replies if response.get("evidence"))
        # Schema is valid but the real parser's required data/size arguments
        # are absent. Source evidence cannot turn this into an accepted plan.
        proposal = {"steps": [{"step_id": "parse", "kind": "call",
            "function_id": sample[5]["parse"], "arguments": {}, "guard_ids": [],
            "evidence_ids": body["evidence_ids"], "hypothesis_ids": []}],
            "hypotheses": [], "open_questions": []}
        return AgentModelResponse(tool_calls=(AgentToolCall("invalid", "submit_harness_strategies",
            canonical({"strategies": [proposal]})),))

    model = FakeAgentModel([AgentModelResponse(tool_calls=(AgentToolCall("body", "get_function",
        canonical({"function": sample[5]["parse"]})),)), invalid_submit, invalid_submit])
    run = StrategyPlanner(model, budget).plan(context.strategy_input, context.snapshot, context.make_strategy_tools(budget))
    assert run.result["status"] == "blocked"
    assert run.result["selected_strategy_id"] is None and not run.result["ranked_strategy_ids"]
    model_invocations = len(model.calls)
    store = LightweightContextStore(tmp_path)
    configuration = strategy_run_configuration(context, budget, model, build_analysis_directory=sample[1])
    run_id = save_strategy_run(store, context, run, configuration)
    replayed = replay_strategy_run(store, context, run_id)
    assert replayed["run"].result == run.result
    assert replayed["run"].evidence == run.evidence
    assert replayed["run"].trace == run.trace
    assert replayed["run"].metadata == run.metadata
    assert replayed["replay"]["model_calls"] == replayed["replay"]["provider_requests"] == 0
    assert len(model.calls) == model_invocations
    with pytest.raises(ValueError, match="no structurally valid"):
        load_strategy_inputs(store, context, run_id)
