"""The planner describes each independently issued context with its own authority."""
import json

from harness_generation.harness_strategy.models import StrategyBudget
from harness_generation.harness_strategy.planner import (
    LIGHTWEIGHT_SYSTEM_PROMPT, SYSTEM_PROMPT, StrategyPlanner,
)
from harness_generation.semantic_discovery.models import (
    AgentModelResponse, AgentToolCall, FakeAgentModel, canonical,
)
from v05_fixtures import planner_fixture as prepared, run_planner_fixture as run_fixture
from v05_fixtures import context_for, proposal_for, lightweight_sample as sample


def test_existing_ft_prompt_and_input_keep_their_authority(tmp_path):
    fixture = prepared(tmp_path)
    run, model, _ = run_fixture(fixture)
    assert run.result["status"] == "proposed"
    first = model.calls[0]["messages"]
    assert first[0]["content"] == SYSTEM_PROMPT
    payload = json.loads(first[1]["content"])
    assert payload["minimal_ft"] == fixture[1]
    assert "lightweight_api_context" not in payload
    assert "context_authorization" not in payload


def test_lightweight_prompt_names_its_context_and_fixed_live_scope(sample):
    context = context_for(sample)
    ids = sample[5]
    calls = tuple(AgentToolCall(name, "get_function", canonical({"function": ids[name]}))
                  for name in ("parse", "destroy"))

    def terminal(messages, schemas):
        outputs = [json.loads(row["content"]) for row in messages if row["role"] == "tool"]
        evidence = {row["evidence"][0]["function_id"]: row["evidence_ids"] for row in outputs}
        proposal = proposal_for(sample, context, evidence)
        return AgentModelResponse(tool_calls=(AgentToolCall("submit", "submit_harness_strategies",
            canonical({"strategies": [proposal]})),))

    budget = StrategyBudget()
    model = FakeAgentModel([AgentModelResponse(tool_calls=calls), terminal])
    run = StrategyPlanner(model, budget).plan(context.strategy_input, context.snapshot,
                                             context.make_strategy_tools(budget))
    assert run.result["status"] == "proposed"
    assert run.result["generation_allowed"] is False
    first = model.calls[0]["messages"]
    assert first[0]["content"] == LIGHTWEIGHT_SYSTEM_PROMPT
    assert first[0]["content"].startswith(
        "Plan a finite set of typed harness call strategies for ONE live-authorized Lightweight API Context."
    )
    assert "cannot add a constructor, cleanup, callback or other callable API" in first[0]["content"]
    assert "Discover a missing constructor" not in first[0]["content"]
    payload = json.loads(first[1]["content"])
    assert "minimal_ft" not in payload
    assert payload["lightweight_api_context"] == context.strategy_input
    assert payload["context_authorization"] == context.scope.receipt
    assert payload["context_authorization"]["allowed_function_ids"] == sorted(context.scope.function_ids)
    assert payload["context_authorization"]["semantic_verified"] is False
    assert payload["context_authorization"]["generation_allowed"] is False
