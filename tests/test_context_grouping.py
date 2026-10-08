"""Grouped calls preserve atomic contracts, strict evidence and resume gates."""
from copy import deepcopy
import json

import pytest

from harness_generation.harness_context import HarnessContextMiningLoop, ContextBudget
from harness_generation.harness_context.agent import parse_group_resolution
from harness_generation.harness_context.persistence import run_configuration
from harness_generation.semantic_discovery.models import AgentModelResponse, AgentToolCall, canonical, FakeAgentModel
from test_harness_context import setup, direct_specs, assert_gate, ScriptedModel, CONTEXT, context_specs


class GroupedFixtureModel(ScriptedModel):
    """Explicit fixture adapter, used only for offline grouped-loop tests."""
    def complete(self, messages, schemas):
        request = json.loads(next(m["content"] for m in messages if m["role"] == "user"))
        results, queries = [], []
        for requirement in request["requirements"]:
            rewritten = deepcopy(messages)
            next(m for m in rewritten if m["role"] == "user")["content"] = canonical({**request, "requirement": requirement})
            response = super().complete(rewritten, schemas)
            for call in response.tool_calls:
                if call.name == "submit_requirement_resolution":
                    results.append(json.loads(call.arguments))
                else:
                    queries.append(call)
        if queries:
            return AgentModelResponse(tool_calls=tuple({(c.name, c.arguments): c for c in queries}.values()))
        self.serial += 1
        from harness_generation.harness_context.terminal import compact_submission
        signed = request["signed_proposal_registry"]
        for message in messages:
            if message["role"] == "tool":
                from harness_generation.harness_context.proposals import merge_registry
                signed = merge_registry(signed, json.loads(message["content"]))
        return AgentModelResponse(tool_calls=(AgentToolCall(f"group_{self.serial}", "submit_requirement_resolutions", canonical(compact_submission(results, request["requirements"], signed))),))


def test_group_uses_one_model_call_and_preserves_every_predicate(tmp_path):
    prepared = setup(tmp_path)
    model = GroupedFixtureModel(direct_specs(prepared[0][-1]["parse"]))
    configuration = run_configuration(prepared[1], prepared[2], prepared[3], prepared[4].budget, model, requirement_mode="grouped")
    run = HarnessContextMiningLoop(model, prepared[4], group_requirements=True).run(prepared[1], prepared[3], prepared[5],
        store=prepared[0][0], configuration=configuration)
    assert_gate(run)
    assert prepared[4].model_calls == 1
    assert {f["predicate"] for f in run.context["facts"]} == {key[1] for key in direct_specs(prepared[0][-1]["parse"])}
    assert len(run.requirements["requirements"]) == 5
    for req in run.requirements["requirements"]:
        assert req["status"] == "resolved"
    schema = next(s["function"]["parameters"] for s in model.calls[0]["schemas"] if s["function"]["name"] == "submit_requirement_resolutions")
    for item in schema["properties"]["resolutions"]["properties"].values():
        properties = item["properties"]
        assert "requirement_id" not in properties
        assert "predicate" not in properties["facts"]["items"]["properties"]
        assert "required_by" not in properties["discovered_api_dependencies"]["items"]["properties"]


def test_group_unknown_ownership_stays_a_hard_gap(tmp_path):
    prepared = setup(tmp_path)
    specs = direct_specs(prepared[0][-1]["parse"])
    del specs[(prepared[0][-1]["parse"], "ownership")]
    model = GroupedFixtureModel(specs)
    run = HarnessContextMiningLoop(model, prepared[4], group_requirements=True).run(prepared[1], prepared[3], prepared[5])
    assert_gate(run, "incomplete")
    assert any(gap["kind"] == "ownership" for gap in run.completeness["hard_missing"])
    assert any(row["status"] == "resolved" for row in run.requirements["requirements"])


def test_group_semantic_failure_keeps_valid_items_after_bounded_correction(tmp_path):
    prepared = setup(tmp_path)
    def mutate(req, value):
            if req["kind"] == "ownership":
                value["facts"][0]["evidence_ids"] = []
    model = GroupedFixtureModel(direct_specs(prepared[0][-1]["parse"]), mutate=mutate)
    run = HarnessContextMiningLoop(model, prepared[4], group_requirements=True).run(prepared[1], prepared[3], prepared[5])
    assert_gate(run, "incomplete")
    assert {row["kind"] for row in run.requirements["requirements"] if row["status"] == "resolved"} == {
        "input_binding", "argument_construction", "buffer_length", "return_semantics"}
    # The two investigated groups may each spend one remaining ordinary round
    # on explicit correction. The invalid evidence never becomes a fact.
    assert prepared[4].model_calls == 4
    assert prepared[4].model_calls <= prepared[4].budget.max_total_model_calls
    assert run.metadata["unchanged_investigation_skips"]


def test_unchanged_malformed_terminal_stops_without_extra_completeness_attempts(tmp_path):
    prepared = setup(tmp_path, budget=ContextBudget(max_completeness_rounds=7, max_total_model_calls=80))
    model = FakeAgentModel([AgentModelResponse(tool_calls=(
        AgentToolCall(f"malformed_{i}", "submit_requirement_resolutions", "{"),)) for i in range(40)])
    configuration = run_configuration(prepared[1], prepared[2], prepared[3], prepared[4].budget,
        model, requirement_mode="grouped")
    run = HarnessContextMiningLoop(model, prepared[4], group_requirements=True).run(
        prepared[1], prepared[3], prepared[5], store=prepared[0][0], configuration=configuration)
    assert_gate(run, "incomplete")
    assert run.context["facts"] == []
    assert run.metadata["termination"] == "execution_failure"
    assert run.metadata["metrics"]["completeness_rounds"] == 1
    # Ordinary correction and protocol/schema recovery are bounded within the
    # one investigation; unchanged source cannot purchase another attempt.
    assert len(model.calls) <= prepared[4].budget.max_rounds_per_requirement + 2
    root = prepared[0][0].root / "harness_contexts" / prepared[1]["ft_id"] / "agent_runs"
    assert all(len(list(directory.glob("attempt_*"))) == 1 for directory in root.iterdir())


def test_provider_failure_without_new_source_never_retries_completeness_rounds(tmp_path):
    prepared = setup(tmp_path, budget=ContextBudget(max_completeness_rounds=7, max_total_model_calls=80))
    model = FakeAgentModel([])
    configuration = run_configuration(prepared[1], prepared[2], prepared[3], prepared[4].budget,
        model, requirement_mode="grouped")
    run = HarnessContextMiningLoop(model, prepared[4], group_requirements=True).run(
        prepared[1], prepared[3], prepared[5], store=prepared[0][0], configuration=configuration)
    assert_gate(run, "incomplete")
    assert run.context["facts"] == []
    assert run.metadata["termination"] == "execution_failure"
    assert run.metadata["metrics"]["completeness_rounds"] == 1
    assert 1 <= len(model.calls) <= 2
    assert run.metadata["metrics"]["model_calls"] == len(model.calls)
    root = prepared[0][0].root / "harness_contexts" / prepared[1]["ft_id"] / "agent_runs"
    assert all(len(list(directory.glob("attempt_*"))) == 1 for directory in root.iterdir())
    assert all(json.loads((directory / "metadata.json").read_text())["resolution_attempt_failed"]
        == "provider_error" for directory in root.iterdir())


def test_newly_issued_cleanup_scope_retries_order_and_preserves_billed_attempts(tmp_path):
    prepared = setup(tmp_path, CONTEXT, roles={"parse": ("core", "accepted_anchor"),
        "create": ("support", "resource_creation")}, extras={"create": ["required_initialization"]})

    class UsageFixtureModel(ScriptedModel):
        def complete(self, messages, schemas):
            response = super().complete(messages, schemas)
            return AgentModelResponse(response.content, response.tool_calls, response.reasoning_content,
                {"response_id": f"offline_scope_{len(self.calls)}",
                 "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}})

    model = UsageFixtureModel(context_specs(prepared[0][-1]), query_type="Context",
        initial_ids=prepared[5].initial_ids)
    configuration = run_configuration(prepared[1], prepared[2], prepared[3], prepared[4].budget, model)
    run = HarnessContextMiningLoop(model, prepared[4]).run(prepared[1], prepared[3], prepared[5],
        store=prepared[0][0], configuration=configuration)
    assert_gate(run)
    assert not run.completeness["execution_failed_requirements"]
    order = next(r for r in run.requirements["requirements"] if r["kind"] == "call_order"
        and r["subject_function_id"] == prepared[0][-1]["parse"])
    root = prepared[0][0].root / "harness_contexts" / prepared[1]["ft_id"] / "agent_runs"
    attempts = sorted((root / order["requirement_id"]).glob("attempt_*"))
    assert len(attempts) == 2
    first, second = [json.loads((attempt / "metadata.json").read_text()) for attempt in attempts]
    assert first["resolution_attempt_failed"] == "protocol_error"
    assert not second.get("resolution_attempt_failed")
    rejected = json.loads((attempts[0] / "trace.json").read_text())
    assert any(e.get("detail") == "fact_api_outside_discovered_scope" for e in rejected["events"])
    responses = [e for path in root.glob("*/attempt_*/trace.json")
        for e in json.loads(path.read_text())["events"] if e["kind"] == "model_response"]
    assert len(responses) == len(model.calls) == run.metadata["metrics"]["model_calls"]
    assert len({e["metadata"]["response_id"] for e in responses}) == len(responses)
    assert sum(e["metadata"]["usage"]["total_tokens"] for e in responses) == (
        run.metadata["metrics"]["tokens"]["total_tokens"]) == 12 * len(model.calls)


def test_body_evidence_reused_with_scope_and_bounded_source_charge(tmp_path):
    prepared = setup(tmp_path)
    tools = prepared[5]
    rows = __import__("harness_generation.harness_context", fromlist=["HarnessRequirementBuilder"]).HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"]
    tools.activate(rows[0]); first = tools.bootstrap(); chars = prepared[4].source_chars
    tools.activate(rows[1]); second = tools.bootstrap()
    assert first["evidence_ids"] == second["evidence_ids"]
    assert prepared[4].source_chars == chars and tools.bootstrap_reuses == 1
    assert prepared[4].tool_calls == 1
    assert set(second["evidence_ids"]) <= tools.visible_ids
    assert tools.execute("get_function", {"function": "foreign.c:1:parse"})["error"].startswith("outside_requirement_scope")


def test_creator_cleanup_structural_ranking_is_bounded_without_name_heuristics(tmp_path):
    source = CONTEXT.replace("create", "z_build").replace("destroy", "z_finish")
    source += "\n".join(f"int a_{i}(Context *ctx) {{ return ctx->calls; }}" for i in range(50))
    prepared = setup(tmp_path, source)
    from harness_generation.harness_context import HarnessRequirementBuilder
    requirement = next(r for r in HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"] if r["kind"] == "lifecycle")
    tools = prepared[5]; tools.activate(requirement)
    for name, target in (("find_initializers", "z_build"), ("find_cleanup_candidates", "z_finish")):
        result = tools.execute(name, {"type": "Context"})
        assert result["evidence"][0]["function"] == target
        assert result["query_truncated"] and len(result["evidence"]) <= prepared[4].budget.max_references_per_query
        assert all(r["structural_hint_only"] for r in result["evidence"])


def test_support_questions_merge_by_exact_identity_without_losing_questions(tmp_path):
    prepared = setup(tmp_path, CONTEXT, roles={"parse": ("core", "accepted_anchor"), "create": ("support", "resource_creation")},
                     extras={"create": ["required_initialization"]})
    from harness_generation.harness_context import HarnessRequirementBuilder
    rows = HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"]
    creator = prepared[0][-1]["create"]
    decisions = [r for r in rows if r["subject_function_id"] == creator and r["kind"] == "support_decision"]
    assert len(decisions) == 1
    for gap in prepared[1]["unresolved_dependencies"]:
        if gap["function_id"] == creator:
            assert all(question in decisions[0]["question"] for question in gap["questions"])


@pytest.mark.parametrize("change", ["missing", "duplicate", "foreign", "predicate"])
def test_group_validator_never_collapses_or_relabels_requirements(tmp_path, change):
    prepared = setup(tmp_path)
    from harness_generation.harness_context import HarnessRequirementBuilder
    rows = HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"]
    tools = prepared[5]; tools.activate(rows[0]); seed = tools.bootstrap()
    specs = direct_specs(prepared[0][-1]["parse"])
    values = [{"requirement_id": r["requirement_id"], "status": "resolved", "facts": [{"function_id": r["subject_function_id"],
        "predicate": r["kind"], "value": specs[(r["subject_function_id"], r["kind"])]["value"], "evidence_ids": seed["evidence_ids"]}],
        "discovered_api_dependencies": [], "open_questions": []} for r in rows]
    if change == "missing": values.pop()
    elif change == "duplicate": values[-1] = values[0]
    elif change == "foreign": values[0]["facts"][0]["evidence_ids"] = ["ev_foreign"]
    else: values[0]["facts"][0]["predicate"] = "ownership"
    with pytest.raises(ValueError):
        parse_group_resolution(canonical({"resolutions": values}), rows, tools)
