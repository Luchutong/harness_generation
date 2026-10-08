"""Proof acquisition, bounded evidence reuse and complete terminal snapshots."""
from copy import deepcopy
import json

import pytest

from harness_generation.harness_context import HarnessRequirementBuilder, ContextBudget
from harness_generation.harness_context.agent import HarnessContextAgent
from harness_generation.harness_context.repairs import merge_resolution
from harness_generation.semantic_discovery import FakeAgentModel, AgentModelResponse, AgentToolCall
from harness_generation.semantic_discovery.models import canonical, DecisionSchemaError
from test_harness_context import (setup, CONTEXT, OWNED, direct_specs, ScriptedModel, owner)
from test_context_grouping import GroupedFixtureModel


def req(prepared, kind):
    return next(r for r in HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"] if r["kind"] == kind)


def test_unresolved_attempt_source_reappears_without_requery_or_source_charge(tmp_path):
    prepared = setup(tmp_path, CONTEXT)
    tools, state, requirement = prepared[5], prepared[4], req(prepared, "lifecycle")
    tools.activate(requirement)
    tools.bootstrap()
    tools.execute("find_initializers", {"type": "Context"})
    source = tools.execute("get_function", {"function": prepared[0][-1]["create"]})
    body_id = source["evidence_ids"][0]
    charged, calls = state.source_chars, state.tool_calls
    tools.activate(requirement, facts=[])
    second = tools.bootstrap()
    assert body_id in second["evidence_ids"] and body_id in second["reused_requirement_evidence_ids"]
    assert state.source_chars == charged and state.tool_calls == calls
    assert body_id in tools.visible_ids


def test_memory_reuses_authorized_source_without_importing_candidate_history(tmp_path):
    prepared = setup(tmp_path, CONTEXT)
    tools = prepared[5]
    tools.activate(req(prepared, "lifecycle"))
    tools.bootstrap()
    history = tools.execute("find_initializers", {"type": "Context"})['evidence_ids']
    eid = tools.execute("get_function", {"function": prepared[0][-1]["create"]})["evidence_ids"][0]
    tools.activate(req(prepared, "ownership"))
    # A full authenticated body from this subject's authorized dependency may
    # be reused across predicates. A prior type-candidate list is not a proof.
    assert eid in tools.visible_ids and not set(history) & tools.visible_ids
    bootstrap = tools.bootstrap()
    assert eid in bootstrap['evidence_ids'] and not set(history) & set(bootstrap['evidence_ids'])


def test_memory_rejects_a_changed_live_range(tmp_path):
    prepared = setup(tmp_path)
    tools, requirement = prepared[5], req(prepared, "ownership")
    tools.activate(requirement)
    function = prepared[3].functions[requirement["subject_function_id"]]
    query = {"file": function["file"], "line_start": function["start_line"], "line_end": function["end_line"]}
    eid = tools.execute("read_source_range", query)["evidence_ids"][0]
    source = tools.index.owned_path(function["file"])
    source.write_text(source.read_text() + "\n/* source changed */\n")
    tools.activate(requirement)
    assert eid not in tools.visible_ids


def test_group_agenda_and_focus_cover_every_slot(tmp_path):
    prepared = setup(tmp_path, CONTEXT)
    rows = [req(prepared, "ownership"), req(prepared, "state")]
    results = [{"requirement_id": r["requirement_id"], "status": "unresolved", "facts": [],
        "discovered_api_dependencies": [], "open_questions": ["Exact ctx origin and initializer evidence are missing."]} for r in rows]
    response = AgentModelResponse(tool_calls=(AgentToolCall("submit", "submit_requirement_resolutions", canonical({"resolutions": results})),))
    model = FakeAgentModel([response])
    tasks = [{"requirement_id": r["requirement_id"], "task_id": "task_" + str(i), "blocked_roots": ["root"],
        "missing_proofs": [{"subject_parameter": "ctx", "predicate": r["kind"], "diagnostics": []}]} for i, r in enumerate(rows)]
    runs = HarnessContextAgent(model, prepared[4]).investigate_group(rows, prepared[5], missing_tasks=tasks)
    messages = runs[0].trace["messages"]
    request = json.loads(next(m["content"] for m in messages if m["role"] == "user"))
    assert [s["requirement_id"] for s in request["proof_agenda"]["slots"]] == [r["requirement_id"] for r in rows]
    assert all(s["target_parameters"] == ["ctx"] for s in request["proof_agenda"]["slots"])
    assert len(request["missing_tasks"]) == 2
    assert not any('"obligation_focus"' in (m.get("content") or "") for m in messages)
    assert request["contract_guidance"]["terminal_name"] == "submit_requirement_resolutions"
    assert all(r.metadata["proof_investigation"]["unresolved_questions"] == r.result["open_questions"] for r in runs)


def test_existing_group_terminal_remains_one_model_call(tmp_path):
    prepared = setup(tmp_path)
    rows = HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"]
    model = GroupedFixtureModel(direct_specs(prepared[0][-1]["parse"]))
    runs = HarnessContextAgent(model, prepared[4]).investigate_group(rows, prepared[5])
    assert all(r.result["status"] == "resolved" for r in runs)
    assert prepared[4].model_calls == 1


def test_followup_can_discover_read_and_submit_inside_original_round_ceiling(tmp_path):
    prepared = setup(tmp_path, OWNED, budget=ContextBudget(max_total_model_calls=4, max_tool_calls=8))
    fid, cleanup = prepared[0][-1]["parse"], prepared[0][-1]["node_free"]
    specs = {(fid, "ownership"): {"value": {"entries": [owner("data"), owner(returned=True,
        ownership="owned", release=cleanup)]}, "dependencies": [{"function_id": cleanup, "necessity": "required", "reason": "cleanup"}]}}
    class SequentialModel(ScriptedModel):
        phase = 0
        def complete(self, messages, schemas):
            self.phase += 1
            if self.phase <= 2:
                name, arguments = ("find_cleanup_candidates", {"type": "Node"}) if self.phase == 1 else ("get_function", {"function": cleanup})
                return AgentModelResponse(tool_calls=(AgentToolCall("q" + str(self.phase), name, canonical(arguments)),))
            return super().complete(messages, schemas)
    model = SequentialModel(specs)
    requirement = req(prepared, "ownership")
    run = HarnessContextAgent(model, prepared[4]).investigate(requirement, prepared[5], missing_tasks=[{
        "requirement_id": requirement["requirement_id"], "task_id": "owned_return_cleanup", "missing_proofs": []}])
    assert run.result["status"] == "resolved", run.trace
    assert prepared[4].model_calls == 3 <= prepared[4].budget.max_total_model_calls
    assert run.metadata["proof_investigation"]["effective_round_limit"] == 4
    assert prepared[4].tool_calls <= 8
    assert "get_function" in {e.get("tool") for e in run.trace["events"] if e.get("round") == 2}


def previous_data_owner(prepared):
    requirement = req(prepared, "ownership")
    model = ScriptedModel({(prepared[0][-1]["parse"], "ownership"): {"value": {"entries": [owner("data")]}}})
    run = HarnessContextAgent(model, prepared[4]).investigate(requirement, prepared[5])
    assert run.result["status"] == "resolved"
    return requirement, run.result["facts"]


def test_partial_submission_merges_previously_established_subject(tmp_path):
    prepared = setup(tmp_path, CONTEXT)
    requirement, facts = previous_data_owner(prepared)
    result = {"status": "resolved", "facts": [{"value": {"entries": [owner("ctx")]},
        "evidence_ids": facts[0]["evidence_ids"]}], "discovered_api_dependencies": [], "open_questions": []}
    merged, audit = merge_resolution({"status":"resolved","facts":facts,"discovered_api_dependencies":[]}, result, requirement)
    assert {r['parameter'] for f in merged['facts'] for r in f['value']['entries']} == {'data','ctx'}
    assert not audit['conflicts']


def test_subject_patch_merges_without_promoting_uncertified_observations(tmp_path):
    prepared = setup(tmp_path, CONTEXT, budget=ContextBudget(max_total_model_calls=4))
    requirement, facts = previous_data_owner(prepared)
    attempts = []
    def mutate(req, result):
        attempts.append(1)
        if len(attempts) == 1:
            result["facts"][0]["value"]["entries"] = [owner("ctx")]
    model = ScriptedModel({(prepared[0][-1]["parse"], "ownership"): {"value": {"entries": [owner("data"), owner("ctx")]}}}, mutate=mutate)
    run = HarnessContextAgent(model, prepared[4]).investigate(requirement, prepared[5], facts,
        [{"requirement_id": requirement["requirement_id"], "task_id": "missing_ctx", "missing_proofs": [{
            "subject_parameter": "ctx", "diagnostics": []}]}])
    assert run.result["status"] == "resolved" and not run.metadata["schema_repair_attempted"]
    assert {e["parameter"] for f in run.result["facts"] for e in f["value"]["entries"]} == {"data", "ctx"}
    assert prepared[4].model_calls == 2 <= 4
    memory = run.metadata["proof_agenda"]["slots"][0]["retained_entries"]
    assert not memory
    request = json.loads(next(m["content"] for m in run.trace["messages"] if m["role"] == "user"))
    observed = [f for f in request["observed_proposals"] if f["requirement_id"] == requirement["requirement_id"]]
    assert observed and all(f["proof_status"] == "unverified" for f in observed)
    assert all(p["proof_status"] == "unverified" for f in observed for p in f["claim_proofs"])


def test_global_exhaustion_still_bounds_group_without_extra_calls(tmp_path):
    prepared = setup(tmp_path, budget=ContextBudget(max_total_model_calls=1))
    prepared[4].model_calls = 1
    runs = HarnessContextAgent(FakeAgentModel([]), prepared[4]).investigate_group([req(prepared, "ownership")], prepared[5])
    assert runs[0].result["status"] == "unresolved" and prepared[4].model_calls == 1


def test_missing_proof_template_is_valid_without_unknown_fact_or_semantic_guess(tmp_path):
    prepared = setup(tmp_path, CONTEXT)
    requirement = req(prepared, "state")
    from harness_generation.harness_context.evidence import parse_resolution
    from harness_generation.harness_context.terminal import expand_submission
    from harness_generation.harness_context.proposals import registry
    run = HarnessContextAgent(FakeAgentModel([AgentModelResponse(tool_calls=(AgentToolCall("no_proof",
        "submit_requirement_resolution", canonical({"resolutions": {"r0": {"status": "unresolved",
            "facts": [], "discovered_api_dependencies": [], "open_questions": ["ctx writer evidence is missing"]}}})),))]),
        prepared[4]).investigate(requirement, prepared[5])
    template = run.metadata["proof_agenda"]["slots"][0]["unresolved_template"]
    assert set(template) == {"status", "facts", "discovered_api_dependencies", "open_questions"}
    template["open_questions"] = ["ctx.ready needs a same-object writer; next query find_resource_flows on " + requirement["subject_function_id"]]
    expanded = expand_submission({"resolutions": {"r0": template}}, [requirement],
        registry(prepared[5], [requirement]), prepared[3])
    result = parse_resolution(canonical(expanded["resolutions"][0]), prepared[5])
    assert result["status"] == "unresolved" and not result["facts"]


def test_agenda_remembers_exact_discovery_query_and_does_not_suggest_it_again(tmp_path):
    prepared = setup(tmp_path, CONTEXT)
    requirement, tools = req(prepared, "state"), prepared[5]
    tools.activate(requirement)
    tools.bootstrap()
    discovery = tools.execute("find_initializers", {"type": "Context"})
    result = {"status": "unresolved", "facts": [], "discovered_api_dependencies": [],
        "open_questions": ["No same-object ctx writer has been proved."]}
    run = HarnessContextAgent(FakeAgentModel([AgentModelResponse(tool_calls=(AgentToolCall("done",
        "submit_requirement_resolution", canonical({"resolutions": {"r0": result}})),))]),
        prepared[4]).investigate(requirement, tools)
    agenda = run.metadata["proof_agenda"]
    rows = [r for r in agenda["issued_evidence_inventory"] if r["evidence_id"] in discovery["evidence_ids"]]
    assert rows and all(r["query"] == {"type": "Context"} for r in rows)
    assert not any(q["tool"] == "find_initializers" and q["arguments"] == {"type": "Context"}
        for q in agenda["slots"][0]["query_options"])


def test_no_agent_execution_tools_or_new_repository_tool_are_registered(tmp_path):
    prepared = setup(tmp_path)
    from harness_generation.semantic_discovery.tools import TOOL_SCHEMAS
    from harness_generation.harness_context.tools import EXTRA_SCHEMAS
    assert {s["function"]["name"] for s in prepared[5].schemas} == {s["function"]["name"] for s in TOOL_SCHEMAS + EXTRA_SCHEMAS}
    assert not {"shell", "compile", "fuzz", "proof_search", "write_file"} & {s["function"]["name"] for s in prepared[5].schemas}
