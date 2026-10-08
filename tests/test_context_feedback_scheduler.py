"""Native context mining repairs a missed extent inside the original budgets."""
from copy import deepcopy
import hashlib
import json
import re

import pytest

from harness_generation.context_generation import HarnessPlanBuilder
from harness_generation.harness_context import ContextBudget, HarnessContextMiningLoop
from harness_generation.harness_context.models import resource_id
from harness_generation.harness_context.persistence import (context_directory, load_context_documents,
    load_requirement, requirement_configuration, run_configuration)
from harness_generation.semantic_discovery.models import AgentModelError
from test_context_grouping import GroupedFixtureModel
from test_harness_context import (OWNED, argument, assert_gate, direct_specs, lifecycle_value,
                                 order, owner, setup, ScriptedModel)


SOURCE = "#include <stdlib.h>\n" + re.sub(r"\bsize\b", "cb", OWNED.replace("data", "src"))


def owned_specs(ids):
    fid, cleanup = ids["parse"], ids["node_free"]
    resource = resource_id(fid)
    specs = direct_specs(fid, data="src", size="cb")
    specs[(fid, "return_semantics")]["value"] = {
        "success": "nonnull", "nullable": True, "owned": True, "error_cleanup": False}
    specs[(fid, "ownership")]["value"]["entries"].append(
        owner(returned=True, ownership="owned", release=cleanup, resource=resource))
    specs[(fid, "lifecycle")] = {"value": lifecycle_value(fid, resource, "Node", None, fid, cleanup),
        "dependencies": [{"function_id": cleanup, "necessity": "required", "reason": "cleanup"}]}
    specs[(fid, "call_order")] = {"value": {"constraints": [order(fid, cleanup)]}}
    specs[(cleanup, "argument_construction")] = {"value": {"arguments": [argument("node", "derived")]}}
    specs[(cleanup, "ownership")] = {"value": {"entries": [owner("node", ownership="transferred")]}}
    specs[(cleanup, "support_decision")] = {"value": {
        "decision": "required", "reason": "cleanup", "required_by": [fid]},
        "dependencies": [{"function_id": cleanup, "required_by": fid, "necessity": "required", "reason": "cleanup"}]}
    return specs


class FeedbackExtentModel(GroupedFixtureModel):
    """Real typed fixture proposals; correction requires the new feedback."""
    def __init__(self, specs, fid, *, correct=True, fail_revision=None, **kwargs):
        self.fid, self.correct, self.fail_revision = fid, correct, fail_revision
        self.requests, self.feedback_requests, self.submissions = [], [], []
        self.current_feedback = False
        super().__init__(specs, mutate=self.mutate_extent, **kwargs)

    def mutate_extent(self, requirement, result):
        if requirement["subject_function_id"] == self.fid and not (self.correct and self.current_feedback):
            for proposal in result["facts"]:
                for binding in proposal["value"].get("bindings", []):
                    if binding["parameter"] == "src":
                        binding["size_parameter"] = None
                for link in proposal["value"].get("links", []):
                    if link["buffer_parameter"] == "src":
                        link["length_parameter"] = None
        self.submissions.append(deepcopy(result))

    def complete(self, messages, schemas):
        request = json.loads(next(m["content"] for m in messages if m["role"] == "user"))
        self.requests.append(deepcopy(request))
        items = [item for task in request.get("missing_tasks", [])
            for item in task.get("closure_feedback", {}).get("items", [])]
        self.current_feedback = any(item["category"] == "contract_correction" and
            any(path.endswith((".size_parameter", ".length_parameter")) for target in item["correction_targets"]
                for path in target["field_paths"]) for item in items)
        if self.current_feedback:
            self.feedback_requests.append(deepcopy(request))
            if self.fail_revision:
                failure = AgentModelError("Recorded offline revision failure")
                failure.category = self.fail_revision
                raise failure
        return (super().complete(messages, schemas) if 'requirements' in request
            else ScriptedModel.complete(self, messages, schemas))


def run_fixture(tmp_path, *, correct=True, fail_revision=None, persist=False, group_requirements=True):
    budget = ContextBudget()
    prepared = setup(tmp_path, SOURCE, budget=budget)
    model = FeedbackExtentModel(owned_specs(prepared[0][-1]), prepared[0][-1]["parse"],
        correct=correct, fail_revision=fail_revision, query_type="Node", initial_ids=prepared[5].initial_ids)
    accepted = []
    archive_hashes = {}
    before_ft = deepcopy(prepared[1])
    configuration = run_configuration(prepared[1], prepared[2], prepared[3], budget, model,
        requirement_mode="grouped" if group_requirements else "single")
    store = prepared[0][0] if persist else None
    directory = context_directory(store, prepared[1]["ft_id"]) if persist else None

    def record_archives():
        if not persist:
            return
        for path in (directory / "agent_runs").glob("*/attempt_*/*.json"):
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            assert path not in archive_hashes or archive_hashes[path] == actual, "Archived native attempts are immutable"
            archive_hashes[path] = actual

    def on_requirement(row, result, resumed, state):
        accepted.append({"requirement": deepcopy(row), "result": deepcopy(result),
            "model_calls": state.model_calls, "tool_calls": state.tool_calls, "source_chars": state.source_chars})
        record_archives()

    run = HarnessContextMiningLoop(model, prepared[4], group_requirements=group_requirements).run(
        prepared[1], prepared[3], prepared[5], store=store, configuration=configuration,
        on_requirement=on_requirement)
    record_archives()
    assert prepared[1] == before_ft
    assert prepared[4].budget is budget and budget.to_dict() == ContextBudget().to_dict()
    assert len(model.requests) == prepared[4].model_calls == run.metadata["metrics"]["model_calls"]
    assert prepared[4].model_calls <= 24 and prepared[4].tool_calls <= 64 and prepared[4].source_chars <= 96000
    assert run.metadata["metrics"]["completeness_rounds"] <= 3
    revision_ids = [rid for batch in run.metadata["context_revision_history"] for rid in batch["requirement_ids"]]
    assert len(revision_ids) == len(set(revision_ids)), "Each requirement has at most one unchanged-evidence revision"
    assert all(batch["budget_after"]["model_calls"] <= 24 and batch["budget_after"]["tool_calls"] <= 64
               and batch["budget_after"]["source_chars"] <= 96000 for batch in run.metadata["context_revision_history"])
    assert all(batch["budget_before"]["source_chars"] == batch["budget_after"]["source_chars"]
               for batch in run.metadata["context_revision_history"]), "Contract revision reuses issued source"
    return prepared, run, model, accepted


@pytest.mark.parametrize('group_requirements', [True, False])
def test_native_scheduler_reopens_closed_extent_contracts_and_closes_plan(tmp_path, group_requirements):
    prepared, run, model, accepted = run_fixture(tmp_path, group_requirements=group_requirements)
    assert_gate(run)
    assert model.feedback_requests and run.metadata["context_revision_history"]
    initial = {row["requirement"]["requirement_id"]: row["result"] for row in reversed(accepted)}
    parse = prepared[0][-1]["parse"]
    extent_rids = {r["requirement_id"] for r in run.requirements["requirements"]
        if r["subject_function_id"] == parse and r["kind"] in {"input_binding", "buffer_length"}}
    revised = {rid for batch in run.metadata["context_revision_history"] for rid in batch["requirement_ids"]}
    assert extent_rids <= revised
    for rid in extent_rids:
        assert initial[rid]["status"] == "resolved"
        for fact in initial[rid]["facts"]:
            for binding in fact["value"].get("bindings", []):
                if binding["parameter"] == "src":
                    assert binding["size_parameter"] is None
            for link in fact["value"].get("links", []):
                assert link["length_parameter"] is None
    assert next(b for b in run.context["input_contract"]["bindings"] if b["function_id"] == parse)["size_parameter"] == "cb"
    assert next(b for b in run.context["buffer_length_contract"]["links"] if b["function_id"] == parse)["length_parameter"] == "cb"
    retained = {f["fact_id"]: f for f in run.context["facts"]}
    independent = [fact for result in initial.values() for fact in result["facts"]
        if fact["requirement_id"] not in revised]
    assert independent and all(retained.get(fact["fact_id"]) == fact for fact in independent)
    plan = HarnessPlanBuilder().build(prepared[1], run.context, run.closure, prepared[3], run.completeness)
    assert plan["frozen"] and plan["call_sequence"] and plan["cleanup_sequence"]
    assert plan["call_sequence"][0]["return_resource"] == plan["cleanup_sequence"][0]["arguments"][0]["resource_id"]


def test_repeated_old_extent_answer_records_no_progress_and_stops_with_original_budget(tmp_path):
    prepared, run, model, _ = run_fixture(tmp_path, correct=False)
    assert_gate(run, "incomplete")
    assert model.feedback_requests
    batches = run.metadata["context_revision_history"]
    assert batches and all(batch["outcome"] == "no_progress" for batch in batches)
    assert all(batch["old_fact_ids"] == batch["retained_fact_ids"] for batch in batches)
    assert run.metadata["unchanged_investigation_skips"]
    assert run.completeness["hard_missing"] and not run.context["frozen"]


@pytest.mark.parametrize("category", ["http_401", "transport_error"])
def test_provider_failure_during_contract_revision_cannot_buy_another_semantic_attempt(tmp_path, category):
    _, run, model, _ = run_fixture(tmp_path, fail_revision=category)
    assert_gate(run, "incomplete")
    assert len(model.feedback_requests) == 1
    assert run.metadata["execution_failures"]
    assert all(row["execution_status"] == "provider_error" for row in run.metadata["execution_failures"])
    assert run.completeness["execution_failed_requirements"]
    assert all(batch["outcome"] == "execution_failure"
               for batch in run.metadata["context_revision_history"])


@pytest.mark.parametrize('group_requirements', [True, False])
def test_persisted_revision_commits_latest_resolutions_without_rewriting_agent_attempts(tmp_path, group_requirements):
    prepared, run, model, _ = run_fixture(tmp_path, persist=True, group_requirements=group_requirements)
    assert_gate(run)
    store, ft_id = prepared[0][0], prepared[1]["ft_id"]
    configuration = run_configuration(prepared[1], prepared[2], prepared[3], prepared[4].budget, model,
        requirement_mode="grouped" if group_requirements else "single")
    directory = context_directory(store, ft_id)
    documents = load_context_documents(store, ft_id, configuration, prepared[5].index)
    assert documents is not None
    assert documents["harness_context"] == run.context
    assert documents["closure_feedback"] == run.metadata["closure_feedback"]
    assert documents["context_revision_history"]["revisions"] == run.metadata["context_revision_history"]
    resolutions = documents["resolutions"]["resolutions"]
    for req in run.requirements["requirements"]:
        rid = req["requirement_id"]
        root = directory / "agent_runs" / rid
        if rid not in resolutions:
            continue
        latest = json.loads((root / "result.json").read_text())
        assert latest == resolutions[rid]
        assert load_requirement(store, ft_id, req, requirement_configuration(configuration, req), prepared[5].index)
        for attempt in root.glob("attempt_*"):
            metadata = json.loads((attempt / "metadata.json").read_text())
            trace = json.loads((attempt / "trace.json").read_text())
            assert metadata.get("group_model_calls", metadata["model_calls"]) > 0
            assert any(e["kind"] == "model_response" for e in trace["events"])
            assert "framework_reconciliations" not in metadata

    # Commit markers cover the new feedback/audit files just like source facts.
    for name in ("closure_feedback", "context_revision_history"):
        path = directory / (name + ".json")
        original = path.read_bytes()
        changed = json.loads(original)
        changed["tampered"] = True
        path.write_text(json.dumps(changed))
        assert load_context_documents(store, ft_id, configuration, prepared[5].index) is None
        path.write_bytes(original)
        assert load_context_documents(store, ft_id, configuration, prepared[5].index) is not None

    req = next(r for r in run.requirements["requirements"] if r["requirement_id"] in resolutions)
    for key in ("policy_version", "agent_prompt_version", "closure_feedback_version"):
        incompatible = deepcopy(configuration)
        incompatible[key] = "previous-incompatible-version"
        assert load_context_documents(store, ft_id, incompatible, prepared[5].index) is None
        assert load_requirement(store, ft_id, req, requirement_configuration(incompatible, req), prepared[5].index) is None
