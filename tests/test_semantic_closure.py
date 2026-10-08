"""Obligation closure retracts downstream proofs and authenticates frozen input."""
from copy import deepcopy
import json

import pytest

from harness_generation.context_generation import HarnessPlanBuilder, PlanError
from harness_generation.context_generation.persistence import load_frozen_inputs
from harness_generation.harness_context import HarnessContextCompletenessValidator
from harness_generation.harness_context.api_closure import build_api_closure
from harness_generation.harness_context.completeness import missing_requirement_tasks
from harness_generation.harness_context.evidence import build_context
from harness_generation.harness_context.obligations import close_obligations, investigation_view
from harness_generation.harness_context.persistence import context_directory
from harness_generation.records import write_json
from harness_generation.semantic_discovery.models import digest
from test_context_generation import ready
from test_callback_boundaries import callback_plan
from test_context_semantics import shared_ready
from test_harness_context import (setup, mine, direct_specs, context_specs, CONTEXT, assert_gate)


def local_node(nid, status="proved", dependencies=()):
    return {"obligation_id": nid, "local_proof": {"status": status},
        "dependencies": [{"obligation_id": dep, "relation": "requires"} for dep in dependencies]}


def test_closure_retracts_shared_dependency_and_never_accepts_cached_status():
    nodes = [local_node("parse", dependencies=["field", "ownership"]),
        local_node("field", dependencies=["init"]), local_node("init", dependencies=["ownership"]),
        local_node("ownership")]
    proved = close_obligations(nodes, ["parse"])
    assert proved["closed_roots"] == ["parse"]
    # Leave the previous closure statuses in place to expose a stale-cache bug.
    nodes = proved["nodes"]
    next(n for n in nodes if n["obligation_id"] == "ownership")["local_proof"]["status"] = "missing"
    missing = close_obligations(nodes, ["parse"])
    assert missing["open_roots"] == ["parse"] and missing["frontier"] == ["ownership"]
    assert all(n["proof_status"] == "blocked" for n in missing["nodes"] if n["obligation_id"] != "ownership")


@pytest.mark.parametrize("nodes,code", [
    ([local_node("a", dependencies=["b"]), local_node("b", dependencies=["a"])], "semantic_obligation_cycle"),
    ([local_node("a", dependencies=["foreign"])], "obligation_dependency_missing"),
    ([local_node("a"), local_node("a")], "duplicate_obligation_identity"),
])
def test_cycles_foreign_dependencies_and_duplicate_nodes_cannot_prove(nodes, code):
    closed = close_obligations(nodes, ["a"])
    assert code in {d["code"] for d in closed["diagnostics"]}
    if code != "duplicate_obligation_identity":
        assert closed["open_roots"] == ["a"]


def test_optional_unknown_does_not_enter_mandatory_closure():
    graph = close_obligations([local_node("core"), local_node("optional", "missing")], ["core"])
    assert graph["open_roots"] == [] and graph["frontier"] == []
    assert next(n for n in graph["nodes"] if n["obligation_id"] == "optional")["proof_status"] == "missing"


def requirement_node(graph, fid, kind):
    return next(n for n in graph["nodes"] if n["subject_function_id"] == fid and n["predicate"] == kind)


def retract(prepared, run, fid, kind):
    """Rebuild from coherent local evidence, not edited proof_status flags."""
    requirements = deepcopy(run.requirements["requirements"])
    req = next(r for r in requirements if r["subject_function_id"] == fid and r["kind"] == kind)
    directory = context_directory(prepared[0][0], prepared[1]["ft_id"])
    resolutions = json.loads((directory / "resolutions.json").read_text())["resolutions"]
    resolutions.pop(req["requirement_id"])
    req["status"], req["evidence_ids"] = "open", []
    facts = [f for f in run.context["facts"] if f["requirement_id"] != req["requirement_id"]]
    closure = build_api_closure(prepared[1], requirements, resolutions, prepared[3], prepared[4])
    context = build_context(prepared[1], requirements, facts, prepared[3], prepared[4].evidence)
    context["dependencies"] = closure["unresolved_api_dependencies"]
    report = HarnessContextCompletenessValidator().validate(context, closure, prepared[1], prepared[3], requirements, resolutions, prepared[4])
    return report, requirements


@pytest.mark.parametrize("initializer", ["feed", "create"])
def test_initialized_state_requires_initializer_ownership_proof(tmp_path, initializer):
    prepared, run, _ = shared_ready(tmp_path, feed_initialization=True)
    assert_gate(run)
    ids = prepared[0][-1]
    before = run.completeness["semantic_obligation_graph"]
    fields = [n for n in before["nodes"] if n["predicate"] == "resource_field_written"]
    assert {p["field"] for n in fields for p in n["local_proof"]["sources"]} == {"data", "size"}
    assert all(n["evidence_ids"] and n["proof_status"] == "proved" for n in fields)
    report, requirements = retract(prepared, run, ids[initializer], "ownership")
    assert report["status"] == "incomplete" and not report["generation_allowed"]
    graph = report["semantic_obligation_graph"]
    state = requirement_node(graph, ids["parse"], "state")
    ownership = requirement_node(graph, ids[initializer], "ownership")
    assert state["local_proof"]["status"] == "proved" and state["proof_status"] == "blocked"
    leaves = {n['obligation_id'] for n in graph['nodes'] if n['predicate']=='ownership_subject'
        and n['subject_function_id']==ids[initializer] and n['proof_status']=='missing'}
    assert leaves and leaves <= set(state["blocking_obligations"])
    # The established state proposal remains available; the agent investigates
    # only the independent missing ownership proof, not every blocked parent.
    tasks = missing_requirement_tasks(report)
    assert len(tasks) == 1 and tasks[0]["subject_function_id"] == ids[initializer]
    assert tasks[0]["kind"] == "ownership" and tasks[0]["blocked_roots"]
    assert "state" not in {t["kind"] for t in tasks}
    view = investigation_view(graph, [r for r in requirements if r["subject_function_id"] == ids["parse"] and r["kind"] == "state"])
    assert state["obligation_id"] in {n["obligation_id"] for n in view["blocked"]}
    assert leaves <= {n["obligation_id"] for n in view["missing_evidence"]}
    assert view["proved"]


def test_length_gap_is_coalesced_and_agent_gets_proof_task(tmp_path):
    prepared = setup(tmp_path)
    fid = prepared[0][-1]["parse"]
    specs = direct_specs(fid)
    del specs[fid, "buffer_length"]
    run, model = mine(prepared, specs)
    assert_gate(run, "incomplete")
    tasks = missing_requirement_tasks(run.completeness)
    assert len(tasks) == 1 and tasks[0]["kind"] == "buffer_length"
    state = requirement_node(run.completeness["semantic_obligation_graph"], fid, "input_binding")
    assert state["local_proof"]["status"] == "proved" and state["proof_status"] == "blocked"
    for call in model.calls:
        request = json.loads(next(m["content"] for m in call["messages"] if m["role"] == "user"))
        assert request["task"] == "semantic_obligation_proof"
        assert request["semantic_obligations"]["targets"]
        if request["missing_tasks"]:
            assert all(t['requirement_id']==request['requirement']['requirement_id'] for t in request['missing_tasks'])


def test_empty_state_proposal_cannot_close_initialized_context(tmp_path):
    prepared = setup(tmp_path, CONTEXT)
    specs = context_specs(prepared[0][-1])
    specs[prepared[0][-1]["parse"], "state"]["value"] = {"preconditions": []}
    run, _ = mine(prepared, specs, query_type="Context")
    assert_gate(run, "incomplete")
    assert "state_precondition_unresolved" in {r["code"] for r in run.completeness["hard_missing"]}


def test_graph_is_published_and_pin_survives_freeze(tmp_path):
    store, frozen, plan = ready(tmp_path)
    ft, context, closure, snapshot, report = frozen[:5]
    graph = report["semantic_obligation_graph"]
    directory = context_directory(store, ft["ft_id"])
    assert json.loads((directory / "semantic_obligation_graph.json").read_text()) == graph
    marker = json.loads((directory / "metadata.json").read_text())
    assert marker["document_digests"]["semantic_obligation_graph"] == digest(graph)
    assert plan["input_digests"]["semantic_obligation_graph"] == graph["graph_digest"]
    assert graph["input_digests"]["harness_context"] == digest({k: v for k, v in context.items() if k != "frozen"})
    assert graph["mandatory_roots"] == graph["closed_roots"]
    assert plan == HarnessPlanBuilder().build(ft, context, closure, snapshot, report)


def test_forged_saved_proof_with_resealed_digests_fails_source_rebuild(tmp_path):
    store, frozen, _ = ready(tmp_path)
    directory = context_directory(store, frozen[0]["ft_id"])
    graph = deepcopy(frozen[4]["semantic_obligation_graph"])
    # Keep an internally closed graph, but replace the basis of a local proof.
    graph["nodes"][0]["evidence_ids"] = ["ev_invented"]
    graph["graph_digest"] = digest({k: v for k, v in graph.items() if k != "graph_digest"})
    report = deepcopy(frozen[4])
    report["semantic_obligation_graph"] = graph
    report["semantic_obligation_graph_digest"] = graph["graph_digest"]
    marker = json.loads((directory / "metadata.json").read_text())
    for name, document in [("semantic_obligation_graph", graph), ("completeness", report)]:
        write_json(directory / (name + ".json"), document)
        marker["document_digests"][name] = digest(document)
    write_json(directory / "metadata.json", marker)
    with pytest.raises(ValueError, match="current validators"):
        load_frozen_inputs(store, frozen[0]["ft_id"])


def test_old_complete_label_and_changed_context_cannot_authorize_plan(tmp_path):
    _, frozen, _ = ready(tmp_path)
    ft, context, closure, snapshot, report = frozen[:5]
    old = {k: v for k, v in report.items() if not k.startswith("semantic_obligation_")}
    with pytest.raises(PlanError, match="Semantic Obligation Graph"):
        HarnessPlanBuilder().build(ft, context, closure, snapshot, old)
    changed = deepcopy(context)
    changed["facts"][0]["evidence_ids"] = ["ev_other"]
    with pytest.raises(PlanError, match="different frozen inputs"):
        HarnessPlanBuilder().build(ft, changed, closure, snapshot, report)


def test_callback_userdata_depends_on_creator_ownership(tmp_path):
    from types import SimpleNamespace
    from harness_generation.harness_context import MiningState, ContextBudget
    store, _ = callback_plan(tmp_path)
    marker = next((store.root / "harness_contexts").glob("*/metadata.json"))
    metadata = json.loads(marker.read_text())
    directory = marker.parent
    ft, context, _, snapshot, _, _ = load_frozen_inputs(store, metadata["ft_id"])
    state = MiningState(ContextBudget(**metadata["configuration"]["budget"]))
    state.evidence = {r["evidence_id"]: r for r in json.loads((directory / "evidence.json").read_text())["records"]}
    state.discoveries = metadata["discoveries"]
    ids = {row["name"]: fid for fid, row in snapshot.functions.items()}
    prepared = ((store, None, ids), ft, None, snapshot, state)
    run = SimpleNamespace(requirements=json.loads((directory / "requirements.json").read_text()), context=context)
    report, _ = retract(prepared, run, ids["acquire"], "ownership")
    assert report["status"] == "incomplete"
    callback = requirement_node(report["semantic_obligation_graph"], ids["parse"], "callback")
    ownership = requirement_node(report["semantic_obligation_graph"], ids["acquire"], "ownership")
    assert callback["local_proof"]["status"] == "proved" and callback["proof_status"] == "blocked"
    leaves = {n['obligation_id'] for n in report['semantic_obligation_graph']['nodes'] if n['predicate']=='ownership_subject'
        and n['subject_function_id']==ids['acquire'] and n['proof_status']=='missing'}
    assert leaves and leaves <= set(callback["blocking_obligations"])
