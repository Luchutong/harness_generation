"""Feedback names exact corrections while retaining every unresolved proof."""
from copy import deepcopy

import pytest

from harness_generation.harness_context.closure_feedback import build_closure_feedback, attach_closure_feedback
from harness_generation.harness_context.obligations import close_obligations
from harness_generation.semantic_discovery.models import digest


def node(nid, rid, kind, parameter=None, *, fid="parse", diagnostics=(), deps=(), pid=None, status="missing"):
    return {"obligation_id": nid, "requirement_id": rid, "subject_function_id": fid,
        "kind": kind, "predicate": "parameter_recipe" if kind == "argument_construction" else kind,
        "subject_parameter": parameter, "subject_field": None, "resource_id": None,
        "local_proof": {"status": status, "sources": [{"kind": "canonical_construction", "parameter_id": pid}] if pid else []},
        "diagnostics": list(diagnostics), "dependencies": [{"obligation_id": d, "relation": "recipe_argument"} for d in deps],
        "evidence_ids": [], "fact_ids": []}


def fact(rid, kind, row, *, fid="parse", extra_rows=()):
    collection = {"argument_construction": "arguments", "buffer_length": "links", "input_binding": "bindings"}[kind]
    result = {"requirement_id": rid, "function_id": fid, "predicate": kind,
        "value": {collection: [row, *extra_rows]}, "evidence_ids": ["ev_parse"]}
    result["fact_id"] = "fact_" + digest(result)[:12]
    return result


def extent_fixture():
    requirements = [{"requirement_id": rid, "subject_function_id": "parse", "kind": kind} for rid, kind in
        (("arg", "argument_construction"), ("input", "input_binding"), ("length", "buffer_length"))]
    facts = [fact("arg", "argument_construction", {"parameter": "cb", "construction": "derived", "api": None,
        "constant": None, "resource_id": None}, extra_rows=[{"parameter": "src", "construction": "input"}]),
        fact("input", "input_binding", {"parameter": "src", "size_parameter": None, "size_relation": "bytes",
            "source": "fuzz_data", "alignment": "none"}),
        fact("length", "buffer_length", {"buffer_parameter": "src", "length_parameter": None, "relation": "bytes"})]
    diagnostic = {"code": "canonical_construction_unresolved", "subject_parameter": "cb", "graph_holes": [
        {"code": "argument_origin_missing", "parameter_id": "pid_cb"}]}
    rows = [node("cb", "arg", "argument_construction", "cb", diagnostics=[diagnostic], pid="pid_cb"),
        node("parse_invoke", None, "invocation", deps=["cb"], status="proved")]
    graph = {"graph_digest": "current_graph", **close_obligations(rows, ["parse_invoke"])}
    signed = {"subject_function_id": "parse", "subject_evidence_ids": ["ev_parse"],
        "input_length_choices": [{"binding_id": "issued_pair", "function_id": "parse", "buffer_parameter": "src",
            "length_parameter": "cb", "units": "bytes", "source_relation": "indexed_or_guarded_buffer_read"}]}
    evidence = {"ev_parse": {"evidence_id": "ev_parse", "function_id": "parse", "tool": "get_function",
        "content": "{ return cb ? src[0] : 0; }", "defined": True, "truncated": False}}
    return graph, requirements, facts, signed, evidence


def test_missing_extent_names_related_slots_and_old_fields_without_selecting_values():
    graph, reqs, facts, signed, evidence = extent_fixture()
    before = deepcopy((graph, reqs, facts, signed, evidence))
    feedback = build_closure_feedback(graph, reqs, facts, signed=signed, evidence=evidence)
    item, = feedback["items"]
    assert item["category"] == "contract_correction"
    assert item["repair_requirement_ids"] == ["arg", "input", "length"]
    assert item["affected_roots"] == ["parse_invoke"]
    targets = {t["requirement_id"]: t for t in item["correction_targets"]}
    assert targets["input"]["field_paths"] == ["value.bindings[0].size_parameter"]
    assert targets["input"]["observed_values"] == {"size_parameter": None}
    assert targets["length"]["observed_values"] == {"length_parameter": None}
    assert item["issued_options"]["input_length_choices"] == signed["input_length_choices"]
    assert all("replacement" not in t and "new_value" not in t for t in targets.values())
    assert item["preserve_rows"][0]["value"] == {"parameter": "src", "construction": "input"}
    assert (graph, reqs, facts, signed, evidence) == before


def test_cascades_coalesce_at_missing_prerequisite_but_remain_unresolved():
    graph, reqs, facts, signed, evidence = extent_fixture()
    rows = deepcopy(graph["nodes"])
    for fid in ("observe", "dispose"):
        diagnostic = {"code": "canonical_construction_unresolved", "graph_holes": [
            {"code": "creator_argument_missing", "parameter_id": "pid_" + fid, "missing_dependencies": ["pid_cb"]}]}
        rows.append(node(fid + "_r", fid + "_arg", "argument_construction", "r", fid=fid,
            diagnostics=[diagnostic], deps=["cb"], pid="pid_" + fid))
        rows.append(node(fid + "_invoke", None, "invocation", fid=fid, deps=[fid + "_r"], status="proved"))
    graph.update(close_obligations(rows, ["parse_invoke", "observe_invoke", "dispose_invoke"]))
    item, = build_closure_feedback(graph, reqs, facts, signed=signed, evidence=evidence)["items"]
    assert item["frontier_obligation_ids"] == ["cb"]
    assert {g["obligation_id"] for g in item["dependent_gaps"]} == {"observe_r", "dispose_r"}
    assert item["affected_roots"] == ["dispose_invoke", "observe_invoke", "parse_invoke"]
    assert graph["open_roots"] == ["dispose_invoke", "observe_invoke", "parse_invoke"]


def test_graph_hole_dependency_connects_input_gap_without_an_obligation_edge():
    graph, reqs, facts, signed, evidence = extent_fixture()
    rows = deepcopy(graph["nodes"])
    rows.append(node("observe_input", "observe_input_req", "input_binding", fid="observe", diagnostics=[
        {"code": "core_fuzz_input_path_unresolved", "graph_holes": [
            {"code": "creator_argument_missing", "missing_dependencies": ["pid_cb"]}]}]))
    graph.update(close_obligations(rows, ["parse_invoke", "observe_input"]))
    item, = build_closure_feedback(graph, reqs, facts, signed=signed, evidence=evidence)["items"]
    assert item["dependent_gaps"][0]["obligation_id"] == "observe_input"
    assert "observe_input" in item["affected_roots"]


def test_independent_local_failure_is_never_hidden_by_a_missing_dependency():
    graph, reqs, facts, signed, evidence = extent_fixture()
    rows = deepcopy(graph["nodes"])
    rows.append(node("other", "other_req", "input_binding", "data", fid="other", deps=["cb"], diagnostics=[
        {"code": "input_constraints_unresolved", "detail": {"unknown_fields": ["alignment"]}}]))
    graph.update(close_obligations(rows, ["parse_invoke", "other"]))
    result = build_closure_feedback(graph, reqs, facts, signed=signed, evidence=evidence)
    assert {i["requirement_id"] for i in result["items"]} == {"arg", "other_req"}
    assert not next(i for i in result["items"] if i["requirement_id"] == "arg")["dependent_gaps"]


@pytest.mark.parametrize("diagnostic,complete,expected", [
    ({"code": "input_constraints_unresolved"}, False, "missing_evidence"),
    ({"code": "input_constraints_unresolved"}, True, "contract_correction"),
    ({"code": "upstream_excluded"}, True, "upstream_blocker"),
    ({"code": "source_form_unsupported"}, True, "unsupported"),
])
def test_categories_require_explicit_blocker_or_complete_issued_body(diagnostic, complete, expected):
    graph, reqs, facts, signed, evidence = extent_fixture()
    row = node("cb", "arg", "argument_construction", "cb", diagnostics=[diagnostic])
    graph.update(close_obligations([row], ["cb"]))
    evidence["ev_parse"]["truncated"] = not complete
    result = build_closure_feedback(graph, reqs, facts, evidence=evidence)
    assert result["items"][0]["category"] == expected


def test_unknown_fields_are_exact_and_other_fact_evidence_is_preserved():
    graph, reqs, facts, signed, evidence = extent_fixture()
    facts[1]["value"]["bindings"][0]["alignment"] = "unknown"
    row = node("input_gap", "input", "input_binding", "src", diagnostics=[
        {"code": "input_constraints_unresolved", "detail": {"unknown_fields": ["alignment"]}}])
    graph.update(close_obligations([row], ["input_gap"]))
    result = build_closure_feedback(graph, reqs, facts, evidence=evidence)
    item, = result["items"]
    target, = item["correction_targets"]
    assert target["field_paths"] == ["value.bindings[0].alignment"]
    assert target["observed_values"] == {"alignment": "unknown"}
    assert set(item["preserve_fact_ids"]) == {facts[0]["fact_id"], facts[2]["fact_id"]}


def test_collection_root_uses_diagnostic_subject_and_preserves_other_bindings():
    graph, reqs, facts, signed, evidence = extent_fixture()
    facts[1]["value"]["bindings"].append({"parameter": "other", "source": "derived", "alignment": "none"})
    rows = [node("input_gap", "input", "input_binding", diagnostics=[
        {"code": "input_constraints_unresolved", "subject_parameter": "src", "detail": {"unknown_fields": ["alignment"]}}])]
    graph.update(close_obligations(rows, ["input_gap"]))
    item, = build_closure_feedback(graph, reqs, facts, evidence=evidence)["items"]
    target, = item["correction_targets"]
    assert item["subject_parameter"] == "src" and target["subject_key"] == ["src"]
    assert item["preserve_rows"][0]["value"]["parameter"] == "other"


def test_explicit_scope_blocker_does_not_issue_or_activate_a_candidate():
    graph, reqs, facts, signed, evidence = extent_fixture()
    blocker = {"requirement_id": "arg", "subject_function_id": "parse", "diagnostic": {
        "all_cleanup_shaped_signatures_excluded": True, "excluded_structural_candidates": [{"function_id": "excluded_release"}]}}
    before = deepcopy((signed, evidence, blocker))
    item, = build_closure_feedback(graph, reqs, facts, signed=signed, evidence=evidence, scope_blockers=[blocker])["items"]
    assert item["category"] == "upstream_blocker" and item["upstream_scope_blockers"] == [blocker]
    assert not item["issued_options"]["support_candidates"]
    assert (signed, evidence, blocker) == before


def test_feedback_identity_changes_when_old_contract_changes_and_attachment_is_read_only():
    graph, reqs, facts, signed, evidence = extent_fixture()
    first = build_closure_feedback(graph, reqs, facts, signed=signed, evidence=evidence)
    assert first == build_closure_feedback(graph, reqs, facts, signed=signed, evidence=evidence)
    tasks = [{"task_id": "old_identity", "requirement_id": "input"}, {"requirement_id": "unrelated"}]
    before = deepcopy(tasks)
    attached = attach_closure_feedback(tasks, first)
    assert tasks == before and attached[0]["task_id"] == "old_identity"
    assert "closure_feedback" in attached[0] and "closure_feedback" not in attached[1]
    facts[1]["value"]["bindings"][0]["size_parameter"] = "cb"
    second = build_closure_feedback(graph, reqs, facts, signed=signed, evidence=evidence)
    assert second["frontier_digest"] != first["frontier_digest"]
    assert all(t["requirement_id"] != "input" for t in second["items"][0]["correction_targets"])


def test_closed_graph_has_no_feedback_or_invented_tasks():
    graph = {"graph_digest": "closed", **close_obligations([node("ready", None, "invocation", status="proved")], ["ready"])}
    result = build_closure_feedback(graph, [], [])
    assert result["items"] == [] and attach_closure_feedback([], result) == []
