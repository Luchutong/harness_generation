"""Input-origin repair must cover both separately typed contract slots."""
from copy import deepcopy

import pytest

from harness_generation.harness_context.closure_feedback import (
    attach_closure_feedback, build_closure_feedback)
from harness_generation.harness_context.obligations import close_obligations
from test_closure_feedback import extent_fixture, fact, node


def disputed_origin(*, construction="derived", source="derived", via=None):
    graph, rows, _, signed, evidence = extent_fixture()
    facts = [fact("arg", "argument_construction", {"parameter": "src", "construction": construction,
        "api": None, "resource_id": None, "constant": None}, extra_rows=[
            {"parameter": "independent", "construction": "constant", "constant": 7}]),
        fact("input", "input_binding", {"parameter": "src", "source": source, "via_function_id": via,
            "transform": "none", "size_parameter": "cb", "size_relation": "bytes", "alignment": "none"}),
        fact("length", "buffer_length", {"buffer_parameter": "src", "length_parameter": "cb", "relation": "bytes"})]
    gap = node("src_recipe", "arg", "argument_construction", "src", diagnostics=[
        {"code": "canonical_construction_unresolved", "subject_parameter": "src", "graph_holes": [
            {"code": "construction_source_missing", "parameter_id": "pid_src"}]}], pid="pid_src")
    local_input = node("input_local", "input", "input_binding", "src", status="proved")
    graph.update(close_obligations([gap, local_input], ["src_recipe", "input_local"]))
    return graph, rows, facts, signed, evidence


@pytest.mark.parametrize("construction,source", [("derived", "derived"), ("input", "derived"),
    ("input", "context"), ("derived", "fuzz_data")])
def test_existing_origin_and_construction_are_reopened_together_without_selecting_a_value(construction, source):
    graph, rows, facts, signed, evidence = disputed_origin(construction=construction, source=source)
    before = deepcopy((graph, rows, facts, signed, evidence))
    item, = build_closure_feedback(graph, rows, facts, signed=signed, evidence=evidence)["items"]
    assert item["repair_requirement_ids"] == ["arg", "input"]
    target = next(t for t in item["correction_targets"] if t["kind"] == "input_binding")
    assert target["observed_values"] == {"source": source, "via_function_id": None, "transform": "none"}
    assert target["field_paths"] == ["value.bindings[0].source", "value.bindings[0].via_function_id",
        "value.bindings[0].transform"]
    assert "does not replace input_binding.source" in target["goal"]
    assert all("new_value" not in t and "replacement" not in t for t in item["correction_targets"])
    assert item["preserve_rows"][0]["value"]["parameter"] == "independent"
    assert facts[2]["fact_id"] in item["preserve_fact_ids"]
    assert (graph, rows, facts, signed, evidence) == before
    attached = attach_closure_feedback([{"requirement_id": "input"}], {"items": [item],
        "frontier_digest": "test", "version": "context-closure-feedback-v2"})
    assert attached[0]["closure_feedback"]["items"][0]["correction_targets"] == item["correction_targets"]


def test_extent_frontier_can_reopen_origin_slot_even_when_extent_fields_are_already_complete():
    graph, rows, facts, signed, evidence = disputed_origin()
    gap = node("extent", "arg", "argument_construction", "cb", diagnostics=[
        {"code": "canonical_construction_unresolved", "subject_parameter": "cb"}])
    graph.update(close_obligations([gap], ["extent"]))
    item, = build_closure_feedback(graph, rows, facts, signed=signed, evidence=evidence)["items"]
    assert item["repair_requirement_ids"] == ["arg", "input"]
    assert any(t["subject_parameter"] == "src" and "value.bindings[0].source" in t["field_paths"]
        for t in item["correction_targets"])
    assert all(t["kind"] != "buffer_length" for t in item["correction_targets"])


def test_competing_constructions_keep_each_old_claim_visible_without_choosing_the_last_one():
    graph, rows, facts, signed, evidence = disputed_origin(construction="input", source="fuzz_data")
    facts.append(fact("arg", "argument_construction", {"parameter": "src", "construction": "derived",
        "api": None, "resource_id": None, "constant": None}))
    item, = build_closure_feedback(graph, rows, facts, signed=signed, evidence=evidence)["items"]
    origin_targets = [t for t in item["correction_targets"] if t["kind"] == "input_binding"]
    assert len(origin_targets) == 1 and origin_targets[0]["observed_values"]["source"] == "fuzz_data"
    assert {t["fact_id"] for t in item["correction_targets"] if t["kind"] == "argument_construction"} >= {
        facts[0]["fact_id"], facts[-1]["fact_id"]}


def test_consistent_input_and_unrelated_alignment_gap_do_not_reopen_construction():
    graph, rows, facts, signed, evidence = disputed_origin(construction="input", source="fuzz_data")
    gap = node("alignment", "input", "input_binding", "src", diagnostics=[
        {"code": "input_constraints_unresolved", "detail": {"unknown_fields": ["alignment"]}}])
    graph.update(close_obligations([gap], ["alignment"]))
    item, = build_closure_feedback(graph, rows, facts, signed=signed, evidence=evidence)["items"]
    assert item["repair_requirement_ids"] == ["input"]
    target, = item["correction_targets"]
    assert target["field_paths"] == ["value.bindings[0].alignment"]


def test_output_storage_without_input_claim_never_acquires_a_fuzz_origin_target():
    graph, rows, facts, signed, evidence = disputed_origin()
    facts = [fact("arg", "argument_construction", {"parameter": "src", "construction": "stack",
        "api": None, "resource_id": None, "constant": None})]
    item, = build_closure_feedback(graph, rows, facts, signed=signed, evidence=evidence)["items"]
    assert item["repair_requirement_ids"] == ["arg"]
    assert all(t["kind"] == "argument_construction" for t in item["correction_targets"])


def test_same_parameter_in_another_function_is_never_a_related_repair():
    graph, rows, facts, signed, evidence = disputed_origin()
    other = fact("other", "input_binding", {"parameter": "src", "source": "derived", "via_function_id": None},
        fid="other_function")
    facts.append(other)
    rows.append({"requirement_id": "other", "subject_function_id": "other_function", "kind": "input_binding"})
    item, = build_closure_feedback(graph, rows, facts, signed=signed, evidence=evidence)["items"]
    assert "other" not in item["repair_requirement_ids"]
    assert other["fact_id"] in item["preserve_fact_ids"]
