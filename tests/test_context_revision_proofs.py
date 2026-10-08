"""Omitted extent slots need explicit proposals and recomputed local proofs."""
from copy import deepcopy
import json

import pytest

from harness_generation.harness_context.models import fact_id
from harness_generation.harness_context.persistence import context_directory
from harness_generation.harness_context.repairs import merge_resolution, fact_conflicts
from test_evidence_repairs import configure, target
from test_harness_context import setup, mine, direct_specs, argument
from test_proof_reliability import rebuild


def extent_fixture(tmp_path, *, source=None, extra_constant=None, discover_callers=False, extra_buffer=None):
    prepared = setup(tmp_path, discover_callers=discover_callers,
        **({"source": source} if source is not None else {}))
    fid = prepared[0][-1]["parse"]
    specs = direct_specs(fid)
    if extra_constant:
        specs[fid, "argument_construction"]["value"]["arguments"].append(
            {**argument(extra_constant, "constant"), "constant": 0})
    if extra_buffer:
        additional = direct_specs(fid, data=extra_buffer[0], size=extra_buffer[1])
        for kind, field in (("input_binding", "bindings"), ("buffer_length", "links"),
                ("argument_construction", "arguments"), ("ownership", "entries")):
            specs[fid, kind]["value"][field] += additional[fid, kind]["value"][field]
    run, _ = mine(prepared, specs, persist=True)
    assert run.completeness["generation_allowed"]
    directory = context_directory(prepared[0][0], prepared[1]["ft_id"])
    requirements = json.loads((directory / "requirements.json").read_text())["requirements"]
    resolutions = json.loads((directory / "resolutions.json").read_text())["resolutions"]
    return prepared[1], prepared[3], requirements, resolutions, prepared[4], run.completeness


def extent_patch(resolution, kind, value):
    field, slot = ("bindings", "size_parameter") if kind == "input_binding" else ("links", "length_parameter")
    result = deepcopy(resolution)
    result["facts"] = [f for f in result["facts"] if f["value"][field][0].get("parameter", f["value"][field][0].get("buffer_parameter")) == "data"]
    assert len(result["facts"]) == 1
    result["facts"][0]["value"][field][0][slot] = value
    result["facts"][0]["fact_id"] = fact_id(result["facts"][0])
    return result


def submit_missing_and_corrected(fixture, *, reverse=False):
    original = {}
    for kind in ("input_binding", "buffer_length"):
        requirement = target(fixture, "parse", kind)
        good = deepcopy(fixture[3][requirement["requirement_id"]])
        original[kind] = good
        missing = extent_patch(good, kind, None)
        previous, incoming = (good, missing) if reverse else (missing, good)
        fixture[3][requirement["requirement_id"]], _ = merge_resolution(previous, incoming, requirement)
    return original


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("reconcile_first", ["input_binding", "buffer_length"])
def test_explicit_extent_completions_close_in_either_order(tmp_path, reverse, reconcile_first):
    fixture = extent_fixture(tmp_path)
    submit_missing_and_corrected(fixture, reverse=reverse)
    assert not rebuild(fixture)["generation_allowed"]
    history = []
    for kind in (reconcile_first, "buffer_length" if reconcile_first == "input_binding" else "input_binding"):
        requirement = target(fixture, "parse", kind)
        resolution = fixture[3][requirement["requirement_id"]]
        merged, audit = merge_resolution(None, resolution, requirement, proof_evaluator=configure(fixture))
        assert len(audit["withdrawals"]) == 1 and not fact_conflicts(merged["facts"])
        fixture[3][requirement["requirement_id"]] = merged
        history += audit["withdrawals"]
    assert rebuild(fixture)["generation_allowed"]
    assert len(history) == 2
    for event in history:
        assert event["reason"] == "omitted_extent_slot_completed"
        assert event["previous_proof"]["status"] == "missing"
        assert event["replacement_proof"]["status"] == "proved"
        assert event["replacement_proof"]["source_choice_is_unit_proof"] is False
        assert len(event["replacement_proof"]["obligation_ids"]) == 2
        assert event["replacement_proof"]["evidence_ids"]
        assert event["source_fingerprint"] == fixture[1].source_fingerprint


def test_completion_preserves_independent_scalar_binding(tmp_path):
    fixture = extent_fixture(tmp_path)
    requirement = target(fixture, "parse", "input_binding")
    resolution = fixture[3][requirement["requirement_id"]]
    independent = deepcopy(resolution["facts"][0])
    independent["value"]["bindings"][0].update(parameter="size", source="derived", transform="none",
        size_parameter=None, size_relation="none", binary_zero_allowed=None)
    independent["fact_id"] = fact_id(independent)
    resolution["facts"].append(independent)
    submit_missing_and_corrected(fixture)
    merged, audit = merge_resolution(None, fixture[3][requirement["requirement_id"]], requirement,
        proof_evaluator=configure(fixture))
    assert len(audit["withdrawals"]) == 1
    assert independent in merged["facts"]
    assert len(merged["facts"]) == 2


@pytest.mark.parametrize("additional_issued_reference", [False, True])
@pytest.mark.parametrize("reconcile_first", ["input_binding", "buffer_length"])
def test_counterfactual_fact_sorting_with_original_issued_evidence(tmp_path, additional_issued_reference, reconcile_first):
    fixture = extent_fixture(tmp_path)
    requirement = target(fixture, "parse", "input_binding")
    resolution = fixture[3][requirement["requirement_id"]]
    independent = deepcopy(resolution["facts"][0])
    independent["value"]["bindings"][0].update(parameter="size", source="derived", transform="none",
        size_parameter=None, size_relation="none", binary_zero_allowed=None)
    independent["fact_id"] = fact_id(independent)
    resolution["facts"].append(independent)
    originals = submit_missing_and_corrected(fixture)
    if additional_issued_reference:
        # Reuse a caller source record that was issued in the original mining
        # run. No tool/model call or new evidence is purchased by this repair.
        eid = next(eid for eid, record in fixture[4].evidence.items() if record["tool"] == "find_resource_flows")
        chosen = next(f for f in fixture[3][requirement["requirement_id"]]["facts"]
            if f["value"]["bindings"][0]["size_parameter"] == "size")
        chosen["evidence_ids"] = sorted({*chosen["evidence_ids"], eid})
        chosen["fact_id"] = fact_id(chosen)
    else:
        chosen = originals["input_binding"]["facts"][0]
        if chosen["value"]["bindings"][0]["parameter"] != "data":
            chosen = next(f for f in originals["input_binding"]["facts"]
                if f["value"]["bindings"][0]["parameter"] == "data")
    assert (chosen["fact_id"] < independent["fact_id"]) is additional_issued_reference
    issued_before = deepcopy(fixture[4].evidence)
    budget_before = (fixture[4].model_calls, fixture[4].tool_calls, fixture[4].source_chars)
    for kind in (reconcile_first, "buffer_length" if reconcile_first == "input_binding" else "input_binding"):
        req = target(fixture, "parse", kind)
        merged, audit = merge_resolution(None, fixture[3][req["requirement_id"]], req,
            proof_evaluator=configure(fixture))
        assert len(audit["withdrawals"]) == 1
        assert merged["facts"] == sorted(merged["facts"], key=lambda f: f["fact_id"])
        fixture[3][req["requirement_id"]] = merged
    assert independent in fixture[3][requirement["requirement_id"]]["facts"]
    assert fixture[4].evidence == issued_before
    assert (fixture[4].model_calls, fixture[4].tool_calls, fixture[4].source_chars) == budget_before
    assert rebuild(fixture)["generation_allowed"]


def test_completion_preserves_another_proved_buffer(tmp_path):
    source = """typedef unsigned long size_t;
int parse(const unsigned char *data,size_t size,const unsigned char *other,size_t count){
    return (size?data[0]:0)+(count?other[0]:0);
}
"""
    fixture = extent_fixture(tmp_path, source=source, extra_buffer=("other", "count"))
    originals = submit_missing_and_corrected(fixture)
    for kind, field in (("input_binding", "bindings"), ("buffer_length", "links")):
        requirement = target(fixture, "parse", kind)
        independent = next(f for f in originals[kind]["facts"]
            if f["value"][field][0].get("parameter", f["value"][field][0].get("buffer_parameter")) == "other")
        merged, audit = merge_resolution(None, fixture[3][requirement["requirement_id"]], requirement,
            proof_evaluator=configure(fixture))
        assert len(audit["withdrawals"]) == 1 and independent in merged["facts"]
        fixture[3][requirement["requirement_id"]] = merged
    assert rebuild(fixture)["generation_allowed"]


@pytest.mark.parametrize("kind", ["input_binding", "buffer_length"])
def test_an_unsubmitted_counterpart_does_not_authorize_completion(tmp_path, kind):
    fixture = extent_fixture(tmp_path)
    good = submit_missing_and_corrected(fixture)
    opposite = "buffer_length" if kind == "input_binding" else "input_binding"
    other = target(fixture, "parse", opposite)
    fixture[3][other["requirement_id"]] = extent_patch(good[opposite], opposite, None)
    requirement = target(fixture, "parse", kind)
    original = fixture[3][requirement["requirement_id"]]
    merged, audit = merge_resolution(None, original, requirement, proof_evaluator=configure(fixture))
    assert not audit["withdrawals"]
    assert merged["facts"] == original["facts"]


@pytest.mark.parametrize("mutation", ["missing_source", "different_units", "counterpart_units",
    "different_other_field", "invalid_recipe"])
def test_completion_rejects_incomplete_or_changed_proof_scope(tmp_path, mutation):
    fixture = extent_fixture(tmp_path)
    submit_missing_and_corrected(fixture)
    requirement = target(fixture, "parse", "input_binding")
    original = fixture[3][requirement["requirement_id"]]
    if mutation == "missing_source":
        fixture[4].evidence = {eid: record for eid, record in fixture[4].evidence.items()
            if record.get("function_id") != requirement["subject_function_id"]}
    elif mutation in {"different_units", "different_other_field"}:
        proposed = next(f for f in original["facts"] if f["value"]["bindings"][0]["size_parameter"] is not None)
        proposed["value"]["bindings"][0]["size_relation" if mutation == "different_units" else "mutable"] = (
            "elements" if mutation == "different_units" else True)
        proposed["fact_id"] = fact_id(proposed)
    elif mutation == "counterpart_units":
        other = target(fixture, "parse", "buffer_length")
        for fact in fixture[3][other["requirement_id"]]["facts"]:
            fact["value"]["links"][0]["relation"] = "elements"
            fact["fact_id"] = fact_id(fact)
    else:
        arguments = target(fixture, "parse", "argument_construction")
        size = next(f for f in fixture[3][arguments["requirement_id"]]["facts"]
            if f["value"]["arguments"][0]["parameter"] == "size")
        size["value"]["arguments"][0].update(construction="constant", constant=0)
        size["fact_id"] = fact_id(size)
    merged, audit = merge_resolution(None, original, requirement, proof_evaluator=configure(fixture))
    assert not audit["withdrawals"]
    assert merged["facts"] == sorted(original["facts"], key=lambda f: f["fact_id"])
    assert not rebuild(fixture)["generation_allowed"]


@pytest.mark.parametrize("kind", ["input_binding", "buffer_length"])
def test_concrete_extent_alternatives_are_retained(tmp_path, kind):
    source = """typedef unsigned long size_t;
int parse(const unsigned char *data,size_t size,size_t flag){return size?data[0]+flag:0;}
void usage(const unsigned char *data,size_t size){parse(data,size,0);}
"""
    fixture = extent_fixture(tmp_path, source=source, extra_constant="flag", discover_callers=True)
    requirement = target(fixture, "parse", kind)
    original = fixture[3][requirement["requirement_id"]]
    old = extent_patch(original, kind, "flag")
    fixture[3][requirement["requirement_id"]], _ = merge_resolution(old, original, requirement)
    merged, audit = merge_resolution(None, fixture[3][requirement["requirement_id"]], requirement,
        proof_evaluator=configure(fixture))
    assert not audit["withdrawals"] and len(merged["facts"]) == 2
    field, slot = ("bindings", "size_parameter") if kind == "input_binding" else ("links", "length_parameter")
    assert {f["value"][field][0][slot] for f in merged["facts"]} == {"flag", "size"}
    assert not rebuild(fixture)["generation_allowed"]


def test_a_null_slot_and_two_concrete_choices_stay_unresolved(tmp_path):
    source = """typedef unsigned long size_t;
int parse(const unsigned char *data,size_t size,size_t flag){return size?data[0]+flag:0;}
void usage(const unsigned char *data,size_t size){parse(data,size,0);}
"""
    fixture = extent_fixture(tmp_path, source=source, extra_constant="flag", discover_callers=True)
    originals = submit_missing_and_corrected(fixture)
    requirement = target(fixture, "parse", "input_binding")
    previous = fixture[3][requirement["requirement_id"]]
    third = extent_patch(originals["input_binding"], "input_binding", "flag")
    merged, audit = merge_resolution(previous, third, requirement, proof_evaluator=configure(fixture))
    assert not audit["withdrawals"] and len(merged["facts"]) == 3
    assert audit["conflicts"]


def test_unique_source_hint_does_not_fill_an_omitted_slot(tmp_path):
    fixture = extent_fixture(tmp_path)
    for kind in ("input_binding", "buffer_length"):
        requirement = target(fixture, "parse", kind)
        missing = extent_patch(fixture[3][requirement["requirement_id"]], kind, None)
        fixture[3][requirement["requirement_id"]] = missing
    for kind in ("input_binding", "buffer_length"):
        requirement = target(fixture, "parse", kind)
        original = fixture[3][requirement["requirement_id"]]
        merged, audit = merge_resolution(None, original, requirement, proof_evaluator=configure(fixture))
        assert not audit["withdrawals"] and merged["facts"] == original["facts"]
    assert not rebuild(fixture)["generation_allowed"]
