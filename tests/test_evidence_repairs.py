"""Retirement uses real source/graph projections, never model proof flags."""
from copy import deepcopy
import json

import pytest

from harness_generation.harness_context.models import fact_id
from harness_generation.harness_context.persistence import context_directory
from harness_generation.harness_context.repair_proofs import RepairProofEvaluator
from harness_generation.harness_context.repairs import merge_resolution, fact_conflicts
from test_proof_reliability import coherent_context, rebuild


def shared_context(tmp_path):
    from test_context_semantics import shared_ready
    prepared, run, _ = shared_ready(tmp_path)
    directory = context_directory(prepared[0][0], prepared[1]["ft_id"])
    reqs = json.loads((directory / "requirements.json").read_text())["requirements"]
    resolutions = json.loads((directory / "resolutions.json").read_text())["resolutions"]
    return prepared[1], prepared[3], reqs, resolutions, prepared[4], run.completeness


def configure(prepared):
    ft, snapshot, reqs, resolutions, state, _ = prepared
    facts = [f for resolution in resolutions.values() for f in resolution["facts"]]
    return RepairProofEvaluator(ft, snapshot, state).configure(facts, reqs, resolutions)


def target(prepared, function, kind):
    return next(r for r in prepared[2] if r["kind"] == kind
        and prepared[1].functions[r["subject_function_id"]]["name"] == function)


def patch(resolution, field, parameter, **changes):
    value = deepcopy(resolution)
    value["facts"] = [f for f in value["facts"] if f["value"][field][0]["parameter"] == parameter]
    assert len(value["facts"]) == 1
    value["facts"][0]["value"][field][0].update(changes)
    value["facts"][0]["fact_id"] = fact_id(value["facts"][0])
    return value


def test_retained_feed_lifetime_is_retired_without_losing_ctx(tmp_path):
    prepared = shared_context(tmp_path)
    req = target(prepared, "feed", "ownership")
    original = deepcopy(prepared[3][req["requirement_id"]])
    bad = deepcopy(original)
    data = next(f for f in bad["facts"] if f["value"]["entries"][0]["parameter"] == "data")
    data["value"]["entries"][0]["lifetime"] = "during_call"
    data["fact_id"] = fact_id(data)
    prepared[3][req["requirement_id"]] = bad
    before = rebuild(prepared)
    assert not before["generation_allowed"]
    good = patch(original, "entries", "data")
    merged, audit = merge_resolution(bad, good, req, proof_evaluator=configure(prepared))
    assert len(audit["withdrawals"]) == 1 and not audit["conflicts"]
    event = audit["withdrawals"][0]
    assert event["reason"] == "source_disproved"
    assert event["previous_proof"]["status"] == "contradicted"
    assert event["replacement_proof"]["source_witness"]["kind"] == "source_retention_in_cleanup_bound_resource"
    ctx_before = next(f for f in bad["facts"] if f["value"]["entries"][0]["parameter"] == "ctx")
    assert ctx_before in merged["facts"]
    assert event["withdrawn_fact"] not in merged["facts"]
    prepared[3][req["requirement_id"]] = merged
    assert rebuild(prepared)["generation_allowed"]


def test_unverified_static_lifetime_cannot_replace_disproved_short_lifetime(tmp_path):
    prepared = shared_context(tmp_path)
    req = target(prepared, "feed", "ownership")
    original = prepared[3][req["requirement_id"]]
    bad = patch(original, "entries", "data", lifetime="during_call")
    proposed = patch(original, "entries", "data", lifetime="static")
    merged, audit = merge_resolution(bad, proposed, req, proof_evaluator=configure(prepared))
    assert not audit["withdrawals"] and fact_conflicts(merged["facts"])


def test_proved_pointer_ownership_is_not_overwritten(tmp_path):
    prepared = coherent_context(tmp_path)
    req = target(prepared, "parse", "ownership")
    original = deepcopy(prepared[3][req["requirement_id"]])
    evaluator = configure(prepared)
    # Use the actual current graph to establish historical protection.
    from harness_generation.harness_context.evidence import build_context
    context = build_context(prepared[0], prepared[2], evaluator.facts, prepared[1], prepared[4].evidence)
    evaluator.remember(context, prepared[5]["semantic_obligation_graph"])
    proposed = patch(original, "entries", "ctx", ownership="transferred")
    merged, audit = merge_resolution(original, proposed, req, proof_evaluator=evaluator)
    assert not audit["withdrawals"] and audit["conflicts"]
    prepared[3][req["requirement_id"]] = merged
    assert not rebuild(prepared)["generation_allowed"]


def test_equivalent_length_recipes_are_canonicalized_in_both_orders(tmp_path):
    from test_harness_context import setup, mine, direct_specs
    prepared = setup(tmp_path)
    run, _ = mine(prepared, direct_specs(prepared[0][-1]["parse"]), persist=True)
    directory = context_directory(prepared[0][0], prepared[1]["ft_id"])
    reqs = json.loads((directory / "requirements.json").read_text())["requirements"]
    resolutions = json.loads((directory / "resolutions.json").read_text())["resolutions"]
    fixture = prepared[1], prepared[3], reqs, resolutions, prepared[4], run.completeness
    req = target(fixture, "parse", "argument_construction")
    previous = resolutions[req["requirement_id"]]
    derived = patch(previous, "arguments", "size", construction="input")
    evaluator = configure(fixture)
    first, audit = merge_resolution(previous, derived, req, proof_evaluator=evaluator)
    second, reverse = merge_resolution(derived, previous, req, proof_evaluator=configure(fixture))
    assert first == second and not fact_conflicts(first["facts"])
    assert audit["withdrawals"] and reverse["withdrawals"]
    assert audit["withdrawals"][0]["reason"] == "equivalent_proven_recipe"
    resolutions[req["requirement_id"]] = first
    assert rebuild(fixture)["generation_allowed"]


def test_source_contradicted_scalar_recipe_can_be_replaced(tmp_path):
    from test_harness_context import setup, mine, direct_specs
    prepared = setup(tmp_path)
    run, _ = mine(prepared, direct_specs(prepared[0][-1]["parse"]), persist=True)
    directory = context_directory(prepared[0][0], prepared[1]["ft_id"])
    reqs = json.loads((directory / "requirements.json").read_text())["requirements"]
    resolutions = json.loads((directory / "resolutions.json").read_text())["resolutions"]
    fixture = prepared[1], prepared[3], reqs, resolutions, prepared[4], run.completeness
    req = target(fixture, "parse", "argument_construction")
    original = deepcopy(resolutions[req["requirement_id"]])
    bad = deepcopy(original)
    size = next(f for f in bad["facts"] if f["value"]["arguments"][0]["parameter"] == "size")
    size["value"]["arguments"][0].update(construction="constant", constant=0)
    size["fact_id"] = fact_id(size)
    resolutions[req["requirement_id"]] = bad
    good = patch(original, "arguments", "size")
    merged, audit = merge_resolution(bad, good, req, proof_evaluator=configure(fixture))
    assert audit["withdrawals"] and not audit["conflicts"]
    assert next(f for f in bad["facts"] if f["value"]["arguments"][0]["parameter"] == "data") in merged["facts"]
    resolutions[req["requirement_id"]] = merged
    assert rebuild(fixture)["generation_allowed"]


def test_missing_subject_body_does_not_authorize_retirement(tmp_path):
    prepared = shared_context(tmp_path)
    req = target(prepared, "feed", "ownership")
    original = prepared[3][req["requirement_id"]]
    bad = patch(original, "entries", "data", lifetime="during_call")
    good = patch(original, "entries", "data")
    prepared[4].evidence = {eid: record for eid, record in prepared[4].evidence.items()
        if record.get("function_id") != req["subject_function_id"]}
    merged, audit = merge_resolution(bad, good, req, proof_evaluator=configure(prepared))
    assert not audit["withdrawals"] and audit["conflicts"]


def test_proved_claim_is_preserved_when_source_becomes_unavailable(tmp_path):
    prepared = shared_context(tmp_path)
    req = target(prepared, "feed", "ownership")
    original = deepcopy(prepared[3][req["requirement_id"]])
    evaluator = configure(prepared)
    from harness_generation.harness_context.evidence import build_context
    context = build_context(prepared[0], prepared[2], evaluator.facts, prepared[1], prepared[4].evidence)
    evaluator.remember(context, prepared[5]["semantic_obligation_graph"])
    # Unavailable source does not authorize overwriting a closed proof.
    for record in prepared[4].evidence.values():
        if record.get("function_id") == req["subject_function_id"]:
            record["truncated"] = True
    bad = patch(original, "entries", "data", lifetime="during_call")
    merged, audit = merge_resolution(original, bad, req, proof_evaluator=evaluator)
    assert not audit["withdrawals"] and audit["conflicts"]


def test_wrong_initializer_is_retired_only_after_same_object_field_proof(tmp_path):
    from test_harness_context import setup, mine, context_specs, argument, owner, order
    from test_context_semantics import issued_flow
    source = '''#include <stdlib.h>
#include <stddef.h>
typedef struct Context {unsigned ready;unsigned other;} Context;
Context *create(void){return calloc(1,sizeof(Context));}
void destroy(Context *ctx){free(ctx);}
void prime(Context *ctx){ctx->ready=1;ctx->other=0;}
int parse(Context *ctx,const unsigned char *data,size_t size){if(ctx->ready!=1)__builtin_trap();return size?data[0]^ctx->other:ctx->other;}
void usage(const unsigned char *data,size_t size){Context *ctx=create();prime(ctx);parse(ctx,data,size);destroy(ctx);}
'''
    roles = {"parse": ("core", "accepted_anchor"), "create": ("support", "resource_creation"),
        "destroy": ("support", "resource_cleanup"), "prime": ("support", "required_initialization"),
        "usage": ("exclude", "diagnostic_only")}
    prepared = setup(tmp_path, source, roles=roles, discover_callers=True)
    ids = prepared[0][-1]
    fid, prime = ids["parse"], ids["prime"]
    specs = context_specs(ids)
    specs[fid, "state"]["value"]["preconditions"][0]["api"] = prime
    specs[fid, "lifecycle"]["value"]["resources"][0]["initialization"] = {"api": prime, "mandatory": True}
    specs[fid, "lifecycle"]["dependencies"].append({"function_id": prime, "necessity": "required", "reason": "initialization"})
    specs[fid, "call_order"]["value"]["constraints"].append(order(prime, fid))
    specs[prime, "argument_construction"] = {"value": {"arguments": [argument("ctx", "derived")]}}
    specs[prime, "ownership"] = {"value": {"entries": [owner("ctx")]}}
    specs[prime, "support_decision"] = {"value": {"decision": "required", "reason": "initialization", "required_by": [fid]},
        "dependencies": [{"function_id": prime, "necessity": "required", "reason": "initialization", "required_by": fid}]}
    issued_flow(prepared)
    run, _ = mine(prepared, specs, persist=True)
    assert run.completeness["generation_allowed"]
    directory = context_directory(prepared[0][0], prepared[1]["ft_id"])
    reqs = json.loads((directory / "requirements.json").read_text())["requirements"]
    resolutions = json.loads((directory / "resolutions.json").read_text())["resolutions"]
    fixture = prepared[1], prepared[3], reqs, resolutions, prepared[4], run.completeness
    req = target(fixture, "parse", "state")
    original = deepcopy(resolutions[req["requirement_id"]])
    bad = deepcopy(original)
    bad["facts"][0]["value"]["preconditions"][0]["api"] = ids["create"]
    bad["facts"][0]["fact_id"] = fact_id(bad["facts"][0])
    bad["discovered_api_dependencies"] = []
    resolutions[req["requirement_id"]] = bad
    assert not rebuild(fixture)["generation_allowed"]
    merged, audit = merge_resolution(bad, original, req, proof_evaluator=configure(fixture))
    assert audit["withdrawals"] and not audit["conflicts"]
    assert audit["withdrawals"][0]["reason"] == "source_disproved"
    resolutions[req["requirement_id"]] = merged
    assert rebuild(fixture)["generation_allowed"]


def test_mining_loop_corrects_feed_then_freezes_with_auditable_history(tmp_path):
    from harness_generation.entry_candidates import CandidateCatalog
    from harness_generation.harness_context import MiningState, HarnessContextMiningLoop
    from harness_generation.harness_context.tools import HarnessContextTools
    from harness_generation.harness_context.persistence import run_configuration
    from harness_generation.context_generation import HarnessPlanBuilder
    from test_context_semantics import shared_ready
    from test_harness_context import ScriptedModel
    prepared, _, reference_model = shared_ready(tmp_path)
    sample, ft, metadata, snapshot, previous_state, previous_tools = prepared
    state = MiningState(previous_state.budget)
    tools = HarnessContextTools(snapshot, CandidateCatalog((), snapshot.source_fingerprint), ft, state,
        index=previous_tools.index)
    feed = prepared[0][-1]["feed"]
    submissions = []
    def mutate(requirement, result):
        if requirement["subject_function_id"] == feed and requirement["kind"] == "ownership":
            submissions.append(deepcopy(result))
            if len(submissions) == 1:
                entry = next(r for r in result["facts"][0]["value"]["entries"] if r["parameter"] == "data")
                entry["lifetime"] = "during_call"
            else:
                result["facts"][0]["value"]["entries"] = [r for r in result["facts"][0]["value"]["entries"]
                    if r["parameter"] == "data"]
    model = ScriptedModel(reference_model.specs, initial_ids=tools.initial_ids, mutate=mutate)
    configuration = run_configuration(ft, metadata, snapshot, state.budget, model)
    run = HarnessContextMiningLoop(model, state).run(ft, snapshot, tools, store=sample[0], configuration=configuration)
    assert run.completeness["generation_allowed"] and run.context["frozen"] and len(submissions) == 2
    assert run.metadata["metrics"]["retired_semantic_proposals"] == 1
    event = run.metadata["subject_repair_history"][0]
    assert event["withdrawn_fact"]["value"]["entries"][0]["lifetime"] == "during_call"
    assert event["replacement_proof"]["status"] == "proved"
    assert state.model_calls <= state.budget.max_total_model_calls and state.tool_calls <= state.budget.max_tool_calls
    directory = context_directory(sample[0], ft["ft_id"])
    saved = json.loads((directory / "subject_repair_history.json").read_text())
    assert saved["withdrawals"] == run.metadata["subject_repair_history"]
    metadata = json.loads((directory / "metadata.json").read_text())
    assert "subject_repair_history" in metadata["document_digests"]
    plan = HarnessPlanBuilder().build(ft, run.context, run.closure, snapshot, run.completeness)
    assert plan["call_sequence"]


def test_invalid_semantic_conflict_gets_a_bounded_followup(tmp_path):
    from test_harness_context import setup, mine, direct_specs, argument
    prepared = setup(tmp_path)
    fid = prepared[0][-1]["parse"]
    specs = direct_specs(fid)
    attempts = []
    def mutate(requirement, result):
        if requirement["kind"] == "argument_construction":
            attempts.append(1)
            if len(attempts) == 1:
                # Neither old proposal agrees with the issued size relationship.
                result["facts"][0]["value"]["arguments"] = [argument("data", "input"),
                    {**argument("size", "constant"), "constant": 0},
                    {**argument("size", "constant"), "constant": 1}]
            else:
                result["facts"][0]["value"]["arguments"] = [argument("size", "derived")]
    run, _ = mine(prepared, specs, mutate=mutate)
    assert run.completeness["generation_allowed"] and len(attempts) == 2
    assert run.metadata["recoverable_invalid_rounds"]
    assert all(not r["generation_allowed"] for r in run.metadata["recoverable_invalid_rounds"])
    assert run.metadata["metrics"]["retired_semantic_proposals"] == 2


@pytest.mark.parametrize("extra", [
    "saved=data;", "if(size) saved=data;", "unknown(data);",
])
def test_nonlocal_or_unknown_retention_never_acquires_cleanup_bound_proof(tmp_path, extra):
    from test_context_semantics import SHARED, shared_ready
    source = SHARED.replace("void feed(", "static const unsigned char *saved;\nvoid feed(")
    source = source.replace("ctx->data=data; ctx->size=size;", "ctx->data=data; ctx->size=size;" + extra)
    prepared, run, _ = shared_ready(tmp_path, source=source)
    directory = context_directory(prepared[0][0], prepared[1]["ft_id"])
    reqs = json.loads((directory / "requirements.json").read_text())["requirements"]
    resolutions = json.loads((directory / "resolutions.json").read_text())["resolutions"]
    fixture = prepared[1], prepared[3], reqs, resolutions, prepared[4], run.completeness
    req = target(fixture, "feed", "ownership")
    original = resolutions[req["requirement_id"]]
    merged, audit = merge_resolution(patch(original, "entries", "data", lifetime="during_call"),
        patch(original, "entries", "data"), req, proof_evaluator=configure(fixture))
    assert audit["conflicts"] and not audit["withdrawals"]
