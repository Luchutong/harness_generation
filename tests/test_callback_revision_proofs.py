"""Explicit callback hole completion needs an exact unconditional source call."""
from copy import deepcopy
import json

import pytest

from harness_generation.harness_context.models import fact_id
from harness_generation.harness_context.persistence import context_directory
from harness_generation.harness_context.repairs import merge_resolution, fact_conflicts
from test_callback_boundaries import callback_plan
from test_evidence_repairs import configure, target
from test_harness_context import mine
from test_proof_reliability import rebuild


def callback_fixture(tmp_path, *, monkeypatch=None, body=None):
    if body is not None:
        import test_callback_boundaries
        monkeypatch.setattr(test_callback_boundaries, "SOURCE", test_callback_boundaries.SOURCE.replace(
            "return handler(user,src,cb);", body))
    prepared, specs = callback_plan(tmp_path, prepared_only=True)
    run, _ = mine(prepared, specs, query_type="User", persist=True)
    if body is None:
        assert run.completeness["generation_allowed"]
    root = context_directory(prepared[0][0], prepared[1]["ft_id"])
    rows = json.loads((root / "requirements.json").read_text())["requirements"]
    resolutions = json.loads((root / "resolutions.json").read_text())["resolutions"]
    return prepared[1], prepared[3], rows, resolutions, prepared[4], run.completeness


def callback_patch(result, **changes):
    patched = deepcopy(result)
    assert len(patched["facts"]) == 1
    patched["facts"][0]["value"]["callbacks"][0].update(changes)
    patched["facts"][0]["fact_id"] = fact_id(patched["facts"][0])
    return patched


def stage_completion(fixture, *, reverse=False, omit_setup=True):
    req = target(fixture, "parse", "callback")
    good = deepcopy(fixture[3][req["requirement_id"]])
    old = callback_patch(good, null_allowed=None,
        **({"setup_api": None} if omit_setup else {}))
    previous, incoming = (good, old) if reverse else (old, good)
    staged, _ = merge_resolution(previous, incoming, req)
    assert fact_conflicts(staged["facts"])
    fixture[3][req["requirement_id"]] = staged
    return req, good, old


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("omit_setup", [False, True])
def test_explicit_callback_completion_retires_only_missing_slots_and_closes(tmp_path, reverse, omit_setup):
    fixture = callback_fixture(tmp_path)
    req, good, old = stage_completion(fixture, reverse=reverse, omit_setup=omit_setup)
    assert not rebuild(fixture)["generation_allowed"]
    issued_before, ft_before = deepcopy(fixture[4].evidence), deepcopy(fixture[0])
    independent = {rid: deepcopy(result) for rid, result in fixture[3].items() if rid != req["requirement_id"]}
    ledger = fixture[4].model_calls, fixture[4].tool_calls, fixture[4].source_chars
    merged, audit = merge_resolution(None, fixture[3][req["requirement_id"]], req,
        proof_evaluator=configure(fixture))
    assert merged == good and len(audit["withdrawals"]) == 1 and not fact_conflicts(merged["facts"])
    event = audit["withdrawals"][0]
    assert event["withdrawn_fact"] == old["facts"][0]
    assert event["reason"] == "omitted_callback_contract_completed"
    assert event["previous_proof"]["status"] == "missing"
    assert event["previous_proof"]["proof_scope"] == (["null_allowed", "setup_api"] if omit_setup else ["null_allowed"])
    witness = event["replacement_proof"]
    assert witness["status"] == "proved"
    assert witness["kind"] == "source_checked_direct_callback_completion"
    assert witness["null_behavior"] == "unconditional_unmodified_declared_handler_call"
    assert witness["declaration_identity"]["parameter"] == "handler"
    assert witness["declaration_identity"]["field"] is None
    assert witness["canonical_producer_api"] == witness["dispatch"]["function_id"]
    assert witness["dispatch"]["callback_parameter"] == "handler"
    assert witness["dispatch"]["calls_per_invocation"] == 1
    assert witness["obligation_ids"] and witness["evidence_ids"]
    fixture[3][req["requirement_id"]] = merged
    assert rebuild(fixture)["generation_allowed"]
    assert fixture[0] == ft_before and fixture[4].evidence == issued_before
    assert (fixture[4].model_calls, fixture[4].tool_calls, fixture[4].source_chars) == ledger
    assert all(fixture[3][rid] == result for rid, result in independent.items())
    assert merged["facts"] == sorted(merged["facts"], key=lambda f: f["fact_id"])


def test_missing_callback_without_explicit_concrete_submission_stays_missing(tmp_path):
    fixture = callback_fixture(tmp_path)
    req = target(fixture, "parse", "callback")
    old = callback_patch(fixture[3][req["requirement_id"]], setup_api=None, null_allowed=None)
    fixture[3][req["requirement_id"]] = old
    merged, audit = merge_resolution(None, old, req, proof_evaluator=configure(fixture))
    assert merged == old and not audit["withdrawals"]
    assert not rebuild(fixture)["generation_allowed"]


def test_specific_null_behavior_with_no_setup_is_not_retired_as_an_omission(tmp_path):
    fixture = callback_fixture(tmp_path)
    req = target(fixture, "parse", "callback")
    good = deepcopy(fixture[3][req["requirement_id"]])
    no_setup = callback_patch(good, setup_api=None)
    # Exercise the completion evaluator directly: ordinary compatible null-API
    # merge is existing behavior, not a source-authorized withdrawal rule.
    original = deepcopy(good)
    original["facts"] += deepcopy(no_setup["facts"])
    original["facts"].sort(key=lambda f: f["fact_id"])
    fixture[3][req["requirement_id"]] = original
    retained, withdrawals = configure(fixture).reconcile(original, req)
    assert retained == original and not withdrawals


@pytest.mark.parametrize("mutation", ["missing_consumer_body", "missing_producer_body", "wrong_abi",
    "wrong_userdata", "changed_lifetime", "optional_callback", "null_true", "wrong_canonical_producer"])
def test_unproved_or_changed_callback_completion_cannot_retire(tmp_path, mutation):
    fixture = callback_fixture(tmp_path)
    req, good, old = stage_completion(fixture)
    fid = req["subject_function_id"]
    producer = good["facts"][0]["value"]["callbacks"][0]["setup_api"]
    if mutation.startswith("missing_"):
        unavailable = fid if mutation == "missing_consumer_body" else producer
        body = fixture[1].functions[unavailable]["body"]
        fixture[4].evidence = {eid: record for eid, record in fixture[4].evidence.items()
            if body not in record.get("content", "")}
    elif mutation == "wrong_canonical_producer":
        construction = target(fixture, "parse", "argument_construction")
        current = fixture[3][construction["requirement_id"]]
        for fact in current["facts"]:
            for argument in fact["value"]["arguments"]:
                if argument["parameter"] == "handler":
                    argument["api"] = next(f for f in fixture[1].functions if fixture[1].functions[f]["name"] == "acquire")
                    fact["fact_id"] = fact_id(fact)
    else:
        fields = {"wrong_abi": {"signature": "long (*)(void *user,const unsigned char *src,size_t cb)"},
            "wrong_userdata": {"userdata": "src"}, "changed_lifetime": {"lifetime": "per_context"},
            "optional_callback": {"mandatory": False}, "null_true": {"null_allowed": True}}
        incoming = callback_patch(good, **fields[mutation])
        fixture[3][req["requirement_id"]], _ = merge_resolution(old, incoming, req)
    original = deepcopy(fixture[3][req["requirement_id"]])
    merged, audit = merge_resolution(None, original, req, proof_evaluator=configure(fixture))
    assert merged == original and not audit["withdrawals"]
    assert not rebuild(fixture)["generation_allowed"]


@pytest.mark.parametrize("body", [
    "return handler ? handler(user,src,cb) : 0;",
    "if(!handler) return 0; return handler(user,src,cb);",
    "handler=NULL; return handler(user,src,cb);",
    "handler(user,src,cb); return handler(user,src,cb);",
    "return 0; handler(user,src,cb);",
    "int extra=0; return handler(user,src,cb);",
])
def test_guard_fallback_rebinding_multiple_calls_and_unknown_dispatch_do_not_prove_false(tmp_path, monkeypatch, body):
    fixture = callback_fixture(tmp_path, monkeypatch=monkeypatch, body=body)
    req, _, _ = stage_completion(fixture)
    original = deepcopy(fixture[3][req["requirement_id"]])
    merged, audit = merge_resolution(None, original, req, proof_evaluator=configure(fixture))
    assert merged == original and not audit["withdrawals"]
    assert not rebuild(fixture)["generation_allowed"]


def test_competing_concrete_callback_producers_remain_blocking(tmp_path):
    fixture = callback_fixture(tmp_path)
    req, good, _ = stage_completion(fixture)
    other = callback_patch(good, setup_api=next(fid for fid in fixture[1].functions
        if fixture[1].functions[fid]["name"] == "acquire"))
    fixture[3][req["requirement_id"]], _ = merge_resolution(fixture[3][req["requirement_id"]], other, req)
    original = deepcopy(fixture[3][req["requirement_id"]])
    merged, audit = merge_resolution(None, original, req, proof_evaluator=configure(fixture))
    assert merged == original and len(merged["facts"]) == 3 and not audit["withdrawals"]
    assert fact_conflicts(merged["facts"]) and not rebuild(fixture)["generation_allowed"]
