"""Generation admission on real small Clang projects; no model or fuzz run."""
from copy import deepcopy
import shutil

import pytest

from harness_generation.api_contracts import APIContract, ContractStatus
from harness_generation.execution_preflight import ExecutionPreflightGate
from harness_generation.harness_strategy.normalization import normalize_strategy
from v05_fixtures import entry_fixture as prepared
from v05_fixtures import block_legacy_proof_imports, proposal, step

pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="real Clang required")
HEADER = """#include <stddef.h>
#include <stdlib.h>
typedef struct Node { struct Node *next; int value; } Node;
typedef Node *Handle;
"""
SOURCE = """#include "api.h"
Node *make(const unsigned char *data, size_t size) {
  Node *node = malloc(sizeof(Node));
  if (node) { node->next = NULL; node->value = size ? data[0] : 0; }
  return node;
}
int run(Node *node, const unsigned char *data, size_t size) {
  if (node == NULL) return -1;
  return node->value + (size ? data[0] : 0);
}
void drop(Node *node) { free(node); }
void complex_drop(Node *node) {
  while (node) { Node *next = node->next; free(node); node = next; }
}
void conditional_drop(Node *node, int flag) { if (flag) free(node); }
Node *borrow(const unsigned char *data, size_t size) { return (Node *)data; }
Handle opaque_make(const unsigned char *data, size_t size) { return make(data, size); }
int opaque_run(Handle node, const unsigned char *data, size_t size) {
  if (node == NULL) return -1;
  return node->value + (size ? data[0] : 0);
}
void opaque_drop(Handle node) { free(node); }
"""


@pytest.fixture(scope="module")
def fixture(tmp_path_factory):
    return prepared(tmp_path_factory.mktemp("v05_preflight"), SOURCE, header=HEADER, name="run")


def selected(prep, *, maker="make", runner="run", cleanup="complex_drop", cleanup_kind="cleanup"):
    ids, eids = prep[2], prep[4]
    steps = [step("call", "create", eids[maker], function_id=ids[maker],
                  arguments={"data": {"kind": "fuzz_bytes"}, "size": {"kind": "fuzz_size"}}, guard_ids=[]),
        step("capture", "capture", eids[maker], value_id="node", call_step_id="create", source="return", parameter=""),
        step("guard", "exists", eids[maker], condition={"kind": "nonnull", "value_id": "node"}),
        step("call", "target", eids[runner], function_id=ids[runner],
             arguments={"node": {"kind": "value", "value_id": "node"},
                        "data": {"kind": "fuzz_bytes"}, "size": {"kind": "fuzz_size"}}, guard_ids=["exists"])]
    if cleanup:
        values = {"function_id": ids[cleanup], "arguments": {"node": {"kind": "value", "value_id": "node"}}, "guard_ids": ["exists"]}
        if cleanup == "conditional_drop":
            values["arguments"]["flag"] = {"kind": "integer", "value": 0}
        if cleanup_kind == "cleanup":
            values["resource_value_id"] = "node"
        steps.append(step(cleanup_kind, "dispose", eids[cleanup], **values))
    ft = deepcopy(prep[0])
    ft["anchor_function_id"] = ids[runner]
    ft["core_functions"] = [{"function_id": ids[runner], "role": "anchor"}]
    return ft, normalize_strategy(proposal(*steps), ft, prep[1])


def evaluate(prep, ft, strategy, **options):
    return ExecutionPreflightGate().evaluate(ft, prep[1], strategy, options.pop("evidence", prep[3]),
        options.pop("allowed", set(prep[2].values())), build_analysis=options.pop("build", prep[5]),
        project_root=prep[6], **options)


def codes(gate):
    return {row["code"] for row in gate["known_violations"]}


def test_complex_cleanup_unknown_allows_without_formal_calls(fixture, monkeypatch):
    block_legacy_proof_imports(monkeypatch)
    ft, strategy = selected(fixture)
    original = deepcopy(strategy)
    gate = evaluate(fixture, ft, strategy)
    assert gate["allowed"], gate["known_violations"]
    assert gate["artifact_kind"] == "execution_preflight"
    assert gate["semantic_verified"] is gate["generation_allowed"] is False
    assert gate["formal_semantics"]["status"] == "not_evaluated"
    assert any(row["kind"] == "cleanup_internal_effect_unverified" for row in gate["unknown_contracts"])
    assert strategy == original
    assert all(row["status"] == ContractStatus.UNKNOWN.value for row in gate["unknown_contracts"])


def test_explicit_null_core_rejected_by_live_entry_contract(fixture):
    ft = fixture[0]
    document = proposal(step("call", "null_target", fixture[4]["run"], function_id=fixture[2]["run"],
        arguments={"node": {"kind": "null"}, "data": {"kind": "fuzz_bytes"}, "size": {"kind": "fuzz_size"}}, guard_ids=[]))
    gate = evaluate(fixture, ft, normalize_strategy(document, ft, fixture[1]))
    assert not gate["allowed"]
    assert "execution_core_resource_entry_rejected" in codes(gate)
    rejected = next(row for row in gate["known_violations"] if row["code"] == "execution_core_resource_entry_rejected")
    assert rejected["contract"]["resource_state"] == "ENTRY_REJECTED"


def test_opaque_typedef_capture_and_cleanup_use_canonical_pointer(fixture):
    ft, strategy = selected(fixture, maker="opaque_make", runner="opaque_run", cleanup="opaque_drop")
    assert fixture[1].functions[fixture[2]["opaque_make"]]["return_type"] == "Handle"
    gate = evaluate(fixture, ft, strategy)
    assert gate["allowed"], gate["known_violations"]
    resource, = gate["execution_context"]["resources"]
    assert resource["pointer_depth"] == 1
    original, = strategy["resources"]
    assert resource["origin"] == original["origin"] and resource["resource_id"] == original["resource_id"]
    declaration = next(row for row in gate["execution_context"]["api_declarations"] if row["function_id"] == fixture[2]["opaque_run"])
    assert declaration["parameters"][0]["type"] == "Handle"
    assert declaration["parameters"][0]["pointer_depth"] == 1


def test_opaque_null_is_rejected_instead_of_source_spelling_mismatch(fixture):
    ft, strategy = selected(fixture, maker="opaque_make", runner="opaque_run", cleanup="opaque_drop")
    document = proposal(step("call", "null_target", fixture[4]["opaque_run"], function_id=fixture[2]["opaque_run"],
        arguments={"node": {"kind": "null"}, "data": {"kind": "fuzz_bytes"}, "size": {"kind": "fuzz_size"}}, guard_ids=[]))
    gate = evaluate(fixture, ft, normalize_strategy(document, ft, fixture[1]))
    assert codes(gate) == {"execution_core_resource_entry_rejected"}


def test_source_proven_release_before_target_rejected(fixture):
    ft, strategy = selected(fixture, cleanup="drop", cleanup_kind="call")
    document = {key: deepcopy(strategy[key]) for key in ("steps", "hypotheses", "open_questions")}
    dispose = document["steps"].pop()
    document["steps"].insert(3, dispose)
    document["steps"].append(step("cleanup", "final_cleanup", fixture[4]["complex_drop"], function_id=fixture[2]["complex_drop"],
        arguments={"node": {"kind": "value", "value_id": "node"}}, guard_ids=["exists"], resource_value_id="node"))
    gate = evaluate(fixture, ft, normalize_strategy(document, ft, fixture[1]))
    assert "execution_use_after_local_release" in codes(gate)
    assert not gate["allowed"]


def test_conditional_release_not_selected_stays_unknown(fixture):
    ft, strategy = selected(fixture, cleanup="conditional_drop", cleanup_kind="call")
    document = {key: deepcopy(strategy[key]) for key in ("steps", "hypotheses", "open_questions")}
    dispose = document["steps"].pop()
    document["steps"].insert(3, dispose)
    document["steps"].append(step("cleanup", "final_cleanup", fixture[4]["complex_drop"], function_id=fixture[2]["complex_drop"],
        arguments={"node": {"kind": "value", "value_id": "node"}}, guard_ids=["exists"], resource_value_id="node"))
    gate = evaluate(fixture, ft, normalize_strategy(document, ft, fixture[1]))
    assert gate["allowed"], gate["known_violations"]
    assert any(row["kind"] == "local_resource_effect_unverified" for row in gate["unknown_contracts"])


def test_known_borrowed_alias_must_not_release_framework_bytes(fixture):
    ft, strategy = selected(fixture, maker="borrow", cleanup="drop")
    gate = evaluate(fixture, ft, strategy)
    assert "execution_release_of_framework_storage" in codes(gate)
    assert not gate["allowed"]


def test_duplicate_cleanup_and_use_after_cleanup_are_structure_errors(fixture):
    ft, strategy = selected(fixture, cleanup="complex_drop")
    document = {key: deepcopy(strategy[key]) for key in ("steps", "hypotheses", "open_questions")}
    duplicate = deepcopy(document["steps"][-1]); duplicate["step_id"] = "second_dispose"
    document["steps"].append(duplicate)
    gate = evaluate(fixture, ft, normalize_strategy(document, ft, fixture[1]))
    assert "double_cleanup" in codes(gate) and "use_after_cleanup" in codes(gate)
    assert not gate["allowed"]


@pytest.mark.parametrize("mutation,expected", [
    ("scope", "strategy_api_not_authorized"),
    ("parameter", "strategy_parameter_mismatch"),
    ("type", "strategy_argument_type_mismatch"),
    ("forward", "forward_or_unknown_value"),
    ("envelope", "execution_preflight_identity_or_schema_invalid"),
])
def test_structural_or_scope_errors_still_reject(fixture, mutation, expected):
    ft, strategy = selected(fixture)
    document = {key: deepcopy(strategy[key]) for key in ("steps", "hypotheses", "open_questions")}
    options = {}
    if mutation == "scope":
        options["allowed"] = {fixture[2]["make"], fixture[2]["run"]}
    if mutation == "parameter":
        document["steps"][3]["arguments"].pop("size")
    if mutation == "type":
        document["steps"][3]["arguments"]["node"] = {"kind": "fuzz_size"}
    if mutation == "forward":
        document["steps"][3]["arguments"]["node"] = {"kind": "value", "value_id": "invented"}
    strategy = normalize_strategy(document, ft, fixture[1])
    if mutation == "envelope":
        strategy["generation_allowed"] = True
    gate = evaluate(fixture, ft, strategy, **options)
    assert not gate["allowed"] and expected in codes(gate), gate["known_violations"]


@pytest.mark.parametrize("build", [None, {"authenticated": True, "verified": True}])
def test_saved_build_labels_do_not_authorize_preflight(fixture, build):
    ft, strategy = selected(fixture)
    gate = evaluate(fixture, ft, strategy, build=build)
    assert not gate["allowed"]
    assert "execution_preflight_identity_or_schema_invalid" in codes(gate)


def test_serialized_contract_violation_labels_remain_untrusted(fixture):
    ft, strategy = selected(fixture)
    supplied = APIContract(fixture[2]["run"], "requires_nonnull", "human_review", "v1", {},
        {"status": "violated", "verified": True}, trust="live_source_build").to_dict()
    gate = evaluate(fixture, ft, strategy, contracts=[supplied])
    assert gate["allowed"], gate["known_violations"]
    proposal_contract, = gate["execution_context"]["contract_proposals"]
    assert proposal_contract["trust"] == "proposal"
    assert any(row["kind"] == "api_contract_proposal_unverified" for row in gate["unknown_contracts"])


def test_mutated_evidence_is_rejected(fixture):
    ft, strategy = selected(fixture)
    records = deepcopy(fixture[3])
    records[fixture[4]["run"][0]]["source_sha256"] = "0" * 64
    gate = evaluate(fixture, ft, strategy, evidence=records)
    assert not gate["allowed"]
    assert "execution_source_evidence_invalid" in codes(gate)


def test_ownership_cleanup_omission_remains_explicit_unknown(fixture):
    ft, strategy = selected(fixture, maker="opaque_make", runner="opaque_run", cleanup=None)
    gate = evaluate(fixture, ft, strategy)
    assert gate["allowed"], gate["known_violations"]
    assert any(row["kind"] == "cleanup_omitted_ownership_unverified" for row in gate["unknown_contracts"])
    assumption, = gate["execution_context"]["ownership_assumptions"]
    assert assumption["ownership"] == "unknown" and assumption["cleanup_step_ids"] == []


def test_live_dependency_drift_refuses_preflight(tmp_path):
    prep = prepared(tmp_path, SOURCE, header=HEADER, name="run")
    ft, strategy = selected(prep)
    path = prep[6] / "api.h"
    path.write_text(path.read_text() + "\n#define CHANGED_IDENTITY 1\n")
    gate = evaluate(prep, ft, strategy)
    assert not gate["allowed"] and "execution_preflight_identity_or_schema_invalid" in codes(gate)
