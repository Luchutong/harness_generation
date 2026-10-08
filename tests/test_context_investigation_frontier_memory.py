"""Investigation memory and cleanup search hints stay separate from proof.

These regressions are authored while execution is paused; they are not a fresh
cohort, a provider experiment or evidence that runtime closure is stable.
"""
from copy import deepcopy

from harness_generation.harness_context import HarnessRequirementBuilder
from harness_generation.harness_context.investigation import (
    _candidate_roles, _focused_candidates, _repair_subjects, established, proof_agenda, retained_rows,
)
from harness_generation.harness_context.proposals import registry
from harness_generation.semantic_discovery.models import digest
from test_harness_context import setup


def memory_fixture(*, owned=False, release=None):
    requirement = {"requirement_id": "req_owner", "subject_function_id": "parse", "kind": "ownership"}
    row = {"subject_id": "subject_return", "parameter": None, "return_value": True,
        "field": None, "subject_kind": "PointerReturn", "resource_id": "origin_first",
        "ownership": "owned" if owned else "borrowed", "release_api": release,
        "lifetime": "until_release" if owned else "during_call"}
    fact = {"fact_id": "fact_owner", "requirement_id": "req_owner", "function_id": "parse",
        "predicate": "ownership", "value": {"entries": [row]}, "evidence_ids": ["source_body"]}
    graph = {"nodes": [{"obligation_id": "owner_exact", "requirement_id": "req_owner",
        "subject_function_id": "parse", "subject_parameter": None, "subject_field": None,
        "predicate": "ownership_subject", "fact_ids": ["fact_owner"], "proof_status": "proved",
        "evidence_ids": ["source_body"], "local_proof": {"status": "proved", "sources": [{
            "kind": "source_checked_ownership_projection", "semantic_fact_ids": ["fact_owner"]}]}}]}
    preview = {"ownership_contract": {"entries": [{**deepcopy(row), "fact_id": "fact_owner"}]}}
    return requirement, fact, graph, preview


def test_owned_until_release_null_api_never_becomes_established_memory():
    requirement, fact, graph, preview = memory_fixture(owned=True)
    before = digest([requirement, fact, graph, preview])
    assert not established("ownership", fact["value"]["entries"][0])
    assert retained_rows(requirement, [fact], obligation_graph=graph, preview=preview) == []
    assert digest([requirement, fact, graph, preview]) == before


def test_non_unknown_uncertified_proposal_is_observed_only():
    requirement, fact, _, _ = memory_fixture()
    assert established("ownership", fact["value"]["entries"][0])
    assert retained_rows(requirement, [fact]) == []


def test_exact_certificate_keeps_copyable_row_and_changed_projection_drops_it():
    requirement, fact, graph, preview = memory_fixture(owned=True, release="release")
    retained = retained_rows(requirement, [fact], obligation_graph=graph, preview=preview)
    assert retained == fact["value"]["entries"]
    retained[0]["resource_id"] = "changed_copy"
    assert fact["value"]["entries"][0]["resource_id"] == "origin_first"
    preview["ownership_contract"]["entries"][0]["release_api"] = "different_release"
    assert retained_rows(requirement, [fact], obligation_graph=graph, preview=preview) == []


def test_aggregate_proved_requirement_does_not_certify_complete_row():
    requirement, fact, graph, preview = memory_fixture()
    graph["nodes"][0]["predicate"] = "ownership"
    graph["nodes"][0]["local_proof"]["sources"] = [{"kind": "validated_semantic_proposal", "fact_id": "fact_owner"}]
    assert retained_rows(requirement, [fact], obligation_graph=graph, preview=preview) == []


def test_same_subject_distinct_origins_remain_observed_and_uncertified():
    from harness_generation.harness_context.prompt_projection import proposal_view

    requirement, fact, graph, preview = memory_fixture(owned=True, release="release")
    second = {**deepcopy(fact["value"]["entries"][0]), "resource_id": "origin_second"}
    fact["value"]["entries"].append(second)
    preview["ownership_contract"]["entries"].append({**deepcopy(second), "fact_id": "fact_owner"})
    before = deepcopy([fact, graph, preview])
    retained = retained_rows(requirement, [fact], obligation_graph=graph, preview=preview)
    assert retained == []
    observed = proposal_view([fact], graph, preview)
    assert all(proof["proof_status"] == "unverified" for proof in observed[0]["claim_proofs"])
    assert {row["resource_id"] for row in fact["value"]["entries"]} == {"origin_first", "origin_second"}
    assert {row["resource_id"] for row in preview["ownership_contract"]["entries"]} == {"origin_first", "origin_second"}
    assert [fact, graph, preview] == before


def candidate(identity, *, parent="parse", reason="cleanup", parameter=None, subject_kind="PointerReturn"):
    return {"candidate_id": identity, "function_id": identity, "required_by": parent,
        "reason": reason, "subject_bindings": [{"parameter": parameter, "subject_kind": subject_kind}],
        "evidence_ids": [], "necessity_proven": False}


def test_owned_return_candidates_exclude_other_action_parent_and_subject():
    requirement = {"subject_function_id": "parse", "kind": "lifecycle", "required_by": []}
    candidates = [candidate("return_release"), candidate("other_parent", parent="wrapper"),
        candidate("parameter_release", parameter="data", subject_kind="PointerParameter"),
        candidate("creator", reason="creation")]
    before = digest(candidates)
    roles = _candidate_roles("lifecycle", [], return_cleanup_focus=True)
    selected = _focused_candidates(requirement, candidates, roles, [], return_cleanup_focus=True)
    assert [row["candidate_id"] for row in selected] == ["return_release"]
    assert digest(candidates) == before


def test_cleanup_correction_limits_lifecycle_action_without_changing_registry():
    task = {"requirement_id": "lifecycle", "closure_feedback": {"items": [{"correction_targets": [{
        "requirement_id": "lifecycle", "field_paths": ["value.resources[0].cleanup.api"]}]}]}}
    assert _candidate_roles("lifecycle", [task]) == {"cleanup"}
    assert _candidate_roles("argument_construction", []) == {"creation", "callback"}
    assert _candidate_roles("state", []) == {"initialization", "other"}


def test_signed_out_pointee_correction_does_not_select_its_storage_cell():
    requirement = {"requirement_id": "owner", "subject_function_id": "parse", "kind": "ownership", "required_by": []}
    task = {"requirement_id": "owner", "closure_feedback": {"items": [{"correction_targets": [{
        "requirement_id": "owner", "subject_key": ["out", False, None, "OutParameterPointee"]}]}]}}
    subjects = _repair_subjects(requirement, [task])
    candidates = [candidate("storage_cell", parameter="out", subject_kind="PointerParameter"),
        candidate("pointee", parameter="out", subject_kind="OutParameterPointee")]
    selected = _focused_candidates(requirement, candidates, {"cleanup"}, ["out"], subjects=subjects)
    assert [row["candidate_id"] for row in selected] == ["pointee"]


LATE_CLEANUP = """typedef unsigned long size_t;
typedef struct Node { int value; } Node;
void drop(Node *node) { free(node); }
int h0(const unsigned char *data) { return data[0]; }
int h1(const unsigned char *data) { return data[0]; }
int h2(const unsigned char *data) { return data[0]; }
int h3(const unsigned char *data) { return data[0]; }
int h4(const unsigned char *data) { return data[0]; }
int h5(const unsigned char *data) { return data[0]; }
int h6(const unsigned char *data) { return data[0]; }
Node *parse(const unsigned char *data, size_t size) {
 Node *node = malloc(sizeof(Node));
 if (!node) return 0;
 node->value = size ? h0(data)+h1(data)+h2(data)+h3(data)+h4(data)+h5(data)+h6(data) : 0;
 if (!size) { drop(node); return 0; }
 return node;
}
"""


def agenda(prepared, *, bootstrap=True):
    tools = prepared[5]
    requirement = next(row for row in HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"]
        if row["kind"] == "lifecycle" and row["subject_function_id"] == prepared[0][-1]["parse"])
    tools.activate(requirement)
    if bootstrap:
        tools.bootstrap()
    signed = registry(tools, [requirement])
    before = digest({"evidence": tools.evidence, "discoveries": tools.state.discoveries,
        "scope": sorted(tools.scope_ids), "calls": tools.state.tool_calls, "source_chars": tools.state.source_chars})
    slot = proof_agenda([requirement], [], [], tools, signed,
        {"proved": [], "missing_evidence": [], "blocked": []}, {"parameters": []})["slots"][0]
    after = digest({"evidence": tools.evidence, "discoveries": tools.state.discoveries,
        "scope": sorted(tools.scope_ids), "calls": tools.state.tool_calls, "source_chars": tools.state.source_chars})
    assert before == after
    return slot


def test_late_cleanup_call_is_first_scoped_query_without_issuing_helper_or_proof(tmp_path):
    prepared = setup(tmp_path, LATE_CLEANUP)
    slot = agenda(prepared)
    query = slot["query_options"][0]
    assert query["tool"] == "get_call_sites"
    assert query["arguments"] == {"function": prepared[0][-1]["parse"], "callee": "drop"}
    assert len(slot["query_options"]) <= prepared[4].budget.max_references_per_query
    assert prepared[0][-1]["drop"] not in prepared[5].scope_ids
    assert not slot["candidate_effects"] and not slot["retained_entries"]


def test_unissued_subject_body_does_not_supply_hidden_ast_cleanup_hint(tmp_path):
    prepared = setup(tmp_path, LATE_CLEANUP)
    slot = agenda(prepared, bootstrap=False)
    assert not any(query["tool"] == "get_call_sites" for query in slot["query_options"])
    assert not slot["retained_entries"]


def test_excluded_release_endpoint_is_not_restored_by_ast_hint(tmp_path):
    prepared = setup(tmp_path, LATE_CLEANUP,
        roles={"parse": ("core", "accepted_anchor"), "drop": ("exclude", "diagnostic_only")})
    slot = agenda(prepared)
    assert not any(query["tool"] == "get_call_sites" and query["arguments"].get("callee") == "drop"
        for query in slot["query_options"])
    assert prepared[0][-1]["drop"] in prepared[5].excluded
