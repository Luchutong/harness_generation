"""Pending regressions for exact cleanup feedback, not closure certificates.

These tests exercise the diagnostic projection. They deliberately do not
replace the source-evaluator/Gate tests that authorize an actual commit.
"""
from copy import deepcopy

import pytest

from harness_generation.harness_context.closure_feedback import build_closure_feedback
from harness_generation.semantic_discovery.models import digest


def fact(kind, rows, *, fid="parse", rid=None):
    collection = {"lifecycle": "resources", "ownership": "entries"}[kind]
    result = {"requirement_id": rid or kind, "function_id": fid, "predicate": kind,
        "value": {collection: rows}, "evidence_ids": ["ev_parse"]}
    return {**result, "fact_id": "fact_" + digest(result)[:16]}


def resource(parameter=None, *, returned=True, rid="returned_object", cleanup=None, mandatory=True):
    return {"subject_parameter": parameter, "return_value": returned, "resource_id": rid,
        "type": "Object", "creation": {"kind": "creator_api", "api": "parse"},
        "initialization": {"api": None, "mandatory": False},
        "cleanup": {"api": cleanup, "mandatory": mandatory}, "reuse": "per_input"}


def owner(parameter=None, *, returned=True, rid="returned_object", cleanup=None, field=None, subject_kind=None):
    return {"parameter": parameter, "return_value": returned, "field": field, "resource_id": rid,
        "subject_kind": subject_kind or ("PointerReturn" if returned else "PointerParameter"),
        "ownership": "owned", "lifetime": "until_release", "release_api": cleanup}


def candidate(api="release", *, reason="cleanup", parameter=None, subject_kind="PointerReturn", field=None):
    binding = {"parameter": parameter, "subject_kind": subject_kind, "type": "Object", "pointer_depth": 1,
        "api_parameter": "object", "effect": "parameter_release", "fields": []}
    if field is not None:
        binding["field"] = field
    return {"candidate_id": "candidate_" + api, "function_id": api, "required_by": "parse", "reason": reason,
        "subject_bindings": [binding], "evidence_ids": ["ev_" + api], "necessity_proven": False,
        "source_status": "issued_complete_body"}


def graph(*, code="mandatory_cleanup_unresolved", parameter=None, field=None, rid=None, kind="lifecycle", declared_kind=None):
    node = {"obligation_id": "gap", "requirement_id": kind, "subject_function_id": "parse", "kind": kind,
        "subject_parameter": parameter, "subject_field": field, "resource_id": rid,
        "diagnostics": [{"code": code}], "dependencies": [],
        "local_proof": {"status": "missing", "sources": ([{"kind": "declared_ownership_subject",
            "subject_kind": declared_kind}] if declared_kind else [])}}
    return {"graph_digest": "current_graph", "nodes": [node], "frontier": ["gap"], "open_roots": ["gap"]}


def fixture(*, rows=None, owners=None, candidates=()):
    requirements = [{"requirement_id": kind, "subject_function_id": "parse", "kind": kind}
        for kind in ("lifecycle", "ownership")]
    facts = [fact("lifecycle", rows if rows is not None else [resource()]),
        fact("ownership", owners if owners is not None else [owner()])]
    signed = {"subject_function_id": "parse", "subject_evidence_ids": ["ev_parse"],
        "ownership_subjects": [{"function_id": "parse", "subject_id": "return_subject", "parameter": None,
            "return_value": True, "field": None, "subject_kind": "PointerReturn"}],
        "support_candidates": list(candidates)}
    evidence = {"ev_parse": {"evidence_id": "ev_parse", "tool": "get_function", "function_id": "parse",
        "defined": True, "truncated": False, "content": "{ return create(); }"}}
    return requirements, facts, signed, evidence


def feedback(current_graph, requirements, facts, signed, evidence, **kwargs):
    return build_closure_feedback(current_graph, requirements, facts, signed=signed, evidence=evidence, **kwargs)


def test_owned_return_links_cleanup_and_release_without_mutating_active_facts_or_proving_candidate():
    reqs, facts, signed, evidence = fixture(candidates=[candidate()])
    before = deepcopy((reqs, facts, signed, evidence))
    result = feedback(graph(), reqs, facts, signed, evidence)
    item, = result["items"]
    assert item["repair_requirement_ids"] == ["lifecycle", "ownership"]
    assert any(target["field_paths"] == ["value.entries[0].release_api"]
        and target["observed_values"] == {"release_api": None} for target in item["correction_targets"])
    assert any("value.resources[0].cleanup.api" in target["field_paths"] for target in item["correction_targets"])
    assert {entry["field_path"] for entry in item["preserve_fields"]} >= {
        "value.entries[0].ownership", "value.entries[0].lifetime", "value.resources[0].creation.api"}
    assert item["active_fact_ids"] == sorted(row["fact_id"] for row in facts)
    assert result["transaction_groups"][0]["requirement_ids"] == ["lifecycle", "ownership"]
    assert item["issued_options"]["support_candidates"][0]["necessity_proven"] is False
    assert all("replacement" not in target and "new_value" not in target for target in item["correction_targets"])
    assert (reqs, facts, signed, evidence) == before


def test_cleanup_options_exclude_creators_other_parameters_and_unmatched_return_kinds():
    reqs, facts, signed, evidence = fixture(candidates=[candidate(), candidate("creator", reason="creation"),
        candidate("release_other", parameter="buffer", subject_kind="PointerParameter"),
        candidate("release_cell", subject_kind="OutParameterPointee")])
    item, = feedback(graph(), reqs, facts, signed, evidence)["items"]
    assert [row["function_id"] for row in item["issued_options"]["support_candidates"]] == ["release"]
    assert item["issued_options"]["action_filter"] == ["cleanup"]
    assert not item["issued_options"]["input_length_choices"]


def test_callback_binding_filter_understands_the_exact_parameter_field_source_shape():
    reqs = [{"requirement_id": "callback", "subject_function_id": "parse", "kind": "callback"}]
    facts = [{"fact_id": "callback_fact", "function_id": "parse", "requirement_id": "callback", "predicate": "callback",
        "value": {"callbacks": [{"parameter": "ctx.on_data", "signature": None, "setup_api": None,
            "userdata": None, "lifetime": "unknown", "null_allowed": None}]}, "evidence_ids": ["ev_parse"]}]
    _, _, signed, evidence = fixture()
    signed["source_callback_bindings"] = [{"root_function_id": "parse", "owner_origin": "parameter:ctx",
        "field": field, "callee_expression": "ctx->" + field, "status": "missing"}
        for field in ("on_data", "on_other")]
    item, = feedback(graph(kind="callback", parameter="ctx.on_data", code="mandatory_callback_abi_unresolved"),
        reqs, facts, signed, evidence)["items"]
    assert [row["field"] for row in item["issued_options"]["source_callback_bindings"]] == ["on_data"]


def test_collection_cleanup_gap_preserves_healthy_borrowed_input_row():
    other_resource = resource("buffer", returned=False, rid="buffer", mandatory=False)
    other_owner = {**owner("buffer", returned=False, rid="buffer"), "ownership": "borrowed", "lifetime": "during_call"}
    reqs, facts, signed, evidence = fixture(rows=[resource(), other_resource], owners=[owner(), other_owner],
        candidates=[candidate(), candidate("release_other", parameter="buffer", subject_kind="PointerParameter")])
    item, = feedback(graph(), reqs, facts, signed, evidence)["items"]
    assert all(target["subject_parameter"] is None for target in item["correction_targets"])
    assert {entry["value"].get("parameter", entry["value"].get("subject_parameter")) for entry in item["preserve_rows"]} == {"buffer"}
    assert [row["function_id"] for row in item["issued_options"]["support_candidates"]] == ["release"]


@pytest.mark.parametrize('ownership', ['borrowed', 'static', 'transferred'])
def test_nonowned_optional_cleanup_does_not_reopen_an_independent_subject(ownership):
    other_resource = resource('buffer', returned=False, rid='buffer', cleanup='optional_hint', mandatory=False)
    other_owner = {**owner('buffer', returned=False, rid='buffer'),
        'ownership': ownership, 'release_api': None, 'lifetime': 'during_call'}
    reqs, facts, signed, evidence = fixture(rows=[resource(), other_resource], owners=[owner(), other_owner],
        candidates=[candidate(), candidate('optional_hint', parameter='buffer', subject_kind='PointerParameter')])
    item, = feedback(graph(), reqs, facts, signed, evidence)['items']
    assert all(target['resource_id'] != 'buffer' for target in item['correction_targets'])
    assert any(row['value'].get('resource_id') == 'buffer' for row in item['preserve_rows'])


def test_exact_parameter_resource_links_and_preserves_a_different_resource_owner():
    reqs, facts, signed, evidence = fixture(rows=[resource("ctx", returned=False, rid="ctx_1")],
        owners=[owner("ctx", returned=False, rid="ctx_1"), owner("ctx", returned=False, rid="ctx_2")],
        candidates=[candidate("release_ctx", parameter="ctx", subject_kind="PointerParameter")])
    item, = feedback(graph(parameter="ctx", rid="ctx_1"), reqs, facts, signed, evidence)["items"]
    assert {target["resource_id"] for target in item["correction_targets"]} == {"ctx_1"}
    assert any(entry["value"]["resource_id"] == "ctx_2" for entry in item["preserve_rows"])


def test_two_lifecycle_rows_with_same_declaration_keep_untargeted_resource_row_and_evidence():
    reqs, facts, signed, evidence = fixture(rows=[resource("ctx", returned=False, rid="ctx_1"),
        resource("ctx", returned=False, rid="ctx_2", cleanup="already_release")],
        owners=[owner("ctx", returned=False, rid="ctx_1"),
            owner("ctx", returned=False, rid="ctx_2", cleanup="already_release")])
    item, = feedback(graph(parameter="ctx", rid="ctx_1"), reqs, facts, signed, evidence)["items"]
    kept, = [entry for entry in item["preserve_rows"] if entry["field_path"] == "value.resources[1]"]
    assert kept["value"]["resource_id"] == "ctx_2" and kept["evidence_ids"] == ["ev_parse"]


@pytest.mark.parametrize("owner_rid,expected_link", [("out_value", True), (None, False), ("pointer_storage", False)])
def test_out_pointee_is_linked_only_by_an_existing_exact_resource(owner_rid, expected_link):
    reqs, facts, signed, evidence = fixture(rows=[resource("out", returned=False, rid="out_value")],
        owners=[owner("out", returned=False, rid=owner_rid, subject_kind="OutParameterPointee")])
    item, = feedback(graph(parameter="out", rid="out_value"), reqs, facts, signed, evidence)["items"]
    assert ("ownership" in item["repair_requirement_ids"]) is expected_link


def test_pointer_field_needs_exact_resource_and_does_not_select_owner_cleanup_from_effect_field_names():
    reqs, facts, signed, evidence = fixture(rows=[resource("ctx", returned=False, rid="field_value")],
        owners=[owner("ctx", returned=False, rid="field_value", field="owned", subject_kind="ResourceObject"),
            owner("ctx", returned=False, rid="another_field", field="other", subject_kind="ResourceObject")],
        candidates=[candidate("release_container", parameter="ctx", subject_kind="PointerParameter")])
    item, = feedback(graph(parameter="ctx", rid="field_value"), reqs, facts, signed, evidence)["items"]
    owned_targets = [target for target in item["correction_targets"] if target["kind"] == "ownership"]
    assert len(owned_targets) == 1 and owned_targets[0]["subject_field"] == "owned"
    assert not item["issued_options"]["support_candidates"]


def test_complete_anchor_body_does_not_substitute_for_missing_named_cleanup_body():
    reqs, facts, signed, evidence = fixture(rows=[resource(cleanup="release")], owners=[owner(cleanup="release")])
    item, = feedback(graph(rid="returned_object"), reqs, facts, signed, evidence)["items"]
    assert item["category"] == "missing_evidence"
    assert item["evidence_state"]["complete_body_evidence_ids"] == ["ev_parse"]
    assert item["evidence_state"]["missing_complete_body_function_ids"] == ["release"]
    assert item["actionable_blocker"]["body_inventory_is_proof"] is False


def test_missing_cleanup_choices_remain_an_investigation_gap_despite_complete_anchor():
    reqs, facts, signed, evidence = fixture()
    item, = feedback(graph(), reqs, facts, signed, evidence)["items"]
    assert item["category"] == "missing_evidence"
    assert item["evidence_state"]["missing_source_roles"] == ["cleanup"]
    assert "ownership" in item["repair_requirement_ids"]


def test_helper_body_inventory_allows_correction_but_does_not_commit_or_certify_it():
    reqs, facts, signed, evidence = fixture(rows=[resource(cleanup="release")], owners=[owner(cleanup="release")])
    evidence["ev_release"] = {"evidence_id": "ev_release", "tool": "get_function", "function_id": "release",
        "defined": True, "truncated": False, "content": "{ free(object); }"}
    item, = feedback(graph(rid="returned_object"), reqs, facts, signed, evidence)["items"]
    assert item["category"] == "contract_correction"
    assert not item["evidence_state"]["missing_complete_body_function_ids"]
    assert "commit" not in item and "proved" not in item


def test_current_framework_body_certificate_recognizes_a_complete_range_read_without_proving_cleanup():
    reqs, facts, signed, evidence = fixture()
    signed.pop("subject_evidence_ids")
    evidence["ev_parse"]["tool"] = "read_source_range"
    current_graph = graph()
    current_graph["nodes"].append({"obligation_id": "available_body", "subject_function_id": "parse",
        "predicate": "api_source_available", "kind": "api_closure", "evidence_ids": ["ev_parse"],
        "local_proof": {"status": "proved", "sources": [{"kind": "source_definition", "active": True}]}})
    item, = feedback(current_graph, reqs, facts, signed, evidence)["items"]
    assert item["evidence_state"]["complete_body_evidence_ids"] == ["ev_parse"]
    assert item["category"] == "missing_evidence"
    assert item["evidence_state"]["missing_source_roles"] == ["cleanup"]


def test_invocation_ambiguity_projects_exact_distinct_origins_without_labeling_them_unsupported():
    reqs, facts, signed, evidence = fixture()
    identity = {"unresolved": [{"function_id": "parse", "parameter": None,
        "reason": "multiple_runtime_origins", "origins": ["wrapper_a", "wrapper_b"], "evidence_ids": ["ev_a", "ev_b"]}],
        "value_flow": {"observations": [
            {"function_id": "parse", "parameter": None, "return_value": True, "resource_id": "wrapper_a",
                "caller_id": "caller_a", "call_offset": 235, "evidence_ids": ["ev_a"]},
            {"function_id": "parse", "parameter": None, "return_value": True, "resource_id": "wrapper_b",
                "caller_id": "caller_b", "call_offset": 33, "evidence_ids": ["ev_b"]}]}}
    before = deepcopy(identity)
    item, = feedback(graph(code="resource_identity_multiple_origins"), reqs, facts, signed, evidence,
        resource_identity=identity)["items"]
    assert item["category"] == "contract_correction"
    assert item["blocker_kind"] == "resource_identity_ambiguity"
    assert {row["call_offset"] for row in item["identity_frontier"]["observations"]} == {33, 235}
    assert "unsupported" not in item["actionable_blocker"]["category"]
    assert "do not select or merge" in item["actionable_blocker"]["next_action"]
    assert identity == before


@pytest.mark.parametrize("code,category", [("source_form_unsupported", "unsupported"),
    ("helper_body_missing", "missing_evidence"), ("upstream_excluded", "upstream_blocker")])
def test_explicit_blocker_types_override_complete_anchor_inventory(code, category):
    reqs, facts, signed, evidence = fixture()
    item, = feedback(graph(code=code), reqs, facts, signed, evidence)["items"]
    assert item["category"] == category


def test_null_resource_owner_is_not_linked_to_multiple_runtime_objects_by_parameter_alone():
    reqs, facts, signed, evidence = fixture(rows=[resource(rid="origin_a"), resource(rid="origin_b")],
        owners=[owner(rid=None)])
    item, = feedback(graph(), reqs, facts, signed, evidence)["items"]
    assert "ownership" not in item["repair_requirement_ids"]
    assert facts[1]["fact_id"] in item["preserve_fact_ids"]
