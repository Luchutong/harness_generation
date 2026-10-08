"""Call-order investigation reads authorized endpoints without inventing edges."""
from copy import deepcopy

import pytest

from harness_generation.harness_context import HarnessRequirementBuilder
from harness_generation.harness_context.investigation import VERSION, proof_agenda
from harness_generation.harness_context.models import validate_shape
from harness_generation.harness_context.proposals import registry
from harness_generation.harness_context.terminal import scoped_value_schema
from harness_generation.semantic_discovery.models import DecisionSchemaError, canonical, digest
from test_harness_context import setup, order
from test_semantic_slicing import HUB


ROLES = {"parse": ("core", "accepted_anchor"),
    "feed": ("core", "external_input_injection"),
    "create": ("support", "resource_creation"),
    "destroy": ("support", "resource_cleanup"),
    "set_logger": ("exclude", "diagnostic_only")}


def prepared_order(tmp_path):
    prepared = setup(tmp_path, HUB, roles=ROLES)
    tools = prepared[5]
    requirement = next(r for r in HarnessRequirementBuilder().build(prepared[1], prepared[3])["requirements"]
        if r["kind"] == "call_order" and r["subject_function_id"] == prepared[0][-1]["parse"])
    tools.activate(requirement)
    tools.bootstrap()
    return prepared, tools, requirement


def agenda(tools, requirement, *, signed=None, facts=(), proved=()):
    return proof_agenda([requirement], facts, [], tools, signed or registry(tools, [requirement]),
        {"proved": list(proved), "missing_evidence": [], "blocked": []}, {"parameters": []})["slots"][0]


def function_queries(slot):
    return [q["arguments"]["function"] for q in slot["query_options"] if q["tool"] == "get_function"]


def test_authorized_missing_core_has_exact_read_choice_but_no_order_fact(tmp_path):
    prepared, tools, requirement = prepared_order(tmp_path)
    ids = prepared[0][-1]
    slot = agenda(tools, requirement)
    assert VERSION == "proof-focused-investigation-v10"
    assert function_queries(slot) == [ids["feed"]]
    assert slot["ordering_endpoints"]["issued_function_ids"] == [ids["parse"]]
    assert slot["ordering_endpoints"]["needed_authorized_function_ids"] == [ids["feed"]]
    assert {q["tool"] for q in slot["query_options"]} == {"get_function"}
    assert not slot["retained_entries"] and not slot["existing_local_proofs"]
    assert slot["unresolved_template"]["facts"] == []
    assert slot["unresolved_template"]["discovered_api_dependencies"] == []


def test_cached_core_read_enables_exact_terminal_endpoint_without_source_charge(tmp_path):
    prepared, tools, requirement = prepared_order(tmp_path)
    ids = prepared[0][-1]
    source = tools.execute("get_function", {"function": ids["feed"]})
    tools.visible_ids.difference_update(source["evidence_ids"])
    signed = registry(tools, [requirement])
    value = {"constraints": [order(ids["feed"], ids["parse"])]}
    with pytest.raises(DecisionSchemaError):
        validate_shape(value, scoped_value_schema(requirement, signed, tools.snapshot))
    before_source = prepared[4].source_chars
    before_calls = prepared[4].tool_calls
    slot = agenda(tools, requirement, signed=signed)
    query = slot["query_options"][0]
    assert query["arguments"] == {"function": ids["feed"]}
    assert ids["feed"] not in slot["ordering_endpoints"]["issued_function_ids"]
    assert prepared[4].source_chars == before_source and prepared[4].tool_calls == before_calls
    reread = tools.execute(query["tool"], query["arguments"])
    assert reread["evidence_ids"] == source["evidence_ids"]
    assert prepared[4].source_chars == before_source
    assert prepared[4].tool_calls == before_calls + 1
    signed_after = registry(tools, [requirement])
    validate_shape(value, scoped_value_schema(requirement, signed_after, tools.snapshot))
    assert canonical(value) == canonical({"constraints": [order(ids["feed"], ids["parse"])]})
    complete_slot = agenda(tools, requirement, signed=signed_after)
    assert not function_queries(complete_slot)
    assert not complete_slot["ordering_endpoints"]["needed_authorized_function_ids"]


def test_complete_visible_core_is_not_suggested_again(tmp_path):
    prepared, tools, requirement = prepared_order(tmp_path)
    tools.execute("get_function", {"function": prepared[0][-1]["feed"]})
    assert function_queries(agenda(tools, requirement)) == []


@pytest.mark.parametrize("blocked", ["excluded", "outside_scope", "fake_id"])
def test_missing_endpoint_read_filters_exclude_scope_and_snapshot(tmp_path, blocked):
    prepared, tools, requirement = prepared_order(tmp_path)
    feed = prepared[0][-1]["feed"]
    signed = registry(tools, [requirement])
    if blocked == "excluded":
        # A read-only caller can be in scope while still excluded from API use.
        tools.excluded.add(feed)
    elif blocked == "outside_scope":
        tools.scope_ids.remove(feed)
    else:
        tools.core_ids.remove(feed)
        tools.core_ids.add("function_not_in_snapshot")
        tools.scope_ids.add("function_not_in_snapshot")
    slot = agenda(tools, requirement, signed=signed)
    assert not function_queries(slot)
    assert not slot["ordering_endpoints"]["needed_authorized_function_ids"]


def test_cached_optional_support_is_not_promoted_to_needed_order_endpoint(tmp_path):
    prepared, tools, requirement = prepared_order(tmp_path)
    ids = prepared[0][-1]
    source = tools.execute("get_function", {"function": ids["create"]})
    prior = registry(tools, [requirement])
    assert any(c["function_id"] == ids["create"] for c in prior["support_candidates"])
    tools.visible_ids.difference_update(source["evidence_ids"])
    signed = registry(tools, [requirement])
    # Even a previously issued candidate hint does not prove required use.
    signed["support_candidates"] = prior["support_candidates"]
    requirement["required_by"] = [ids["create"]]
    slot = agenda(tools, requirement, signed=signed)
    assert function_queries(slot) == [ids["feed"]]
    assert ids["create"] not in slot["ordering_endpoints"]["needed_authorized_function_ids"]
    assert ids["create"] not in slot["ordering_endpoints"]["issued_function_ids"]


@pytest.mark.parametrize("predicate,status,needed", [
    ("api_invocation_proved", "proved", True),
    ("api_invocation_proved", "blocked", False),
    ("ownership", "proved", False),
])
def test_required_parent_read_needs_proved_invocation_and_exact_relation(tmp_path, predicate, status, needed):
    prepared, tools, requirement = prepared_order(tmp_path)
    ids = prepared[0][-1]
    requirement["required_by"] = [ids["destroy"]]
    node = {"obligation_id": "existing_parent_proof", "requirement_id": None,
        "subject_function_id": ids["destroy"], "predicate": predicate, "proof_status": status}
    slot = agenda(tools, requirement, proved=[node])
    assert (ids["destroy"] in function_queries(slot)) is needed
    assert (ids["destroy"] in slot["ordering_endpoints"]["needed_authorized_function_ids"]) is needed
    # A proved but unrelated optional support cannot be scheduled.
    node["subject_function_id"] = ids["create"]
    assert ids["create"] not in function_queries(agenda(tools, requirement, proved=[node]))


def test_complete_body_never_adds_an_id_absent_from_signed_registry(tmp_path):
    prepared, tools, requirement = prepared_order(tmp_path)
    ids = prepared[0][-1]
    tools.execute("get_function", {"function": ids["feed"]})
    signed = registry(tools, [requirement])
    signed["issued_function_ids"] = [ids["parse"], "function_not_in_snapshot", ids["set_logger"]]
    slot = agenda(tools, requirement, signed=signed)
    assert slot["ordering_endpoints"]["issued_function_ids"] == [ids["parse"]]
    assert not function_queries(slot)


def test_agenda_does_not_mutate_semantics_evidence_or_budgets(tmp_path):
    prepared, tools, requirement = prepared_order(tmp_path)
    facts = [{"requirement_id": requirement["requirement_id"], "function_id": requirement["subject_function_id"],
        "predicate": "call_order", "value": {"constraints": []}, "evidence_ids": []}]
    signed = registry(tools, [requirement])
    inputs_before = digest([facts, signed, requirement, tools.evidence, tools.state.budget.to_dict()])
    counts_before = (tools.state.model_calls, tools.state.tool_calls, tools.state.source_chars,
        deepcopy(tools.state.discoveries), deepcopy(tools.visible_ids), deepcopy(tools.scope_ids))
    agenda(tools, requirement, signed=signed, facts=facts)
    assert digest([facts, signed, requirement, tools.evidence, tools.state.budget.to_dict()]) == inputs_before
    assert (tools.state.model_calls, tools.state.tool_calls, tools.state.source_chars,
        tools.state.discoveries, tools.visible_ids, tools.scope_ids) == counts_before


def test_support_order_can_read_missing_required_core_consumer(tmp_path):
    prepared, tools, _ = prepared_order(tmp_path)
    ids = prepared[0][-1]
    from harness_generation.harness_context.requirements import requirement
    req = requirement(tools.ft["ft_id"], ids["create"], "call_order", required_by=[ids["parse"]])
    tools.activate(req)
    tools.bootstrap()
    # Other CORE bodies can be cached globally without being issued in this slot.
    tools.visible_ids = {eid for eid in tools.visible_ids if tools.evidence[eid].get("function_id") == ids["create"]}
    signed = registry(tools, [req])
    edge = {"constraints": [order(ids["create"], ids["parse"])]}
    with pytest.raises(DecisionSchemaError):
        validate_shape(edge, scoped_value_schema(req, signed, tools.snapshot))
    slot = agenda(tools, req, signed=signed)
    assert slot["query_options"][0]["arguments"] == {"function": ids["parse"]}
    assert ids["parse"] not in slot["ordering_endpoints"]["issued_function_ids"]
    tools.execute("get_function", {"function": ids["parse"]})
    validate_shape(edge, scoped_value_schema(req, registry(tools, [req]), tools.snapshot))
    assert edge["constraints"][0]["after"] == ids["parse"]
