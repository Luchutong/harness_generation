"""Deterministic strategy identity and invocation-specific value origins.

Type information identifies representation, never object identity. This module
issues neither semantic certificates nor a frozen harness plan.
"""
from __future__ import annotations

from copy import deepcopy

from ..semantic_discovery.models import digest
from .models import ARTIFACT_KIND, POLICY_VERSION, SCHEMA_VERSION, StrategyBudget, validate_proposal


def proposal_projection(strategy):
    """Extract model-owned fields without trusting persisted framework metadata."""
    return {key: deepcopy(strategy[key]) for key in ("steps", "hypotheses", "open_questions")}


def _capture_type(step, calls, snapshot):
    call = calls.get(step["call_step_id"], {})
    function = snapshot.functions.get(call.get("function_id"), {})
    if step["source"] == "return":
        return function.get("return_base_type", ""), function.get("return_pointer_depth", 0)
    parameter = next((row for row in function.get("parameters", []) if row.get("name") == step["parameter"]), {})
    return parameter.get("base_type", ""), max(parameter.get("pointer_depth", 0) - 1, 0)


def normalize_strategy(proposal, ft, snapshot, budget=None):
    """Attach trusted identity and resources to a strictly shaped proposal.

References are retained for readable replay; no ordering of calls is changed.
Evidence and hypothesis reference arrays are sets and sorted canonically.
Invalid API/type/order choices remain proposals for the structural validator.
"""
    budget = budget or StrategyBudget()
    normalized = validate_proposal(proposal, budget)
    for step in normalized["steps"]:
        step["evidence_ids"].sort()
        step["hypothesis_ids"].sort()
        if "guard_ids" in step:
            step["guard_ids"].sort()
        for expression in step.get("arguments", {}).values():
            if expression.get("kind") == "source_function":
                expression["evidence_ids"].sort()
    for hypothesis in normalized["hypotheses"]:
        hypothesis["evidence_ids"].sort()
    normalized["hypotheses"].sort(key=lambda row: row["hypothesis_id"])
    identity = {
        "schema_version": SCHEMA_VERSION, "policy_version": POLICY_VERSION,
        "ft_id": ft["ft_id"], "ft_digest": digest(ft),
        "source_fingerprint": snapshot.source_fingerprint,
        "functions_fingerprint": snapshot.functions_fingerprint,
        "input_policy": {"source": "fuzzer", "max_input_bytes": budget.max_input_bytes},
        **deepcopy(normalized),
    }
    strategy_id = "strategy_" + digest(identity)[:24]
    calls = {step["step_id"]: step for step in normalized["steps"] if step["kind"] in ("call", "cleanup")}
    resources = []
    for step in normalized["steps"]:
        kind = step["kind"]
        if kind not in ("construct", "transform_input", "capture"):
            continue
        if kind == "capture":
            call = calls.get(step["call_step_id"], {})
            origin = {"kind": step["source"], "call_step_id": step["call_step_id"],
                      "function_id": call.get("function_id", ""), "parameter": step["parameter"]}
            type_name, pointer_depth = _capture_type(step, calls, snapshot)
            storage, ownership = "captured", "unknown"
        elif kind == "construct":
            origin = {"kind": kind, "step_id": step["step_id"]}
            type_name, pointer_depth = step["type_name"], step["pointer_depth"]
            storage, ownership = step["storage"], "unknown"
        else:
            origin = {"kind": kind, "step_id": step["step_id"]}
            type_name = step["type_name"]
            pointer_depth = 0 if step["operation"] == "decode_integer" else 1
            storage, ownership = "framework_managed", "framework_managed"
        resources.append({
            "resource_id": "resource_" + digest({"strategy_id": strategy_id, "origin": origin})[:24],
            "value_id": step["value_id"], "introduced_by": step["step_id"], "origin": origin,
            "type_name": type_name, "pointer_depth": pointer_depth, "storage": storage, "ownership": ownership,
        })
    strategy = {
        **identity, "artifact_kind": ARTIFACT_KIND, "strategy_id": strategy_id,
        "anchor_function_id": ft["anchor_function_id"],
        "core_function_ids": sorted(row["function_id"] if isinstance(row, dict) else row for row in ft.get("core_functions", [])),
        "resources": resources, "status": "proposed", "generation_allowed": False,
    }
    strategy["strategy_digest"] = digest(strategy)
    return strategy
