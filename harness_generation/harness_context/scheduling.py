"""Bounded investigation allocation; no semantic facts or permissions are issued."""

VERSION = "frontier-budget-scheduling-v1"


def optional_allocation(state):
    """Leave a small, configurable part of existing calls for mandatory work.

    Reserves are clamped for small budgets and disabled for a single pass.
    These are absolute ceilings, never fresh per-batch budgets. A mandatory
    investigation or revision can use the original full FT budget.
    """
    budget = state.budget
    multiple_passes = budget.max_completeness_rounds > 1
    model_reserve = min(budget.repair_reserve_model_calls,
                        budget.max_total_model_calls // 3) if multiple_passes else 0
    tool_reserve = min(budget.repair_reserve_tool_calls,
                       budget.max_tool_calls // 3) if multiple_passes else 0
    model_limit = budget.max_total_model_calls - model_reserve
    tool_limit = budget.max_tool_calls - tool_reserve
    return {"version": VERSION, "model_limit": model_limit, "tool_limit": tool_limit,
            "reserved_model_calls": model_reserve, "reserved_tool_calls": tool_reserve,
            "remaining_optional_model_calls": max(0, model_limit - state.model_calls),
            "remaining_optional_tool_calls": max(0, tool_limit - state.tool_calls),
            "rule": "Optional ceilings protect existing calls. They never increase or reset the FT budget."}


def revisable_requirements(feedback, attempt_inputs, execution_failures, revision_counts):
    """Find previously submitted, explicitly targeted slots eligible for revision.

    This only changes scheduling. Source/transaction validators retain the
    authority to reject a replacement and the existing retry limits apply.
    """
    return {rid for item in feedback.get("items", [])
            if (item.get("category") == "contract_correction"
                or (item.get("category") == "missing_evidence"
                    and item.get("evidence_state", {}).get("complete_body_evidence_ids")))
            and item.get("correction_targets")
            for rid in item["repair_requirement_ids"]
            if any(isinstance(target, dict) and target.get('requirement_id') == rid
                and target.get('fact_id') for target in item['correction_targets'])
            if rid in attempt_inputs and rid not in execution_failures and not revision_counts.get(rid)}


def repair_routes(feedback):
    """Report where a blocked investigation belongs without executing a rollback.

    A route is diagnostic DATA. It cannot modify a frozen FT, authorize tools,
    clear a hard gap, or claim that an unsupported proof is repaired.
    """
    routes = []
    for item in feedback.get("items", []):
        category = item.get("category", "missing_evidence")
        if category == "upstream_blocker":
            stage, action = "semantic_slice", "review_frozen_upstream_scope"
        elif category == "unsupported":
            stage, action = "framework_source_proof", "implement_missing_proof_capability"
        elif category == "contract_correction":
            stage, action = "harness_context", "revise_linked_typed_slots"
        else:
            stage, action = "harness_context", "obtain_exact_missing_evidence"
        routes.append({"feedback_id": item["feedback_id"],
                       "requirement_ids": item["repair_requirement_ids"],
                       "subject_function_id": item["subject_function_id"],
                       "category": category, "recommended_stage": stage, "action": action,
                       "blocker_kind": item.get("blocker_kind"),
                       "next_action": item.get("actionable_blocker", {}).get("next_action"),
                       "missing_complete_body_function_ids": item.get("evidence_state", {}).get(
                           "missing_complete_body_function_ids", []),
                       "missing_source_roles": item.get("evidence_state", {}).get("missing_source_roles", []),
                       "automatically_executed": False,
                       "rule": "Diagnostic route only; scope, proof and budget checks still apply."})
    return routes
