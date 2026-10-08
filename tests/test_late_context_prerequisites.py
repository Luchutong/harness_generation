"""Late cleanup proofs must schedule their unasked order within the same pass."""
import pytest
from harness_generation.harness_context import ContextBudget, HarnessContextMiningLoop
from test_callback_boundaries import callback_plan
from test_harness_context import assert_gate, ScriptedModel


@pytest.mark.parametrize("model_cap", [80, 24])
def test_final_cleanup_repair_investigates_new_creator_order_without_fourth_pass(tmp_path, model_cap):
    prepared, specs = callback_plan(tmp_path, prepared_only=True,
        budget=ContextBudget(max_total_model_calls=model_cap, max_tool_calls=64,
            max_source_chars=96000, max_completeness_rounds=3))
    ids = prepared[0][-1]
    # The source says this return is owned. The release/order claim arrives
    # only after the agent's last lifecycle repair; it is never supplied by a
    # framework default.
    specs[ids["acquire"], "ownership"]["value"]["entries"][0]["release_api"] = None
    lifecycle_submissions = 0

    def delay_cleanup(requirement, result):
        nonlocal lifecycle_submissions
        if requirement["subject_function_id"] == ids["acquire"] and requirement["kind"] == "lifecycle":
            lifecycle_submissions += 1
            if lifecycle_submissions < 3:
                resource = result["facts"][0]["value"]["resources"][0]
                resource["cleanup"] = {"api": None, "mandatory": lifecycle_submissions == 2}
                result["discovered_api_dependencies"] = []

    model = ScriptedModel(specs, query_type="User",
        initial_ids=prepared[5].initial_ids, mutate=delay_cleanup)
    run = HarnessContextMiningLoop(model, prepared[4]).run(
        prepared[1], prepared[3], prepared[5])
    assert prepared[4].model_calls <= model_cap
    assert prepared[4].tool_calls <= 64
    assert prepared[4].source_chars <= 96000
    if model_cap == 24:
        # This single-requirement fixture intentionally costs more than the
        # production grouped fixture. A late prerequisite cannot bypass its
        # explicit lower cap or turn the remaining unknowns into defaults.
        assert_gate(run, "incomplete")
        assert prepared[4].model_calls == 24
        assert run.metadata["termination"] == "max_total_model_calls"
        return
    assert_gate(run)
    assert lifecycle_submissions == 3
    assert run.metadata["metrics"]["completeness_rounds"] == 3
    creator_order = next(row for row in run.requirements["requirements"]
        if row["subject_function_id"] == ids["acquire"] and row["kind"] == "call_order")
    assert creator_order["status"] == "resolved"
    activated = [row for row in run.metadata["late_prerequisite_activations"]
        if row["requirement_id"] == creator_order["requirement_id"]]
    assert activated and activated[-1]["round"] == 3
    assert any(creator_order["requirement_id"] in row["requirement_ids"] and row["round"] == 3
        for row in run.metadata["investigation_schedule"])
    assert run.context["lifecycle_contract"]["resources"]
