import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.orchestrator import (
    PIPELINE_STAGES,
    STAGE_1_DOCS,
    STAGE_2_SNIPPETS,
    STAGE_3_ROUGH,
    STAGE_4_HARNESS,
    CallableStage,
    PipelineOrchestrator,
    PipelineState,
    StagedRollbackStrategy,
    latest_unresolved_rollback,
)
from harness_generation.validation import ValidationResult


class RecordingStage:
    def __init__(self, stage, events, validations=None):
        self.stage = stage
        self.events = events
        self.validations = list(validations or [True])
        self.run_count = 0

    def input(self, context):
        self.events.append((self.stage, "input", context.rollback_level))
        previous = context.checkpoint(type(self.stage)(int(self.stage) - 1)) \
            if self.stage != STAGE_1_DOCS else "root"
        return {"previous": previous, "run": self.run_count + 1}

    def run(self, stage_input):
        self.run_count += 1
        self.events.append((self.stage, "run", self.run_count))
        return {"stage": self.stage.name, "input": stage_input}

    def validate(self, output):
        self.events.append((self.stage, "validate", self.run_count))
        value = self.validations.pop(0) if self.validations else True
        return ValidationResult(
            success=value,
            errors=() if value else ("synthetic rejection",),
            warnings=(),
            metadata={"validator": "synthetic"},
        )

    def persist(self, output):
        self.events.append((self.stage, "persist", self.run_count))
        return {**output, "persisted": True}

    def checkpoint(self, persisted):
        self.events.append((self.stage, "checkpoint", self.run_count))
        return {"stage": self.stage.name, "run": self.run_count}


def pipeline(root, *, validations=None, maximum=3):
    events = []
    stages = []
    for stage in PIPELINE_STAGES:
        outcomes = validations if stage == STAGE_4_HARNESS else None
        stages.append(RecordingStage(stage, events, outcomes))
    orchestrator = PipelineOrchestrator(
        "ft_0001",
        stages,
        artifacts=root,
        max_regen_per_level=maximum,
    )
    return orchestrator, stages, events


class PipelineOrchestratorTests(unittest.TestCase):
    def test_success_calls_every_stage_phase_and_persists_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            orchestrator, stages, events = pipeline(Path(temporary))
            result = orchestrator.run()
            persisted = json.loads(result.state_path.read_text(encoding="utf-8"))

        self.assertTrue(result.success)
        self.assertEqual(
            result.state_path,
            Path(temporary) / "generation" / "ft_0001" / "pipeline_state.json",
        )
        self.assertEqual(result.state.status, "completed")
        self.assertEqual(result.state.current_stage, STAGE_4_HARNESS)
        self.assertEqual(persisted["ft_id"], "ft_0001")
        self.assertEqual(persisted["current_stage"], 4)
        self.assertEqual(persisted["attempt"], 1)
        self.assertIsNone(persisted["rollback_level"])
        self.assertTrue(persisted["history"])
        for stage in stages:
            phases = [event[1] for event in events if event[0] == stage.stage]
            self.assertEqual(
                phases, ["input", "run", "persist", "validate", "checkpoint"]
            )

    def test_stage4_failure_rolls_back_one_checkpoint_at_a_time(self):
        with tempfile.TemporaryDirectory() as temporary:
            orchestrator, stages, _ = pipeline(
                Path(temporary),
                validations=[False, False, False, False, True],
                maximum=1,
            )
            result = orchestrator.run()

        self.assertTrue(result.success)
        self.assertEqual([stage.run_count for stage in stages], [2, 3, 4, 5])
        rollbacks = [
            event for event in result.state.history if event["event"] == "rollback"
        ]
        self.assertEqual(
            [event["checkpoint_level"] for event in rollbacks], [3, 2, 1, 0]
        )
        self.assertEqual(
            [event["restart_stage"] for event in rollbacks],
            [
                "STAGE_4_HARNESS",
                "STAGE_3_ROUGH",
                "STAGE_2_SNIPPETS",
                "STAGE_1_DOCS",
            ],
        )
        for event in rollbacks:
            self.assertEqual(event["validator"], "synthetic")
            self.assertEqual(event["failure_type"], "validation_failed")
            self.assertEqual(event["rollback_target"], event["restart_stage"])
            self.assertIn("reason", event)
        self.assertEqual(result.state.rollback_level, 0)

    def test_configurable_regeneration_limit_retries_nearest_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            orchestrator, stages, _ = pipeline(
                Path(temporary), validations=[False, False, True], maximum=2
            )
            result = orchestrator.run()

        self.assertTrue(result.success)
        self.assertEqual([stage.run_count for stage in stages], [1, 1, 1, 3])
        rollbacks = [
            event for event in result.state.history if event["event"] == "rollback"
        ]
        self.assertEqual(
            [(event["checkpoint_level"], event["attempt"]) for event in rollbacks],
            [(3, 1), (3, 2)],
        )
        self.assertEqual(result.state.attempts_by_level, {3: 2})

    def test_exhausted_root_regeneration_returns_failed_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            orchestrator, _, _ = pipeline(
                Path(temporary), validations=[False] * 5, maximum=1
            )
            result = orchestrator.run()
            state = PipelineState.load(result.state_path)

        self.assertFalse(result.success)
        self.assertEqual(state.status, "failed")
        self.assertEqual(state.current_stage, STAGE_4_HARNESS)
        self.assertEqual(state.rollback_level, 0)
        self.assertEqual(state.attempt, 1)
        self.assertEqual(state.history[-1]["event"], "pipeline_failed")
        self.assertTrue(state.history[-1]["rollback_exhausted"])

    def test_callable_stage_adapts_existing_stage_functions(self):
        calls = []
        adapter = CallableStage(
            stage=STAGE_1_DOCS,
            input_fn=lambda context: calls.append("input") or context.ft_id,
            run_fn=lambda value: calls.append("run") or value,
            validate_fn=lambda value: calls.append("validate") or ValidationResult(
                True, (), (), {"validator": "synthetic"}
            ),
            persist_fn=lambda value: calls.append("persist") or value,
            checkpoint_fn=lambda value: calls.append("checkpoint") or value,
        )
        self.assertEqual(adapter.input(type("Context", (), {"ft_id": "ft_1"})()), "ft_1")
        output = adapter.run("ft_1")
        self.assertTrue(adapter.validate(output))
        persisted = adapter.persist(output)
        self.assertEqual(adapter.checkpoint(persisted), "ft_1")
        self.assertEqual(
            calls, ["input", "run", "validate", "persist", "checkpoint"]
        )

    def test_passed_with_limitations_is_explicit_and_accepted(self):
        statuses = (
            "passed", "passed_with_limitations", "passed", "passed"
        )
        stages = []
        for stage, status in zip(PIPELINE_STAGES, statuses):
            stages.append(CallableStage(
                stage=stage,
                input_fn=lambda context: context,
                run_fn=lambda context: context.stage,
                persist_fn=lambda output: output,
                validate_fn=lambda _output, status=status: ValidationResult(
                    success=True,
                    errors=(),
                    warnings=() if status == "passed" else (status,),
                    metadata={"validator": "synthetic"},
                    status=status,
                ),
                checkpoint_fn=lambda output: output,
            ))
        with tempfile.TemporaryDirectory() as temporary:
            result = PipelineOrchestrator(
                "ft_0001", stages, artifacts=temporary
            ).run()
        validations = [
            event for event in result.state.history
            if event["event"] == "stage_validated"
        ]
        self.assertTrue(result.success)
        self.assertEqual(
            [event["status"] for event in validations], list(statuses)
        )

    def test_strategy_default_and_configuration_validation(self):
        strategy = StagedRollbackStrategy()
        self.assertEqual(strategy.max_regen_per_level, 3)
        decision = strategy.after_failure(
            STAGE_4_HARNESS, checkpoint_level=None, attempt=1
        )
        self.assertEqual(decision.checkpoint_level, 3)
        self.assertEqual(decision.restart_stage, STAGE_4_HARNESS)
        with self.assertRaisesRegex(ValueError, "max_regen_per_level"):
            StagedRollbackStrategy(0)


class LatestUnresolvedRollbackTests(unittest.TestCase):
    def test_rollback_of_a_regenerated_stage_does_not_shadow_the_original(self):
        # The slice of a real run that motivated the rule: stage 4 fails first,
        # the wave restarts stage 3, stage 3 fails on its own, then stage 3
        # passes and is checkpointed. The newest rollback belongs to stage 3,
        # which has since been retired; stage 4 still owes an answer.
        history = [
            {"event": "stage_failed", "stage": "STAGE_4_HARNESS",
             "reason": "Stage4Error: HarnessPlan omits FT functions: node_process"},
            {"event": "rollback", "failed_stage": "STAGE_4_HARNESS",
             "rollback_target": "STAGE_3_ROUGH", "attempt": 1,
             "reason": "Stage4Error: HarnessPlan omits FT functions: node_process"},
            {"event": "stage_started", "stage": "STAGE_3_ROUGH"},
            {"event": "stage_failed", "stage": "STAGE_3_ROUGH",
             "reason": "unexpected target function calls: parser_free"},
            {"event": "rollback", "failed_stage": "STAGE_3_ROUGH",
             "rollback_target": "STAGE_3_ROUGH", "attempt": 2,
             "reason": "unexpected target function calls: parser_free"},
            {"event": "stage_started", "stage": "STAGE_3_ROUGH"},
            {"event": "stage_validated", "stage": "STAGE_3_ROUGH",
             "status": "passed", "validator": "stage3"},
            {"event": "checkpoint_created", "stage": "STAGE_3_ROUGH"},
            {"event": "stage_started", "stage": "STAGE_4_HARNESS"},
        ]
        selected = latest_unresolved_rollback(history)
        self.assertEqual(selected["failed_stage"], "STAGE_4_HARNESS")
        self.assertIn("omits FT functions", selected["reason"])

    def test_a_checkpoint_retires_limitations_just_as_plain_passes_do(self):
        # ``checkpoint_created`` is recorded only after validation.accepted, so
        # it retires a rollback for a stage that passed with declared
        # limitations too. A status comparison against "passed" alone would
        # leave that rollback shadowing forever.
        history = [
            {"event": "rollback", "failed_stage": "STAGE_3_ROUGH",
             "reason": "stage3"},
            {"event": "stage_validated", "stage": "STAGE_3_ROUGH",
             "status": "passed_with_limitations"},
            {"event": "checkpoint_created", "stage": "STAGE_3_ROUGH"},
        ]
        self.assertIsNone(latest_unresolved_rollback(history))

    def test_a_validation_alone_does_not_retire_without_a_checkpoint(self):
        # Validation and the checkpoint are separate events; only the
        # checkpoint means the pipeline accepted the stage and moved on.
        history = [
            {"event": "rollback", "failed_stage": "STAGE_3_ROUGH",
             "reason": "stage3"},
            {"event": "stage_validated", "stage": "STAGE_3_ROUGH",
             "status": "passed"},
        ]
        self.assertEqual(
            latest_unresolved_rollback(history)["failed_stage"], "STAGE_3_ROUGH"
        )

    def test_a_repeated_failure_reports_the_newer_rollback(self):
        history = [
            {"event": "rollback", "failed_stage": "STAGE_3_ROUGH", "reason": "old"},
            {"event": "checkpoint_created", "stage": "STAGE_3_ROUGH"},
            {"event": "rollback", "failed_stage": "STAGE_3_ROUGH", "reason": "new"},
        ]
        self.assertEqual(latest_unresolved_rollback(history)["reason"], "new")

    def test_every_retired_rollback_leaves_nothing_outstanding(self):
        history = [
            {"event": "rollback", "failed_stage": "STAGE_4_HARNESS",
             "reason": "cleared"},
            {"event": "checkpoint_created", "stage": "STAGE_4_HARNESS"},
        ]
        self.assertIsNone(latest_unresolved_rollback(history))
        self.assertIsNone(latest_unresolved_rollback([]))
        self.assertIsNone(latest_unresolved_rollback([
            {"event": "stage_validated", "stage": "STAGE_1_DOCS",
             "status": "passed"},
        ]))

    def test_malformed_history_is_skipped_rather_than_raising(self):
        history = [
            "not an event",
            {"event": "rollback"},
            {"event": "rollback", "failed_stage": 4},
            {"event": "checkpoint_created", "stage": 3},
            None,
            {"event": "rollback", "failed_stage": "STAGE_2_SNIPPETS",
             "reason": "survivor"},
        ]
        self.assertEqual(
            latest_unresolved_rollback(history)["reason"], "survivor"
        )

    def test_a_rollback_without_a_stage_is_reported_rather_than_dropped(self):
        # Malformed entries are not evidence that no failure happened, so the
        # newest rollback is still surfaced when it cannot be attributed to a
        # stage. Silence would be the one answer that hides a real problem.
        history = [
            {"event": "rollback", "failed_stage": "STAGE_3_ROUGH"},
            {"event": "rollback", "reason": "unattributed"},
        ]
        self.assertEqual(
            latest_unresolved_rollback(history)["reason"], "unattributed"
        )


if __name__ == "__main__":
    unittest.main()
