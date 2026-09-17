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


if __name__ == "__main__":
    unittest.main()
