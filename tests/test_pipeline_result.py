"""The reported failure belongs to the attempt that determines the result."""

from pathlib import Path
import tempfile
import unittest

from harness_generation.orchestrator import PipelineRunResult, PipelineState
from harness_generation.pipeline_result import PipelineResult


class FailureAttributionTests(unittest.TestCase):
    def result(self, history, *, run_succeeded):
        with tempfile.TemporaryDirectory() as temporary:
            state = PipelineState(ft_id="ft_test")
            state.history = history
            run = PipelineRunResult(
                run_succeeded, state, Path(temporary) / "state.json", {}, {}
            )
            return PipelineResult.from_run(
                run,
                artifacts=temporary,
                validate_requested=True,
                build_requested=False,
                fuzz_requested=False,
            )

    def test_recovered_failure_cannot_explain_missing_current_milestone(self):
        result = self.result([
            {"event": "stage_failed", "stage": "STAGE_4_HARNESS",
             "reason": "HarnessPlan duplicates FT functions: mp_destroy"},
            {"event": "rollback", "failed_attempt": 1, "attempt": 2,
             "rollback_target": "STAGE_4_HARNESS"},
            {"event": "checkpoint_created", "stage": "STAGE_4_HARNESS",
             "attempt": 2},
            {"event": "pipeline_completed", "stage": "STAGE_4_HARNESS"},
        ], run_succeeded=True)

        self.assertFalse(result.success)
        self.assertEqual(result.failure_reason, "validation did not pass")
        self.assertEqual(result.rollback_count, 1)

    def test_terminal_failure_after_rollback_remains_specific(self):
        result = self.result([
            {"event": "stage_failed", "stage": "STAGE_4_HARNESS",
             "reason": "old failure"},
            {"event": "rollback", "failed_attempt": 1, "attempt": 2},
            {"event": "stage_failed", "stage": "STAGE_4_HARNESS",
             "reason": "current compiler failure"},
            {"event": "pipeline_failed", "stage": "STAGE_4_HARNESS",
             "reason": "current compiler failure"},
        ], run_succeeded=False)

        self.assertEqual(result.failure_reason, "current compiler failure")


if __name__ == "__main__":
    unittest.main()
