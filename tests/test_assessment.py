from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from tests.toolchain_probe import LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON

from harness_generation.assessment import collect_metrics, execute_pipeline
from harness_generation.config import CandidateConfig
from harness_generation.core import compile_harness
from harness_generation.smoke import run_smoke

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "benchmarks/mini_parser/target.c"
REFERENCE = ROOT / "benchmarks/mini_parser/harnesses/structured.c"
FUNCTION = "mp_parse"


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name)
        self.config = CandidateConfig(SOURCE, FUNCTION, self.output, fuzz_seconds=1)
        self.result = {"candidate_id": "test", "source_sha256": "source", "compilation": {"status": "not_started"},
                       "smoke": {"status": "not_started"}, "fuzzing": {"status": "not_started"}}

    @patch("harness_generation.assessment.run_fuzzer")
    @patch("harness_generation.assessment.run_smoke")
    @patch("harness_generation.assessment.compile_harness", return_value={"status": "failed"})
    def test_compile_failure_blocks_runtime_but_retains_metrics(self, compile_mock, smoke, fuzz):
        self.assertEqual(execute_pipeline(self.config, self.result), 1)
        smoke.assert_not_called()
        fuzz.assert_not_called()
        self.assertEqual(self.result["smoke"]["status"], "blocked")
        self.assertEqual(self.result["fuzzing"]["status"], "blocked")
        metrics = collect_metrics(self.result)
        self.assertEqual(metrics["stages"]["compilation"]["status"], "failed")
        self.assertEqual([m["name"] for m in metrics["measurements"]], ["compile_time"])

    @patch("harness_generation.assessment.run_fuzzer")
    @patch("harness_generation.assessment.run_smoke", return_value={"status": "finding", "completed_cases": 1})
    @patch("harness_generation.assessment.compile_harness", return_value={"status": "passed"})
    def test_smoke_finding_blocks_fuzz(self, compile_mock, smoke, fuzz):
        self.assertEqual(execute_pipeline(self.config, self.result), 1)
        fuzz.assert_not_called()
        self.assertEqual(self.result["failure_stage"], "smoke")
        self.assertEqual(self.result["fuzzing"]["status"], "blocked")

    @patch("harness_generation.assessment.run_fuzzer")
    @patch("harness_generation.assessment.run_smoke", return_value={
        "status": "finding",
        "completed_cases": 1,
        "crash_classification": {"classification": "potential_target_crash"},
    })
    @patch("harness_generation.assessment.compile_harness", return_value={"status": "passed"})
    def test_target_smoke_finding_is_not_harness_failure(
        self, compile_mock, smoke, fuzz,
    ):
        self.assertEqual(execute_pipeline(self.config, self.result), 0)
        fuzz.assert_not_called()
        self.assertNotIn("failure_stage", self.result)
        self.assertTrue(self.result["smoke"]["accepted"])
        self.assertEqual(self.result["fuzzing"]["status"], "blocked")

    def test_pipeline_order(self):
        events = []
        def stage(name, status):
            def invoke(*args):
                events.append(name)
                return {"status": status}
            return invoke
        with patch("harness_generation.assessment.compile_harness", side_effect=stage("compile", "passed")), \
             patch("harness_generation.assessment.run_smoke", side_effect=stage("smoke", "passed")), \
             patch("harness_generation.assessment.run_fuzzer", side_effect=stage("fuzz", "completed")):
            self.assertEqual(execute_pipeline(self.config, self.result), 0)
        self.assertEqual(events, ["compile", "smoke", "fuzz"])

    @patch("harness_generation.assessment.run_fuzzer", return_value={
        "status": "finding",
        "crash_classification": {"classification": "potential_target_crash"},
        "statistics": {"coverage_edges_or_blocks": 12, "features": 18},
    })
    @patch("harness_generation.assessment.run_smoke", return_value={"status": "passed"})
    @patch("harness_generation.assessment.compile_harness", return_value={"status": "passed"})
    def test_target_fuzz_finding_is_accepted_not_rollback_failure(
        self, compile_mock, smoke, fuzz,
    ):
        self.assertEqual(execute_pipeline(self.config, self.result), 0)
        self.assertNotIn("failure_stage", self.result)
        self.assertEqual(self.result["fuzzing"]["status"], "finding")
        self.assertTrue(self.result["fuzzing"]["accepted"])

    @patch("harness_generation.assessment.run_fuzzer", return_value={
        "status": "finding",
        "crash_classification": {"classification": "generated_harness_crash"},
        "statistics": {"coverage_edges_or_blocks": 12, "features": 18},
    })
    @patch("harness_generation.assessment.run_smoke", return_value={"status": "passed"})
    @patch("harness_generation.assessment.compile_harness", return_value={"status": "passed"})
    def test_harness_fuzz_finding_remains_failure(self, compile_mock, smoke, fuzz):
        self.assertEqual(execute_pipeline(self.config, self.result), 1)
        self.assertEqual(self.result["failure_stage"], "fuzzing")

    def test_missing_measurements_not_replaced_with_zero(self):
        result = collect_metrics(self.result)
        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["measurements"], [])
        self.result["fuzzing"] = {"status": "completed", "statistics": {"coverage_edges_or_blocks": 0}}
        measurement = collect_metrics(self.result)["measurements"][0]
        self.assertEqual(measurement["value"], 0)
        self.assertEqual(measurement["scope"], "instrumented_program")

    @unittest.skipUnless(LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON)
    def test_real_smoke_records_structured_reference_finding(self):
        shutil.copyfile(SOURCE, self.output / "target.c")
        shutil.copyfile(REFERENCE, self.output / "harness.c")
        self.assertEqual(compile_harness(self.output)["status"], "passed")
        result = run_smoke(self.output)
        self.assertEqual(result["status"], "finding")
        self.assertGreater(result["completed_cases"], 0)
        self.assertEqual(result["cases"][0]["size"], 0)
        self.assertEqual(result["cases"][-1]["size"], 4096)

    @unittest.skipUnless(LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON)
    def test_real_finding_records_trigger_input(self):
        (self.output / "harness.c").write_text('''#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!size) return 0;
    volatile uint8_t *p = (volatile uint8_t *)malloc(1);
    if (!p) return 0;
    p[data[0]] = 7; /* Intentional test bug. */
    free((void *)p);
    return 0;
}
''')
        self.assertEqual(compile_harness(self.output)["status"], "passed")
        result = run_smoke(self.output)
        self.assertEqual(result["status"], "finding")
        self.assertEqual(result["completed_cases"], 2)
        self.assertEqual(result["cases"][2]["name"], "one_ff")
        self.assertEqual(result["cases"][3]["status"], "not_started")
        self.assertIn("AddressSanitizer", (self.output / "smoke/one_ff_stderr.txt").read_text())
