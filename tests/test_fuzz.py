import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from harness_generation.core import compile_harness
from harness_generation.fuzz import run_fuzzer
from tests.toolchain_probe import LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "benchmarks/mini_parser/target.c"
REFERENCE = ROOT / "benchmarks/mini_parser/harnesses/structured.c"


class FuzzTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "run"
        self.output.mkdir()

    @unittest.skipUnless(LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON)
    def test_structured_reference_finds_target_bug(self):
        shutil.copyfile(SOURCE, self.output / "target.c")
        shutil.copyfile(REFERENCE, self.output / "harness.c")
        self.assertEqual(compile_harness(self.output)["status"], "passed")
        result = run_fuzzer(self.output, 1, ROOT / "benchmarks/mini_parser/corpus/structured")
        self.assertEqual(result["status"], "finding")
        self.assertTrue(result["findings"])
        self.assertTrue(result["artifacts"])
        self.assertGreater(result["statistics"]["number_of_executed_units"], 0)
        self.assertGreater(result["statistics"]["coverage_edges_or_blocks"], 0)

    @unittest.skipUnless(LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON)
    def test_real_asan_finding_and_reproduction(self):
        (self.output / "harness.c").write_text('''#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;
    volatile uint8_t *buffer = (volatile uint8_t *)malloc(1);
    if (!buffer) return 0;
    buffer[data[0]] = 42; /* Intentional regression fixture: heap overflow. */
    free((void *)buffer);
    return 0;
}
''')
        self.assertEqual(compile_harness(self.output)["status"], "passed")
        seeds = Path(self.temp.name) / "seeds"
        seeds.mkdir()
        (seeds / "trigger").write_bytes(b"\x08")
        result = run_fuzzer(self.output, 1, seeds)
        self.assertEqual(result["status"], "finding")
        self.assertIn("address_sanitizer", result["findings"])
        self.assertTrue(result["artifacts"])
        self.assertEqual(list(seeds.iterdir()), [seeds / "trigger"])
        self.assertEqual((seeds / "trigger").read_bytes(), b"\x08")
        reproduced = subprocess.run(["./fuzz_target", result["artifacts"][0]], cwd=self.output,
                                    capture_output=True, timeout=10,
                                    env={"PATH": os.defpath, "ASAN_OPTIONS": "symbolize=0:abort_on_error=1"})
        self.assertNotEqual(reproduced.returncode, 0)
        self.assertIn(b"heap-buffer-overflow", reproduced.stderr)

    @patch("harness_generation.fuzz.os.killpg")
    @patch("harness_generation.fuzz.subprocess.Popen")
    def test_wall_timeout_cleans_up_and_removes_credentials(self, popen, killpg):
        process = popen.return_value
        process.pid = 12345
        process.returncode = -9
        process.wait.side_effect = [subprocess.TimeoutExpired("fuzz_target", 8), -9]
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "secret", "ASAN_OPTIONS": "bad-option"}):
            result = run_fuzzer(self.output, 1)
        self.assertEqual(result["status"], "wall_timeout")
        killpg.assert_called_once()
        self.assertNotIn("DEEPSEEK_API_KEY", popen.call_args.kwargs["env"])
        self.assertNotEqual(popen.call_args.kwargs["env"]["ASAN_OPTIONS"], "bad-option")

    @patch("harness_generation.fuzz.os.killpg")
    @patch("harness_generation.fuzz.subprocess.Popen")
    def test_interrupt_saved(self, popen, killpg):
        process = popen.return_value
        process.returncode = -9
        process.wait.side_effect = [KeyboardInterrupt, -9]
        result = run_fuzzer(self.output, 1)
        self.assertEqual(result["status"], "interrupted")
        self.assertTrue((self.output / "fuzz_result.json").exists())
        killpg.assert_called_once()

    def test_missing_executable_is_error_not_finding(self):
        result = run_fuzzer(self.output, 1)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["findings"], [])

    @patch("harness_generation.fuzz.run_logged")
    def test_runs_replaces_the_wall_clock_budget(self, run_logged):
        run_logged.return_value = {"status": "completed", "returncode": 0}
        (self.output / "fuzz_stderr.txt").write_text("", encoding="utf-8")

        result = run_fuzzer(self.output, 1, runs=2000)

        command = run_logged.call_args.args[1]
        self.assertIn("-runs=2000", command)
        self.assertNotIn("-max_total_time=1", command)
        # The wall cap survives the switch: it bounds the process either way,
        # so a run that overshoots is still reported instead of hanging.
        self.assertEqual(run_logged.call_args.args[2], 8)
        self.assertEqual(result["requested_runs"], 2000)
        self.assertEqual(
            json.loads((self.output / "fuzz_command.json").read_text())[2],
            "-runs=2000",
        )

    @patch("harness_generation.fuzz.run_logged")
    def test_the_default_budget_is_still_wall_clock(self, run_logged):
        run_logged.return_value = {"status": "completed", "returncode": 0}
        (self.output / "fuzz_stderr.txt").write_text("", encoding="utf-8")

        result = run_fuzzer(self.output, 1)

        command = run_logged.call_args.args[1]
        self.assertIn("-max_total_time=1", command)
        self.assertFalse([item for item in command if item.startswith("-runs=")])
        self.assertIsNone(result["requested_runs"])

    @patch("harness_generation.fuzz.run_logged")
    def test_the_seed_defaults_to_the_one_this_always_ran_with(self, run_logged):
        """A single harness is described fine by it, so nothing changes here."""

        run_logged.return_value = {"status": "completed", "returncode": 0}
        (self.output / "fuzz_stderr.txt").write_text("", encoding="utf-8")

        result = run_fuzzer(self.output, 1)

        self.assertIn("-seed=1", run_logged.call_args.args[1])
        self.assertEqual(result["seed"], 1)

    @patch("harness_generation.fuzz.run_logged")
    def test_and_a_named_seed_is_what_reaches_the_engine(self, run_logged):
        """Repeats at one seed replay one search; comparing harnesses needs more."""

        run_logged.return_value = {"status": "completed", "returncode": 0}
        (self.output / "fuzz_stderr.txt").write_text("", encoding="utf-8")

        result = run_fuzzer(self.output, 1, runs=2000, seed=7)

        command = run_logged.call_args.args[1]
        self.assertIn("-seed=7", command)
        self.assertNotIn("-seed=1", command)
        self.assertEqual(result["seed"], 7)
        self.assertEqual(
            json.loads((self.output / "fuzz_command.json").read_text()),
            command,
        )

    @patch("harness_generation.fuzz.run_logged")
    def test_fuzz_finding_is_attributed_to_target_or_harness(self, run_logged):
        target = self.output / "target.c"
        harness = self.output / "harness.c"
        target.write_text("int target;\n", encoding="utf-8")
        harness.write_text("int harness;\n", encoding="utf-8")

        def fake_run(output, command, wall_timeout, stdout_file, stderr_file):
            (output / stdout_file).write_text("", encoding="utf-8")
            (output / stderr_file).write_text(
                f"ERROR: AddressSanitizer: boom\n#0 0x1 in mp_parse {target}:3:2\n",
                encoding="utf-8",
            )
            return {"status": "error", "returncode": 1}

        run_logged.side_effect = fake_run
        result = run_fuzzer(self.output, 1)

        self.assertEqual(result["status"], "finding")
        self.assertEqual(
            result["crash_classification"]["classification"],
            "potential_target_crash",
        )
        persisted = json.loads((self.output / "fuzz_result.json").read_text())
        self.assertEqual(
            persisted["crash_classification"]["classification"],
            "potential_target_crash",
        )
