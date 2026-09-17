import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from harness_generation.fuzz_smoke import (
    LibFuzzerSmokeConfig,
    LibFuzzerSmokeValidator,
    parse_final_stats,
)
from harness_generation.pipeline_validation import (
    PipelineStageValidator,
    PipelineValidationConfig,
)
from harness_generation.stage4 import Stage4Result
from harness_generation.triplet import load_triplets_json
from tests.toolchain_probe import LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ARTIFACTS = ROOT / "artifacts" / "simple"
SIMPLE_PROJECT = ROOT / "tests" / "fixtures" / "simple_project"
HARNESS_CODE = """#include <stddef.h>
#include <stdint.h>
extern "C" {
#include "parser.h"
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Parser parser = {0};
    parser_from_memory(&parser, data, (unsigned long)size);
    Node node = parser_next(&parser);
    node_process(&node);
    parser_free(&parser);
    return 0;
}
"""


SUCCESS_LOG = """INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1
#2 DONE   cov: 8 ft: 10 corp: 4/7b lim: 4 exec/s: 22 rss: 30Mb
stat::number_of_executed_units: 42
stat::average_exec_per_sec: 21
"""


class FakeRunner:
    def __init__(self, *, returncode=0, stderr=SUCCESS_LOG, effect=None):
        self.returncode = returncode
        self.stderr = stderr
        self.effect = effect
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if isinstance(self.effect, BaseException):
            raise self.effect
        if self.effect is not None:
            self.effect(command)
        return subprocess.CompletedProcess(command, self.returncode, "", self.stderr)


class LibFuzzerSmokeTests(unittest.TestCase):
    def executable(self, root):
        path = root / "fuzzer"
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_duration_is_bounded_and_defaults_to_sixty_seconds(self):
        self.assertEqual(LibFuzzerSmokeConfig().duration_seconds, 60)
        self.assertEqual(
            PipelineValidationConfig().fuzz_smoke.duration_seconds, 60
        )
        for value in (29, 121, True, 60.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                LibFuzzerSmokeConfig(duration_seconds=value)
        with self.assertRaises(ValueError):
            LibFuzzerSmokeConfig(duration_seconds=60, process_timeout_seconds=60)

    def test_success_persists_bounded_command_corpus_and_observed_stats(self):
        runner = FakeRunner()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "artifacts"
            result = LibFuzzerSmokeValidator(
                LibFuzzerSmokeConfig(30), runner=runner
            ).validate_triplet(
                self.executable(root),
                artifacts=artifacts,
                ft_id="ft_smoke_success",
                generated_sources=(root / "harness.c",),
                target_root=root / "target",
            )
            smoke = artifacts / "fuzz/ft_smoke_success/smoke_001"
            metadata = json.loads((smoke / "metadata.json").read_text())
            stats = json.loads((smoke / "final_stats.json").read_text())

            self.assertEqual(result.status, "passed")
            self.assertEqual(runner.calls[0][1]["timeout"], 45)
            self.assertIn("-max_total_time=30", runner.calls[0][0])
            self.assertIn("-print_final_stats=1", runner.calls[0][0])
            self.assertEqual((smoke / "corpus/empty").read_bytes(), b"")
            self.assertEqual(len(list((smoke / "corpus").iterdir())), 4)
            self.assertTrue((smoke / "crashes").is_dir())
            self.assertTrue((smoke / "command.txt").read_text().strip())
            self.assertTrue((smoke / "stdout.txt").is_file())
            self.assertTrue((smoke / "stderr.txt").is_file())
            self.assertEqual(stats["execs_done"], 42)
            self.assertEqual(stats["execs_per_sec"], 21)
            self.assertEqual(stats["cov"], 8)
            self.assertEqual(stats["ft"], 10)
            self.assertEqual(stats["corp"], 4)
            self.assertEqual(stats["crashes"], 0)
            self.assertTrue(metadata["initialized"])
            self.assertTrue(metadata["final_stats_present"])
            self.assertNotIn("LLM_API_KEY", runner.calls[0][1]["env"])

    def test_unobserved_output_fields_are_not_invented(self):
        with tempfile.TemporaryDirectory() as temporary:
            crashes = Path(temporary)
            stats, final = parse_final_stats(
                "INFO: Seed: 1\nstat::number_of_executed_units: 3\n",
                crashes,
            )
        self.assertTrue(final)
        self.assertEqual(stats["execs_done"], 3)
        self.assertNotIn("cov", stats)
        self.assertNotIn("ft", stats)
        self.assertNotIn("corp", stats)

    def test_target_crash_preserves_input_without_triggering_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target/src/parser.c"
            target.parent.mkdir(parents=True)
            target.write_text("int target;\n", encoding="utf-8")

            def save_crash(command):
                prefix = next(arg.split("=", 1)[1] for arg in command
                              if arg.startswith("-artifact_prefix="))
                (Path(prefix) / "crash-deadbeef").write_bytes(b"bad")

            runner = FakeRunner(
                returncode=77,
                stderr=("INFO: Seed: 1\n#1 NEW cov: 2 ft: 2 corp: 1/1b\n"
                        f"#0 0x123 in parser_from_memory {target}:4:2\n"),
                effect=save_crash,
            )
            artifacts = root / "artifacts"
            result = LibFuzzerSmokeValidator(
                LibFuzzerSmokeConfig(30), runner=runner
            ).validate_triplet(
                self.executable(root), artifacts=artifacts,
                ft_id="ft_target_crash", generated_sources=(root / "harness.c",),
                target_root=root / "target",
            )
            smoke = artifacts / "fuzz/ft_target_crash/smoke_001"
            metadata = json.loads((smoke / "metadata.json").read_text())

        self.assertEqual(result.status, "passed_with_limitations")
        self.assertTrue(result.accepted)
        self.assertEqual(metadata["crash_classification"], "potential_target_crash")
        self.assertEqual(metadata["crash_inputs"], ["crashes/crash-deadbeef"])

    def test_generated_harness_crash_and_timeout_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated = root / "harness.c"
            generated.write_text("int harness;\n", encoding="utf-8")
            runner = FakeRunner(
                returncode=-11,
                stderr=f"INFO: Seed: 1\n#0 0x123 in fuzzer {generated}:7:3\n",
            )
            result = LibFuzzerSmokeValidator(
                LibFuzzerSmokeConfig(30), runner=runner
            ).validate_triplet(
                self.executable(root), artifacts=root / "artifacts",
                ft_id="ft_harness_crash", generated_sources=(generated,),
                target_root=root / "target",
            )
            timeout_runner = FakeRunner(effect=subprocess.TimeoutExpired(
                ["fuzzer"], 45, output=b"partial", stderr=b"still running"
            ))
            timed_out = LibFuzzerSmokeValidator(
                LibFuzzerSmokeConfig(30), runner=timeout_runner
            ).validate_triplet(
                self.executable(root), artifacts=root / "artifacts",
                ft_id="ft_timeout", generated_sources=(generated,),
                target_root=root / "target",
            )

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.metadata["failure_type"], "generated_harness_crash")
        self.assertEqual(timed_out.status, "failed")
        self.assertEqual(timed_out.metadata["failure_type"], "fuzz_smoke_timeout")

    def test_attempt_ids_are_monotonic_and_existing_attempt_is_preserved(self):
        runner = FakeRunner()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = self.executable(root)
            validator = LibFuzzerSmokeValidator(
                LibFuzzerSmokeConfig(30), runner=runner
            )
            for _ in range(2):
                validator.validate_triplet(
                    executable, artifacts=root / "artifacts", ft_id="ft_attempts",
                    generated_sources=(root / "harness.c",),
                    target_root=root / "target",
                )
            attempts = sorted(path.name for path in (
                root / "artifacts/fuzz/ft_attempts"
            ).iterdir())
        self.assertEqual(attempts, ["smoke_001", "smoke_002"])

    @unittest.skipUnless(LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON)
    def test_stage4_runs_fuzz_smoke_only_after_real_build_and_runtime(self):
        runner = FakeRunner()
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copy2(SOURCE_ARTIFACTS / name, artifacts / name)
            triplet = load_triplets_json(artifacts / "triplets.json")[0]
            generation = artifacts / "generation" / triplet.id
            attempt = generation / "stage4/attempt_001"
            attempt.mkdir(parents=True)
            harness = generation / "stage4_harness.c"
            harness.write_text(HARNESS_CODE, encoding="utf-8")
            result = PipelineStageValidator(
                triplet,
                artifacts=artifacts,
                functions_json=artifacts / "functions.json",
                project_root=SIMPLE_PROJECT,
                config=PipelineValidationConfig(
                    fuzz_smoke=LibFuzzerSmokeConfig(30), fuzz_runner=runner
                ),
            ).validate_stage4(Stage4Result(
                triplet_id=triplet.id,
                harness_code=HARNESS_CODE,
                harness_path=harness,
                stable_path=None,
                generation_metadata={},
                attempt_directory=attempt,
            ))

            self.assertEqual(result.status, "passed")
            self.assertEqual(result.metadata["component_statuses"],
                             ("passed", "passed", "passed", "passed", "passed"))
            self.assertTrue((artifacts / "build" / triplet.id / "fuzzer").is_file())
            self.assertTrue((artifacts / "fuzz" / triplet.id /
                             "smoke_001/metadata.json").is_file())
            self.assertEqual(len(runner.calls), 1)


if __name__ == "__main__":
    unittest.main()
