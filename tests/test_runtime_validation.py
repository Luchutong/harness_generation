import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from harness_generation.runtime_validation import (
    CRASH_CLASSIFICATIONS,
    RuntimeValidationResult,
    RuntimeValidator,
)


class FakeRunner:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if isinstance(self.result, BaseException):
            raise self.result
        return subprocess.CompletedProcess(command, *self.result)


class SequenceRunner:
    def __init__(self, *results):
        self.results = list(results)
        self.calls = []
        self.inputs = []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        self.inputs.append(Path(command[-1]).read_bytes())
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return subprocess.CompletedProcess(command, *result)


class CrashClassificationAuthorityTests(unittest.TestCase):
    """Every consumer must read the classification from its one definition.

    These strings are written into saved metadata and read back by evaluators,
    feedback loops and promotion gates. A consumer holding its own literal stops
    covering new values the moment one is added -- silently, because an
    unmatched string falls through to whatever the `else` branch does.
    """

    def test_only_the_defining_module_spells_the_classifications(self):
        root = Path(__file__).resolve().parents[1] / "harness_generation"
        offenders = []
        for path in sorted(root.rglob("*.py")):
            if path.name == "runtime_validation.py":
                continue
            text = path.read_text(encoding="utf-8")
            for value in CRASH_CLASSIFICATIONS:
                if f'"{value}"' in text or f"'{value}'" in text:
                    offenders.append(f"{path.relative_to(root)}: {value}")
        # `generated_harness_crash` doubles as a failure_type string, which is a
        # separate namespace with its own literal at the point of use.
        offenders = [item for item in offenders
                     if not item.endswith(": generated_harness_crash")]
        self.assertEqual(offenders, [])


class RuntimeValidatorTests(unittest.TestCase):
    @staticmethod
    def executable(root: Path) -> Path:
        path = root / "fuzz_target"
        path.write_text("test executable placeholder", encoding="utf-8")
        path.chmod(path.stat().st_mode | 0o111)
        return path

    def test_available_executable_runs_smoke_test_with_default_timeout(self):
        runner = FakeRunner((0, "smoke stdout", "smoke stderr"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = self.executable(root)
            validation = root / "validation.json"
            result = RuntimeValidator(runner=runner).validate(
                executable,
                arguments=("-runs=1", "seed.bin"),
                validation_path=validation,
            )
            persisted = json.loads(validation.read_text(encoding="utf-8"))

        self.assertEqual(result.status, "passed")
        self.assertTrue(result.success)
        self.assertEqual(result.timeout_seconds, 30.0)
        self.assertEqual(result.command, (
            str(executable.resolve()), "-runs=1", "seed.bin"
        ))
        self.assertEqual(result.stdout, "smoke stdout")
        self.assertEqual(result.stderr, "smoke stderr")
        self.assertEqual(result.return_code, 0)
        self.assertFalse(result.timed_out)
        self.assertEqual(persisted, result.to_dict())
        self.assertEqual(runner.calls[0][1]["timeout"], 30.0)
        self.assertEqual(runner.calls[0][1]["cwd"], executable.parent)

    def test_missing_executable_is_skipped_with_reason_and_not_success(self):
        runner = FakeRunner((0, "must not run", ""))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = root / "missing_target"
            validation = root / "validation.json"
            result = RuntimeValidator(runner=runner).validate(
                missing, validation_path=validation
            )
            persisted = json.loads(validation.read_text(encoding="utf-8"))

        self.assertEqual(result.status, "skipped")
        self.assertIsNone(result.success)
        self.assertIn("does not exist", result.reason)
        self.assertIsNone(result.return_code)
        self.assertEqual(runner.calls, [])
        self.assertEqual(persisted["status"], "skipped")
        self.assertIsNone(persisted["success"])
        self.assertTrue(persisted["reason"])

    def test_no_executable_is_explicitly_skipped(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = RuntimeValidator().validate(
                None, validation_path=Path(temporary) / "validation.json"
            )
        self.assertEqual(result.status, "skipped")
        self.assertEqual(result.reason, "executable was not provided")
        self.assertEqual(result.command, ())

    def test_non_executable_file_is_skipped(self):
        runner = FakeRunner((0, "must not run", ""))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "target"
            path.write_text("not executable", encoding="utf-8")
            path.chmod(path.stat().st_mode & ~0o111)
            result = RuntimeValidator(runner=runner).validate(
                path, validation_path=Path(temporary) / "validation.json"
            )
        self.assertEqual(result.status, "skipped")
        self.assertIn("not executable", result.reason)
        self.assertEqual(runner.calls, [])

    def test_nonzero_exit_is_failed_and_preserves_output(self):
        runner = FakeRunner((7, "partial work", "runtime failure"))
        with tempfile.TemporaryDirectory() as temporary:
            executable = self.executable(Path(temporary))
            result = RuntimeValidator(runner=runner).validate(
                executable,
                validation_path=Path(temporary) / "validation.json",
                working_directory=Path(temporary) / "work",
            )
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.success)
        self.assertEqual(result.return_code, 7)
        self.assertEqual(result.stdout, "partial work")
        self.assertEqual(result.stderr, "runtime failure")
        self.assertIn("return code 7", result.reason)
        self.assertEqual(
            runner.calls[0][1]["cwd"], Path(temporary) / "work"
        )

    def test_timeout_is_not_reported_as_success(self):
        timeout = subprocess.TimeoutExpired(
            ["fuzz_target"], 4, output=b"partial stdout", stderr=b"hung"
        )
        runner = FakeRunner(timeout)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = self.executable(root)
            validation = root / "validation.json"
            result = RuntimeValidator(timeout=4, runner=runner).validate(
                executable, validation_path=validation
            )
            persisted = json.loads(validation.read_text(encoding="utf-8"))

        self.assertEqual(result.status, "timed_out")
        self.assertFalse(result.success)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.timeout_seconds, 4)
        self.assertEqual(result.stdout, "partial stdout")
        self.assertEqual(result.stderr, "hung")
        self.assertIsNone(result.return_code)
        self.assertTrue(persisted["timed_out"])

    def test_start_failure_becomes_skipped_instead_of_passed(self):
        runner = FakeRunner(OSError("exec format error"))
        with tempfile.TemporaryDirectory() as temporary:
            executable = self.executable(Path(temporary))
            result = RuntimeValidator(runner=runner).validate(
                executable,
                validation_path=Path(temporary) / "validation.json",
            )
        self.assertEqual(result.status, "skipped")
        self.assertIsNone(result.success)
        self.assertIn("could not be started", result.reason)

    def test_result_and_validator_reject_inconsistent_configuration(self):
        with self.assertRaisesRegex(ValueError, "timeout"):
            RuntimeValidator(timeout=float("inf"))
        with self.assertRaisesRegex(ValueError, "requires a reason"):
            RuntimeValidationResult(
                status="skipped",
                reason=None,
                stdout="",
                stderr="",
                return_code=None,
                command=(),
                timed_out=False,
                timeout_seconds=30,
                metadata={},
            )

    def test_fixed_input_smoke_runs_empty_and_minimal_without_fuzzing(self):
        runner = SequenceRunner((0, "empty", ""), (0, "minimal", ""))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = self.executable(root)
            artifacts = root / "artifacts"
            result = RuntimeValidator(runner=runner).validate_smoke_triplet(
                executable,
                artifacts=artifacts,
                ft_id="ft_runtime_smoke",
                generated_sources=(root / "stage4_harness.c",),
                target_root=root / "target",
            )
            document = json.loads((
                artifacts / "generation/ft_runtime_smoke/validation/runtime.json"
            ).read_text(encoding="utf-8"))

        self.assertEqual(result.status, "passed")
        self.assertEqual(runner.inputs, [b"", b"\x00"])
        self.assertEqual(len(runner.calls), 2)
        self.assertTrue(all(
            not any(argument.startswith("-runs=") for argument in call[0])
            for call in runner.calls
        ))
        self.assertLessEqual(runner.calls[0][1]["timeout"], 30)
        self.assertEqual(document["metadata"]["mode"], "fixed_inputs")
        self.assertFalse(document["metadata"]["fuzzing"])
        self.assertEqual(
            [case["input_size"] for case in document["metadata"]["cases"]],
            [0, 1],
        )

    def test_generated_harness_crash_is_validation_failure_with_signal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = self.executable(root)
            generated = root / "generation" / "stage4_harness.c"
            generated.parent.mkdir()
            generated.write_text("int harness;\n", encoding="utf-8")
            stderr = (
                "AddressSanitizer:DEADLYSIGNAL\n"
                f"#0 0x123 in LLVMFuzzerTestOneInput {generated}:7:3\n"
            )
            runner = SequenceRunner((0, "", ""), (-11, "", stderr))
            artifacts = root / "artifacts"
            result = RuntimeValidator(runner=runner).validate_smoke_triplet(
                executable,
                artifacts=artifacts,
                ft_id="ft_harness_crash",
                generated_sources=(generated,),
                target_root=root / "target",
            )
            document = json.loads((
                artifacts / "generation/ft_harness_crash/validation/runtime.json"
            ).read_text(encoding="utf-8"))

        self.assertEqual(result.status, "failed")
        self.assertEqual(
            result.metadata["failure_type"], "generated_harness_crash"
        )
        crashed = document["metadata"]["cases"][1]
        self.assertEqual(crashed["signal"], 11)
        self.assertEqual(crashed["signal_name"], "SIGSEGV")
        self.assertEqual(crashed["stack_parser_status"], "parsed")

    def test_target_crash_is_preserved_without_requesting_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = self.executable(root)
            target_root = root / "target"
            target_source = target_root / "src/parser.c"
            target_source.parent.mkdir(parents=True)
            target_source.write_text("int parser;\n", encoding="utf-8")
            stderr = f"#0 0x456 in parser_from_memory {target_source}:9:5\n"
            runner = SequenceRunner((0, "", ""), (1, "", stderr))
            result = RuntimeValidator(runner=runner).validate_smoke_triplet(
                executable,
                artifacts=root / "artifacts",
                ft_id="ft_target_crash",
                generated_sources=(root / "stage4_harness.c",),
                target_root=target_root,
            )

        self.assertEqual(result.status, "passed_with_limitations")
        self.assertTrue(result.accepted)
        self.assertEqual(
            result.metadata["crash_classification"], "potential_target_crash"
        )

    @staticmethod
    def leak_stderr(target_source: Path, harness: Path | None = None) -> str:
        """Reproduce a LeakSanitizer report's frame order.

        The allocation site is the target's allocator and the frame that
        answers for it, when it is present at all, is the generated entry point
        four frames down -- exactly the shape observed for the json-parser
        harness.
        """
        frames = [
            "    #0 0x55d1 in calloc\n",
            f"    #1 0x55d2 in new_value {target_source}:280:34\n",
            f"    #2 0x55d3 in json_parse_ex {target_source}:768:33\n",
            f"    #3 0x55d4 in json_parse {target_source}:1128:11\n",
        ]
        if harness is not None:
            frames.append(
                f"    #4 0x55d5 in LLVMFuzzerTestOneInput {harness}:11:20\n"
            )
        frames.append(
            "    #5 0x55d6 in fuzzer::Fuzzer::ExecuteCallback(unsigned char "
            "const*, unsigned long)\n"
        )
        return (
            "=================================================================\n"
            "==85934==ERROR: LeakSanitizer: detected memory leaks\n"
            "\n"
            "Direct leak of 40 byte(s) in 1 object(s) allocated from:\n"
            + "".join(frames)
            + "\nSUMMARY: AddressSanitizer: 40 byte(s) leaked in 1 allocation(s).\n"
        )

    def test_mixed_leak_stack_is_blocked_without_claiming_fault_ownership(self):
        """An allocation stack cannot prove which side omitted the release."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = self.executable(root)
            target_source = root / "target" / "json.c"
            target_source.parent.mkdir(parents=True)
            target_source.write_text("int json;\n", encoding="utf-8")
            harness = root / "run" / "harness.c"
            harness.parent.mkdir(parents=True)
            harness.write_text("int harness;\n", encoding="utf-8")
            runner = SequenceRunner(
                (0, "", ""), (77, "", self.leak_stderr(target_source, harness))
            )
            result = RuntimeValidator(runner=runner).validate_smoke_triplet(
                executable,
                artifacts=root / "artifacts",
                ft_id="ft_harness_leak",
                generated_sources=(harness,),
                target_root=root / "target",
            )
            document = json.loads((
                root / "artifacts/generation/ft_harness_leak/validation/runtime.json"
            ).read_text(encoding="utf-8"))

        self.assertEqual(result.status, "failed")
        self.assertFalse(result.success)
        self.assertEqual(result.metadata["failure_type"], "unclassified_runtime_crash")
        self.assertEqual(
            result.metadata["crash_classification"], "unclassified_crash"
        )
        # The first attributed allocation frame remains available for triage.
        crashed = [case for case in document["metadata"]["cases"]
                   if case["return_code"] not in (None, 0)][0]
        self.assertEqual(crashed["attribution_frame"]["source"], str(target_source))
        self.assertEqual(crashed["top_frame"]["source"], str(target_source))

    def test_target_fault_with_harness_caller_remains_a_target_finding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target" / "parser.c"
            target.parent.mkdir()
            target.write_text("int parser;\n", encoding="utf-8")
            harness = root / "harness.c"
            harness.write_text("int harness;\n", encoding="utf-8")
            stderr = (
                "AddressSanitizer:DEADLYSIGNAL\n"
                f"#0 0x123 in parser {target}:9:2\n"
                f"#1 0x456 in LLVMFuzzerTestOneInput {harness}:11:3\n"
            )
            result = RuntimeValidator(
                runner=SequenceRunner((0, "", ""), (1, "", stderr))
            ).validate_smoke_triplet(
                self.executable(root), artifacts=root / "artifacts",
                ft_id="ft_target_with_harness_caller",
                generated_sources=(harness,), target_root=target.parent,
            )
        self.assertEqual(result.status, "passed_with_limitations")
        self.assertEqual(
            result.metadata["crash_classification"], "potential_target_crash"
        )

    def test_direct_generated_leak_is_classified_as_harness_leak(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness = root / "harness.c"
            harness.write_text("int harness;\n", encoding="utf-8")
            stderr = (
                "ERROR: LeakSanitizer: detected memory leaks\n"
                f"#1 0x123 in LLVMFuzzerTestOneInput {harness}:9:2\n"
            )
            result = RuntimeValidator(
                runner=SequenceRunner((0, "", ""), (77, "", stderr))
            ).validate_smoke_triplet(
                self.executable(root), artifacts=root / "artifacts",
                ft_id="ft_direct_harness_leak",
                generated_sources=(harness,), target_root=root / "target",
            )
        self.assertEqual(result.status, "failed")
        self.assertEqual(
            result.metadata["crash_classification"], "generated_harness_leak"
        )

    def test_leak_without_a_harness_frame_remains_unattributed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = self.executable(root)
            target_source = root / "target" / "json.c"
            target_source.parent.mkdir(parents=True)
            target_source.write_text("int json;\n", encoding="utf-8")
            runner = SequenceRunner(
                (0, "", ""), (1, "", self.leak_stderr(target_source))
            )
            result = RuntimeValidator(runner=runner).validate_smoke_triplet(
                executable,
                artifacts=root / "artifacts",
                ft_id="ft_target_leak",
                generated_sources=(root / "stage4_harness.c",),
                target_root=root / "target",
            )

        self.assertEqual(result.status, "failed")
        self.assertEqual(
            result.metadata["crash_classification"], "unclassified_crash"
        )

    def test_harness_crash_without_leak_evidence_is_not_a_leak(self):
        runner = SequenceRunner((7, "partial", ""), (0, "", ""))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = self.executable(root)
            harness = root / "run" / "harness.c"
            harness.parent.mkdir(parents=True)
            harness.write_text("int harness;\n", encoding="utf-8")
            stderr = (
                "AddressSanitizer:DEADLYSIGNAL\n"
                f"#0 0x123 in LLVMFuzzerTestOneInput {harness}:7:3\n"
            )
            runner = SequenceRunner((0, "", ""), (-11, "", stderr))
            result = RuntimeValidator(runner=runner).validate_smoke_triplet(
                executable,
                artifacts=root / "artifacts",
                ft_id="ft_harness_crash_downstack",
                generated_sources=(harness,),
                target_root=root / "target",
            )

        self.assertEqual(result.status, "failed")
        self.assertEqual(
            result.metadata["crash_classification"], "generated_harness_crash"
        )

    def test_unparsed_crash_preserves_raw_stderr_and_fails_explicitly(self):
        runner = SequenceRunner((7, "partial", "raw crash without stack frames"),
                                (0, "", ""))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = self.executable(root)
            artifacts = root / "artifacts"
            result = RuntimeValidator(runner=runner).validate_smoke_triplet(
                executable,
                artifacts=artifacts,
                ft_id="ft_unparsed_crash",
                generated_sources=(root / "stage4_harness.c",),
                target_root=root / "target",
            )
            document = json.loads((
                artifacts / "generation/ft_unparsed_crash/validation/runtime.json"
            ).read_text(encoding="utf-8"))

        self.assertEqual(result.status, "failed")
        self.assertEqual(
            result.metadata["failure_type"], "unclassified_runtime_crash"
        )
        self.assertEqual(document["metadata"]["stack_parser_status"], "unavailable")
        self.assertIn("raw crash without stack frames", document["stderr"])

    def test_fixed_input_smoke_timeout_is_recorded_as_failure(self):
        timeout = subprocess.TimeoutExpired(
            ["fuzz_target"], 2, output=b"partial", stderr=b"stalled"
        )
        runner = SequenceRunner(timeout)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = self.executable(root)
            artifacts = root / "artifacts"
            result = RuntimeValidator(timeout=2, runner=runner).validate_smoke_triplet(
                executable,
                artifacts=artifacts,
                ft_id="ft_runtime_timeout",
                generated_sources=(root / "stage4_harness.c",),
                target_root=root / "target",
            )
            document = json.loads((
                artifacts / "generation/ft_runtime_timeout/validation/runtime.json"
            ).read_text(encoding="utf-8"))

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.metadata["failure_type"], "runtime_timeout")
        self.assertTrue(document["timed_out"])
        self.assertEqual(document["metadata"]["cases"][0]["status"], "timed_out")
        self.assertEqual(document["metadata"]["cases"][0]["stderr"], "stalled")


if __name__ == "__main__":
    unittest.main()
