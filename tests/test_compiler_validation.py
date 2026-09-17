import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from harness_generation.compiler_validation import (
    BuildAdapter,
    CompilerConfig,
    CompilerValidator,
)


class FakeRunner:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return subprocess.CompletedProcess(command, *result)


class CompilerValidationTests(unittest.TestCase):
    def test_syntax_fallback_succeeds_without_link_configuration(self):
        runner = FakeRunner([(0, "syntax stdout", "syntax stderr")])
        config = CompilerConfig(
            include_paths=(Path("include"),),
            compiler_flags=("-std=c11", "-Wall"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "harness.c"
            source.write_text("int main(void) { return 0; }", encoding="utf-8")
            validation = root / "validation.json"
            result = CompilerValidator(config, runner=runner).validate(
                source, validation_path=validation
            )
            persisted = json.loads(validation.read_text(encoding="utf-8"))

        expected = [
            "clang", "-std=c11", "-Wall", "-Iinclude", "-fsyntax-only",
            str(source.resolve()),
        ]
        self.assertTrue(result.success)
        self.assertTrue(result.metadata["syntax_valid"])
        self.assertEqual(result.metadata["link_validation"], "unavailable")
        self.assertEqual(result.metadata["command"], expected)
        self.assertEqual(result.metadata["stdout"], "syntax stdout")
        self.assertEqual(result.metadata["stderr"], "syntax stderr")
        self.assertEqual(result.metadata["return_code"], 0)
        self.assertEqual(persisted, result.to_dict())
        self.assertIn("no build or link configuration", result.warnings[0])

    def test_build_command_is_parameterized_and_link_is_validated(self):
        runner = FakeRunner([
            (0, "syntax ok", ""),
            (0, "build ok", "build note"),
        ])
        config = CompilerConfig.from_mapping({
            "compiler": "custom-cc",
            "compiler_flags": ["-std=c17"],
            "build_command": "project-build --input {source} --output {output}",
            "working_directory": "project",
            "timeout": 12,
        })
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "generated.c"
            output = Path(temporary) / "fuzz_target"
            result = CompilerValidator(config, runner=runner).validate(
                source,
                output=output,
                validation_path=Path(temporary) / "validation.json",
            )

        self.assertTrue(result.success)
        self.assertTrue(result.metadata["syntax_valid"])
        self.assertEqual(result.metadata["link_validation"], "valid")
        self.assertEqual(result.metadata["command"], [
            "project-build", "--input", str(source.resolve()),
            "--output", str(output.resolve()),
        ])
        self.assertEqual(result.metadata["stdout"], "build ok")
        self.assertEqual(result.metadata["stderr"], "build note")
        self.assertEqual(len(runner.calls), 2)
        self.assertEqual(runner.calls[1][1]["cwd"], Path("project"))
        self.assertEqual(runner.calls[1][1]["timeout"], 12)
        self.assertFalse(runner.calls[1][1]["check"])

    def test_adapter_builds_configured_default_link_command(self):
        config = CompilerConfig(
            compiler="cc",
            include_paths=(Path("headers"),),
            library_paths=(Path("libs"),),
            compiler_flags=("-std=c11",),
            link_flags=("-ltarget", "-lm"),
        )
        command = BuildAdapter().link_command(
            Path("harness.c"), Path("fuzz_target"), config
        )
        self.assertEqual(command, (
            "cc", "-std=c11", "-Iheaders", "harness.c", "-Llibs",
            "-ltarget", "-lm", "-o", "fuzz_target",
        ))

    def test_adapter_builds_object_and_archive_commands(self):
        config = CompilerConfig(
            compiler="cc",
            include_paths=(Path("headers"),),
            compiler_flags=("-std=c11",),
        )
        adapter = BuildAdapter()
        self.assertEqual(
            adapter.object_command(Path("src/a.c"), Path("obj/a.o"), config),
            (
                "cc", "-std=c11", "-Iheaders", "-c", "src/a.c", "-o",
                "obj/a.o",
            ),
        )
        self.assertEqual(
            adapter.archive_command(
                (Path("obj/a.o"), Path("obj/b.o")),
                Path("libtarget.a"),
            ),
            ("ar", "rcs", "libtarget.a", "obj/a.o", "obj/b.o"),
        )
        link_config = CompilerConfig(
            compiler="cc", link_flags=("-fsanitize=fuzzer,address",)
        )
        self.assertEqual(
            adapter.objects_link_command(
                (Path("obj/a.o"), Path("obj/harness.o")),
                Path("fuzzer"),
                link_config,
            ),
            (
                "cc", "obj/a.o", "obj/harness.o",
                "-fsanitize=fuzzer,address", "-o", "fuzzer",
            ),
        )

    def test_syntax_failure_skips_link_and_is_a_failure(self):
        runner = FakeRunner([(1, "", "parse error")])
        config = CompilerConfig(build_command=("make", "harness"))
        with tempfile.TemporaryDirectory() as temporary:
            result = CompilerValidator(config, runner=runner).validate(
                Path(temporary) / "bad.c",
                validation_path=Path(temporary) / "validation.json",
            )

        self.assertFalse(result.success)
        self.assertFalse(result.metadata["syntax_valid"])
        self.assertEqual(result.metadata["link_validation"], "unavailable")
        self.assertIsNone(result.metadata["link"])
        self.assertEqual(len(runner.calls), 1)
        self.assertIn("syntax validation failed", result.errors[0])

    def test_link_failure_preserves_both_phase_diagnostics(self):
        runner = FakeRunner([(0, "syntax", ""), (2, "build", "undefined ref")])
        config = CompilerConfig(link_flags=("-ltarget",))
        with tempfile.TemporaryDirectory() as temporary:
            result = CompilerValidator(config, runner=runner).validate(
                Path(temporary) / "harness.c",
                validation_path=Path(temporary) / "validation.json",
            )

        self.assertFalse(result.success)
        self.assertTrue(result.metadata["syntax_valid"])
        self.assertEqual(result.metadata["link_validation"], "invalid")
        self.assertEqual(result.metadata["syntax"]["stdout"], "syntax")
        self.assertEqual(result.metadata["link"]["stderr"], "undefined ref")
        self.assertEqual(result.metadata["return_code"], 2)

    def test_unavailable_link_command_does_not_fail_valid_syntax(self):
        runner = FakeRunner([
            (0, "", ""),
            FileNotFoundError("project builder is missing"),
        ])
        config = CompilerConfig(build_command=("project-builder",))
        with tempfile.TemporaryDirectory() as temporary:
            result = CompilerValidator(config, runner=runner).validate(
                Path(temporary) / "harness.c",
                validation_path=Path(temporary) / "validation.json",
            )

        self.assertTrue(result.success)
        self.assertTrue(result.metadata["syntax_valid"])
        self.assertEqual(result.metadata["link_validation"], "unavailable")
        self.assertEqual(result.metadata["link"]["status"], "unavailable")
        self.assertIn("link validation unavailable", result.warnings[0])

    def test_timeout_diagnostics_are_saved(self):
        timeout = subprocess.TimeoutExpired(
            ["clang"], 30, output=b"partial output", stderr=b"stalled"
        )
        runner = FakeRunner([timeout])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "validation.json"
            result = CompilerValidator(runner=runner).validate(
                Path(temporary) / "harness.c", validation_path=path
            )
            persisted = json.loads(path.read_text(encoding="utf-8"))

        self.assertFalse(result.success)
        self.assertFalse(result.metadata["syntax_valid"])
        self.assertEqual(result.metadata["stdout"], "partial output")
        self.assertEqual(result.metadata["stderr"], "stalled")
        self.assertIsNone(result.metadata["return_code"])
        self.assertEqual(persisted["metadata"]["syntax"]["status"], "timed_out")

    def test_missing_compiler_is_explicitly_unavailable(self):
        runner = FakeRunner([FileNotFoundError("clang is unavailable")])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = CompilerValidator(runner=runner).validate(
                root / "harness.c",
                validation_path=root / "validation.json",
            )

        self.assertIsNone(result.success)
        self.assertEqual(result.status, "unavailable")
        self.assertEqual(result.errors, ())
        self.assertIn("unavailable", result.warnings[0])

    def test_config_rejects_scalar_paths_and_invalid_timeout(self):
        with self.assertRaisesRegex(ValueError, "include_paths"):
            CompilerConfig.from_mapping({"include_paths": "include"})
        with self.assertRaisesRegex(ValueError, "timeout"):
            CompilerConfig(timeout=float("nan"))


if __name__ == "__main__":
    unittest.main()
