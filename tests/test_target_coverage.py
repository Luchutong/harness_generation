import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from harness_generation.cli import main
from harness_generation.evaluation import (
    EvaluationContext,
    EvaluationEngine,
    MetricId,
    MetricStatus,
    TargetCoverageEvaluator,
)
from harness_generation.target_build import TargetBuildConfig
from harness_generation.target_coverage import (
    TargetCoverageCollector,
    TargetCoverageConfig,
    latest_target_coverage_summary,
    target_only_summary,
)
from tests.toolchain_probe import LLVM_COVERAGE_AVAILABLE, LLVM_COVERAGE_SKIP_REASON


ROOT = Path(__file__).resolve().parents[1]
SIMPLE_PROJECT = ROOT / "tests" / "fixtures" / "simple_project"
MINI_PARSER = ROOT / "benchmarks" / "mini_parser"


VALID_HARNESS = """#include <stddef.h>
#include <stdint.h>
#include "parser.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Parser parser = {0};
    parser_from_memory(&parser, data, (unsigned long)size);
    Node node = parser_next(&parser);
    node_process(&node);
    parser_free(&parser);
    return 0;
}
"""


class TargetCoverageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def test_target_only_summary_filters_out_harness_file(self):
        target = (self.directory / "target.c").resolve()
        harness = (self.directory / "harness.c").resolve()
        export = {
            "data": [{
                "files": [
                    {
                        "filename": str(target),
                        "summary": {
                            "lines": {"count": 10, "covered": 7},
                            "regions": {"count": 5, "covered": 4},
                            "functions": {"count": 2, "covered": 1},
                        },
                    },
                    {
                        "filename": str(harness),
                        "summary": {
                            "lines": {"count": 100, "covered": 100},
                            "regions": {"count": 50, "covered": 50},
                            "functions": {"count": 1, "covered": 1},
                        },
                    },
                ],
                "functions": [
                    {"name": "target_api", "count": 3, "filenames": [str(target)]},
                    {"name": "LLVMFuzzerTestOneInput", "count": 3,
                     "filenames": [str(harness)]},
                ],
            }],
        }

        summary = target_only_summary(export, [target])

        self.assertEqual(len(summary["files"]), 1)
        self.assertEqual(summary["files"][0]["filename"], str(target))
        self.assertEqual(summary["totals"]["lines"]["covered"], 7)
        self.assertEqual(summary["totals"]["lines"]["percent"], 70.0)
        self.assertEqual(summary["entered_functions"], ["target_api"])
        self.assertNotIn("LLVMFuzzerTestOneInput", json.dumps(summary))

    def test_latest_target_coverage_summary_finds_latest_run(self):
        root = self.directory / "coverage" / "ft_example"
        first = root / "run_001" / "target_coverage.json"
        second = root / "run_002" / "target_coverage.json"
        first.parent.mkdir(parents=True)
        second.parent.mkdir(parents=True)
        first.write_text("{}", encoding="utf-8")
        second.write_text("{}", encoding="utf-8")

        self.assertEqual(latest_target_coverage_summary(root), second)
        self.assertEqual(latest_target_coverage_summary(second), second)

    def test_target_coverage_evaluator_reports_target_code_scope(self):
        summary_path = self.directory / "target_coverage.json"
        summary_path.write_text(json.dumps({
            "status": "passed",
            "target_only": {
                "totals": {
                    "lines": {"count": 10, "covered": 5, "percent": 50.0},
                    "regions": {"count": 4, "covered": 1, "percent": 25.0},
                }
            },
        }), encoding="utf-8")
        context = EvaluationContext(
            "candidate_0001", None, 0, self.directory,
            "parser_from_memory", "source", "harness", {},
        )

        report = EvaluationEngine([TargetCoverageEvaluator()]).evaluate(context)
        metric = report.metrics[list(MetricId).index(MetricId.COVERAGE)]

        self.assertEqual(metric.status, MetricStatus.MEASURED)
        self.assertEqual(metric.score, 0.25)
        self.assertTrue(metric.evidence)
        self.assertTrue(all(m.scope == "target_code" for m in metric.measurements))

    def test_the_seed_is_configurable_and_recorded(self):
        """One seed replayed is one sample, so an arm comparison needs the knob.

        The default is the value this always ran with, so a single measurement
        is byte for byte what it was.
        """

        self.assertEqual(TargetCoverageConfig().seed, 1)
        self.assertEqual(TargetCoverageConfig(seed=7).seed, 7)
        for invalid in (-1, 1.0, True, "1"):
            with self.subTest(seed=invalid):
                with self.assertRaises(ValueError):
                    TargetCoverageConfig(seed=invalid)

    def test_the_harness_compiler_is_taken_as_a_pair_or_not_at_all(self):
        """A harness's language and sanitizer set are not derivable.

        Unset, the harness compiles exactly like the target -- what this always
        did, and right when the harness is C.  Set, it is a different language
        standard and probably a different sanitizer set, so a caller that
        supplied one half would be describing a build nobody can make sense of.
        """

        self.assertIsNone(TargetCoverageConfig().harness_compiler)
        self.assertIsNone(TargetCoverageConfig().harness_compiler_flags)
        config = TargetCoverageConfig(
            harness_compiler="clang++", harness_compiler_flags=("-x", "c++"),
        )
        self.assertEqual(config.harness_compiler_flags, ("-x", "c++"))

        with self.assertRaises(ValueError):
            TargetCoverageConfig(harness_compiler="clang++")
        with self.assertRaises(ValueError):
            TargetCoverageConfig(harness_compiler_flags=("-x", "c++"))
        for invalid in ("", "   ", 7):
            with self.subTest(compiler=invalid):
                with self.assertRaises(ValueError):
                    TargetCoverageConfig(
                        harness_compiler=invalid, harness_compiler_flags=(),
                    )
        for invalid in (("-x", ""), "-x c++", ("-x", 7)):
            with self.subTest(flags=invalid):
                with self.assertRaises(ValueError):
                    TargetCoverageConfig(
                        harness_compiler="clang++", harness_compiler_flags=invalid,
                    )

    @unittest.skipUnless(LLVM_COVERAGE_AVAILABLE, LLVM_COVERAGE_SKIP_REASON)
    def test_a_named_seed_reaches_the_coverage_fuzzer(self):
        artifacts = self.directory / "artifacts"
        harness = self.directory / "harness.c"
        harness.write_text(VALID_HARNESS, encoding="utf-8")
        ft_id = "ft_target_coverage_seed"

        result = TargetCoverageCollector(
            TargetCoverageConfig(runs=8, seed=5)
        ).measure(
            harness,
            TargetBuildConfig.for_simple_project(SIMPLE_PROJECT),
            artifacts=artifacts,
            ft_id=ft_id,
        )

        self.assertEqual(result.status, "passed", result.errors)
        run = artifacts / "coverage" / ft_id / "run_001"
        summary = json.loads((run / "target_coverage.json").read_text())
        self.assertEqual(summary["seed"], 5)
        commands = json.loads((run / "commands.json").read_text(encoding="utf-8"))
        run_command = commands[-3]["command"]
        self.assertIn("-seed=5", run_command)
        self.assertIn("-runs=8", run_command)

    @unittest.skipUnless(LLVM_COVERAGE_AVAILABLE, LLVM_COVERAGE_SKIP_REASON)
    def test_real_simple_target_coverage_excludes_generated_harness(self):
        artifacts = self.directory / "artifacts"
        harness = self.directory / "harness.c"
        harness.write_text(VALID_HARNESS, encoding="utf-8")
        ft_id = "ft_target_coverage_simple"

        result = TargetCoverageCollector(TargetCoverageConfig(runs=8)).measure(
            harness,
            TargetBuildConfig.for_simple_project(SIMPLE_PROJECT),
            artifacts=artifacts,
            ft_id=ft_id,
        )

        self.assertEqual(result.status, "passed", result.errors)
        run = artifacts / "coverage" / ft_id / "run_001"
        summary = json.loads((run / "target_coverage.json").read_text())
        self.assertTrue((run / "coverage_export.json").is_file())
        self.assertEqual(summary["scope"], "target_code")
        filenames = [Path(item["filename"]).name
                     for item in summary["target_only"]["files"]]
        self.assertEqual(filenames, ["parser.c"])
        self.assertIn(
            "parser_from_memory",
            summary["target_only"]["entered_functions"],
        )
        self.assertNotIn("harness.c", json.dumps(summary["target_only"]))

    @unittest.skipUnless(LLVM_COVERAGE_AVAILABLE, LLVM_COVERAGE_SKIP_REASON)
    def test_cli_can_measure_mini_parser_harness_that_includes_target(self):
        artifacts = self.directory / "artifacts"
        ft_id = "ft_mini_parser_structured"
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = main([
                "measure-target",
                "--artifacts", str(artifacts),
                "--ft", ft_id,
                "--project-root", str(MINI_PARSER.relative_to(ROOT)),
                "--harness", str((MINI_PARSER / "harnesses" / "structured.c").relative_to(ROOT)),
                "--target-source", str((MINI_PARSER / "target.c").relative_to(ROOT)),
                "--include", str(MINI_PARSER.relative_to(ROOT)),
                "--corpus", str((MINI_PARSER / "corpus" / "structured").relative_to(ROOT)),
                "--runs", "8",
                "--harness-includes-target",
            ])

        self.assertEqual(code, 0, stdout.getvalue())
        summary = json.loads((
            artifacts / "coverage" / ft_id / "run_001" / "target_coverage.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(summary["status"], "passed")
        self.assertIn("mp_parse", summary["target_only"]["entered_functions"])
        self.assertIn("Target coverage: passed", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
