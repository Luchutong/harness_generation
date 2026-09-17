from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.candidate import run_candidate
from harness_generation.config import CandidateConfig
from harness_generation.evaluation import (EvaluationContext, MetricId,
                                           MetricStatus, default_quality_engine)
from harness_generation.feedback import load_revision
from harness_generation.iteration import AutomaticFeedbackBuilder


ROOT = Path(__file__).resolve().parents[1]
MINI_PARSER = ROOT / "benchmarks" / "mini_parser"
SOURCE = MINI_PARSER / "target.c"
REFERENCE = MINI_PARSER / "harnesses" / "structured.c"


def metric_by_id(report, metric_id: MetricId):
    return next(metric for metric in report.metrics if metric.metric_id == metric_id)


class QualitySignalTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        (self.directory / "target.c").write_bytes(SOURCE.read_bytes())
        (self.directory / "harness.c").write_text(REFERENCE.read_text(), encoding="utf-8")

    def context(self, *, execution_result: dict | None = None) -> EvaluationContext:
        return EvaluationContext(
            "candidate_0001", None, 0, self.directory, "mp_parse",
            "source-hash", "harness-hash", execution_result or {},
        )

    def test_structured_reference_has_multiple_ast_quality_signals(self) -> None:
        report = default_quality_engine().evaluate(self.context())

        self.assertEqual(metric_by_id(report, MetricId.REACHABILITY).status,
                         MetricStatus.MEASURED)
        self.assertAlmostEqual(metric_by_id(report, MetricId.REACHABILITY).score, 0.65)
        self.assertEqual(metric_by_id(report, MetricId.INPUT_EXPRESSIVENESS).score, 1.0)
        self.assertEqual(metric_by_id(report, MetricId.TARGET_ISOLATION).score, 1.0)
        self.assertEqual(metric_by_id(report, MetricId.RESOURCE_BOUND).score, 1.0)
        self.assertEqual(metric_by_id(report, MetricId.CRASH_FIDELITY).score, 1.0)
        self.assertEqual(metric_by_id(report, MetricId.DETERMINISM).status,
                         MetricStatus.UNAVAILABLE)
        self.assertEqual(metric_by_id(report, MetricId.STATE_RESET).status,
                         MetricStatus.UNAVAILABLE)
        self.assertIn("Static input-dependence", metric_by_id(
            report, MetricId.INPUT_EXPRESSIVENESS).reason)

    def test_static_signals_identify_weak_input_mapping_and_risks(self) -> None:
        (self.directory / "harness.c").write_text("""#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include <stdio.h>
#include \"target.c\"
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    for (size_t i = 0; i < Size; ++i) { printf("%u", Data[i]); }
    signal(SIGSEGV, SIG_IGN);
    mp_context ctx;
    mp_init(&ctx);
    mp_parse(&ctx, (const uint8_t *)"", 0);
    mp_destroy(&ctx);
    return 0;
}
""", encoding="utf-8")

        report = default_quality_engine().evaluate(self.context())

        self.assertLess(metric_by_id(report, MetricId.INPUT_EXPRESSIVENESS).score, 0.5)
        self.assertLess(metric_by_id(report, MetricId.RESOURCE_BOUND).score, 1.0)
        self.assertLess(metric_by_id(report, MetricId.CRASH_FIDELITY).score, 1.0)
        self.assertLess(metric_by_id(report, MetricId.TARGET_ISOLATION).score, 1.0)
        self.assertIn("signal", metric_by_id(report, MetricId.CRASH_FIDELITY).reason)

    def test_runtime_speed_and_target_depth_use_separate_evidence(self) -> None:
        (self.directory / "metrics.json").write_text(json.dumps({
            "measurements": [
                {"name": "fuzzer_average_exec_per_sec", "value": 5000,
                 "unit": "executions/second", "scope": "instrumented_program"},
                {"name": "fuzzer_number_of_executed_units", "value": 80,
                 "unit": "executions", "scope": "instrumented_program"},
            ],
        }), encoding="utf-8")
        (self.directory / "target_coverage.json").write_text(json.dumps({
            "status": "passed",
            "target_only": {"entered_functions": ["mp_parse", "mp_checksum"]},
        }), encoding="utf-8")

        report = default_quality_engine().evaluate(self.context())

        speed = metric_by_id(report, MetricId.EXECUTION_SPEED)
        deep = metric_by_id(report, MetricId.DEEP_REACHABILITY)
        self.assertEqual(speed.status, MetricStatus.MEASURED)
        self.assertEqual(speed.score, 0.5)
        self.assertEqual(speed.measurements[0].scope, "instrumented_program")
        self.assertEqual(deep.status, MetricStatus.MEASURED)
        self.assertGreater(deep.score, 0.0)
        self.assertTrue(all(item.artifact in {"target_coverage.json", "target.c"}
                            for item in deep.evidence))

    def test_engine_cov_ft_and_new_units_are_dynamic_selection_evidence(self) -> None:
        (self.directory / "metrics.json").write_text(json.dumps({
            "measurements": [
                {"name": "fuzzer_average_exec_per_sec", "value": 100,
                 "unit": "executions/second", "scope": "instrumented_program"},
                {"name": "fuzzer_number_of_executed_units", "value": 40,
                 "unit": "executions", "scope": "instrumented_program"},
                {"name": "fuzzer_coverage_edges_or_blocks", "value": 38,
                 "unit": "edges_or_blocks", "scope": "instrumented_program"},
                {"name": "fuzzer_features", "value": 52,
                 "unit": "features", "scope": "instrumented_program"},
                {"name": "fuzzer_new_units_added", "value": 16,
                 "unit": "corpus_units", "scope": "instrumented_program"},
            ],
        }), encoding="utf-8")

        report = default_quality_engine().evaluate(self.context())
        coverage = metric_by_id(report, MetricId.COVERAGE)
        deep = metric_by_id(report, MetricId.DEEP_REACHABILITY)
        speed = metric_by_id(report, MetricId.EXECUTION_SPEED)

        self.assertEqual(coverage.status, MetricStatus.MEASURED)
        self.assertIn("engine cov/ft telemetry", coverage.reason)
        self.assertIn("engine_features", [item.name for item in coverage.measurements])
        self.assertEqual(deep.status, MetricStatus.MEASURED)
        self.assertIn("corpus-discovery telemetry", deep.reason)
        self.assertIn("fuzzer_features", [item.name for item in speed.measurements])
        self.assertIn("fuzzer_new_units_added", [item.name for item in speed.measurements])

    def test_crash_fidelity_scores_target_findings_separately_from_harness_crashes(self) -> None:
        target_report = default_quality_engine().evaluate(self.context(
            execution_result={"fuzzing": {
                "status": "finding",
                "findings": ["address_sanitizer"],
                "artifacts": ["artifacts/crash-a"],
                "crash_classification": {"classification": "potential_target_crash"},
            }}
        ))
        harness_report = default_quality_engine().evaluate(self.context(
            execution_result={"fuzzing": {
                "status": "finding",
                "findings": ["address_sanitizer"],
                "artifacts": ["artifacts/crash-b"],
                "crash_classification": {"classification": "generated_harness_crash"},
            }}
        ))

        target = metric_by_id(target_report, MetricId.CRASH_FIDELITY)
        harness = metric_by_id(harness_report, MetricId.CRASH_FIDELITY)
        self.assertEqual(target.score, 1.0)
        self.assertEqual(harness.score, 0.0)
        self.assertIn("target source", target.reason)
        self.assertIn("generated Harness code", harness.reason)

    def test_low_multi_dimensional_signal_becomes_evidence_bound_feedback(self) -> None:
        (self.directory / "harness.c").write_text("""#include <stdint.h>
#include <stddef.h>
#include <signal.h>
#include \"target.c\"
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    for (size_t i = 0; i < Size; ++i) { (void)Data[i]; }
    signal(SIGSEGV, SIG_IGN);
    mp_context ctx;
    mp_init(&ctx);
    mp_parse(&ctx, (const uint8_t *)"", 0);
    mp_destroy(&ctx);
    return 0;
}
""", encoding="utf-8")
        (self.directory / "evaluation.json").write_text("{}", encoding="utf-8")
        report = default_quality_engine().evaluate(self.context())
        packet = AutomaticFeedbackBuilder(low_score_threshold=0.7).build(
            self.context(), report,
        )

        by_metric = {item.metric_id: item for item in packet.items if item.metric_id}
        self.assertIn(MetricId.INPUT_EXPRESSIVENESS, by_metric)
        self.assertIn(MetricId.RESOURCE_BOUND, by_metric)
        self.assertIn(MetricId.CRASH_FIDELITY, by_metric)
        self.assertEqual(by_metric[MetricId.INPUT_EXPRESSIVENESS].evidence[0].artifact,
                         "harness.c")
        json.loads(json.dumps(asdict(packet)))

    def test_candidate_persists_default_evaluation_aggregate_and_feedback(self) -> None:
        output = self.directory / "candidate"
        output.mkdir()
        config = CandidateConfig(
            SOURCE, "mp_parse", output, harness=REFERENCE, generate_only=True,
        )
        result, code = run_candidate(config, SOURCE.read_bytes(), REFERENCE.read_text())

        self.assertEqual(code, 0)
        evaluation = json.loads((output / "evaluation.json").read_text(encoding="utf-8"))
        automatic_feedback = json.loads(
            (output / "automatic_feedback.json").read_text(encoding="utf-8")
        )
        self.assertEqual(evaluation["metrics"][0]["metric_id"], "reachability")
        self.assertEqual(evaluation["metrics"][0]["status"], "measured")
        self.assertEqual(evaluation["aggregate"]["status"], "scored")
        self.assertEqual(result["automatic_feedback"]["status"], "available")
        self.assertEqual(automatic_feedback["candidate_id"], "candidate_0001")
        revision = load_revision(
            output, output / "automatic_feedback.json", SOURCE.read_bytes(), "mp_parse",
        )
        self.assertEqual(revision.feedback.candidate_id, "candidate_0001")


if __name__ == "__main__":
    unittest.main()
