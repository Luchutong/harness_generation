from dataclasses import asdict
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from harness_generation.candidate import run_candidate
from harness_generation.config import CandidateConfig
from harness_generation.evaluation import (METRIC_SPECS, AggregateResult, EvaluationContext,
    EvaluationEngine, Evidence, Measurement, MetricId, MetricResult, MetricStatus)
from harness_generation.iteration import FeedbackItem, FeedbackPacket, RegenerationRequest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "benchmarks/mini_parser/target.c"
REFERENCE = ROOT / "benchmarks/mini_parser/harnesses/structured.c"
FUNCTION = "mp_parse"


class FixtureEvaluator:
    metric_id = MetricId.REACHABILITY

    def evaluate(self, context):
        # Synthetic evidence for interface testing, not an actual scorer.
        return MetricResult(self.metric_id, MetricStatus.MEASURED, "fixture", "1",
                            "Synthetic contract test", score=0.5,
                            measurements=(Measurement("entered_ratio", 0.5, "ratio", "target_api"),),
                            evidence=(Evidence("fixture.json", "Synthetic test evidence"),))


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.context = EvaluationContext("candidate_0001", None, 0, self.directory,
                                         FUNCTION, "source-hash", "harness-hash", {})

    def test_default_ten_metrics_are_unmeasured(self):
        report = EvaluationEngine().evaluate(self.context)
        self.assertEqual(len(report.metrics), 10)
        self.assertEqual([s.metric_id for s in METRIC_SPECS if s.primary], list(MetricId)[:7])
        self.assertEqual(report.status, "not_implemented")
        self.assertTrue(all(m.score is None for m in report.metrics))
        self.assertIsNone(report.aggregate.score)
        self.assertIsNone(report.aggregate.eligible)
        serialized = json.loads(json.dumps(report.to_dict(), allow_nan=False))
        self.assertEqual(serialized["metrics"][0]["metric_id"], "reachability")
        self.assertEqual(serialized["aggregate"]["status"], "not_configured")

    def test_register_one_metric_does_not_fill_others(self):
        engine = EvaluationEngine([FixtureEvaluator()])
        report = engine.evaluate(self.context)
        self.assertEqual(report.status, "partial")
        self.assertEqual(report.metrics[0].score, 0.5)
        self.assertEqual(report.metrics[0].evidence[0].artifact, "fixture.json")
        self.assertTrue(all(m.status == MetricStatus.NOT_IMPLEMENTED for m in report.metrics[1:]))
        with self.assertRaises(ValueError):
            engine.register(FixtureEvaluator())

    def test_unavailable_is_not_zero(self):
        class Unavailable:
            metric_id = MetricId.COVERAGE

            def evaluate(self, context):
                return MetricResult(self.metric_id, MetricStatus.UNAVAILABLE, "coverage", "1",
                                    "No target-scoped coverage artifacts available")
        metric = EvaluationEngine([Unavailable()]).evaluate(self.context).metrics[1]
        self.assertEqual(metric.status, MetricStatus.UNAVAILABLE)
        self.assertIsNone(metric.score)

    def test_bad_evaluator_is_isolated(self):
        class Broken:
            metric_id = MetricId.COVERAGE

            def evaluate(self, context):
                raise RuntimeError("private diagnostic")
        report = EvaluationEngine([Broken(), FixtureEvaluator()]).evaluate(self.context)
        self.assertEqual(report.status, "error")
        self.assertEqual(report.metrics[0].score, 0.5)
        self.assertEqual(report.metrics[1].status, MetricStatus.ERROR)
        self.assertNotIn("private diagnostic", json.dumps(report.to_dict()))

    def test_wrong_metric_rejected(self):
        class Wrong(FixtureEvaluator):
            metric_id = MetricId.COVERAGE

            def evaluate(self, context):
                return FixtureEvaluator().evaluate(context)
        self.assertEqual(EvaluationEngine([Wrong()]).evaluate(self.context).metrics[1].status,
                         MetricStatus.ERROR)

    def test_result_contract_rejects_fabricated_scores(self):
        for status, score in ((MetricStatus.NOT_IMPLEMENTED, 0), (MetricStatus.UNAVAILABLE, 1),
                              (MetricStatus.MEASURED, float("nan")), (MetricStatus.MEASURED, 2)):
            with self.subTest(status=status, score=score), self.assertRaises(ValueError):
                MetricResult(MetricId.COVERAGE, status, "test", "1", "test", score)
        with self.assertRaises(ValueError):
            MetricResult(MetricId.COVERAGE, MetricStatus.MEASURED, "test", "1", "No evidence", 0.5)
        with self.assertRaises(ValueError):
            AggregateResult(score=0)

    def test_metric_interrupt_propagates(self):
        class Interrupted:
            metric_id = MetricId.COVERAGE

            def evaluate(self, context):
                raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            EvaluationEngine([Interrupted()]).evaluate(self.context)

    def test_artifact_path_stays_in_candidate(self):
        self.assertEqual(self.context.artifact("fuzz_result.json"), self.directory / "fuzz_result.json")
        with self.assertRaises(ValueError):
            self.context.artifact("../unrelated.json")

    def test_candidate_saves_default_multi_dimensional_report_without_api(self):
        source = SOURCE
        harness = REFERENCE
        config = CandidateConfig(source, FUNCTION, self.directory, harness=harness, generate_only=True,
                                 parent_id="previous_candidate", round_index=1)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result, code = run_candidate(config, source.read_bytes(), harness.read_text())
        self.assertEqual(code, 0)
        report = json.loads((self.directory / "evaluation.json").read_text())
        self.assertEqual(report["parent_id"], "previous_candidate")
        self.assertEqual(report["round_index"], 1)
        self.assertEqual(report["harness_sha256"], result["harness_sha256"])
        self.assertEqual(result["evaluation"]["status"], "partial")
        self.assertEqual(report["metrics"][0]["metric_id"], "reachability")
        self.assertEqual(report["metrics"][0]["status"], "measured")
        self.assertEqual(report["aggregate"]["status"], "scored")
        self.assertTrue((self.directory / "automatic_feedback.json").is_file())

    def test_failed_candidate_still_has_unknown_scores(self):
        source = SOURCE
        config = CandidateConfig(source, FUNCTION, self.directory,
                                 harness=Path("invalid.c"), generate_only=True)
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            result, code = run_candidate(config, source.read_bytes(), "invalid harness")
        self.assertEqual(code, 1)
        report = json.loads((self.directory / "evaluation.json").read_text())
        self.assertIsNone(report["harness_sha256"])
        self.assertEqual(report["status"], "partial")
        self.assertTrue(all(metric["score"] is None for metric in report["metrics"]))
        self.assertEqual(report["aggregate"]["status"], "insufficient_evidence")

    def test_feedback_round_linkage(self):
        feedback = FeedbackPacket("candidate_0001", 0, "source-hash", "harness-hash",
                                  (FeedbackItem(MetricId.REACHABILITY, "Observed fewer target calls",
                                                (Evidence("probe.json", "Synthetic test trace"),),
                                                "A precondition might filter inputs", "Inspect the guard"),))
        request = RegenerationRequest("candidate_0001", 1, feedback, 3)
        self.assertEqual(json.loads(json.dumps(asdict(request)))["candidate_count"], 3)
        for parent, round_index, count in (("wrong", 1, 3), ("candidate_0001", 0, 3),
                                            ("candidate_0001", 1, 0)):
            with self.assertRaises(ValueError):
                RegenerationRequest(parent, round_index, feedback, count)
