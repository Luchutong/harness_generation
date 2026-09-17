from dataclasses import asdict
import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.evaluation import (AggregateResult, EvaluationContext,
                                           EvaluationReport, Evidence,
                                           Measurement, MetricId, MetricResult,
                                           MetricStatus)
from harness_generation.iteration import (AutomaticFeedbackBuilder,
                                          FeedbackDrivenIterationPlanner,
                                          ScoreCandidateSelector,
                                          SelectionResult,
                                          WeightedAggregationPolicy)


def measured_metric(metric_id: MetricId, score: float) -> MetricResult:
    return MetricResult(
        metric_id,
        MetricStatus.MEASURED,
        "test",
        "1",
        f"{metric_id.value} measured",
        score=score,
        measurements=(Measurement(metric_id.value, score, "ratio", "target_api"),),
        evidence=(Evidence(f"{metric_id.value}.json", "metric evidence"),),
    )


def measured_metric_with_values(
    metric_id: MetricId,
    score: float,
    measurements: tuple[Measurement, ...],
) -> MetricResult:
    return MetricResult(
        metric_id,
        MetricStatus.MEASURED,
        "test",
        "1",
        f"{metric_id.value} measured",
        score=score,
        measurements=measurements,
        evidence=(Evidence(f"{metric_id.value}.json", "metric evidence"),),
    )


def metric_result(metric_id: MetricId, status: MetricStatus,
                  reason: str = "not measured") -> MetricResult:
    return MetricResult(metric_id, status, "test", "1", reason)


def report(candidate_id: str, *, metrics: tuple[MetricResult, ...],
           harness_sha256: str | None = "harness-hash",
           aggregate: AggregateResult | None = None) -> EvaluationReport:
    return EvaluationReport(
        candidate_id,
        None,
        0,
        "source-hash",
        harness_sha256,
        metrics,
        aggregate=aggregate or AggregateResult(),
    )


def scored_report(candidate_id: str, score: float, harness_sha256: str) -> EvaluationReport:
    return report(
        candidate_id,
        metrics=(),
        harness_sha256=harness_sha256,
        aggregate=AggregateResult(
            "scored",
            score,
            True,
            "fixture aggregate",
            "fixture",
            "1",
        ),
    )


class IterationPolicyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def context(self, execution_result: dict | None = None,
                candidate_id: str = "candidate_0001",
                harness_sha256: str | None = "harness-hash") -> EvaluationContext:
        return EvaluationContext(
            candidate_id,
            None,
            0,
            self.directory,
            "mp_parse",
            "source-hash",
            harness_sha256,
            execution_result or {},
        )

    def test_weighted_aggregation_scores_only_measured_metrics(self):
        evaluation = report("candidate_0001", metrics=(
            measured_metric(MetricId.REACHABILITY, 0.75),
            measured_metric(MetricId.COVERAGE, 0.25),
            metric_result(MetricId.EXECUTION_SPEED, MetricStatus.UNAVAILABLE,
                          "no runtime artifact"),
        ))

        aggregate = WeightedAggregationPolicy().aggregate(evaluation)

        self.assertEqual(aggregate.status, "scored")
        self.assertTrue(aggregate.eligible)
        self.assertAlmostEqual(aggregate.score, 0.5)
        self.assertIn("not measured", aggregate.reason)

    def test_weighted_aggregation_requires_evidence_and_preserves_errors(self):
        no_harness = report("candidate_0001", harness_sha256=None,
                            metrics=(measured_metric(MetricId.REACHABILITY, 1.0),))
        self.assertEqual(WeightedAggregationPolicy().aggregate(no_harness).status,
                         "insufficient_evidence")

        with_error = report("candidate_0002", metrics=(
            measured_metric(MetricId.REACHABILITY, 1.0),
            metric_result(MetricId.COVERAGE, MetricStatus.ERROR, "sanitized failure"),
        ))
        aggregate = WeightedAggregationPolicy().aggregate(with_error)
        self.assertEqual(aggregate.status, "scored")
        self.assertFalse(aggregate.eligible)
        self.assertIn("coverage", aggregate.reason)

    def test_dynamic_gate_requires_coverage_features_and_deep_reachability(self):
        evaluation = report("candidate_0001", metrics=(
            measured_metric(MetricId.REACHABILITY, 1.0),
            measured_metric(MetricId.COVERAGE, 0.20),
            measured_metric(MetricId.DEEP_REACHABILITY, 0.20),
        ))

        aggregate = WeightedAggregationPolicy(
            require_dynamic_quality=True,
        ).aggregate(evaluation)

        self.assertEqual(aggregate.status, "scored")
        self.assertFalse(aggregate.eligible)
        self.assertIn("feature count is not measured", aggregate.reason)

    def test_dynamic_gate_accepts_target_finding_but_rejects_harness_crash(self):
        target_finding = report("candidate_target", metrics=(
            measured_metric(MetricId.REACHABILITY, 1.0),
            measured_metric_with_values(
                MetricId.COVERAGE,
                0.40,
                (Measurement("engine_features", 20, "features",
                             "instrumented_program"),),
            ),
            measured_metric(MetricId.DEEP_REACHABILITY, 0.50),
            measured_metric_with_values(
                MetricId.CRASH_FIDELITY,
                1.0,
                (Measurement("crash_classification", "potential_target_crash",
                             "category", "sanitizer_diagnostics"),),
            ),
        ))
        harness_crash = report("candidate_harness", metrics=(
            measured_metric(MetricId.REACHABILITY, 1.0),
            measured_metric_with_values(
                MetricId.COVERAGE,
                0.90,
                (Measurement("engine_features", 40, "features",
                             "instrumented_program"),),
            ),
            measured_metric(MetricId.DEEP_REACHABILITY, 0.90),
            measured_metric_with_values(
                MetricId.CRASH_FIDELITY,
                0.0,
                (Measurement("crash_classification", "generated_harness_crash",
                             "category", "sanitizer_diagnostics"),),
            ),
        ))

        policy = WeightedAggregationPolicy(require_dynamic_quality=True)
        self.assertTrue(policy.aggregate(target_finding).eligible)
        self.assertFalse(policy.aggregate(harness_crash).eligible)
        selection = ScoreCandidateSelector(
            aggregation_policy=policy,
            use_persisted_aggregate=False,
        ).select((harness_crash, target_finding), limit=1)

        self.assertEqual(selection.status, "selected")
        self.assertEqual(selection.candidate_ids, ("candidate_target",))

    def test_target_finding_remains_eligible_when_crash_truncates_fuzz_telemetry(self):
        target_finding = report("candidate_target", metrics=(
            measured_metric(MetricId.REACHABILITY, 1.0),
            measured_metric_with_values(
                MetricId.CRASH_FIDELITY,
                1.0,
                (Measurement("crash_classification", "potential_target_crash",
                             "category", "sanitizer_diagnostics"),),
            ),
        ))

        aggregate = WeightedAggregationPolicy(
            require_dynamic_quality=True,
        ).aggregate(target_finding)

        self.assertTrue(aggregate.eligible)
        self.assertIn("Target-code finding preserved", aggregate.reason)

    def test_candidate_selector_ranks_stably_and_deduplicates_harnesses(self):
        selection = ScoreCandidateSelector().select((
            scored_report("candidate_b", 0.9, "same-harness"),
            scored_report("candidate_a", 0.9, "same-harness"),
            scored_report("candidate_c", 0.8, "other-harness"),
            scored_report("candidate_d", 0.1, "third-harness"),
        ), limit=2)

        self.assertEqual(selection.status, "selected")
        self.assertEqual(selection.candidate_ids, ("candidate_a", "candidate_c"))
        self.assertEqual(selection.policy, "score_candidate_selector")

    def test_candidate_selector_reports_insufficient_evidence(self):
        selection = ScoreCandidateSelector().select((
            report("candidate_0001", metrics=()),
        ), limit=1)

        self.assertEqual(selection.status, "insufficient_evidence")
        self.assertEqual(selection.candidate_ids, ())
        with self.assertRaises(ValueError):
            ScoreCandidateSelector().select((), limit=0)

    def test_automatic_feedback_builder_uses_stage_and_metric_evidence(self):
        for filename in ("result.json", "compile_result.json", "review.json",
                         "evaluation.json"):
            self.context().artifact(filename).write_text("{}", encoding="utf-8")
        context = self.context({
            "failure_stage": "compile",
            "error": "undefined_function",
            "compilation": {"status": "failed"},
            "review": {"warnings": ["input bytes do not reach the target deeply"]},
        })
        evaluation = report("candidate_0001", metrics=(
            measured_metric(MetricId.COVERAGE, 0.1),
        ))

        packet = AutomaticFeedbackBuilder().build(context, evaluation)

        self.assertEqual(packet.candidate_id, "candidate_0001")
        self.assertEqual(packet.source_sha256, "source-hash")
        observations = "\n".join(item.observation for item in packet.items)
        self.assertIn("Candidate failed at compile", observations)
        self.assertIn("Compilation status is failed", observations)
        self.assertIn("coverage score is 0.100", observations)
        coverage_item = next(item for item in packet.items
                             if item.metric_id == MetricId.COVERAGE)
        self.assertEqual(coverage_item.evidence[0].artifact, "coverage.json")

    def test_automatic_feedback_preserves_target_findings(self):
        self.context().artifact("fuzz_result.json").write_text("{}", encoding="utf-8")
        context = self.context({
            "fuzzing": {
                "status": "finding",
                "crash_classification": {"classification": "potential_target_crash"},
            },
        })
        packet = AutomaticFeedbackBuilder().build(context, report(
            "candidate_0001",
            metrics=(measured_metric(MetricId.CRASH_FIDELITY, 1.0),),
        ))

        observations = "\n".join(item.observation for item in packet.items)
        suggestions = "\n".join(item.suggestion or "" for item in packet.items)
        self.assertIn("attributed to target code", observations)
        self.assertIn("Preserve this target reachability", suggestions)

    def test_automatic_feedback_builder_falls_back_to_exploratory_feedback(self):
        self.context().artifact("evaluation.json").write_text("{}", encoding="utf-8")
        packet = AutomaticFeedbackBuilder().build(
            self.context(),
            report("candidate_0001", metrics=(measured_metric(MetricId.COVERAGE, 0.9),)),
        )

        self.assertEqual(len(packet.items), 1)
        self.assertIsNone(packet.items[0].metric_id)
        self.assertIn("No automatic quality weakness", packet.items[0].observation)

    def test_feedback_planner_builds_bounded_next_round_requests(self):
        packet_a = AutomaticFeedbackBuilder().build(
            self.context(candidate_id="candidate_a"),
            report("candidate_a", metrics=(measured_metric(MetricId.COVERAGE, 0.1),)),
        )
        packet_b = packet_a.__class__(
            "candidate_b",
            1,
            packet_a.source_sha256,
            packet_a.harness_sha256,
            packet_a.items,
        )
        selection = SelectionResult(
            "selected",
            ("candidate_a", "candidate_b"),
            "fixture selection",
            "fixture",
            "1",
        )

        requests = FeedbackDrivenIterationPlanner(
            children_per_parent=2,
            max_total_children=3,
        ).plan(selection, (packet_a, packet_b))

        self.assertEqual([request.parent_id for request in requests],
                         ["candidate_a", "candidate_b"])
        self.assertEqual([request.round_index for request in requests], [1, 2])
        self.assertEqual([request.candidate_count for request in requests], [2, 1])
        json.loads(json.dumps(asdict(requests[0])))

    def test_feedback_planner_requires_feedback_for_selected_candidate(self):
        selection = SelectionResult(
            "selected",
            ("candidate_missing",),
            "fixture selection",
            "fixture",
            "1",
        )
        with self.assertRaises(ValueError):
            FeedbackDrivenIterationPlanner().plan(selection, ())

        skipped = SelectionResult(
            "insufficient_evidence",
            (),
            "no scored candidate",
            "fixture",
            "1",
        )
        self.assertEqual(FeedbackDrivenIterationPlanner().plan(skipped, ()), ())


if __name__ == "__main__":
    unittest.main()
