"""Ranking, feedback extraction, and next-round planning without API calls."""

from dataclasses import dataclass, field
from typing import Mapping, Protocol, Sequence

from .runtime_validation import (BLOCKING_CRASH_CLASSIFICATIONS,
                                 POTENTIAL_TARGET_CRASH)
from .evaluation import (AggregateResult, EvaluationContext, EvaluationReport,
                         Evidence, MetricId, MetricResult, MetricStatus)


ITERATION_POLICY_VERSION = "1"
DEFAULT_METRIC_WEIGHTS: Mapping[MetricId, float] = {
    MetricId.REACHABILITY: 0.25,
    MetricId.COVERAGE: 0.25,
    MetricId.DEEP_REACHABILITY: 0.15,
    MetricId.INPUT_EXPRESSIVENESS: 0.10,
    MetricId.EXECUTION_SPEED: 0.10,
    MetricId.DETERMINISM: 0.05,
    MetricId.STATE_RESET: 0.05,
    MetricId.TARGET_ISOLATION: 0.05,
}
PRIMARY_METRICS = frozenset({
    MetricId.REACHABILITY,
    MetricId.COVERAGE,
    MetricId.EXECUTION_SPEED,
    MetricId.DETERMINISM,
    MetricId.STATE_RESET,
    MetricId.INPUT_EXPRESSIVENESS,
    MetricId.DEEP_REACHABILITY,
})


class AggregationPolicy(Protocol):
    def aggregate(self, report: EvaluationReport) -> AggregateResult:
        """Apply an explicit, versioned scoring/gating policy; preserve unknowns."""
        ...


@dataclass(frozen=True)
class SelectionResult:
    status: str  # selected / insufficient_evidence / not_configured
    candidate_ids: tuple[str, ...]
    reason: str
    policy: str
    version: str

    def __post_init__(self):
        if self.status not in {"selected", "insufficient_evidence", "not_configured"}:
            raise ValueError("unknown selection status")
        if any(not isinstance(item, str) or not item for item in self.candidate_ids):
            raise ValueError("selection candidate IDs must be non-empty strings")
        if not self.reason or not self.policy or not self.version:
            raise ValueError("selection result requires reason, policy, and version")


class CandidateSelector(Protocol):
    def select(self, reports: Sequence[EvaluationReport], *, limit: int) -> SelectionResult:
        """Compare same-target, comparable-budget reports; never invent rankings."""
        ...


@dataclass(frozen=True)
class FeedbackItem:
    metric_id: MetricId | None  # None supports compiler or other non-metric feedback.
    observation: str
    evidence: tuple[Evidence, ...]
    hypothesis: str | None = None
    suggestion: str | None = None

    def __post_init__(self):
        if not self.observation or not self.evidence:
            raise ValueError("Feedback observations require supporting evidence")


@dataclass(frozen=True)
class FeedbackPacket:
    candidate_id: str
    round_index: int
    source_sha256: str
    harness_sha256: str | None
    items: tuple[FeedbackItem, ...]
    schema_version: int = 1


class FeedbackBuilder(Protocol):
    def build(self, context: EvaluationContext, report: EvaluationReport) -> FeedbackPacket:
        """Separate observed facts, hypotheses and suggestions with source evidence."""
        ...


@dataclass(frozen=True)
class RegenerationRequest:
    parent_id: str
    round_index: int
    feedback: FeedbackPacket
    candidate_count: int

    def __post_init__(self):
        if self.parent_id != self.feedback.candidate_id:
            raise ValueError("Feedback must belong to the parent candidate")
        if self.round_index != self.feedback.round_index + 1:
            raise ValueError("Regeneration must advance to the next round")
        if self.candidate_count < 1:
            raise ValueError("Regeneration requires a positive candidate count")


class IterationPlanner(Protocol):
    def plan(self, selection: SelectionResult,
             feedback: Sequence[FeedbackPacket]) -> Sequence[RegenerationRequest]:
        """Describe next-round children; actual execution and budgets are future work."""
        ...


@dataclass(frozen=True)
class WeightedAggregationPolicy:
    """Score only measured metrics with explicit scores; never impute unknowns."""

    weights: Mapping[MetricId, float] = field(default_factory=lambda: DEFAULT_METRIC_WEIGHTS)
    min_scored_metrics: int = 1
    require_harness: bool = True
    require_dynamic_quality: bool = False
    minimum_coverage_score: float = 0.05
    minimum_feature_count: float = 1.0
    minimum_deep_reachability_score: float = 0.05
    target_finding_bonus: float = 0.05
    policy: str = "weighted_measured_metrics"
    version: str = ITERATION_POLICY_VERSION

    def __post_init__(self):
        if self.min_scored_metrics < 1:
            raise ValueError("min_scored_metrics must be positive")
        if not isinstance(self.require_dynamic_quality, bool):
            raise ValueError("require_dynamic_quality must be boolean")
        for field_name in (
            "minimum_coverage_score", "minimum_feature_count",
            "minimum_deep_reachability_score", "target_finding_bonus",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{field_name} must be a non-negative number")
        for metric_id, weight in self.weights.items():
            if not isinstance(metric_id, MetricId):
                raise ValueError("aggregation weights must use MetricId keys")
            if not isinstance(weight, (int, float)) or weight <= 0:
                raise ValueError("aggregation weights must be positive numbers")

    def aggregate(self, report: EvaluationReport) -> AggregateResult:
        if self.require_harness and report.harness_sha256 is None:
            return AggregateResult(
                status="insufficient_evidence",
                reason="No harness hash is available for this candidate.",
                policy=self.policy,
                version=self.version,
            )
        errored = [metric.metric_id.value for metric in report.metrics
                   if metric.status == MetricStatus.ERROR]
        scored = [
            metric for metric in report.metrics
            if metric.status == MetricStatus.MEASURED and metric.score is not None
        ]
        if len(scored) < self.min_scored_metrics:
            return AggregateResult(
                status="insufficient_evidence",
                reason=(
                    f"Only {len(scored)} measured metric(s) with scores are "
                    f"available; need {self.min_scored_metrics}."
                ),
                policy=self.policy,
                version=self.version,
            )
        total_weight = 0.0
        weighted_sum = 0.0
        for metric in scored:
            weight = float(self.weights.get(metric.metric_id, 1.0))
            weighted_sum += weight * float(metric.score)
            total_weight += weight
        score = weighted_sum / total_weight
        if _has_target_finding(report):
            score = min(1.0, score + self.target_finding_bonus)
        missing_primary = sorted(
            metric.metric_id.value for metric in report.metrics
            if metric.metric_id in PRIMARY_METRICS
            and metric.status != MetricStatus.MEASURED
        )
        gate_failures = (
            _dynamic_quality_gate_failures(report, self)
            if self.require_dynamic_quality else ()
        )
        reason = (
            f"Scored from {len(scored)} measured metric(s); "
            f"{len(missing_primary)} primary metric(s) are not measured."
        )
        if _has_target_finding(report):
            reason += " Target-code finding preserved and scored separately."
        if gate_failures:
            reason += " Dynamic quality gate failed: " + "; ".join(gate_failures) + "."
        if errored:
            reason += " Metric errors: " + ", ".join(errored) + "."
        return AggregateResult(
            status="scored",
            score=score,
            eligible=not errored and not gate_failures,
            reason=reason,
            policy=self.policy,
            version=self.version,
        )


@dataclass(frozen=True)
class ScoreCandidateSelector:
    """Select highest-scoring eligible candidates with stable tie-breaking."""

    aggregation_policy: AggregationPolicy | None = field(default_factory=WeightedAggregationPolicy)
    deduplicate_harnesses: bool = True
    use_persisted_aggregate: bool = True
    policy: str = "score_candidate_selector"
    version: str = ITERATION_POLICY_VERSION

    def select(self, reports: Sequence[EvaluationReport], *, limit: int) -> SelectionResult:
        if limit < 1:
            raise ValueError("selection limit must be positive")
        scored: list[tuple[float, str, EvaluationReport, AggregateResult]] = []
        ineligible: list[str] = []
        for report in reports:
            aggregate = report.aggregate if self.use_persisted_aggregate else AggregateResult()
            if aggregate.status != "scored" and self.aggregation_policy is not None:
                aggregate = self.aggregation_policy.aggregate(report)
            if (
                aggregate.status == "scored"
                and aggregate.eligible is True
                and aggregate.score is not None
            ):
                scored.append((float(aggregate.score), report.candidate_id,
                               report, aggregate))
            elif aggregate.status == "scored" and aggregate.eligible is False:
                ineligible.append(f"{report.candidate_id}: {aggregate.reason}")
        if not scored:
            reason = "No eligible scored candidates are available."
            if ineligible:
                reason += " Ineligible candidates: " + " | ".join(ineligible[:3])
            return SelectionResult(
                "insufficient_evidence",
                (),
                reason,
                self.policy,
                self.version,
            )
        scored.sort(key=lambda item: (-item[0], item[1]))
        selected: list[str] = []
        seen_harnesses: set[str] = set()
        for _score, _candidate_id, report, _aggregate in scored:
            if self.deduplicate_harnesses and report.harness_sha256:
                if report.harness_sha256 in seen_harnesses:
                    continue
                seen_harnesses.add(report.harness_sha256)
            selected.append(report.candidate_id)
            if len(selected) >= limit:
                break
        if not selected:
            return SelectionResult(
                "insufficient_evidence",
                (),
                "Only duplicate harnesses were eligible after deduplication.",
                self.policy,
                self.version,
            )
        return SelectionResult(
            "selected",
            tuple(selected),
            f"Selected {len(selected)} candidate(s) by descending aggregate score.",
            self.policy,
            self.version,
        )


@dataclass(frozen=True)
class AutomaticFeedbackBuilder:
    """Build bounded, evidence-linked feedback from reports and saved artifacts."""

    low_score_threshold: float = 0.5
    include_unavailable_primary: bool = False
    max_items: int = 8
    policy: str = "automatic_feedback_builder"
    version: str = ITERATION_POLICY_VERSION

    def __post_init__(self):
        if not 0 <= self.low_score_threshold <= 1:
            raise ValueError("low_score_threshold must be in [0, 1]")
        if self.max_items < 1:
            raise ValueError("max_items must be positive")

    def build(self, context: EvaluationContext,
              report: EvaluationReport) -> FeedbackPacket:
        items: list[FeedbackItem] = []
        items.extend(self._stage_feedback(context))
        # A registry's declaration order is not a severity ranking.  Sorting
        # low/error signals first makes a bounded packet retain the strongest,
        # independent quality evidence instead of silently crowding out later
        # dimensions such as resource bounds or target isolation.
        for metric in sorted(report.metrics, key=_feedback_metric_order):
            if len(items) >= self.max_items:
                break
            item = self._metric_feedback(context, metric)
            if item is not None:
                items.append(item)
        if not items:
            items.append(FeedbackItem(
                None,
                "No automatic quality weakness was identified from the available evidence.",
                (_best_evidence(context, "evaluation.json",
                                "Evaluation report for the candidate"),),
                "The candidate may need exploratory variation rather than a targeted repair.",
                "Preserve valid behavior while exploring a different input mapping or state schedule.",
            ))
        return FeedbackPacket(
            context.candidate_id,
            context.round_index,
            context.source_sha256,
            context.harness_sha256,
            tuple(items[:self.max_items]),
        )

    def _stage_feedback(self, context: EvaluationContext) -> list[FeedbackItem]:
        result = context.execution_result
        items: list[FeedbackItem] = []
        failure_stage = _string_value(result.get("failure_stage"))
        error = _string_value(result.get("error"))
        if failure_stage or error:
            items.append(FeedbackItem(
                None,
                _bounded(
                    f"Candidate failed at {failure_stage or 'unknown stage'}"
                    + (f": {error}" if error else ".")
                ),
                (_best_evidence(context, "result.json", "Candidate result"),),
                "The generated harness likely violates a build, API, or runtime contract.",
                "Fix the observed failure while keeping the target source and API calls intact.",
            ))
        compilation = result.get("compilation")
        if isinstance(compilation, Mapping) and compilation.get("status") not in {
            None, "passed", "skipped", "not_started", "blocked",
        }:
            items.append(FeedbackItem(
                None,
                f"Compilation status is {compilation.get('status')}.",
                (_best_evidence(context, "compile_result.json",
                                "Compilation result"),),
                "The harness may contain invalid C, missing includes, or an invalid target API call.",
                "Repair compile errors without stubbing or redefining target functions.",
            ))
        for stage, artifact in (("smoke", "smoke_result.json"),
                                ("fuzzing", "fuzz_result.json")):
            value = result.get(stage)
            if _is_target_stage_finding(value):
                items.append(FeedbackItem(
                    MetricId.CRASH_FIDELITY,
                    f"{stage} observed a sanitizer/libFuzzer finding attributed to target code.",
                    (_best_evidence(context, artifact, "Target-attributed fuzz finding"),),
                    "The harness reached target logic deeply enough to expose a target signal.",
                    "Preserve this target reachability and crash visibility; do not mask, catch, or repair the target bug.",
                ))
                continue
            if isinstance(value, Mapping) and value.get("status") not in {
                None, "passed", "skipped", "not_started", "blocked", "completed",
            }:
                items.append(FeedbackItem(
                    None,
                    f"{stage} status is {value.get('status')}.",
                    (_best_evidence(context, artifact, f"{stage} result"),),
                    "The harness may be crashing, timing out, or violating runtime constraints.",
                    "Keep the target call reachable while fixing the evidenced runtime issue.",
                ))
        review = result.get("review")
        if isinstance(review, Mapping):
            warnings = [
                item for item in review.get("warnings", [])
                if isinstance(item, str) and item
            ]
            if warnings:
                items.append(FeedbackItem(
                    None,
                    _bounded("Review warnings: " + "; ".join(warnings[:3])),
                    (_best_evidence(context, "review.json", "Static review warnings"),),
                    "The harness may compile while still having weak input or output handling.",
                    "Address the warning without weakening target invocation.",
                ))
        return items[:self.max_items]

    def _metric_feedback(self, context: EvaluationContext,
                         metric: MetricResult) -> FeedbackItem | None:
        if metric.status == MetricStatus.ERROR:
            return FeedbackItem(
                metric.metric_id,
                f"{metric.metric_id.value} evaluator failed: {metric.reason}",
                _metric_evidence(context, metric),
                "A measurement failure can hide quality regressions.",
                "Preserve artifacts and make the candidate measurable before relying on it.",
            )
        if (
            metric.status == MetricStatus.MEASURED
            and metric.score is not None
            and metric.score <= self.low_score_threshold
        ):
            return FeedbackItem(
                metric.metric_id,
                (
                    f"{metric.metric_id.value} score is {metric.score:.3f}: "
                    f"{metric.reason}"
                ),
                _metric_evidence(context, metric),
                _metric_hypothesis(metric.metric_id),
                _metric_suggestion(metric.metric_id),
            )
        if (
            self.include_unavailable_primary
            and metric.metric_id in PRIMARY_METRICS
            and metric.status == MetricStatus.UNAVAILABLE
        ):
            return FeedbackItem(
                metric.metric_id,
                f"{metric.metric_id.value} is unavailable: {metric.reason}",
                _metric_evidence(context, metric),
                "The current run lacks evidence for this quality dimension.",
                "Enable or preserve the needed measurement artifact before comparing candidates.",
            )
        return None


@dataclass(frozen=True)
class FeedbackDrivenIterationPlanner:
    """Candidate generation strategy for one bounded next-round expansion."""

    children_per_parent: int = 2
    max_total_children: int | None = None
    policy: str = "feedback_driven_iteration_planner"
    version: str = ITERATION_POLICY_VERSION

    def __post_init__(self):
        if self.children_per_parent < 1:
            raise ValueError("children_per_parent must be positive")
        if self.max_total_children is not None and self.max_total_children < 1:
            raise ValueError("max_total_children must be positive or None")

    def plan(self, selection: SelectionResult,
             feedback: Sequence[FeedbackPacket]) -> tuple[RegenerationRequest, ...]:
        if selection.status != "selected":
            return ()
        by_candidate = {packet.candidate_id: packet for packet in feedback}
        requests: list[RegenerationRequest] = []
        remaining = self.max_total_children
        for candidate_id in selection.candidate_ids:
            packet = by_candidate.get(candidate_id)
            if packet is None:
                raise ValueError(f"missing feedback for selected candidate: {candidate_id}")
            count = self.children_per_parent
            if remaining is not None:
                if remaining <= 0:
                    break
                count = min(count, remaining)
                remaining -= count
            requests.append(RegenerationRequest(
                candidate_id,
                packet.round_index + 1,
                packet,
                count,
            ))
        return tuple(requests)


def _metric_evidence(context: EvaluationContext,
                     metric: MetricResult) -> tuple[Evidence, ...]:
    if metric.evidence:
        return metric.evidence
    return (_best_evidence(context, "evaluation.json",
                           f"{metric.metric_id.value} metric result"),)


def _best_evidence(context: EvaluationContext, artifact: str,
                   description: str) -> Evidence:
    path = context.artifact(artifact)
    if path.exists():
        return Evidence(artifact, description)
    fallback = context.artifact("result.json")
    if fallback.exists():
        return Evidence("result.json", "Candidate result fallback")
    return Evidence("evaluation.json", description)


def _metric_hypothesis(metric_id: MetricId) -> str:
    return {
        MetricId.REACHABILITY: "The harness may reject inputs before the target API is reached.",
        MetricId.COVERAGE: "The input mapping may satisfy only shallow target paths.",
        MetricId.EXECUTION_SPEED: "Per-input setup or loops may be too expensive.",
        MetricId.DETERMINISM: "Repeated inputs may not produce stable behavior.",
        MetricId.STATE_RESET: "State may leak across libFuzzer iterations.",
        MetricId.INPUT_EXPRESSIVENESS: "Fuzzer bytes may control too few API-relevant fields.",
        MetricId.DEEP_REACHABILITY: "The harness may not drive inputs toward deeper target logic.",
        MetricId.CRASH_FIDELITY: "The harness may obscure sanitizer or crash signals.",
        MetricId.RESOURCE_BOUND: "Input-dependent resource use may be insufficiently bounded.",
        MetricId.TARGET_ISOLATION: "The harness may exercise wrappers instead of the core target API.",
    }[metric_id]


def _metric_suggestion(metric_id: MetricId) -> str:
    return {
        MetricId.REACHABILITY: "Reduce premature guards and route valid memory/size pairs into the target.",
        MetricId.COVERAGE: "Use the feedback to vary structural fields, lengths, and guarded constants.",
        MetricId.EXECUTION_SPEED: "Move expensive initialization out of per-byte loops and cap input-driven work.",
        MetricId.DETERMINISM: "Remove random, time, file, and cross-process dependencies from the harness.",
        MetricId.STATE_RESET: "Initialize and clean up all target state within each fuzzer iteration.",
        MetricId.INPUT_EXPRESSIVENESS: "Decode the byte stream into multiple semantically distinct parameters.",
        MetricId.DEEP_REACHABILITY: "Preserve API contracts while satisfying deeper parser or state preconditions.",
        MetricId.CRASH_FIDELITY: "Avoid swallowing errors or replacing crashing target behavior with stubs.",
        MetricId.RESOURCE_BOUND: "Bound allocation sizes, loop counts, recursion, and retained state.",
        MetricId.TARGET_ISOLATION: "Call the core target functions directly and avoid unnecessary CLI/file layers.",
    }[metric_id]


def _string_value(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _bounded(value: str, limit: int = 800) -> str:
    return value if len(value) <= limit else value[:limit - 3] + "..."


def _is_target_stage_finding(value: object) -> bool:
    if not isinstance(value, Mapping) or value.get("status") != "finding":
        return False
    classification = value.get("crash_classification")
    return (
        isinstance(classification, Mapping)
        and classification.get("classification") == POTENTIAL_TARGET_CRASH
    )


def _feedback_metric_order(metric: MetricResult) -> tuple[float, str]:
    """Stable weakest-first ordering without assigning scores to unknowns."""

    if metric.status == MetricStatus.ERROR:
        return (-1.0, metric.metric_id.value)
    if metric.status == MetricStatus.MEASURED and metric.score is not None:
        return (float(metric.score), metric.metric_id.value)
    if metric.status == MetricStatus.UNAVAILABLE:
        return (2.0, metric.metric_id.value)
    return (3.0, metric.metric_id.value)


def _dynamic_quality_gate_failures(
    report: EvaluationReport,
    policy: WeightedAggregationPolicy,
) -> tuple[str, ...]:
    if _has_target_finding(report):
        return ()
    failures: list[str] = []
    coverage = _metric(report, MetricId.COVERAGE)
    if coverage is None or coverage.status != MetricStatus.MEASURED or coverage.score is None:
        failures.append("coverage is not measured")
    elif coverage.score < policy.minimum_coverage_score:
        failures.append(
            f"coverage score {coverage.score:.3f} < {policy.minimum_coverage_score:.3f}"
        )

    features = _measurement(report, "engine_features")
    if features is None:
        features = _measurement(report, "fuzzer_features")
    if features is None:
        failures.append("libFuzzer feature count is not measured")
    elif features < policy.minimum_feature_count:
        failures.append(
            f"features {features:g} < {policy.minimum_feature_count:g}"
        )

    deep = _metric(report, MetricId.DEEP_REACHABILITY)
    if deep is None or deep.status != MetricStatus.MEASURED or deep.score is None:
        failures.append("deep_reachability is not measured")
    elif deep.score < policy.minimum_deep_reachability_score:
        failures.append(
            f"deep_reachability score {deep.score:.3f} < "
            f"{policy.minimum_deep_reachability_score:.3f}"
        )

    crash = _crash_classification(report)
    if crash in BLOCKING_CRASH_CLASSIFICATIONS:
        failures.append(f"crash classification is {crash}")
    return tuple(failures)


def _metric(report: EvaluationReport, metric_id: MetricId) -> MetricResult | None:
    return next((metric for metric in report.metrics if metric.metric_id == metric_id), None)


def _measurement(report: EvaluationReport, name: str) -> float | None:
    for metric in report.metrics:
        for measurement in metric.measurements:
            if (
                measurement.name == name
                and isinstance(measurement.value, (int, float))
                and not isinstance(measurement.value, bool)
            ):
                return float(measurement.value)
    return None


def _crash_classification(report: EvaluationReport) -> str | None:
    crash = _metric(report, MetricId.CRASH_FIDELITY)
    if crash is None:
        return None
    for measurement in crash.measurements:
        if measurement.name == "crash_classification" and isinstance(measurement.value, str):
            return measurement.value
    return None


def _has_target_finding(report: EvaluationReport) -> bool:
    return _crash_classification(report) == POTENTIAL_TARGET_CRASH
