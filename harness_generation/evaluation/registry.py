"""Ten independently replaceable evaluator slots; no metric algorithms yet."""

from dataclasses import dataclass
from typing import Iterable, Protocol

from .types import EvaluationContext, EvaluationReport, MetricId, MetricResult, MetricStatus


@dataclass(frozen=True)
class MetricSpec:
    metric_id: MetricId
    primary: bool
    objective: str
    expected_evidence: tuple[str, ...]


METRIC_SPECS = (
    MetricSpec(MetricId.REACHABILITY, True, "Fraction of testcases that actually enter the target API.",
               ("total_testcases", "target_entered_testcases")),
    MetricSpec(MetricId.COVERAGE, True, "Explore target edges, branches and functions.",
               ("target_coverage", "coverage_scope", "execution_budget")),
    MetricSpec(MetricId.EXECUTION_SPEED, True, "Low per-case cost without expensive I/O or initialization.",
               ("executed_testcases", "execution_time", "environment", "initialization_cost")),
    MetricSpec(MetricId.DETERMINISM, True, "Stable paths and outcomes for repeated identical inputs.",
               ("repeated_input_ids", "path_signatures", "outcomes", "seeds")),
    MetricSpec(MetricId.STATE_RESET, True, "No unintended cross-testcase state contamination.",
               ("case_order_comparisons", "fresh_process_comparisons", "state_observations")),
    MetricSpec(MetricId.INPUT_EXPRESSIVENESS, True, "Input controls multiple relevant parameters and relationships.",
               ("input_to_parameter_mapping", "parameter_variation", "api_contract")),
    MetricSpec(MetricId.DEEP_REACHABILITY, True, "Reach designated deep or security-sensitive target logic.",
               ("sensitive_target_definitions", "call_traces", "deep_target_hits")),
    MetricSpec(MetricId.CRASH_FIDELITY, False, "Preserve sanitizer and crash signals.",
               ("known_fault_probes", "exit_signals", "sanitizer_diagnostics")),
    MetricSpec(MetricId.RESOURCE_BOUND, False, "Bound input size, memory, loops and other resource consumption.",
               ("configured_limits", "observed_resource_use", "bound_stress_probes")),
    MetricSpec(MetricId.TARGET_ISOLATION, False, "Call the core library/API without unnecessary CLI layers.",
               ("call_graph", "entrypoint_trace", "wrapper_dependencies")),
)


class MetricEvaluator(Protocol):
    metric_id: MetricId

    def evaluate(self, context: EvaluationContext) -> MetricResult:
        """Return evidence-backed measurements or an explicit unavailable state.

        Implementations must not alter source, harness or prior run artifacts.
        Missing fuzz/probe data is unavailable, not a score of zero. New probes
        must use separate artifacts and declare their execution cost.
        """
        ...


class EvaluationEngine:
    def __init__(self, evaluators: Iterable[MetricEvaluator] = ()):
        self._evaluators: dict[MetricId, MetricEvaluator] = {}
        for evaluator in evaluators:
            self.register(evaluator)

    def register(self, evaluator: MetricEvaluator) -> None:
        if not isinstance(evaluator.metric_id, MetricId):
            raise ValueError("Unknown metric ID")
        if evaluator.metric_id in self._evaluators:
            raise ValueError(f"Evaluator already registered for {evaluator.metric_id.value}")
        self._evaluators[evaluator.metric_id] = evaluator

    def evaluate(self, context: EvaluationContext) -> EvaluationReport:
        results = []
        for spec in METRIC_SPECS:
            evaluator = self._evaluators.get(spec.metric_id)
            if evaluator is None:
                result = MetricResult(spec.metric_id, MetricStatus.NOT_IMPLEMENTED,
                                      "unimplemented", "1", "No evaluator registered for this criterion.")
            else:
                try:
                    result = evaluator.evaluate(context)
                    if not isinstance(result, MetricResult) or result.metric_id != spec.metric_id:
                        raise ValueError("Evaluator returned a result for the wrong metric")
                except Exception as exc:
                    # An evaluator failure must not masquerade as low quality or
                    # prevent other metrics from being evaluated. No raw secrets.
                    result = MetricResult(spec.metric_id, MetricStatus.ERROR,
                                          type(evaluator).__name__, "unknown",
                                          f"Evaluator failed: {type(exc).__name__}")
            results.append(result)
        return EvaluationReport(context.candidate_id, context.parent_id, context.round_index,
                                context.source_sha256, context.harness_sha256, tuple(results))
