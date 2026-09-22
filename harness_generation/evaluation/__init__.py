"""Public extension API for evidence-based Harness evaluation."""

from .coverage import TargetCoverageEvaluator
from .optimizer import (CandidateEvaluation, EvaluationOptimizer, OptimizationConfig,
                        OptimizationResult, OPTIMIZER_SCHEMA_VERSION)
from .registry import METRIC_SPECS, EvaluationEngine, MetricEvaluator, MetricSpec
from .signals import (QUALITY_SIGNAL_VERSION, CrashFidelityEvaluator,
                      DeepReachabilityEvaluator, ExecutionSpeedEvaluator,
                      HarnessSignalError, HarnessStaticFacts,
                      InputExpressivenessEvaluator, QualitySignalConfig,
                      ReplayQualityEvaluator, ResourceBoundEvaluator,
                      StaticReachabilityEvaluator, TargetIsolationEvaluator,
                      analyze_harness_ast, default_quality_evaluators,
                      target_call_graph)
from .types import (AggregateResult, EvaluationContext, EvaluationRecipe, EvaluationReport, Evidence,
                    Measurement, MetricId, MetricResult, MetricStatus,
                    evaluation_report_from_dict)


def default_quality_engine(
    config: QualitySignalConfig | None = None,
) -> EvaluationEngine:
    """Create the standard multi-dimensional signal engine for candidates.

    ``EvaluationEngine()`` remains an intentionally empty extension point for
    callers that need to choose every evaluator themselves.
    """

    return EvaluationEngine(default_quality_evaluators(config))

__all__ = ["METRIC_SPECS", "EvaluationEngine", "MetricEvaluator", "MetricSpec",
           "AggregateResult", "EvaluationContext", "EvaluationRecipe", "EvaluationReport", "Evidence",
           "Measurement", "MetricId", "MetricResult", "MetricStatus",
           "evaluation_report_from_dict",
           "CandidateEvaluation", "EvaluationOptimizer", "OptimizationConfig",
           "OptimizationResult", "OPTIMIZER_SCHEMA_VERSION",
           "TargetCoverageEvaluator", "QUALITY_SIGNAL_VERSION",
           "CrashFidelityEvaluator", "DeepReachabilityEvaluator",
           "ExecutionSpeedEvaluator", "HarnessSignalError", "HarnessStaticFacts",
           "InputExpressivenessEvaluator", "QualitySignalConfig",
           "ReplayQualityEvaluator", "ResourceBoundEvaluator",
           "StaticReachabilityEvaluator", "TargetIsolationEvaluator",
           "analyze_harness_ast", "default_quality_engine",
           "default_quality_evaluators", "target_call_graph"]
