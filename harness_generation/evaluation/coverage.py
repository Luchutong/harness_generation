"""Evaluators backed by target-only LLVM coverage artifacts."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Mapping

from .registry import MetricEvaluator
from .types import Evidence, EvaluationContext, Measurement, MetricId, MetricResult, MetricStatus
from ..target_coverage import latest_target_coverage_summary


class TargetCoverageEvaluator(MetricEvaluator):
    """Report target-code coverage from ``target_coverage.json`` artifacts."""

    metric_id = MetricId.COVERAGE
    version = "2"

    def __init__(
        self,
        artifact: str = "target_coverage.json",
        *,
        metrics_artifact: str = "metrics.json",
        engine_coverage_reference: float = 64.0,
        engine_feature_reference: float = 128.0,
    ) -> None:
        self.artifact = artifact
        self.metrics_artifact = metrics_artifact
        self.engine_coverage_reference = engine_coverage_reference
        self.engine_feature_reference = engine_feature_reference

    def evaluate(self, context: EvaluationContext) -> MetricResult:
        path = latest_target_coverage_summary(context.artifact(self.artifact))
        if path is None:
            proxy = _engine_coverage_proxy(
                context, self.metrics_artifact,
                self.engine_coverage_reference, self.engine_feature_reference,
            )
            if proxy is not None:
                return proxy
            return MetricResult(
                self.metric_id,
                MetricStatus.UNAVAILABLE,
                type(self).__name__,
                self.version,
                "No target-only coverage artifact or libFuzzer cov/ft telemetry is available.",
            )
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, Mapping) or document.get("status") != "passed":
            return MetricResult(
                self.metric_id,
                MetricStatus.UNAVAILABLE,
                type(self).__name__,
                self.version,
                "Target-only coverage did not complete successfully.",
                evidence=(Evidence(_relative(context.directory, path),
                                   "Target-only coverage summary"),),
            )
        target_only = document.get("target_only", {})
        totals = target_only.get("totals", {}) if isinstance(target_only, Mapping) else {}
        measurements = _measurements(totals)
        if not measurements:
            return MetricResult(
                self.metric_id,
                MetricStatus.UNAVAILABLE,
                type(self).__name__,
                self.version,
                "Target-only coverage summary contains no measured totals.",
                evidence=(Evidence(_relative(context.directory, path),
                                   "Target-only coverage summary"),),
            )
        score = _score(totals)
        return MetricResult(
            self.metric_id,
            MetricStatus.MEASURED,
            type(self).__name__,
            self.version,
            "Measured LLVM source coverage scoped to target source files.",
            score=score,
            measurements=measurements,
            evidence=(
                Evidence(_relative(context.directory, path),
                         "Target-only coverage summary",
                         "/target_only/totals"),
            ),
        )


def _measurements(value: Any) -> tuple[Measurement, ...]:
    if not isinstance(value, Mapping):
        return ()
    measurements: list[Measurement] = []
    for key in ("functions", "lines", "regions", "branches"):
        item = value.get(key)
        if not isinstance(item, Mapping):
            continue
        for field, unit in (
            ("count", key),
            ("covered", key),
            ("percent", "percent"),
        ):
            scalar = item.get(field)
            if isinstance(scalar, (int, float)) and not isinstance(scalar, bool):
                measurements.append(
                    Measurement(
                        f"target_{key}_{field}",
                        scalar,
                        unit,
                        "target_code",
                    )
                )
    return tuple(measurements)


def _score(totals: Any) -> float | None:
    if not isinstance(totals, Mapping):
        return None
    for key in ("branches", "regions", "lines", "functions"):
        item = totals.get(key)
        if not isinstance(item, Mapping):
            continue
        percent = item.get("percent")
        if isinstance(percent, (int, float)) and not isinstance(percent, bool):
            return max(0.0, min(1.0, float(percent) / 100.0))
    return None


def _engine_coverage_proxy(
    context: EvaluationContext,
    artifact: str,
    coverage_reference: float,
    feature_reference: float,
) -> MetricResult | None:
    path = context.artifact(artifact)
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    values = _measurement_values(document)
    coverage = values.get("fuzzer_coverage_edges_or_blocks")
    features = values.get("fuzzer_features")
    if coverage is None and features is None:
        return None
    measurements = []
    if coverage is not None:
        measurements.append(Measurement(
            "engine_coverage_edges_or_blocks", coverage, "edges_or_blocks",
            "instrumented_program",
        ))
    if features is not None:
        measurements.append(Measurement(
            "engine_features", features, "features",
            "instrumented_program",
        ))
    coverage_score = 0.0 if coverage is None else min(
        1.0, float(coverage) / max(1.0, float(coverage_reference))
    )
    feature_score = 0.0 if features is None else min(
        1.0, float(features) / max(1.0, float(feature_reference))
    )
    weights = (0.6 if coverage is not None else 0.0) + (
        0.4 if features is not None else 0.0
    )
    score = 0.0 if weights == 0 else (
        (0.6 * coverage_score if coverage is not None else 0.0)
        + (0.4 * feature_score if features is not None else 0.0)
    ) / weights
    return MetricResult(
        MetricId.COVERAGE,
        MetricStatus.MEASURED,
        "TargetCoverageEvaluator",
        "2",
        "No target-only coverage artifact is available; using libFuzzer "
        "engine cov/ft telemetry as a selection proxy. This score is not "
        "target-source coverage.",
        score=round(score, 6),
        measurements=tuple(measurements),
        evidence=(Evidence(artifact, "Collected libFuzzer cov/ft telemetry"),),
    )


def _measurement_values(document: Mapping[str, Any]) -> dict[str, float]:
    values: dict[str, float] = {}
    raw = document.get("measurements")
    if not isinstance(raw, list):
        return values
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        name = item.get("name")
        value = item.get("value")
        if (
            isinstance(name, str)
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
            and math.isfinite(float(value))
        ):
            values[name] = float(value)
    return values


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)
