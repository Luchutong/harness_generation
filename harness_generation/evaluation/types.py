"""Evidence-bearing metric contracts; unknown values are never zero scores."""

from dataclasses import asdict, dataclass, field
from enum import Enum
import math
from pathlib import Path
from typing import Any, Mapping


class MetricId(str, Enum):
    REACHABILITY = "reachability"
    COVERAGE = "coverage"
    EXECUTION_SPEED = "execution_speed"
    DETERMINISM = "determinism"
    STATE_RESET = "state_reset"
    INPUT_EXPRESSIVENESS = "input_expressiveness"
    DEEP_REACHABILITY = "deep_reachability"
    CRASH_FIDELITY = "crash_fidelity"
    RESOURCE_BOUND = "resource_bound"
    TARGET_ISOLATION = "target_isolation"


class MetricStatus(str, Enum):
    NOT_IMPLEMENTED = "not_implemented"
    UNAVAILABLE = "unavailable"
    MEASURED = "measured"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


@dataclass(frozen=True)
class Evidence:
    artifact: str  # Candidate-relative artifact path, or explicitly documented URI.
    description: str
    locator: str | None = None  # e.g. a line number, JSON pointer, or testcase ID.


@dataclass(frozen=True)
class Measurement:
    name: str
    value: float | int | str | bool
    unit: str
    scope: str  # e.g. target_api, target_code, harness, whole_process.


@dataclass(frozen=True)
class EvaluationContext:
    candidate_id: str
    parent_id: str | None
    round_index: int
    directory: Path
    target_function: str
    source_sha256: str
    harness_sha256: str | None
    execution_result: Mapping[str, object]

    def artifact(self, filename: str) -> Path:
        """Resolve a candidate-local artifact without assuming it exists."""
        root = self.directory.resolve()
        path = (root / filename).resolve()
        if not path.is_relative_to(root):
            raise ValueError("Artifact must be inside the candidate directory")
        return path


@dataclass(frozen=True)
class MetricResult:
    metric_id: MetricId
    status: MetricStatus
    evaluator: str
    version: str
    reason: str
    score: float | None = None  # Optional normalized quality, higher is better.
    measurements: tuple[Measurement, ...] = ()
    evidence: tuple[Evidence, ...] = ()

    def __post_init__(self):
        if not isinstance(self.metric_id, MetricId) or not isinstance(self.status, MetricStatus):
            raise ValueError("Use MetricId and MetricStatus enum members")
        if not self.evaluator or not self.version or not self.reason:
            raise ValueError("Evaluator identity, version and explanation are required")
        if self.status != MetricStatus.MEASURED and self.score is not None:
            raise ValueError("Unmeasured metrics cannot have a score")
        if self.score is not None and (
            isinstance(self.score, bool) or not isinstance(self.score, (float, int))
            or not math.isfinite(self.score) or not 0 <= self.score <= 1
        ):
            raise ValueError("A normalized score must be finite and in [0, 1]")
        if self.status == MetricStatus.MEASURED and (not self.measurements or not self.evidence):
            raise ValueError("Measured metrics require raw measurements and evidence")
        for measurement in self.measurements:
            if not isinstance(measurement.value, (str, bool, int, float)):
                raise ValueError("Measurement values must be JSON scalars")
            if isinstance(measurement.value, float) and not math.isfinite(measurement.value):
                raise ValueError("Measurement values must be finite")


@dataclass(frozen=True)
class AggregateResult:
    status: str = "not_configured"
    score: float | None = None
    eligible: bool | None = None
    reason: str = "No aggregation or eligibility policy is implemented."
    policy: str | None = None
    version: str | None = None

    def __post_init__(self):
        if self.status not in ("not_configured", "insufficient_evidence", "scored"):
            raise ValueError("Unknown aggregation status")
        if self.status != "scored" and self.score is not None:
            raise ValueError("Unscored aggregation cannot have a score")
        if self.status == "scored" and (
            isinstance(self.score, bool) or not isinstance(self.score, (int, float))
            or not math.isfinite(self.score) or not 0 <= self.score <= 1
            or not self.policy or not self.version
        ):
            raise ValueError("Scored aggregation requires a finite [0, 1] score and versioned policy")


@dataclass(frozen=True)
class EvaluationReport:
    candidate_id: str
    parent_id: str | None
    round_index: int
    source_sha256: str
    harness_sha256: str | None
    metrics: tuple[MetricResult, ...]
    aggregate: AggregateResult = field(default_factory=AggregateResult)
    schema_version: int = 1

    @property
    def status(self) -> str:
        if any(m.status == MetricStatus.ERROR for m in self.metrics):
            return "error"
        if all(m.status == MetricStatus.NOT_IMPLEMENTED for m in self.metrics):
            return "not_implemented"
        if all(m.status in (MetricStatus.MEASURED, MetricStatus.NOT_APPLICABLE) for m in self.metrics):
            return "complete"
        return "partial"

    def to_dict(self) -> dict:
        return {**asdict(self), "status": self.status}


def evaluation_report_from_dict(value: Mapping[str, Any]) -> EvaluationReport:
    """Load a persisted report without weakening the metric contracts.

    Feedback-loop selection must compare the exact report that was persisted by
    each child candidate, rather than reconstructing scores from prose or
    treating unknown fields as zero.  This parser intentionally accepts only
    the stable JSON shape emitted by :meth:`EvaluationReport.to_dict`.
    """

    if not isinstance(value, Mapping):
        raise ValueError("evaluation report must be an object")
    raw_metrics = value.get("metrics")
    if not isinstance(raw_metrics, list):
        raise ValueError("evaluation report metrics must be a list")
    metrics: list[MetricResult] = []
    for item in raw_metrics:
        if not isinstance(item, Mapping):
            raise ValueError("evaluation report metric must be an object")
        raw_measurements = item.get("measurements", [])
        raw_evidence = item.get("evidence", [])
        if not isinstance(raw_measurements, list) or not isinstance(raw_evidence, list):
            raise ValueError("metric measurements and evidence must be lists")
        try:
            measurements = tuple(
                Measurement(
                    measurement["name"], measurement["value"], measurement["unit"],
                    measurement["scope"],
                )
                for measurement in raw_measurements
                if isinstance(measurement, Mapping)
            )
            evidence = tuple(
                Evidence(
                    entry["artifact"], entry["description"], entry.get("locator"),
                )
                for entry in raw_evidence
                if isinstance(entry, Mapping)
            )
            if len(measurements) != len(raw_measurements) or len(evidence) != len(raw_evidence):
                raise ValueError("metric measurements and evidence must be objects")
            metrics.append(MetricResult(
                MetricId(item["metric_id"]),
                MetricStatus(item["status"]),
                item["evaluator"],
                item["version"],
                item["reason"],
                score=item.get("score"),
                measurements=measurements,
                evidence=evidence,
            ))
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"invalid metric in evaluation report: {type(error).__name__}") from None
    raw_aggregate = value.get("aggregate", {})
    if not isinstance(raw_aggregate, Mapping):
        raise ValueError("evaluation report aggregate must be an object")
    try:
        aggregate = AggregateResult(
            status=raw_aggregate.get("status", "not_configured"),
            score=raw_aggregate.get("score"),
            eligible=raw_aggregate.get("eligible"),
            reason=raw_aggregate.get(
                "reason", "No aggregation or eligibility policy is implemented."
            ),
            policy=raw_aggregate.get("policy"),
            version=raw_aggregate.get("version"),
        )
        candidate_id = value["candidate_id"]
        parent_id = value.get("parent_id")
        round_index = value["round_index"]
        source_sha256 = value["source_sha256"]
        harness_sha256 = value.get("harness_sha256")
        schema_version = value.get("schema_version", 1)
        if (
            not isinstance(candidate_id, str)
            or parent_id is not None and not isinstance(parent_id, str)
            or type(round_index) is not int
            or not isinstance(source_sha256, str)
            or harness_sha256 is not None and not isinstance(harness_sha256, str)
            or type(schema_version) is not int
        ):
            raise ValueError("evaluation report identity fields have invalid types")
        return EvaluationReport(
            candidate_id, parent_id, round_index, source_sha256, harness_sha256,
            tuple(metrics), aggregate=aggregate, schema_version=schema_version,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"invalid evaluation report: {type(error).__name__}") from None
