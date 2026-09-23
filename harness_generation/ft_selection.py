"""Evidence-based ranking and budgeted selection for Function Triplets."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
from typing import Any, Iterable, Mapping, Sequence

from .triplet import FunctionTriplet, triplets_document


FT_SELECTION_SCHEMA_VERSION = 2
FT_SELECTION_POLICY_VERSION = "ft-priority-v4"


@dataclass(frozen=True)
class ScoreMetric:
    """One independently inspectable input to the FT priority score."""

    name: str
    weight: float
    status: str
    score: float | None
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "weight": self.weight,
            "status": self.status,
            "score": self.score,
            "evidence": dict(self.evidence),
        }


@dataclass(frozen=True)
class FTScore:
    triplet_id: str
    eligible: bool
    score: float | None
    estimated_llm_calls: int
    structural_units: int
    metrics: tuple[ScoreMetric, ...]
    exclusion_reasons: tuple[str, ...]
    function_ids: tuple[str, ...]
    structure_ids: tuple[str, ...]
    anchor_function_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "triplet_id": self.triplet_id,
            "eligible": self.eligible,
            "score": self.score,
            "estimated_llm_calls": self.estimated_llm_calls,
            "structural_units": self.structural_units,
            "metrics": [metric.to_dict() for metric in self.metrics],
            "exclusion_reasons": list(self.exclusion_reasons),
            "footprint": {
                "anchor_function_id": self.anchor_function_id,
                "function_ids": list(self.function_ids),
                "structure_ids": list(self.structure_ids),
            },
        }


@dataclass(frozen=True)
class SelectedFT:
    order: int
    triplet_id: str
    base_score: float
    novelty: float
    marginal_benefit: float
    benefit_per_call: float
    estimated_llm_calls: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "order": self.order,
            "triplet_id": self.triplet_id,
            "base_score": self.base_score,
            "novelty": self.novelty,
            "marginal_benefit": self.marginal_benefit,
            "benefit_per_call": self.benefit_per_call,
            "estimated_llm_calls": self.estimated_llm_calls,
        }


def _round(value: float) -> float:
    return round(max(0.0, min(1.0, value)), 6)


def _as_mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _confidence(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return max(0.0, min(1.0, float(value)))


def _annotation_index(annotations: object) -> dict[str, Mapping[str, Any]]:
    if isinstance(annotations, Mapping):
        nested = annotations.get("functions")
        if isinstance(nested, Mapping):
            return {
                str(function_id): _as_mapping(annotation)
                for function_id, annotation in nested.items()
            }
        if annotations and all(
            isinstance(value, Mapping) for value in annotations.values()
        ):
            return {
                str(function_id): _as_mapping(annotation)
                for function_id, annotation in annotations.items()
            }
        records: object = annotations.get("annotations", annotations)
    else:
        records = annotations
    if isinstance(records, Sequence) and not isinstance(records, (str, bytes)):
        indexed: dict[str, Mapping[str, Any]] = {}
        for record in records:
            annotation = _as_mapping(record)
            function_id = annotation.get("function_id")
            if isinstance(function_id, str) and function_id:
                indexed[function_id] = annotation
        return indexed
    return {}


def _function_annotation(
    annotations: Mapping[str, Mapping[str, Any]], function_id: str
) -> Mapping[str, Any]:
    return annotations.get(function_id, {})


def _input_metric(
    triplet: FunctionTriplet, annotations: Mapping[str, Mapping[str, Any]]
) -> ScoreMetric:
    annotation = _function_annotation(annotations, triplet.isf.function_id)
    stream_parameters = annotation.get("stream_parameters")
    positive: list[tuple[str, float]] = []
    if isinstance(stream_parameters, Sequence) and not isinstance(
        stream_parameters, (str, bytes)
    ):
        for item in stream_parameters:
            stream = _as_mapping(item)
            if stream.get("is_byte_stream") is not True:
                continue
            confidence = _confidence(stream.get("confidence"))
            if confidence is not None:
                positive.append((str(stream.get("parameter", "")), confidence))

    if not positive:
        return ScoreMetric(
            name="input_evidence",
            weight=0.30,
            status="unavailable",
            score=None,
            evidence={"positive_byte_stream_parameters": []},
        )

    best = max(confidence for _, confidence in positive)
    return ScoreMetric(
        name="input_evidence",
        weight=0.30,
        status="measured",
        score=_round(best),
        evidence={
            "positive_byte_stream_parameters": [name for name, _ in positive],
            "maximum_confidence": _round(best),
        },
    )


def _structural_confidence_metric(
    triplet: FunctionTriplet, annotations: Mapping[str, Mapping[str, Any]]
) -> ScoreMetric:
    decision_confidences: list[float] = []
    for function in triplet.functions:
        annotation = _function_annotation(annotations, function.function_id)
        decisions = annotation.get("decisions")
        if not isinstance(decisions, Sequence) or isinstance(decisions, (str, bytes)):
            continue
        for item in decisions:
            decision = _as_mapping(item)
            confidence = _confidence(decision.get("confidence"))
            if confidence is not None:
                decision_confidences.append(confidence)

    components: list[tuple[str, float, float]] = []
    if decision_confidences:
        mean = sum(decision_confidences) / len(decision_confidences)
        weakest = min(decision_confidences)
        # The weakest link matters because a single wrong role/direction can break a harness.
        components.append(("annotation_confidence", 0.65, 0.6 * mean + 0.4 * weakest))

    if triplet.edges:
        exact = sum(1 for edge in triplet.edges if not edge.inferred) / len(triplet.edges)
        components.append(("explicit_edge_fraction", 0.35, exact))

    if not components:
        return ScoreMetric(
            name="structural_confidence",
            weight=0.25,
            status="unavailable",
            score=None,
            evidence={"decision_count": 0, "edge_count": 0},
        )

    component_weight = sum(weight for _, weight, _ in components)
    score = sum(weight * value for _, weight, value in components) / component_weight
    return ScoreMetric(
        name="structural_confidence",
        weight=0.25,
        status="measured",
        score=_round(score),
        evidence={
            "decision_count": len(decision_confidences),
            "minimum_decision_confidence": (
                _round(min(decision_confidences)) if decision_confidences else None
            ),
            "edge_count": len(triplet.edges),
            "inferred_edge_count": sum(1 for edge in triplet.edges if edge.inferred),
        },
    )


def _opportunity_metric(triplet: FunctionTriplet) -> ScoreMetric:
    source_files = {function.file for function in triplet.functions}
    components = {
        "prf": min(len(triplet.prfs) / 4.0, 1.0),
        "structures": min(len(triplet.structures) / 3.0, 1.0),
        "source_files": min(len(source_files) / 3.0, 1.0),
        "edges": min(len(triplet.edges) / 6.0, 1.0),
    }
    score = (
        0.50 * components["prf"]
        + 0.25 * components["structures"]
        + 0.15 * components["source_files"]
        + 0.10 * components["edges"]
    )
    return ScoreMetric(
        name="structural_opportunity",
        weight=0.25,
        status="measured",
        score=_round(score),
        evidence={
            "prf_count": len(triplet.prfs),
            "structure_count": len(triplet.structures),
            "source_file_count": len(source_files),
            "edge_count": len(triplet.edges),
            "saturation": {"prf": 4, "structures": 3, "source_files": 3, "edges": 6},
        },
    )


def _readiness_metric(triplet: FunctionTriplet) -> ScoreMetric:
    kinds = {semantic.kind for semantic in triplet.bypass_semantics}
    has_return = bool(kinds & {"return_status", "return_struct"})
    has_struct = bool(kinds & {"struct_access_hint", "return_struct"})
    has_cleanup = bool(triplet.hpfs or triplet.ownership_relations)
    opaque_resources = sorted({
        str(semantic.metadata.get("resource_type"))
        for semantic in triplet.bypass_semantics
        if semantic.kind == "opaque_handle_parameter"
        and semantic.metadata.get("resource_type")
    })
    checks = {
        "fuzzer_input_binding": "fuzzer_input_binding" in kinds,
        "guard_condition": "guard_condition" in kinds,
        "return_semantics": has_return,
        "struct_semantics": has_struct,
        "cleanup_evidence": has_cleanup,
    }
    weights = {
        "fuzzer_input_binding": 0.35,
        "guard_condition": 0.15,
        "return_semantics": 0.15,
        "struct_semantics": 0.15,
        "cleanup_evidence": 0.20,
    }
    score = sum(weights[name] for name, present in checks.items() if present)
    return ScoreMetric(
        name="harness_readiness",
        weight=0.20,
        status="measured",
        score=_round(score),
        evidence={
            "checks": checks,
            "bypass_semantic_kinds": sorted(kinds),
            "hpf_count": len(triplet.hpfs),
            "ownership_relation_count": len(triplet.ownership_relations),
            "opaque_handle_resources": opaque_resources,
            "opaque_lifecycle_closed": (
                not opaque_resources or bool(triplet.ownership_relations)
            ),
        },
    )


def _usage_support_metric(triplet: FunctionTriplet) -> ScoreMetric:
    relations = [
        relation for relation in triplet.ownership_relations
        if relation.source.startswith("usage_mining") and relation.support_total > 0
    ]
    if not relations:
        return ScoreMetric(
            name="usage_support",
            weight=0.20,
            status="unavailable",
            score=None,
            evidence={"support_total": 0, "support_by_source": {}},
        )
    support_total = sum(relation.support_total for relation in relations)
    by_source: dict[str, int] = {}
    for relation in relations:
        for source, count in relation.support_by_source.items():
            by_source[source] = by_source.get(source, 0) + int(count)
    frequency = min(math.log2(1 + support_total) / math.log2(9), 1.0)
    diversity = len({name for name, count in by_source.items() if count > 0}) / 3.0
    production = 1.0 if by_source.get("production", 0) > 0 else 0.0
    lifecycle_confidence = sum(
        relation.confidence for relation in relations
    ) / len(relations)
    score = (
        0.45 * frequency
        + 0.25 * min(diversity, 1.0)
        + 0.10 * production
        + 0.20 * lifecycle_confidence
    )
    return ScoreMetric(
        name="usage_support",
        weight=0.20,
        status="measured",
        score=_round(score),
        evidence={
            "support_total": support_total,
            "support_by_source": dict(sorted(by_source.items())),
            "usage_pattern_ids": sorted(
                relation.usage_pattern_id for relation in relations
                if relation.usage_pattern_id is not None
            ),
            "lifecycle_confidence": _round(lifecycle_confidence),
            "semantic_reviewed": any(
                relation.source in {"usage_mining+llm", "usage_mining+semantic_review"}
                for relation in relations
            ),
            "llm_reviewed": any(
                relation.source == "usage_mining+llm" for relation in relations
            ),
        },
    )


def estimate_structural_units(triplet: FunctionTriplet) -> int:
    """Mirror Stage 2 grouping without importing its private implementation."""
    return len(triplet.structural_steps())


def triplet_catalog_sha256(triplets: Iterable[FunctionTriplet]) -> str:
    """Bind a selection manifest to the exact canonical FT catalog."""
    payload = json.dumps(
        triplets_document(triplets),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def score_triplet(
    triplet: FunctionTriplet, annotations: object
) -> FTScore:
    annotation_index = _annotation_index(annotations)
    metrics = (
        _input_metric(triplet, annotation_index),
        _structural_confidence_metric(triplet, annotation_index),
        _opportunity_metric(triplet),
        _readiness_metric(triplet),
        _usage_support_metric(triplet),
    )
    exclusions: list[str] = []
    input_metric = metrics[0]
    if input_metric.status != "measured":
        exclusions.append("missing_positive_byte_stream_evidence")
    if not triplet.functions:
        exclusions.append("empty_function_footprint")
    if triplet.isf.function == "LLVMFuzzerTestOneInput":
        exclusions.append("existing_fuzzer_entrypoint")
    opaque_anchor_resources = {
        semantic.metadata.get("resource_type")
        for semantic in triplet.bypass_semantics
        if semantic.function_id == triplet.isf.function_id
        and semantic.kind == "opaque_handle_parameter"
        and isinstance(semantic.metadata.get("resource_type"), str)
    }
    closed_resources = {
        relation.resource_type for relation in triplet.ownership_relations
    }
    if opaque_anchor_resources - closed_resources:
        exclusions.append("incomplete_opaque_handle_lifecycle")

    measured = [metric for metric in metrics if metric.status == "measured"]
    total_weight = sum(metric.weight for metric in measured)
    aggregate = (
        sum(metric.weight * float(metric.score) for metric in measured) / total_weight
        if total_weight
        else None
    )
    eligible = not exclusions
    structural_units = estimate_structural_units(triplet)
    # Stage 1 calls once per function, Stage 2 once per structural unit,
    # Stage 3 once, and Stage 4 twice. Retries are intentionally excluded.
    estimated_calls = len(triplet.functions) + structural_units + 3
    return FTScore(
        triplet_id=str(triplet.id),
        eligible=eligible,
        score=_round(aggregate) if aggregate is not None and eligible else None,
        estimated_llm_calls=estimated_calls,
        structural_units=structural_units,
        metrics=metrics,
        exclusion_reasons=tuple(exclusions),
        function_ids=tuple(function.function_id for function in triplet.functions),
        structure_ids=tuple(triplet.structures),
        anchor_function_id=triplet.isf.function_id,
    )


def rank_triplets(
    triplets: Iterable[FunctionTriplet], annotations: object
) -> tuple[FTScore, ...]:
    annotation_index = _annotation_index(annotations)
    scores = [score_triplet(triplet, annotation_index) for triplet in triplets]
    scores.sort(
        key=lambda item: (
            not item.eligible,
            -(item.score if item.score is not None else -1.0),
            item.estimated_llm_calls,
            item.triplet_id,
        )
    )
    return tuple(scores)


def _novelty(
    candidate: FTScore,
    covered_anchors: set[str],
    covered_functions: set[str],
    covered_structures: set[str],
) -> float:
    anchor = candidate.anchor_function_id or (
        candidate.function_ids[0] if candidate.function_ids else ""
    )
    anchor_novelty = 1.0 if anchor and anchor not in covered_anchors else 0.0
    functions = set(candidate.function_ids)
    structures = set(candidate.structure_ids)
    function_novelty = len(functions - covered_functions) / len(functions) if functions else 0.0
    structure_novelty = (
        len(structures - covered_structures) / len(structures) if structures else function_novelty
    )
    # Seeing an API as a helper in another FT does not mean that it has been
    # exercised as the fuzz target.
    return _round(
        0.50 * anchor_novelty
        + 0.35 * function_novelty
        + 0.15 * structure_novelty
    )


def select_triplets(
    ranked: Sequence[FTScore],
    *,
    max_ft: int | None = None,
    max_calls: int | None = None,
    min_score: float = 0.0,
) -> tuple[SelectedFT, ...]:
    if max_ft is not None and max_ft < 0:
        raise ValueError("max_ft must be non-negative")
    if max_calls is not None and max_calls < 0:
        raise ValueError("max_calls must be non-negative")
    if not 0.0 <= min_score <= 1.0:
        raise ValueError("min_score must be between 0 and 1")

    remaining = {
        item.triplet_id: item
        for item in ranked
        if item.eligible and item.score is not None and item.score >= min_score
    }
    selected: list[SelectedFT] = []
    covered_anchors: set[str] = set()
    covered_functions: set[str] = set()
    covered_structures: set[str] = set()
    calls_used = 0

    while remaining and (max_ft is None or len(selected) < max_ft):
        candidates: list[tuple[float, float, float, int, str, FTScore]] = []
        for item in remaining.values():
            if max_calls is not None and calls_used + item.estimated_llm_calls > max_calls:
                continue
            novelty = _novelty(
                item, covered_anchors, covered_functions, covered_structures
            )
            # Retain most of the intrinsic score while discounting highly overlapping FTs.
            benefit = float(item.score) * (0.70 + 0.30 * novelty)
            efficiency = benefit / item.estimated_llm_calls
            candidates.append(
                (
                    benefit,
                    float(item.score),
                    efficiency,
                    -item.estimated_llm_calls,
                    item.triplet_id,
                    item,
                )
            )
        if not candidates:
            break
        candidates.sort(
            key=lambda row: (-row[0], -row[1], -row[2], -row[3], row[4])
        )
        benefit, base_score, _, _, _, chosen = candidates[0]
        novelty = _novelty(
            chosen, covered_anchors, covered_functions, covered_structures
        )
        selected.append(
            SelectedFT(
                order=len(selected) + 1,
                triplet_id=chosen.triplet_id,
                base_score=_round(base_score),
                novelty=novelty,
                marginal_benefit=_round(benefit),
                benefit_per_call=round(benefit / chosen.estimated_llm_calls, 6),
                estimated_llm_calls=chosen.estimated_llm_calls,
            )
        )
        calls_used += chosen.estimated_llm_calls
        if chosen.anchor_function_id:
            covered_anchors.add(chosen.anchor_function_id)
        elif chosen.function_ids:
            covered_anchors.add(chosen.function_ids[0])
        covered_functions.update(chosen.function_ids)
        covered_structures.update(chosen.structure_ids)
        del remaining[chosen.triplet_id]

    return tuple(selected)


def build_selection_manifest(
    triplets: Iterable[FunctionTriplet],
    annotations: object,
    *,
    max_ft: int | None = None,
    max_calls: int | None = None,
    min_score: float = 0.0,
) -> dict[str, Any]:
    triplet_items = tuple(triplets)
    ranked = rank_triplets(triplet_items, annotations)
    selected = select_triplets(
        ranked, max_ft=max_ft, max_calls=max_calls, min_score=min_score
    )
    return {
        "schema_version": FT_SELECTION_SCHEMA_VERSION,
        "policy_version": FT_SELECTION_POLICY_VERSION,
        "inputs": {
            "triplets_sha256": triplet_catalog_sha256(triplet_items),
        },
        "constraints": {
            "max_ft": max_ft,
            "max_calls": max_calls,
            "min_score": min_score,
        },
        "cost_model": {
            "unit": "baseline_llm_calls",
            "formula": "functions + structural_units + 3",
            "includes_retries": False,
        },
        "ranking": [item.to_dict() for item in ranked],
        "selection": [item.to_dict() for item in selected],
        "summary": {
            "triplet_count": len(ranked),
            "eligible_count": sum(1 for item in ranked if item.eligible),
            "selected_count": len(selected),
            "estimated_llm_calls": sum(item.estimated_llm_calls for item in selected),
        },
    }
