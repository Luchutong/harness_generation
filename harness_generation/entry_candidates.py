"""Auditable possible entries, independent of FT construction and ISF proof.

Discovery retains every parsed function. Policies choose what to process next;
they never erase the remaining hypotheses. No semantic provider is called here.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import json
import math
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from .sfg_adapter import SFGArtifacts


CANDIDATE_SCHEMA_VERSION = 1
CANDIDATE_POLICY_VERSION = "entry-discovery-v1"
CANDIDATE_ARTIFACT_KIND = "entry_candidate_catalog"
_POLICIES = {"broad", "legacy", "explicit"}
_BYTE_TYPES = {"char", "signed char", "unsigned char", "int8_t", "uint8_t", "void"}
_LENGTH_NAMES = {
    "size", "len", "length", "n", "count", "cb", "sz", "nbytes", "byte_count",
    "buffer_length", "buffer_size", "input_size", "input_len", "data_size",
    "data_len", "buf_size", "buf_len",
}


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    try:
        canonical = json.loads(json.dumps(dict(value), sort_keys=True, allow_nan=False))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{context} must contain finite JSON values") from error
    return MappingProxyType(canonical)


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} must be non-empty text")
    return value


def _score(value: Any) -> float:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or not 0 <= value <= 1):
        raise ValueError("candidate score must be finite and between 0 and 1")
    return float(value)


def _array(value: Any, context: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"{context} must be an array")
    return value


@dataclass(frozen=True)
class CandidateSignal:
    kind: str
    score: float | None
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.kind, "signal kind")
        if self.score is not None:
            object.__setattr__(self, "score", _score(self.score))
        object.__setattr__(self, "evidence", _object(self.evidence, "signal evidence"))

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "score": self.score, "evidence": dict(self.evidence)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CandidateSignal":
        if not isinstance(value, Mapping):
            raise ValueError("candidate signal must be an object")
        return cls(value.get("kind"), value.get("score"), value.get("evidence", {}))


@dataclass(frozen=True)
class EntryCandidate:
    function_id: str
    function: str
    signature: str
    file: str
    line: int
    signals: tuple[CandidateSignal, ...] = ()
    status: str = "unresolved"
    priority: float = 0.0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("function_id", "function", "file"):
            _text(getattr(self, name), f"candidate {name}")
        if not isinstance(self.signature, str):
            raise ValueError("candidate signature must be text")
        if type(self.line) is not int or self.line < 1:
            raise ValueError("candidate line must be positive")
        if self.status != "unresolved":
            raise ValueError("discovery candidates are unresolved, not validated ISFs")
        if any(not isinstance(signal, CandidateSignal) for signal in self.signals):
            raise ValueError("candidate signals must be CandidateSignal records")
        object.__setattr__(self, "priority", _score(self.priority))
        ordered = sorted(self.signals, key=lambda s: (
            s.kind, json.dumps(dict(s.evidence), sort_keys=True, allow_nan=False),
            -1.0 if s.score is None else s.score))
        object.__setattr__(self, "signals", tuple(ordered))
        object.__setattr__(self, "metadata", _object(self.metadata, "candidate metadata"))

    def to_dict(self) -> dict[str, Any]:
        return {"function_id": self.function_id, "function": self.function,
                "signature": self.signature, "file": self.file, "line": self.line,
                "signals": [s.to_dict() for s in self.signals], "status": self.status,
                "priority": self.priority, "metadata": dict(self.metadata)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EntryCandidate":
        if not isinstance(value, Mapping):
            raise ValueError("entry candidate must be an object")
        return cls(
            function_id=value.get("function_id"), function=value.get("function"),
            signature=value.get("signature"), file=value.get("file"), line=value.get("line"),
            signals=tuple(CandidateSignal.from_dict(s) for s in
                          _array(value.get("signals"), "candidate signals")),
            status=value.get("status"), priority=value.get("priority"),
            metadata=value.get("metadata", {}),
        )


def artifact_fingerprint(artifacts: SFGArtifacts) -> str:
    """Bind candidates to source bodies and their exact Phase 1 evidence."""
    document = {
        "functions": list(artifacts.functions), "structs": list(artifacts.structs),
        "annotations": list(artifacts.annotations), "flows": list(artifacts.flows),
        "nodes": [n.to_dict() for n in artifacts.graph.nodes],
        "edges": [e.to_dict() for e in artifacts.graph.edges],
        "ownership": sorted(artifacts.ownership, key=lambda r: str(r.get("id", ""))),
        "usage_patterns": sorted(artifacts.usage_patterns, key=lambda r: str(r.get("id", ""))),
    }
    digest = hashlib.sha256()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), allow_nan=False)
    for part in encoder.iterencode(document):
        digest.update(part.encode("utf-8"))
    return digest.hexdigest()


@dataclass(frozen=True)
class CandidateCatalog:
    candidates: tuple[EntryCandidate, ...]
    source_fingerprint: str
    policy: str = "broad"
    selected_function_ids: tuple[str, ...] = ()
    deferred_reasons: Mapping[str, str] = field(default_factory=dict)
    max_candidates: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.policy, str) or self.policy not in _POLICIES:
            raise ValueError("unsupported candidate selection policy")
        if (not isinstance(self.source_fingerprint, str) or len(self.source_fingerprint) != 64
                or any(c not in "0123456789abcdef" for c in self.source_fingerprint)):
            raise ValueError("candidate catalog requires a SHA-256 source fingerprint")
        if self.max_candidates is not None and (
                type(self.max_candidates) is not int or self.max_candidates < 0):
            raise ValueError("max_candidates must be a non-negative integer")
        if any(not isinstance(c, EntryCandidate) for c in self.candidates):
            raise ValueError("catalog candidates must be EntryCandidate records")
        ordered = tuple(sorted(self.candidates, key=lambda c: (-c.priority, c.function_id)))
        ids = {c.function_id for c in ordered}
        selected = tuple(self.selected_function_ids)
        if len(ids) != len(ordered) or len(set(selected)) != len(selected):
            raise ValueError("candidate identities and selection must be unique")
        if not set(selected) <= ids:
            raise ValueError("candidate selection references unknown function IDs")
        if set(self.deferred_reasons) != ids - set(selected):
            raise ValueError("every unselected candidate requires a deferred reason")
        if any(not isinstance(r, str) or not r for r in self.deferred_reasons.values()):
            raise ValueError("deferred reasons must be non-empty text")
        if self.max_candidates is not None and len(selected) > self.max_candidates:
            raise ValueError("candidate selection exceeds its budget")
        object.__setattr__(self, "candidates", ordered)
        object.__setattr__(self, "selected_function_ids", selected)
        object.__setattr__(self, "deferred_reasons", MappingProxyType(dict(self.deferred_reasons)))

    @property
    def selected(self) -> tuple[EntryCandidate, ...]:
        by_id = {c.function_id: c for c in self.candidates}
        return tuple(by_id[i] for i in self.selected_function_ids)

    def validate_against(self, artifacts: SFGArtifacts) -> None:
        if self.source_fingerprint != artifact_fingerprint(artifacts):
            raise ValueError("candidate catalog does not match current Phase 1 artifacts; rediscover candidates")
        if {c.function_id for c in self.candidates} != set(artifacts.functions_by_id):
            raise ValueError("candidate catalog must retain every parsed function")
        for c in self.candidates:
            record = artifacts.functions_by_id[c.function_id]
            if (c.function, c.signature, c.file, c.line) != (
                    record.get("name"), record.get("signature", ""),
                    record.get("file"), record.get("start_line")):
                raise ValueError(f"candidate identity does not match functions.json: {c.function_id}")

    def select_anchors(self, function_ids: Sequence[str]) -> "CandidateCatalog":
        """An explicit construction request; this does not validate any entry."""
        ids = tuple(function_ids)
        return replace(self, policy="explicit", selected_function_ids=ids, max_candidates=None,
                       deferred_reasons={c.function_id: "not_requested" for c in self.candidates
                                         if c.function_id not in ids})

    def with_construction_results(self, triplets, exclusions) -> "CandidateCatalog":
        """Keep failed/oversized hypotheses visible, without semantic promotion."""
        built: dict[str, list[str]] = {}
        failed: dict[str, list[dict[str, Any]]] = {}
        for triplet in triplets:
            built.setdefault(triplet.isf.function_id, []).append(triplet.id)
        for exclusion in exclusions:
            failed.setdefault(exclusion["anchor_function_id"], []).append(dict(exclusion))
        candidates = []
        for candidate in self.candidates:
            metadata = dict(candidate.metadata)
            identifier = candidate.function_id
            if identifier in self.selected_function_ids:
                status = ("partial" if identifier in built and identifier in failed else
                          "constructed" if identifier in built else
                          "oversized" if identifier in failed else "no_triplet")
                metadata["construction"] = {"status": status,
                                            "triplet_ids": sorted(built.get(identifier, [])),
                                            "diagnostics": failed.get(identifier, [])}
            elif ("construction" not in metadata
                  or metadata["construction"].get("status") == "deferred"):
                metadata["construction"] = {"status": "deferred",
                                            "reason": self.deferred_reasons[identifier]}
            # Unrequested anchors retain their last construction frontier. A
            # later request for another anchor must not erase an oversized
            # diagnostic. Selection/deferred_reasons describe this run.
            candidates.append(replace(candidate, metadata=metadata))
        return replace(self, candidates=tuple(candidates))

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": CANDIDATE_SCHEMA_VERSION, "artifact_kind": CANDIDATE_ARTIFACT_KIND,
                "policy_version": CANDIDATE_POLICY_VERSION, "source_fingerprint": self.source_fingerprint,
                "policy": self.policy, "ranking": "maximum_signal_score_not_success_probability",
                "candidates": [c.to_dict() for c in self.candidates],
                "selection": {"selected_function_ids": list(self.selected_function_ids),
                              "max_candidates": self.max_candidates,
                              "deferred": [{"function_id": i, "reason": self.deferred_reasons[i]}
                                           for i in sorted(self.deferred_reasons)]}}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CandidateCatalog":
        if (not isinstance(value, Mapping) or type(value.get("schema_version")) is not int
                or value.get("schema_version") != CANDIDATE_SCHEMA_VERSION
                or value.get("artifact_kind") != CANDIDATE_ARTIFACT_KIND
                or value.get("policy_version") != CANDIDATE_POLICY_VERSION):
            raise ValueError("unsupported entry candidate catalog; Phase 1 candidates.json is a different artifact")
        selection = value.get("selection")
        if not isinstance(selection, Mapping):
            raise ValueError("candidate selection must be an object")
        deferred = {}
        for item in _array(selection.get("deferred"), "deferred candidates"):
            if not isinstance(item, Mapping):
                raise ValueError("deferred candidate must be an object")
            identifier = _text(item.get("function_id"), "deferred function ID")
            if identifier in deferred:
                raise ValueError("duplicate deferred function ID")
            deferred[identifier] = _text(item.get("reason"), "deferred reason")
        selected = _array(selection.get("selected_function_ids"), "selected function IDs")
        for identifier in selected:
            _text(identifier, "selected function ID")
        return cls(tuple(EntryCandidate.from_dict(c) for c in _array(value.get("candidates"), "candidates")),
                   value.get("source_fingerprint"), value.get("policy"), tuple(selected),
                   deferred, selection.get("max_candidates"))


def _signals(record: Mapping[str, Any], annotation: Mapping[str, Any], patterns) -> tuple[CandidateSignal, ...]:
    signals = []

    def add(kind, score, evidence):
        signals.append(CandidateSignal(kind, score, evidence))

    parameters = record.get("parameters", [])
    pointers = []
    lengths = []
    for index, parameter in enumerate(parameters):
        evidence = {"index": index, "parameter": parameter.get("name"),
                    "type": parameter.get("type"), "declaration": parameter.get("declaration")}
        array = "[" in str(parameter.get("declaration", ""))
        if parameter.get("is_pointer") is True or array:
            pointers.append(index)
            add("pointer_parameter", 0.4, {**evidence, "array_declaration": array})
            if parameter.get("base_type") in _BYTE_TYPES:
                add("byte_stream_like_parameter", 0.65, evidence)
        if parameter.get("is_struct_like") is True:
            add("context_parameter", 0.45, evidence)
        if (parameter.get("is_pointer") is not True and not array
                and str(parameter.get("name", "")).lower() in _LENGTH_NAMES):
            lengths.append(index)
            add("length_like_parameter", 0.45, evidence)
    for pointer in pointers:
        for length in lengths:
            add("buffer_length_relation_candidate", 0.75,
                {"pointer_index": pointer, "length_index": length,
                 "adjacent": length == pointer + 1, "relation_proven": False})
    if "ISF" in annotation.get("labels", []):
        add("existing_isf_annotation", 0.95, {"source": "annotations.json", "label": "ISF"})
    for stream in annotation.get("stream_parameters", []):
        if stream.get("is_byte_stream") is True:
            add("external_input_usage", 0.8,
                {"source": "annotations.json", "parameter": stream.get("parameter"),
                 "kind": stream.get("kind"), "independently_validated": False})
    name = str(record.get("name", "")).lower()
    if any(word in name for word in ("parse", "decode", "deserialize", "feed", "consume", "read", "scan")):
        add("parser_like_behavior", 0.6, {"source": "function_name", "function": record["name"]})
    if record.get("return_pointer_depth", 0) > 0 or record.get("return_is_struct_like") is True:
        add("returns_resource", 0.55,
            {"return_type": record.get("return_type"), "ownership_proven": False})
    for hint in record.get("access_hints", []):
        if hint.get("writes") is True:
            add("mutates_context", 0.55, {"source": "AST_access_hint", "parameter": hint.get("parameter")})
    for pattern in patterns:
        add("usage_pattern_evidence", 0.8,
            {"pattern_id": pattern.get("id"), "resource_type": pattern.get("resource_type"),
             "producer_function_id": pattern.get("producer_function_id"),
             "consumer_function_ids": pattern.get("consumer_function_ids", []),
             "cleanup_function_id": pattern.get("cleanup_function_id")})
    return tuple(signals)


def discover_candidates(artifacts: SFGArtifacts, *, policy: str = "broad",
                        max_candidates: int | None = None) -> CandidateCatalog:
    """Produce all hypotheses; legacy ISF rules only select the next work set."""
    if not isinstance(policy, str) or policy not in {"broad", "legacy"}:
        raise ValueError("discovery policy must be broad or legacy")
    if max_candidates is not None and (type(max_candidates) is not int or max_candidates < 0):
        raise ValueError("max_candidates must be a non-negative integer")
    patterns_by_id: dict[str, list] = {}
    for pattern in artifacts.usage_patterns:
        members = {pattern.get("producer_function_id"), pattern.get("cleanup_function_id"),
                   *pattern.get("consumer_function_ids", [])}
        for identifier in sorted(i for i in members if isinstance(i, str)):
            patterns_by_id.setdefault(identifier, []).append(pattern)
    candidates = []
    for record in artifacts.functions:
        annotation = artifacts.annotations_by_id.get(record["id"], {})
        signals = _signals(record, annotation, patterns_by_id.get(record["id"], []))
        candidates.append(EntryCandidate(
            record["id"], record["name"], record.get("signature", ""),
            record["file"], record["start_line"], signals,
            priority=max((s.score for s in signals if s.score is not None), default=0.0),
            metadata={"definition_available": record.get("defined") is True,
                      "storage": record.get("storage", []),
                      "legacy_isf_annotation": "ISF" in annotation.get("labels", [])},
        ))
    ordered = sorted(candidates, key=lambda c: (-c.priority, c.function_id))
    selected = []
    deferred = {}
    for candidate in ordered:
        if policy == "legacy" and not candidate.metadata["legacy_isf_annotation"]:
            deferred[candidate.function_id] = "not_selected_by_legacy_isf_policy"
        elif policy == "broad" and not candidate.metadata["definition_available"]:
            deferred[candidate.function_id] = "declaration_only"
        elif max_candidates is not None and len(selected) >= max_candidates:
            deferred[candidate.function_id] = "candidate_budget"
        else:
            selected.append(candidate.function_id)
    return CandidateCatalog(tuple(ordered), artifact_fingerprint(artifacts), policy,
                            tuple(selected), deferred, max_candidates)


def discover_candidates_legacy(artifacts: SFGArtifacts) -> CandidateCatalog:
    """Compatibility strategy: annotations define the old processing set only."""
    return discover_candidates(artifacts, policy="legacy")
