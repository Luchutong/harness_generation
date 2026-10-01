"""Versioned, provider-free records for deterministic semantic projection."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from functools import cached_property
import re

from ..entry_candidates import artifact_fingerprint
from ..semantic_discovery.models import canonical, candidate_id, digest

SCHEMA_VERSION = 1
POLICY_VERSION = "semantic-slice-minimal-ft-v1"
ARTIFACT_KIND = "minimal_function_triplet"
CORE_ROLES = ("anchor", "input", "consume", "state_transition", "processing")
SUPPORT_KINDS = ("initialization", "creation", "cleanup", "allocator", "callback", "configuration", "wrapper", "unknown")
RELATION_KINDS = ("calls", "creates", "destroys", "feeds", "consumes", "shares_resource", "wrapper_delegate", "structural")
STRENGTHS = ("strong", "weak")
BUILD_STATUSES = ("completed", "completed_with_unresolved", "invalid")
SUPPORT_REASON_KINDS = {
    "required_initialization": "initialization", "resource_creation": "creation", "resource_cleanup": "cleanup",
    "allocator_setup": "allocator", "callback_registration": "callback", "minimal_configuration": "configuration",
}


def core_role(fid, anchor, reasons):
    if fid == anchor:
        return "anchor"
    if "external_input_injection" in reasons:
        return "input"
    if "input_consumption" in reasons:
        return "consume"
    if {"target_state_progression", "core_state_dependency"} & set(reasons):
        return "state_transition"
    return "processing"


def support_kind(reasons):
    kinds = {SUPPORT_REASON_KINDS[r] for r in reasons if r in SUPPORT_REASON_KINDS}
    if len(kinds) == 1:
        return next(iter(kinds))
    if not kinds and set(reasons) == {"wrapper_delegation"}:
        return "wrapper"
    return "unknown"


def stable_ft_id(anchor, core_ids, *, anchor_name, policy_version=POLICY_VERSION):
    name = re.sub(r"[^A-Za-z0-9_]", "_", anchor_name)[:48] or "anchor"
    identity = {"anchor_function_id": anchor, "core_function_ids": sorted(set(core_ids)), "policy_version": policy_version}
    return f"ft_{name}_{digest(identity)[:24]}"


def canonical_slice(document):
    """Sort only declared set-like arrays; retain duplicates for validation.

    Parameter order, usage sequences, source bodies and all other content stay
    untouched. This matches the canonical serialization of Semantic Slice v1.
    """
    result = deepcopy(document)
    if not isinstance(result, dict):
        return result
    def ordered(values):
        return sorted(values) if all(isinstance(value, str) for value in values) else sorted(values, key=canonical)
    for key in ("core_functions", "support_functions", "excluded_functions", "unresolved_frontier"):
        if isinstance(result.get(key), list):
            result[key] = ordered(result[key])
    if isinstance(result.get("classification"), list):
        for row in result["classification"]:
            if isinstance(row, dict):
                for key in ("reason_codes", "evidence_ids", "open_questions"):
                    if isinstance(row.get(key), list):
                        row[key] = ordered(row[key])
        result["classification"] = sorted(result["classification"], key=lambda row: (
            row.get("function_id", "") if isinstance(row, dict) and isinstance(row.get("function_id"), str) else "", canonical(row)))
    return result


@dataclass(frozen=True)
class ProjectSnapshot:
    artifacts: object
    source_fingerprint: str
    functions_fingerprint: str

    @classmethod
    def from_artifacts(cls, artifacts):
        return cls(artifacts, artifact_fingerprint(artifacts), digest({
            "schema_version": artifacts.source_schema_versions.get("functions", 1),
            "files": sorted(artifacts.files), "functions": list(artifacts.functions), "structs": list(artifacts.structs),
            **({"callback_typedefs": list(artifacts.callback_typedefs)} if artifacts.callback_typedefs else {})}))

    @property
    def functions(self):
        return self.artifacts.functions_by_id

    @cached_property
    def candidate_anchors(self):
        return {candidate_id(fid): fid for fid in self.functions}

    def anchor_for_candidate(self, cid):
        return self.candidate_anchors.get(cid)


@dataclass
class SliceInput:
    document: object
    metadata: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=lambda: {"schema_version": 1, "records": []})
    trace: dict = field(default_factory=lambda: {"schema_version": 1, "events": []})
    candidate_id: str = ""
    path: str = ""
    load_errors: list = field(default_factory=list)
    validated_catalog: dict | None = None
    legacy: dict = field(default_factory=dict)
    input_digests: dict = field(default_factory=dict)

    @property
    def digest(self):
        return digest(canonical_slice(self.document))

    @property
    def records(self):
        return {r["evidence_id"]: r for r in self.evidence.get("records", [])
                if isinstance(r, dict) and isinstance(r.get("evidence_id"), str)}


@dataclass(frozen=True)
class MinimalFTBuild:
    minimal_ft: dict
    metadata: dict

    @property
    def valid(self):
        return self.minimal_ft["build_status"] != "invalid"
