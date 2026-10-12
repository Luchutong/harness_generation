"""Three-valued API contracts; serialized trust labels grant no authority."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from enum import Enum

from ..semantic_discovery.models import digest

CONTRACT_VERSION = "api-usage-contract-v1"
SOURCES = {"clang", "project_documentation", "project_example", "local_source_effect",
           "svf", "llm_proposal", "human_review"}


class ContractStatus(str, Enum):
    SATISFIED = "satisfied"
    VIOLATED = "violated"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class APIContract:
    function_id: str
    kind: str
    source: str
    version: str
    applicability: dict
    facts: dict = field(default_factory=dict)
    evidence_ids: tuple = ()
    trust: str = "proposal"
    policy_version: str = CONTRACT_VERSION

    def to_dict(self):
        row = {"policy_version": self.policy_version, "function_id": self.function_id,
               "kind": self.kind, "source": self.source, "version": self.version,
               "applicability": deepcopy(self.applicability), "facts": deepcopy(self.facts),
               "evidence_ids": sorted(set(self.evidence_ids)), "trust": self.trust,
               "semantic_verified": False, "generation_authority": False}
        row["contract_id"] = "api_contract_" + digest(row)[:32]
        return row

    @classmethod
    def proposal(cls, row):
        """Import provenance, never the caller's asserted trust or status."""
        if isinstance(row, cls):
            row = row.to_dict()
        if not isinstance(row, dict):
            raise ValueError("api_contract_must_be_an_object")
        for key in ("function_id", "kind", "source", "version"):
            if not isinstance(row.get(key), str) or not 1 <= len(row[key]) <= 512:
                raise ValueError("api_contract_invalid_" + key)
        if row["source"] not in SOURCES:
            raise ValueError("api_contract_unknown_source")
        if not isinstance(row.get("applicability"), dict) or not isinstance(row.get("facts", {}), dict):
            raise ValueError("api_contract_invalid_scope_or_facts")
        ids = row.get("evidence_ids", [])
        if not isinstance(ids, (list, tuple)) or any(not isinstance(eid, str) for eid in ids):
            raise ValueError("api_contract_invalid_evidence")
        return cls(row["function_id"], row["kind"], row["source"], row["version"],
                   deepcopy(row["applicability"]), deepcopy(row.get("facts", {})), tuple(ids))
