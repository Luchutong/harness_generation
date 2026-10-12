"""Independent API-scope authority, never a Minimal FT or semantic receipt."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field

from ..semantic_discovery.models import ValidationBudget, digest

VERSION = "lightweight-api-context-v2"
ARTIFACT_KIND = "lightweight_api_context"
AUTHORIZATION_KIND = "live_clang_api_scope"
_ISSUED = object()


@dataclass(frozen=True)
class ContextBudget:
    max_scanned_functions: int = 1024
    max_allowed_functions: int = 8
    max_callsite_queries: int = 1
    source: ValidationBudget = field(default_factory=lambda: ValidationBudget(
        max_tool_calls=16, max_source_chars=48000, max_references_per_query=4,
        max_callers=4, max_callees=4, max_lines_per_read=80, max_chars_per_record=6000))

    def __post_init__(self):
        for key in ("max_scanned_functions", "max_allowed_functions", "max_callsite_queries"):
            if type(getattr(self, key)) is not int or getattr(self, key) < 1:
                raise ValueError(key + " must be positive")
        if not isinstance(self.source, ValidationBudget):
            raise ValueError("source must be a ValidationBudget")

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("invalid lightweight context budget")
        source = value.get("source")
        if not isinstance(source, dict) or set(source) != set(ValidationBudget.__dataclass_fields__):
            raise ValueError("invalid lightweight source budget")
        return cls(**{**value, "source": ValidationBudget(**source)})


class APIScope:
    __slots__ = ("_context",)

    def __init__(self, context):
        self._context = context

    @property
    def function_ids(self):
        return frozenset(row["function_id"] for row in self._context.document["allowed_api_scope"])

    @property
    def receipt(self):
        document = self._context.document
        return {"authorization_kind": AUTHORIZATION_KIND, "context_type": ARTIFACT_KIND,
            "context_id": document["context_id"], "context_digest": digest(document),
            "allowed_function_ids": sorted(self.function_ids),
            "scope_selection_policy": document["scope_selection_policy"],
            "requested_support_function_ids": document["requested_support_function_ids"],
            "source_fingerprint": document["source_fingerprint"],
            "functions_fingerprint": document["functions_fingerprint"],
            "build_analysis_identity": document["build_analysis"]["identity_digest"],
            "semantic_verified": False, "generation_allowed": False}


class LightweightAPIContext:
    """Process-local receipt issued only by live, deterministic construction.

    Saved documents are proposals to replay. Their hashes and boolean labels
    cannot construct this object or admit callable APIs on their own.
    """
    __slots__ = ("_document", "snapshot", "analysis", "index", "budget", "scope")

    def __init__(self, document, snapshot, analysis, index, budget, *, _token=None):
        if _token is not _ISSUED:
            raise ValueError("lightweight context requires live construction or replay")
        self._document = deepcopy(document)
        self.snapshot, self.analysis, self.index, self.budget = snapshot, analysis, index, budget
        self.scope = APIScope(self)

    @property
    def document(self):
        return deepcopy(self._document)

    @property
    def context_id(self):
        return self._document["context_id"]

    @property
    def metadata(self):
        return {"schema_version": 1, "artifact_kind": ARTIFACT_KIND,
            "policy_version": VERSION, "context_id": self.context_id,
            "context_digest": digest(self._document), "authorization": self.scope.receipt,
            "generation_allowed": False, "semantic_verified": False}

    @property
    def strategy_input(self):
        """Shape adapter for existing IR validators; no Minimal FT identity.

        Legacy ``ft_id``/``ft_digest`` strategy fields bind this exact adapter.
        They do not assert that Candidate or Slice has run or been accepted.
        """
        document = self._document
        anchor = document["anchor_function_id"]
        return {"schema_version": 1, "artifact_kind": "lightweight_api_context_reference",
            "policy_version": VERSION, "context_type": ARTIFACT_KIND,
            "authorization_kind": AUTHORIZATION_KIND,
            "context_id": self.context_id, "context_digest": digest(document),
            "scope_selection_policy": document["scope_selection_policy"],
            "requested_support_function_ids": deepcopy(document["requested_support_function_ids"]),
            "ft_id": self.context_id, "anchor_function_id": anchor,
            "source_fingerprint": document["source_fingerprint"],
            "functions_fingerprint": document["functions_fingerprint"],
            "core_functions": [{"function_id": anchor, "role": "anchor"}],
            "support_candidates": [{"function_id": row["function_id"],
                "kind": "unknown", "candidate_roles": deepcopy(row["candidate_roles"]),
                "relationship_verified": False}
                for row in document["allowed_api_scope"] if row["function_id"] != anchor],
            "excluded_functions": [], "allowed_api_scope": deepcopy(document["allowed_api_scope"]),
            "source_evidence": deepcopy(document["source_evidence"]),
            "unresolved_questions": deepcopy(document["unknowns"]),
            "generation_allowed": False, "semantic_verified": False}

    def validate(self, snapshot=None, index=None):
        selected = snapshot or self.snapshot
        self.analysis.validate_snapshot(selected)
        repository = index or self.index
        if (repository.artifacts != selected.artifacts
                or repository.catalog.source_fingerprint != selected.source_fingerprint):
            raise ValueError("lightweight repository snapshot mismatch")
        if self.analysis.identity_digest != self._document["build_analysis"]["identity_digest"]:
            raise ValueError("lightweight build identity mismatch")
        for row in self._document["allowed_api_scope"]:
            if self.analysis.verify_function(row["function_id"]) != row["clang_function"]:
                raise ValueError("lightweight callable authorization changed")
        from ..harness_strategy.planner import verify_source_identity
        verify_source_identity(selected, repository, self.scope.function_ids,
            self._document["source_evidence"]["records"])
        return True

    def make_strategy_tools(self, budget):
        from .tools import LightweightStrategyTools
        return LightweightStrategyTools(self, budget)
