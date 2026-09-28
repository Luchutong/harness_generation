"""Pure deterministic projection. No models, source parsing or execution."""
from __future__ import annotations

from .models import (ARTIFACT_KIND, POLICY_VERSION, SCHEMA_VERSION, MinimalFTBuild, canonical_slice,
                     core_role, support_kind, stable_ft_id)
from .relations import UnresolvedDependencies, legacy_comparison, project_relations_and_dependencies
from .validation import MinimalFTValidator, validate_slice


class MinimalFTBuilder:
    def build(self, source, snapshot, *, compare_legacy=True):
        # Normalization never deduplicates or repairs declarations. Validation
        # sees every duplicate and contradictory group in the original input.
        from dataclasses import replace
        source = replace(source, document=canonical_slice(source.document))
        errors = validate_slice(source, snapshot)
        doc = source.document if isinstance(source.document, dict) else {}
        expected_anchor = snapshot.anchor_for_candidate(source.candidate_id)
        anchor = expected_anchor or (doc.get("anchor_function_id") if isinstance(doc.get("anchor_function_id"), str) else "unknown")
        name = snapshot.functions[anchor]["name"] if anchor in snapshot.functions else "anchor"
        claimed_core = doc.get("core_functions", [])
        if not isinstance(claimed_core, list):
            claimed_core = []
        ft_id = stable_ft_id(anchor, [fid for fid in claimed_core if isinstance(fid, str)], anchor_name=name)
        result = {"schema_version": SCHEMA_VERSION, "artifact_kind": ARTIFACT_KIND, "policy_version": POLICY_VERSION,
            "ft_id": ft_id, "candidate_id": source.candidate_id, "anchor_function_id": anchor,
            "core_functions": [], "support_candidates": [], "relations": [], "unresolved_dependencies": [],
            "excluded_functions": [], "source_slice": {"path": source.path, "digest": source.digest},
            "source_snapshot": {"source_fingerprint": snapshot.source_fingerprint,
                                "functions_fingerprint": snapshot.functions_fingerprint},
            "build_status": "invalid", "validation_errors": errors}
        dependencies = UnresolvedDependencies()
        if errors:
            for error in errors:
                dependencies.add(None, [error["code"]], reference=error.get("reference"),
                                 provenance={"artifact": source.path, "field": error["field"]})
        else:
            rows = {row["function_id"]: row for row in doc["classification"]}
            for fid in doc["core_functions"]:
                row = rows[fid]
                result["core_functions"].append({"function_id": fid, "function": snapshot.functions[fid]["name"],
                    "role": core_role(fid, anchor, row["reason_codes"]),
                    "evidence_ids": row["evidence_ids"], "reason_codes": row["reason_codes"]})
            for fid in doc["support_functions"]:
                row = rows[fid]
                kind = support_kind(row["reason_codes"])
                result["support_candidates"].append({"function_id": fid, "function": snapshot.functions[fid]["name"],
                    "support_kind": kind, "evidence_ids": row["evidence_ids"], "reason_codes": row["reason_codes"]})
            result["excluded_functions"] = doc["excluded_functions"]
            result["relations"], result["unresolved_dependencies"] = project_relations_and_dependencies(source, snapshot)
        if errors:
            result["unresolved_dependencies"] = dependencies.to_list()
        if compare_legacy:
            result["legacy_comparison"] = legacy_comparison([fid for fid in claimed_core if isinstance(fid, str)], source.legacy)
        if not errors:
            result["build_status"] = "completed_with_unresolved" if result["unresolved_dependencies"] else "completed"
            errors = MinimalFTValidator().validate(result, source, snapshot)
            if errors:
                result["build_status"], result["validation_errors"] = "invalid", errors
        metadata = {"schema_version": SCHEMA_VERSION, "policy_version": POLICY_VERSION,
            "ft_id": ft_id, "candidate_id": source.candidate_id, "source_slice": result["source_slice"],
            "source_fingerprint": snapshot.source_fingerprint, "functions_fingerprint": snapshot.functions_fingerprint,
            "validation_errors": errors, "llm_calls": 0, "repository_rescans": 0,
            "support_is_api_closure": False, "lifecycle_completeness_established": False,
            "harness_generated": False, "legacy_diagnostics": source.legacy.get("diagnostics", [])}
        return MinimalFTBuild(result, metadata)
