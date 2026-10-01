"""Accepted-validation input gate and task-specific reuse of shared persistence."""
from __future__ import annotations

import json

from ..semantic_discovery.models import candidate_id, canonical, digest
from ..semantic_discovery.persistence import (load_compatible_run, load_run_documents,
                                              save_run_documents)
from .models import SLICE_POLICY_VERSION, group_classification, validate_submission
from .tools import SemanticSliceTools


def load_accepted_candidates(store, catalog, index):
    if not store.validated_candidates.is_file():
        raise ValueError("missing candidate_discovery/validated_candidates.json; validate candidates first")
    document = json.loads(store.validated_candidates.read_text(encoding="utf-8"))
    if (not isinstance(document, dict) or type(document.get("schema_version")) is not int
            or document.get("schema_version") != 1
            or document.get("artifact_kind") != "validated_entry_candidate_catalog"
            or document.get("source_fingerprint") != catalog.source_fingerprint
            or document.get("discovery_fingerprint") != digest(catalog.to_dict())):
        raise ValueError("validated candidate catalog is incompatible with discovery/Phase 1")
    known = {c.function_id: c for c in catalog.candidates}
    records = document.get("candidates")
    if not isinstance(records, list) or len(records) != len(known):
        raise ValueError("validated candidate catalog must retain all discovery identities")
    seen, accepted = set(), []
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("invalid validated candidate record")
        fid = record.get("function_id")
        if not isinstance(fid, str) or fid not in known or fid in seen:
            raise ValueError("invalid validated candidate identity")
        seen.add(fid)
        candidate = known[fid]
        if record.get("candidate_id") != candidate_id(fid) or record.get("function") != candidate.function:
            raise ValueError("validated candidate identity mismatch")
        status, result = record.get("status"), record.get("validation")
        if (not isinstance(status, str) or status not in {"accepted", "rejected", "unresolved"}
                or (result is not None and (not isinstance(result, dict) or result.get("verdict") != status))):
            raise ValueError("validated candidate status mismatch")
        if status != "accepted":
            continue
        if (not isinstance(result, dict) or result.get("run_status") != "completed"
                or record.get("run_directory") != f"agent_runs/{candidate_id(fid)}"):
            raise ValueError("accepted candidate lacks a completed validation run")
        directory = store.candidate_agent_run(candidate_id(fid))
        metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
        if not isinstance(metadata, dict) or not isinstance(metadata.get("configuration"), dict):
            raise ValueError("accepted validation metadata is malformed")
        configuration = metadata.get("configuration", {})
        if (configuration.get("source_fingerprint") != catalog.source_fingerprint
                or configuration.get("discovery_fingerprint") != digest(catalog.to_dict())
                or load_compatible_run(store, candidate, configuration, index) != result):
            raise ValueError("accepted validation evidence is missing, changed or stale")
        # v2 results remain valid inputs: schema repair does not redefine accepted.
        accepted.append((candidate, result))
    return sorted(accepted, key=lambda pair: pair[0].function_id)


def run_configuration(catalog, frontier, budget, model, max_discovered_functions):
    from .agent import SYSTEM_PROMPT
    from .models import SLICE_SCHEMA, ROLE_REASONS
    from .core_proofs import VERSION as CORE_PROOF_VERSION
    from .proposals import VERSION as PROPOSAL_VERSION
    from .support_effects import VERSION as EFFECT_VERSION
    config = model.config.to_dict() if hasattr(model, "config") else {
        "provider": model.provider, "model": model.model}
    return {"source_fingerprint": catalog.source_fingerprint, "discovery_fingerprint": digest(catalog.to_dict()),
            "policy_version": SLICE_POLICY_VERSION, "frontier_fingerprint": frontier.fingerprint,
            "core_inclusion_proof_version": CORE_PROOF_VERSION,
            "role_proposal_version": PROPOSAL_VERSION, "support_effect_version": EFFECT_VERSION,
            "task_fingerprint": digest({"prompt": SYSTEM_PROMPT, "schema": SLICE_SCHEMA, "reasons": ROLE_REASONS}),
            "validation_fingerprint": digest(frontier.validation), "budget": budget.to_dict(),
            "max_discovered_functions": max_discovered_functions, "model": config}


def save_run(store, run, configuration):
    return save_run_documents(store.semantic_slice_run(run.result["candidate_id"]), run, configuration,
                              canonical_name="slice")


def load_compatible_slice(store, frontier, configuration, index, budget):
    documents = load_run_documents(store.semantic_slice_run(candidate_id(frontier.candidate.function_id)),
                                   configuration, index, canonical_name="slice")
    if documents is None:
        return None
    try:
        result, metadata = documents["slice"], documents["metadata"]
        if (result["schema_version"] != 1 or result["policy_version"] != SLICE_POLICY_VERSION
                or result["run_status"] not in {"completed", "completed_with_unresolved"}
                or result["candidate_id"] != candidate_id(frontier.candidate.function_id)
                or result["anchor_function_id"] != frontier.candidate.function_id
                or result["anchor_function"] != frontier.candidate.function
                or metadata["frontier_fingerprint"] != frontier.fingerprint
                or metadata["initial_frontier_ids"] != sorted(frontier.function_ids)):
            return None
        tools = SemanticSliceTools(index.artifacts, index.catalog, frontier, budget, index=index,
                                  max_discovered_functions=configuration["max_discovered_functions"])
        tools.evidence = {r["evidence_id"]: r for r in documents["evidence"]["records"]}
        for event in documents["trace"]["events"]:
            if event["kind"] != "tool_call":
                continue
            for eid in event["result_evidence_ids"]:
                record = tools.evidence[eid]
                ids = tools._record_functions(record)
                tools._authorize(ids, eid)
                tools.evidence_functions[eid] = ids & tools.authorized_ids
        if metadata["discovered_function_ids"] != sorted(tools.discovered):
            return None
        raw = {"classification": [{k: row[k] for k in
            ("function_id", "role", "reason_codes", "evidence_ids", "open_questions")}
            for row in result["classification"]]}
        validated = validate_submission(canonical(raw), tools)
        if validated["classification"] != result["classification"]:
            return None
        if any(result[key] != ids for key, ids in group_classification(result["classification"], tools.authorized_ids).items()):
            return None
        return result
    except (ValueError, KeyError, TypeError):
        return None
