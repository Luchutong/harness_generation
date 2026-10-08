"""Atomic run records and validated catalog projection; discovery is untouched."""
from __future__ import annotations

import hashlib
import json

from ..artifacts import ArtifactStore
from ..records import write_json
from .agent import ValidationRun
from .models import POLICY_VERSION, SCHEMA_VERSION, candidate_id, digest, parse_decision
from .tools import RepositoryIndex


def run_configuration(catalog, budget, model, *, max_terminal_repairs=1,
                      max_semantic_recoveries=0, max_provider_recoveries=0,
                      max_protocol_recoveries=0) -> dict:
    config = model.config.to_dict() if hasattr(model, "config") else {
        "provider": model.provider, "model": model.model}
    from .loop import TERMINAL_REPAIR_POLICY_VERSION
    return {"terminal_repair_policy_version": TERMINAL_REPAIR_POLICY_VERSION,
            "terminal_repair_allowed_categories": ["terminal_schema_error", "terminal_json_parse_error", "candidate_unknown_evidence_reference", "terminal_native_submission_missing"],
            "extra_terminal_repair_last_round_only": False,
            "reserve_terminal_round": True,
            "source_fingerprint": catalog.source_fingerprint,
            "discovery_fingerprint": digest(catalog.to_dict()),
            "policy_version": POLICY_VERSION, "budget": budget.to_dict(), "model": config,
            "max_terminal_repairs": max_terminal_repairs,
            "max_semantic_recoveries": max_semantic_recoveries,
            "max_provider_recoveries": max_provider_recoveries,
            "max_protocol_recoveries": max_protocol_recoveries}


def save_run(store: ArtifactStore, run: ValidationRun, configuration: dict) -> dict:
    directory = store.candidate_agent_run(run.result["candidate_id"])
    return save_run_documents(directory, run, configuration)


def save_run_documents(directory, run, configuration, *, canonical_name="result") -> dict:
    """Shared persistence for agent tasks; metadata is the final commit marker."""
    directory.mkdir(parents=True, exist_ok=True)
    documents = {canonical_name: run.result, "trace": run.trace, "evidence": run.evidence}
    metadata = {**run.metadata, "configuration_fingerprint": digest(configuration),
                "configuration": configuration,
                "document_digests": {name: digest(doc) for name, doc in documents.items()}}
    for name, document in documents.items():
        write_json(directory / f"{name}.json", document, sort_keys=True, allow_nan=False)
    # Metadata acts as the commit marker for the preceding independent files.
    write_json(directory / "metadata.json", metadata, sort_keys=True, allow_nan=False)
    return run.result


def load_run_documents(directory, configuration, index, *, canonical_name="result"):
    """Check configuration, document integrity, issued evidence and live sources."""
    try:
        metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
        if (metadata["configuration"] != configuration
                or metadata["configuration_fingerprint"] != digest(configuration)):
            return None
        documents = {name: json.loads((directory / f"{name}.json").read_text(encoding="utf-8"))
                     for name in (canonical_name, "trace", "evidence")}
        if any(digest(doc) != metadata["document_digests"][name] for name, doc in documents.items()):
            return None
        for filename, expected in metadata.get("live_sources", {}).items():
            with index.owned_path(filename).open("rb") as stream:
                data = stream.read(2 * 1024 * 1024 + 1)
            if hashlib.sha256(data).hexdigest() != expected:
                return None
        records = documents["evidence"]["records"]
        issued = {eid for event in documents["trace"]["events"] if event["kind"] == "tool_call"
                  for eid in event["result_evidence_ids"]}
        if len(records) != len({r["evidence_id"] for r in records}) or {r["evidence_id"] for r in records} != issued:
            return None
        return {**documents, "metadata": metadata}
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        return None


def load_compatible_run(store: ArtifactStore, candidate, configuration: dict,
                        index: RepositoryIndex) -> dict | None:
    directory = store.candidate_agent_run(candidate_id(candidate.function_id))
    if not (directory / "metadata.json").is_file():
        return None
    try:
        metadata = json.loads((directory / "metadata.json").read_text(encoding="utf-8"))
        if (metadata["configuration_fingerprint"] != digest(configuration)
                or metadata["configuration"] != configuration
                or metadata["candidate_id"] != candidate_id(candidate.function_id)
                or metadata["function_id"] != candidate.function_id):
            return None
        documents = {name: json.loads((directory / f"{name}.json").read_text(encoding="utf-8"))
                     for name in ("result", "trace", "evidence")}
        if any(digest(doc) != metadata["document_digests"][name]
               for name, doc in documents.items()):
            return None
        for filename, expected in metadata.get("live_sources", {}).items():
            path = index.owned_path(filename)
            with path.open("rb") as stream:
                data = stream.read(2 * 1024 * 1024 + 1)
            if hashlib.sha256(data).hexdigest() != expected:
                return None
        result = documents["result"]
        if (result["schema_version"] != SCHEMA_VERSION
                or result["candidate_id"] != candidate_id(candidate.function_id)
                or result["function_id"] != candidate.function_id
                or result["function"] != candidate.function):
            return None
        evidence = {r["evidence_id"]: r for r in documents["evidence"]["records"]}
        issued = {eid for event in documents["trace"]["events"] if event["kind"] == "tool_call"
                  for eid in event["result_evidence_ids"]}
        if set(evidence) != issued:
            return None
        refs = result["evidence"]
        if any(ref["evidence_id"] not in issued
               or evidence[ref["evidence_id"]]["tool"] != ref["tool"] for ref in refs):
            return None
        parse_decision(json.dumps({key: result[key] for key in
                                  ("verdict", "input_mode", "reason_codes", "discovered_symbols", "open_questions")}
                                 | {"evidence_ids": [ref["evidence_id"] for ref in refs]}), evidence)
        return result
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        return None


def write_validated_catalog(store: ArtifactStore, catalog, results: dict, deferred: dict) -> None:
    records = []
    for candidate in catalog.candidates:
        result = results.get(candidate.function_id)
        record = {"candidate_id": candidate_id(candidate.function_id),
                  "function_id": candidate.function_id, "function": candidate.function,
                  "status": result["verdict"] if result else "unresolved", "validation": result,
                  "run_directory": f"agent_runs/{candidate_id(candidate.function_id)}" if result else None}
        if candidate.function_id in deferred:
            record["deferred_reason"] = deferred[candidate.function_id]
        records.append(record)
    store.candidate_discovery_directory.mkdir(parents=True, exist_ok=True)
    write_json(store.validated_candidates, {
        "schema_version": SCHEMA_VERSION, "artifact_kind": "validated_entry_candidate_catalog",
        "policy_version": POLICY_VERSION, "source_fingerprint": catalog.source_fingerprint,
        "discovery_fingerprint": digest(catalog.to_dict()),
        "discovery_artifact": "candidates.json", "candidates": records,
        "verdict_is_filter": False,
    }, sort_keys=True, allow_nan=False)
