"""Atomic run records and validated catalog projection; discovery is untouched."""
from __future__ import annotations

import hashlib
import json

from ..artifacts import ArtifactStore
from ..records import write_json
from .agent import ValidationRun
from .models import POLICY_VERSION, SCHEMA_VERSION, ValidationBudget, candidate_id, canonical, digest, parse_decision
from .tools import RepositoryIndex, RepositoryTools, ToolBudgetExceeded


def run_configuration(catalog, budget, model, *, max_terminal_repairs=1,
                      max_semantic_recoveries=0, max_provider_recoveries=0,
                      max_protocol_recoveries=0, build_analysis=None, build_analysis_directory=None) -> dict:
    descriptor = getattr(model, "config", None)
    config = descriptor.to_dict() if callable(getattr(descriptor, "to_dict", None)) else {
        "provider": model.provider, "model": model.model}
    from .loop import TERMINAL_REPAIR_POLICY_VERSION
    configuration = {"terminal_repair_policy_version": TERMINAL_REPAIR_POLICY_VERSION,
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
    from ..harness_strategy.build_analysis import analysis_configuration
    analysis = analysis_configuration(build_analysis, build_analysis_directory)
    if analysis is not None:
        from .agent import BUILD_AWARE_PROMPT
        configuration["build_aware_analysis"] = analysis
        configuration["build_aware_prompt_fingerprint"] = digest(BUILD_AWARE_PROMPT)
    return configuration


def replay_build_analysis(configuration, index):
    """Load saved compiler facts independently; legacy inputs remain unchanged."""
    from ..harness_strategy.build_analysis import replay_analysis
    from ..minimal_ft.models import ProjectSnapshot
    return replay_analysis(configuration.get("build_aware_analysis"), ProjectSnapshot.from_artifacts(index.artifacts))


def replay_repository_responses(documents, tools, *, canonical_name="result"):
    """Reissue native source queries and compare complete compiler payloads."""
    events = [row for row in documents["trace"]["events"] if row["kind"] == "tool_call"]
    if len(events) > tools.budget.max_tool_calls:
        raise ValueError("repository transcript exceeds tool budget")
    responses = {}
    for message in documents["trace"]["messages"]:
        if message["role"] == "tool":
            responses.setdefault(message["tool_call_id"], []).append(json.loads(message["content"]))
    for event in events:
        if event.get("framework_bootstrap"):
            # Slice's accounted bootstrap intentionally returns one frontier
            # row, whereas a normal frontier query may return a full page.
            if event["tool"] != "get_semantic_frontier" or event["tool_call_id"] != "framework_frontier_seed":
                raise ValueError("unknown repository bootstrap")
            output = tools._frontier(event["arguments"], page_size=1)
            from ..semantic_slicing.proposals import choices
            output["slice_role_choices"] = choices(tools)
        else:
            try:
                output = tools.execute(event["tool"], event["arguments"])
            except ToolBudgetExceeded:
                output = {"error": "budget_exhausted", "evidence_ids": []}
        if responses.get(event["tool_call_id"]) != [output] or output["evidence_ids"] != event["result_evidence_ids"]:
            raise ValueError("repository compiler response did not reproduce")
    actual = sorted(tools.evidence.values(), key=lambda row: row["evidence_id"])
    saved = sorted(documents["evidence"]["records"], key=lambda row: row["evidence_id"])
    expected_chars = documents["metadata"].get("source_chars", documents[canonical_name].get("budget", {}).get("source_chars"))
    if actual != saved or tools.source_chars != expected_chars:
        raise ValueError("repository evidence or compiler metadata budget changed")


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
        replay_build_analysis(configuration, index)
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
        analysis = replay_build_analysis(configuration, index)
        if analysis is not None:
            tools = RepositoryTools(index.artifacts, index.catalog, ValidationBudget(**configuration["budget"]),
                                    index=index, build_analysis=analysis)
            replay_repository_responses({**documents, "metadata": metadata}, tools)
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
