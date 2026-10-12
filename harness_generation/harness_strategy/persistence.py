"""Immutable strategy runs and provider-free authenticated structural replay."""
from __future__ import annotations

import re
from uuid import uuid4

from ..entry_candidates import CandidateCatalog
from ..minimal_ft.persistence import _load_json, _owned
from ..records import write_json
from ..semantic_discovery.models import AgentModelResponse, AgentToolCall, digest
from ..semantic_discovery.tools import RepositoryIndex
from .models import POLICY_VERSION, StrategyBudget
from .planner import StrategyPlanner, verify_source_identity
from .tools import StrategyTools


class TranscriptModel:
    """Local response playback. It has no provider client or network capability."""
    def __init__(self, rows, descriptor):
        if not isinstance(rows, list):
            raise ValueError("invalid strategy model invocation ledger")
        self.rows, self.position = rows, 0
        self.provider, self.model = descriptor["provider"], descriptor["model"]

    def complete(self, messages, tools):
        if self.position >= len(self.rows):
            raise ValueError("strategy transcript response missing")
        row = self.rows[self.position]
        self.position += 1
        if not isinstance(row, dict) or row.get("request_digest") != digest({"messages": messages, "tools": tools}):
            raise ValueError("strategy transcript request mismatch")
        if "error" in row:
            error = RuntimeError("recorded adapter failure")
            for name, value in row["error"].items():
                setattr(error, name, value)
            raise error
        if row.get("invalid_response") is True:
            return None
        response = row["response"]
        return AgentModelResponse(content=response["content"], reasoning_content=response["reasoning_content"],
            tool_calls=tuple(AgentToolCall(**call) for call in response["tool_calls"]), metadata=response["metadata"])


def run_directory(store, ft_id, run_id):
    # Validate FT spelling and owned-root boundary using the existing store.
    store.minimal_ft_run(ft_id)
    if not isinstance(run_id, str) or not re.fullmatch(r"strategy_run_[0-9a-f]{32}", run_id):
        raise ValueError("invalid strategy run ID")
    return _owned(store.root / "harness_strategies" / ft_id / run_id, store.root)


def run_configuration(ft, ft_metadata, snapshot, budget, model, *, feedback=None, build_analysis=None, build_analysis_directory=None):
    descriptor = getattr(model, "config", None)
    descriptor = descriptor.to_dict() if callable(getattr(descriptor, "to_dict", None)) else {
        "provider": getattr(model, "provider", "unspecified"), "model": getattr(model, "model", "unspecified")}
    configuration = {"policy_version": POLICY_VERSION, "schema_version": 1,
            "minimal_ft_digest": digest(ft), "minimal_ft_metadata_digest": digest(ft_metadata),
            "source_fingerprint": snapshot.source_fingerprint,
            "functions_fingerprint": snapshot.functions_fingerprint,
            "budget": budget.to_dict(), "agent": descriptor,
            "validation_authority": "structure_only", "generation_allowed": False}
    if feedback is not None:
        from ..semantic_discovery.models import canonical
        if not isinstance(feedback, dict) or len(canonical(feedback)) > 24000:
            raise ValueError("invalid strategy recovery feedback")
        configuration["recovery_feedback"] = feedback
    from .build_analysis import analysis_configuration
    analysis = analysis_configuration(build_analysis, build_analysis_directory)
    if analysis is not None:
        configuration["build_aware_analysis"] = analysis
    return configuration


def save_run(store, ft_id, run, configuration):
    run_id = "strategy_run_" + uuid4().hex
    directory = run_directory(store, ft_id, run_id)
    directory.mkdir(parents=True, exist_ok=False)
    documents = {"strategies": run.result, "trace": run.trace, "evidence": run.evidence}
    for name, document in documents.items():
        path = _owned(directory / (name + ".json"), store.root)
        write_json(path, document, sort_keys=True, allow_nan=False)
    metadata = {**run.metadata, "run_id": run_id, "ft_id": ft_id, "configuration": configuration,
                "configuration_fingerprint": digest(configuration),
                "document_digests": {name: digest(document) for name, document in documents.items()}}
    # Commit marker last: a partially written directory is never reusable.
    write_json(_owned(directory / "metadata.json", store.root), metadata, sort_keys=True, allow_nan=False)
    return run_id


def replay_run(store, ft, ft_metadata, snapshot, run_id):
    """Reissue saved read-only queries, validate proposals and recompute ranking.

    No provider client is created. Source, FT, native submissions, evidence,
    scope and resource origins are recomputed using a local response transcript.
    """
    directory = run_directory(store, ft["ft_id"], run_id)
    documents = {name: _load_json(_owned(directory / (name + ".json"), store.root))
                 for name in ("strategies", "trace", "evidence", "metadata")}
    metadata = documents["metadata"]
    if not isinstance(metadata, dict):
        raise ValueError("invalid strategy commit marker")
    configuration = metadata.get("configuration")
    if not isinstance(configuration, dict) or configuration.get("policy_version") != POLICY_VERSION:
        raise ValueError("strategy configuration policy mismatch")
    if metadata.get("run_id") != run_id or metadata.get("ft_id") != ft["ft_id"]:
        raise ValueError("strategy run identity mismatch")
    if metadata.get("configuration_fingerprint") != digest(configuration):
        raise ValueError("strategy configuration digest mismatch")
    expected = {"minimal_ft_digest": digest(ft), "minimal_ft_metadata_digest": digest(ft_metadata),
                "source_fingerprint": snapshot.source_fingerprint, "functions_fingerprint": snapshot.functions_fingerprint,
                "schema_version": 1, "validation_authority": "structure_only", "generation_allowed": False}
    if any(configuration.get(key) != value for key, value in expected.items()):
        raise ValueError("strategy run belongs to a different FT or source snapshot")
    if metadata.get("generation_allowed") is not False:
        raise ValueError("strategy artifact cannot authorize harness generation")
    for name in ("strategies", "trace", "evidence"):
        if not isinstance(documents[name], dict) or metadata.get("document_digests", {}).get(name) != digest(documents[name]):
            raise ValueError("strategy document digest mismatch: " + name)
    budget = StrategyBudget.from_dict(configuration["budget"])
    catalog = CandidateCatalog((), snapshot.source_fingerprint)
    index = RepositoryIndex(snapshot.artifacts, catalog, functions_path=store.functions)
    from .build_analysis import replay_analysis
    analysis = replay_analysis(configuration.get("build_aware_analysis"), snapshot)
    tools = StrategyTools(snapshot, catalog, ft, budget, index=index, build_analysis=analysis)
    trace = documents["trace"]
    calls, invocations = trace.get("repository_calls"), trace.get("model_invocations")
    if (not isinstance(calls, list) or len(calls) > budget.investigation.max_tool_calls
            or not isinstance(invocations, list) or len(invocations) > budget.investigation.max_rounds):
        raise ValueError("strategy transcript exceeds the shared invocation budget")
    saved_ids = documents["evidence"].get("authorized_function_ids")
    saved_records = documents["evidence"].get("records")
    if not isinstance(saved_ids, list) or not isinstance(saved_records, list):
        raise ValueError("invalid strategy evidence audit")
    verify_source_identity(snapshot, index, saved_ids, saved_records)
    playback = TranscriptModel(invocations, configuration["agent"])
    reconstructed = StrategyPlanner(playback, budget).plan(ft, snapshot, tools, feedback=configuration.get("recovery_feedback"))
    if playback.position != len(invocations):
        raise ValueError("strategy transcript contains unused responses")
    for name, value in (("strategies", reconstructed.result), ("trace", reconstructed.trace), ("evidence", reconstructed.evidence)):
        if value != documents[name]:
            raise ValueError("strategy transcript did not reproduce: " + name)
    expected_metadata = {**reconstructed.metadata, "run_id": run_id, "ft_id": ft["ft_id"],
        "configuration": configuration, "configuration_fingerprint": digest(configuration),
        "document_digests": {name: digest(documents[name]) for name in ("strategies", "trace", "evidence")}}
    if metadata != expected_metadata:
        raise ValueError("strategy model/tool/token/repair ledger did not reproduce")
    result = reconstructed.result
    return {"schema_version": 1, "run_id": run_id, "ft_id": ft["ft_id"], "status": "reproduced",
            "strategy_status": result["status"], "ranked_strategy_ids": result["ranked_strategy_ids"],
            "model_calls": 0, "provider_requests": 0, "generation_allowed": False,
            "replayed_repository_calls": len(calls), "replayed_model_invocations": len(invocations)}
