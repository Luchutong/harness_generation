"""Independent context and strategy-run stores with live structural replay."""
from __future__ import annotations

from pathlib import Path
import re
from uuid import uuid4

from ..minimal_ft.persistence import _load_json, _owned
from ..records import write_json
from ..semantic_discovery.models import digest
from .builder import build_context
from .models import ARTIFACT_KIND, AUTHORIZATION_KIND, VERSION, ContextBudget, LightweightAPIContext


class LightweightContextStore:
    """No path or operation enters Candidate, Slice, or Minimal FT directories."""

    def __init__(self, root):
        self.root = Path(root).resolve()

    def context_directory(self, context_id):
        if not isinstance(context_id, str) or not re.fullmatch(r"lac_[A-Za-z0-9_]{1,48}_[0-9a-f]{24}", context_id):
            raise ValueError("invalid lightweight context ID")
        return _owned(self.root / "lightweight_api_contexts" / context_id, self.root)

    def strategy_run_directory(self, context_id, run_id):
        self.context_directory(context_id)
        if not isinstance(run_id, str) or not re.fullmatch(r"strategy_run_[0-9a-f]{32}", run_id):
            raise ValueError("invalid lightweight strategy run ID")
        return _owned(self.root / "lightweight_strategy_runs" / context_id / run_id, self.root)

    def save(self, context):
        if type(context) is not LightweightAPIContext:
            raise ValueError("only live context receipts can be saved")
        context.validate()
        directory = self.context_directory(context.context_id)
        if directory.exists():
            if (_load_json(_owned(directory / "context.json", self.root)) != context.document
                    or _load_json(_owned(directory / "metadata.json", self.root)) != context.metadata):
                raise ValueError("immutable lightweight context already exists with different contents")
            return directory
        directory.mkdir(parents=True, exist_ok=False)
        write_json(_owned(directory / "context.json", self.root), context.document, sort_keys=True, allow_nan=False)
        # Commit marker last. Partial attempts are never accepted as receipts.
        write_json(_owned(directory / "metadata.json", self.root), context.metadata, sort_keys=True, allow_nan=False)
        return directory

    def load(self, context_id, snapshot, build_analysis, index):
        directory = self.context_directory(context_id)
        document = _load_json(_owned(directory / "context.json", self.root))
        metadata = _load_json(_owned(directory / "metadata.json", self.root))
        if not isinstance(document, dict) or document.get("context_id") != context_id:
            raise ValueError("invalid lightweight context document")
        if (document.get("artifact_kind") != ARTIFACT_KIND or document.get("policy_version") != VERSION
                or document.get("authorization_kind") != AUTHORIZATION_KIND):
            raise ValueError("lightweight context policy mismatch")
        budget = ContextBudget.from_dict(document.get("budget"))
        reproduced = build_context(snapshot, build_analysis, index, document.get("anchor_function_id"),
            budget=budget, support_function_ids=document.get("requested_support_function_ids"))
        if reproduced.document != document or reproduced.metadata != metadata:
            raise ValueError("lightweight API context did not reproduce from current source/build")
        return reproduced


ContextStore = LightweightContextStore


def strategy_run_configuration(context, budget, model, *, build_analysis_directory=None):
    """Configuration fields explicitly bind LAC, never Minimal FT authority."""
    context.validate()
    from ..harness_strategy.models import POLICY_VERSION
    descriptor = getattr(model, "config", None)
    descriptor = descriptor.to_dict() if callable(getattr(descriptor, "to_dict", None)) else {
        "provider": getattr(model, "provider", "unspecified"), "model": getattr(model, "model", "unspecified")}
    configuration = {"schema_version": 1, "policy_version": POLICY_VERSION,
        "context_type": ARTIFACT_KIND, "authorization_kind": AUTHORIZATION_KIND,
        "context_id": context.context_id, "context_digest": digest(context.document),
        "context_metadata_digest": digest(context.metadata),
        "strategy_input_digest": digest(context.strategy_input),
        "source_fingerprint": context.snapshot.source_fingerprint,
        "functions_fingerprint": context.snapshot.functions_fingerprint,
        "build_analysis_identity": context.analysis.identity_digest,
        "budget": budget.to_dict(), "agent": descriptor,
        "validation_authority": "structure_and_live_api_scope_only",
        "generation_allowed": False, "semantic_verified": False}
    if build_analysis_directory is not None:
        from ..harness_strategy.build_analysis import analysis_configuration
        configuration["build_aware_analysis"] = analysis_configuration(context.analysis, build_analysis_directory)
    return configuration


def save_strategy_run(store, context, run, configuration):
    """Persist Planner output independently; labels do not confer permission."""
    if not isinstance(store, LightweightContextStore) or type(context) is not LightweightAPIContext:
        raise ValueError("lightweight strategy persistence requires its independent store and receipt")
    context.validate()
    if (configuration.get("context_id") != context.context_id
            or configuration.get("strategy_input_digest") != digest(context.strategy_input)
            or run.result.get("ft_id") != context.context_id):
        raise ValueError("lightweight strategy run context mismatch")
    store.save(context)
    run_id = "strategy_run_" + uuid4().hex
    directory = store.strategy_run_directory(context.context_id, run_id)
    directory.mkdir(parents=True, exist_ok=False)
    documents = {"strategies": run.result, "trace": run.trace, "evidence": run.evidence}
    for name, document in documents.items():
        write_json(_owned(directory / (name + ".json"), store.root), document, sort_keys=True, allow_nan=False)
    metadata = {**run.metadata, "run_id": run_id, "ft_id": context.context_id,
        "context_id": context.context_id, "context_type": ARTIFACT_KIND,
        "authorization_kind": AUTHORIZATION_KIND, "configuration": configuration,
        "configuration_fingerprint": digest(configuration),
        "document_digests": {name: digest(document) for name, document in documents.items()}}
    write_json(_owned(directory / "metadata.json", store.root), metadata, sort_keys=True, allow_nan=False)
    return run_id


def replay_strategy_run(store, context, run_id):
    """Reissue the whole transcript, including a failed planning outcome.

    Caller must obtain ``context`` by live construction or store.load. This
    function creates no provider, effect proof, Slice or Minimal FT receipt.
    """
    if not isinstance(store, LightweightContextStore) or type(context) is not LightweightAPIContext:
        raise ValueError("lightweight strategy replay requires a live context receipt")
    context.validate()
    directory = store.strategy_run_directory(context.context_id, run_id)
    documents = {name: _load_json(_owned(directory / (name + ".json"), store.root))
        for name in ("strategies", "trace", "evidence", "metadata")}
    metadata = documents["metadata"]
    configuration = metadata.get("configuration") if isinstance(metadata, dict) else None
    if not isinstance(configuration, dict):
        raise ValueError("invalid lightweight strategy commit marker")
    from ..harness_strategy.models import StrategyBudget
    budget = StrategyBudget.from_dict(configuration.get("budget"))
    from ..harness_strategy.persistence import TranscriptModel
    from ..harness_strategy.planner import StrategyPlanner, verify_source_identity
    playback = TranscriptModel(documents["trace"].get("model_invocations"), configuration.get("agent", {}))
    # Recompute all framework-owned configuration fields without trusting the
    # file's source/API scope or authority labels. Descriptor is data only.
    expected = strategy_run_configuration(context, budget, playback,
        build_analysis_directory=configuration.get("build_aware_analysis", {}).get("directory"))
    # Transport settings in the saved descriptor are inert transcript data,
    # not authorization to instantiate or contact that provider.
    if not isinstance(configuration.get("agent"), dict):
        raise ValueError("invalid lightweight strategy provider descriptor")
    expected["agent"] = configuration["agent"]
    if expected != configuration or metadata.get("configuration_fingerprint") != digest(configuration):
        raise ValueError("lightweight strategy configuration did not reproduce")
    for name in ("strategies", "trace", "evidence"):
        if not isinstance(documents[name], dict) or metadata.get("document_digests", {}).get(name) != digest(documents[name]):
            raise ValueError("lightweight strategy document digest mismatch: " + name)
    calls = documents["trace"].get("repository_calls")
    if (not isinstance(calls, list) or len(calls) > budget.investigation.max_tool_calls
            or len(playback.rows) > budget.investigation.max_rounds):
        raise ValueError("lightweight strategy transcript exceeds its budget")
    evidence = documents["evidence"]
    if set(evidence.get("authorized_function_ids", [])) != set(context.scope.function_ids):
        raise ValueError("lightweight strategy transcript expanded callable scope")
    verify_source_identity(context.snapshot, context.index, context.scope.function_ids, evidence.get("records", []))
    reconstructed = StrategyPlanner(playback, budget).plan(
        context.strategy_input, context.snapshot, context.make_strategy_tools(budget))
    if playback.position != len(playback.rows):
        raise ValueError("lightweight strategy transcript has unused responses")
    for name, document in (("strategies", reconstructed.result), ("trace", reconstructed.trace), ("evidence", reconstructed.evidence)):
        if document != documents[name]:
            raise ValueError("lightweight strategy transcript did not reproduce: " + name)
    expected_metadata = {**reconstructed.metadata, "run_id": run_id, "ft_id": context.context_id,
        "context_id": context.context_id, "context_type": ARTIFACT_KIND,
        "authorization_kind": AUTHORIZATION_KIND, "configuration": configuration,
        "configuration_fingerprint": digest(configuration),
        "document_digests": {name: digest(documents[name]) for name in ("strategies", "trace", "evidence")}}
    if expected_metadata != metadata:
        raise ValueError("lightweight strategy model/tool/token ledger did not reproduce")
    return {"run": reconstructed, "metadata": metadata, "directory": directory,
        "context": context, "replay": {"status": "reproduced", "model_calls": 0, "provider_requests": 0,
            "replayed_repository_calls": len(calls), "replayed_model_invocations": len(playback.rows),
            "generation_allowed": False, "semantic_verified": False}}


def load_strategy_inputs(store, context, run_id, *, strategy_id=None):
    """Return a structurally valid proposal only after full offline replay."""
    replayed = replay_strategy_run(store, context, run_id)
    reconstructed = replayed["run"]
    selected_id = strategy_id or reconstructed.result.get("selected_strategy_id")
    candidates = {row["strategy"]["strategy_id"]: row for row in reconstructed.result["candidates"]
        if row.get("validation", {}).get("valid") is True}
    if selected_id not in candidates:
        raise ValueError("no structurally valid lightweight strategy selected")
    return {"strategy": candidates[selected_id]["strategy"], "evidence": reconstructed.evidence,
        "validation": candidates[selected_id]["validation"], "metadata": replayed["metadata"],
        "context": context, "context_input": context.strategy_input,
        "context_metadata": context.metadata, "directory": replayed["directory"],
        "replay": replayed["replay"]}
