"""Artifact-first inputs, atomic commits and per-requirement compatible resume."""
from copy import deepcopy
from pathlib import Path

from ..minimal_ft.persistence import (_load_json, _owned, load_slice_input, load_legacy_inputs,
    build_configuration, load_compatible_build)
from ..records import write_json
from ..semantic_discovery.models import digest
from ..semantic_discovery.persistence import save_run_documents, load_run_documents
from .models import POLICY_VERSION, REQUIREMENT_VERSION, PROMPT_VERSION, TOOL_VERSION


def context_directory(store, ft_id):
    store.minimal_ft_run(ft_id)  # Shared ID/path validation, without mutation.
    return _owned(store.root / "harness_contexts" / ft_id, store.root)


def load_minimal_ft(store, ft_id, snapshot):
    directory = store.minimal_ft_run(ft_id)
    metadata = _load_json(_owned(directory / "metadata.json", store.root))
    document = _load_json(_owned(directory / "minimal_ft.json", store.root))
    source = load_slice_input(store, document["candidate_id"])
    compare = metadata["configuration"]["compare_legacy"]
    legacy, manifest = load_legacy_inputs(store, {document["anchor_function_id"]}, enabled=compare)
    source.legacy = legacy[document["anchor_function_id"]]
    configuration = build_configuration(source, snapshot, manifest, compare_legacy=compare)
    valid = load_compatible_build(store, ft_id, configuration, source, snapshot)
    if valid is None:
        raise ValueError("Minimal FT is invalid, stale or missing its commit marker; rebuild it upstream")
    return valid, metadata


def run_configuration(ft, metadata, snapshot, budget, model):
    from .agent import SYSTEM_PROMPT
    from .models import VALUE_SCHEMAS, DEPENDENCY_SCHEMA
    from .tools import EXTRA_SCHEMAS
    from ..semantic_discovery.tools import TOOL_SCHEMAS
    descriptor = model.config.to_dict() if hasattr(model, "config") else {"provider": model.provider, "model": model.model}
    return {"schema_version": 1, "policy_version": POLICY_VERSION, "minimal_ft_digest": digest(ft),
        "minimal_ft_metadata_digest": digest(metadata), "minimal_ft_policy": ft["policy_version"],
        "source_fingerprint": snapshot.source_fingerprint, "functions_fingerprint": snapshot.functions_fingerprint,
        "requirement_builder_version": REQUIREMENT_VERSION, "agent_prompt_version": PROMPT_VERSION,
        "terminal_schema_version": 1, "tool_registry_version": TOOL_VERSION,
        "agent_prompt_digest": digest(SYSTEM_PROMPT), "terminal_schema_digest": digest([VALUE_SCHEMAS, DEPENDENCY_SCHEMA]),
        "tool_registry_digest": digest([TOOL_SCHEMAS, EXTRA_SCHEMAS]),
        "model": descriptor, "budget": budget.to_dict()}


def requirement_configuration(configuration, requirement):
    descriptor = {k: v for k, v in requirement.items() if k not in {"status", "evidence_ids"}}
    return {**configuration, "requirement_digest": digest(descriptor)}


def save_requirement(store, ft_id, run, configuration):
    directory = _owned(context_directory(store, ft_id) / "agent_runs" / run.result["requirement_id"], store.root)
    directory.mkdir(parents=True, exist_ok=True)
    attempts = [int(p.name.split("_")[-1]) for p in directory.glob("attempt_*") if p.name.split("_")[-1].isdigit()]
    history = _owned(directory / f"attempt_{max(attempts, default=0) + 1:04d}", store.root)
    save_run_documents(history, run, configuration)
    save_run_documents(directory, run, configuration)


def load_requirement(store, ft_id, requirement, configuration, index):
    directory = _owned(context_directory(store, ft_id) / "agent_runs" / requirement["requirement_id"], store.root)
    for name in ("metadata", "result", "trace", "evidence"):
        _owned(directory / f"{name}.json", store.root)
    loaded = load_run_documents(directory, configuration, index)
    if loaded and loaded["result"].get("requirement_id") == requirement["requirement_id"] and loaded["result"].get("status") in {"resolved", "not_applicable"}:
        return loaded
    return None


def save_context(store, run, configuration, state, resolutions):
    directory = context_directory(store, run.context["ft_id"])
    directory.mkdir(parents=True, exist_ok=True)
    documents = {"requirements": run.requirements, "facts": {"schema_version": 1, "facts": run.context["facts"]},
        "api_closure": run.closure, "harness_context": run.context, "completeness": run.completeness,
        "evidence": {"schema_version": 1, "records": [state.evidence[eid] for eid in sorted(state.evidence)]},
        "resolutions": {"schema_version": 1, "resolutions": resolutions}}
    for name, document in documents.items():
        write_json(_owned(directory / f"{name}.json", store.root), document, sort_keys=True, allow_nan=False)
    metadata = {**run.metadata, "configuration": configuration, "configuration_fingerprint": digest(configuration),
        "document_digests": {name: digest(document) for name, document in documents.items()},
        "discoveries": deepcopy(state.discoveries), "ft_immutable": True}
    write_json(_owned(directory / "metadata.json", store.root), metadata, sort_keys=True, allow_nan=False)


def load_context_documents(store, ft_id, configuration, index):
    directory = context_directory(store, ft_id)
    try:
        metadata = _load_json(_owned(directory / "metadata.json", store.root))
        if metadata["configuration"] != configuration or metadata["configuration_fingerprint"] != digest(configuration):
            return None
        names = ("requirements", "facts", "api_closure", "harness_context", "completeness", "evidence", "resolutions")
        documents = {name: _load_json(_owned(directory / f"{name}.json", store.root)) for name in names}
        if any(digest(document) != metadata["document_digests"][name] for name, document in documents.items()):
            return None
        # Reuse common live-source checking for every contributing requirement.
        for req in documents["requirements"]["requirements"]:
            if req["status"] in {"resolved", "not_applicable"} and not load_requirement(store, ft_id, req,
                    requirement_configuration(configuration, req), index):
                return None
        return {**documents, "metadata": metadata}
    except (OSError, ValueError, KeyError, TypeError):
        return None
