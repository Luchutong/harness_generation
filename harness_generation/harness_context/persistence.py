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


def run_configuration(ft, metadata, snapshot, budget, model, *, requirement_mode="single"):
    from .agent import SYSTEM_PROMPT, GROUP_PROMPT
    from .models import VALUE_SCHEMAS, DEPENDENCY_SCHEMA
    from .tools import EXTRA_SCHEMAS
    from ..semantic_discovery.tools import TOOL_SCHEMAS
    from .argument_graph import VERSION as GRAPH_VERSION, DEPENDENCY_VERSION
    from ..semantic_discovery.request_diagnostics import VERSION as DIAGNOSTICS_VERSION
    from .reconciliation import VERSION as RECONCILER_VERSION, RECIPE_VERSION
    from .invocations import VERSION as INVOCATION_VERSION
    from .value_roles import VERSION as VALUE_VERSION
    from .parameter_semantics import VERSION as SEMANTIC_VERSION
    from .input_flow import VERSION as INPUT_FLOW_VERSION
    from .proposals import VERSION as PROPOSAL_VERSION
    from .terminal import VERSION as TERMINAL_VERSION
    from .input_pairs import VERSION as PAIR_VERSION
    from ..semantic_slicing.support_effects import VERSION as EFFECT_VERSION
    descriptor = model.config.to_dict() if hasattr(model, "config") else {"provider": model.provider, "model": model.model}
    return {"schema_version": 1, "policy_version": POLICY_VERSION, "minimal_ft_digest": digest(ft),
        "minimal_ft_metadata_digest": digest(metadata), "minimal_ft_policy": ft["policy_version"],
        "source_fingerprint": snapshot.source_fingerprint, "functions_fingerprint": snapshot.functions_fingerprint,
        "requirement_builder_version": REQUIREMENT_VERSION, "agent_prompt_version": PROMPT_VERSION,
        "construction_version": "verified-construction-v2",
        "argument_graph_version": GRAPH_VERSION, "dependency_graph_version": DEPENDENCY_VERSION,
        "request_diagnostics_version": DIAGNOSTICS_VERSION,
        "reconciler_version": RECONCILER_VERSION, "construction_recipe_version": RECIPE_VERSION,
        "invocation_contract_version": INVOCATION_VERSION, "value_origin_version": VALUE_VERSION,
        "parameter_semantic_version": SEMANTIC_VERSION, "external_input_flow_version": INPUT_FLOW_VERSION,
        "terminal_schema_version": TERMINAL_VERSION, "semantic_proposal_version": PROPOSAL_VERSION, "tool_registry_version": TOOL_VERSION,
        "input_length_pair_version": PAIR_VERSION, "support_effect_version": EFFECT_VERSION,
        "requirement_mode": requirement_mode,
        "agent_prompt_digest": digest(GROUP_PROMPT if requirement_mode == "grouped" else SYSTEM_PROMPT),
        "terminal_schema_digest": digest([VALUE_SCHEMAS, DEPENDENCY_SCHEMA]),
        "tool_registry_digest": digest([TOOL_SCHEMAS, EXTRA_SCHEMAS]),
        "model": descriptor, "budget": budget.to_dict()}


def requirement_configuration(configuration, requirement):
    descriptor = {k: v for k, v in requirement.items() if k not in {"status", "evidence_ids", "resolution_attempt_failed"}}
    return {**configuration, "requirement_digest": digest(descriptor)}


def save_requirement(store, ft_id, run, configuration):
    directory = _owned(context_directory(store, ft_id) / "agent_runs" / run.result["requirement_id"], store.root)
    directory.mkdir(parents=True, exist_ok=True)
    attempts = [int(p.name.split("_")[-1]) for p in directory.glob("attempt_*") if p.name.split("_")[-1].isdigit()]
    history = _owned(directory / f"attempt_{max(attempts, default=0) + 1:04d}", store.root)
    save_run_documents(history, run, configuration)
    save_run_documents(directory, run, configuration)


def load_requirement(store, ft_id, requirement, configuration, index, *, preserve_soft_unknown=False):
    directory = _owned(context_directory(store, ft_id) / "agent_runs" / requirement["requirement_id"], store.root)
    for name in ("metadata", "result", "trace", "evidence"):
        _owned(directory / f"{name}.json", store.root)
    loaded = load_run_documents(directory, configuration, index)
    statuses = {"resolved", "not_applicable"} | ({"unresolved"} if preserve_soft_unknown and not requirement["mandatory"] else set())
    if (loaded and not loaded["metadata"].get("resolution_attempt_failed")
            and loaded["result"].get("requirement_id") == requirement["requirement_id"]
            and loaded["result"].get("status") in statuses):
        return loaded
    return None


def save_context(store, run, configuration, state, resolutions):
    directory = context_directory(store, run.context["ft_id"])
    directory.mkdir(parents=True, exist_ok=True)
    documents = {"requirements": run.requirements, "facts": {"schema_version": 1, "facts": run.context["facts"]},
        "api_closure": run.closure, "harness_context": run.context, "completeness": run.completeness,
        "evidence": {"schema_version": 1, "records": [state.evidence[eid] for eid in sorted(state.evidence)]},
        "resolutions": {"schema_version": 1, "resolutions": resolutions}}
    if "argument_graph" in run.context:
        documents["argument_graph"] = run.context["argument_graph"]
    if "canonical_construction" in run.context:
        documents["canonical_construction"] = run.context["canonical_construction"]
    for name in ("resource_contract", "invocation_contract", "parameter_semantic_contract", "external_input_flow"):
        if name in run.context:
            documents[name] = run.context[name]
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
        if configuration.get("argument_graph_version"):
            names += ("argument_graph",)
        if configuration.get("reconciler_version"):
            names += ("canonical_construction",)
        if configuration.get("invocation_contract_version"):
            names += ("resource_contract", "invocation_contract")
        if configuration.get("parameter_semantic_version"):
            names += ("parameter_semantic_contract", "external_input_flow")
        documents = {name: _load_json(_owned(directory / f"{name}.json", store.root)) for name in names}
        if any(digest(document) != metadata["document_digests"][name] for name, document in documents.items()):
            return None
        if configuration.get("argument_graph_version") and documents["argument_graph"] != documents["harness_context"].get("argument_graph"):
            return None
        if configuration.get("reconciler_version") and documents["canonical_construction"] != documents["harness_context"].get("canonical_construction"):
            return None
        if any(documents[name] != documents["harness_context"].get(name) for name in
                ("resource_contract", "invocation_contract", "parameter_semantic_contract", "external_input_flow") if name in documents):
            return None
        # Reuse common live-source checking for every contributing requirement.
        for req in documents["requirements"]["requirements"]:
            if req["status"] in {"resolved", "not_applicable"} and not load_requirement(store, ft_id, req,
                    requirement_configuration(configuration, req), index):
                return None
        return {**documents, "metadata": metadata}
    except (OSError, ValueError, KeyError, TypeError):
        return None
