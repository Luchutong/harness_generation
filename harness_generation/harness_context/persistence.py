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


def run_configuration(ft, metadata, snapshot, budget, model, *, requirement_mode="single",
                      investigation_backend=None):
    from .agent import SYSTEM_PROMPT, GROUP_PROMPT, KIND_PROMPTS, SOURCE_DETAIL_GUIDANCE, OWNED_RETURN_DISCOVERY
    from .models import VALUE_SCHEMAS, DEPENDENCY_SCHEMA
    from .tools import EXTRA_SCHEMAS
    from ..semantic_discovery.tools import TOOL_SCHEMAS
    from .argument_graph import VERSION as GRAPH_VERSION, DEPENDENCY_VERSION
    from ..semantic_discovery.request_diagnostics import VERSION as DIAGNOSTICS_VERSION
    from ..semantic_discovery.loop import TERMINAL_REPAIR_POLICY_VERSION
    from .reconciliation import VERSION as RECONCILER_VERSION, RECIPE_VERSION
    from .invocations import VERSION as INVOCATION_VERSION
    from .internal_invocations import VERSION as INTERNAL_INVOCATION_VERSION
    from .invocation_scope import VERSION as INVOCATION_SCOPE_VERSION
    from .prompt_projection import VERSION as PROMPT_PROJECTION_VERSION
    from .value_roles import VERSION as VALUE_VERSION
    from .parameter_semantics import VERSION as SEMANTIC_VERSION
    from .input_flow import VERSION as INPUT_FLOW_VERSION
    from .proposals import VERSION as PROPOSAL_VERSION
    from .terminal import VERSION as TERMINAL_VERSION
    from .input_pairs import VERSION as PAIR_VERSION
    from ..semantic_slicing.support_effects import VERSION as EFFECT_VERSION
    from .obligations import VERSION as OBLIGATION_VERSION
    from .investigation import VERSION as INVESTIGATION_VERSION
    from .proof_grounding import VERSION as GROUNDING_VERSION
    from .repairs import VERSION as REPAIR_VERSION
    from .closure_feedback import VERSION as CLOSURE_FEEDBACK_VERSION
    from .repair_transactions import VERSION as TRANSACTION_VERSION, MAX_REJECTED_REVISION_CORRECTIONS
    from .transaction_support import VERSION as SOURCE_SUPPORT_VERSION
    from .source_queries import VERSION as SOURCE_QUERY_VERSION
    from .callbacks import VERSION as CALLBACK_VERSION
    from .construction import VERSION as CONSTRUCTION_VERSION
    from .resource_identity import VERSION as IDENTITY_VERSION
    from .callback_resources import VERSION as CALLBACK_RESOURCE_VERSION
    from .scheduling import VERSION as SCHEDULING_VERSION
    from .prompt_projection import COMMON_CONTRACT_GUIDANCE, CONTRACT_GUIDANCE_BY_KIND
    descriptor = model.config.to_dict() if hasattr(model, "config") else {"provider": model.provider, "model": model.model}
    configuration = {"schema_version": 1, "policy_version": POLICY_VERSION, "minimal_ft_digest": digest(ft),
        "terminal_repair_policy_version": TERMINAL_REPAIR_POLICY_VERSION,
        "terminal_repair_allowed_categories": ["terminal_schema_error", "terminal_native_submission_missing"],
        "extra_terminal_repair_last_round_only": False,
        "minimal_ft_metadata_digest": digest(metadata), "minimal_ft_policy": ft["policy_version"],
        "source_fingerprint": snapshot.source_fingerprint, "functions_fingerprint": snapshot.functions_fingerprint,
        "requirement_builder_version": REQUIREMENT_VERSION, "agent_prompt_version": PROMPT_VERSION,
        "construction_version": CONSTRUCTION_VERSION,
        "resource_identity_version": IDENTITY_VERSION,
        "callback_resource_reference_version": CALLBACK_RESOURCE_VERSION,
        "semantic_obligation_graph_version": OBLIGATION_VERSION,
        "proof_investigation_version": INVESTIGATION_VERSION,
        "investigation_scheduling_version": SCHEDULING_VERSION,
        "source_grounding_version": GROUNDING_VERSION,
        "source_detail_query_version": SOURCE_QUERY_VERSION,
        "callback_declaration_version": CALLBACK_VERSION,
        "subject_local_repair_version": REPAIR_VERSION,
        "closure_feedback_version": CLOSURE_FEEDBACK_VERSION,
        "max_unchanged_contract_revisions_per_requirement": 1,
        "context_revision_transaction_version": TRANSACTION_VERSION,
        "max_rejected_revision_corrections_per_requirement": MAX_REJECTED_REVISION_CORRECTIONS,
        "native_submission_version": "native-typed-submission-v1",
        "context_transaction_source_support_version": SOURCE_SUPPORT_VERSION,
        "argument_graph_version": GRAPH_VERSION, "dependency_graph_version": DEPENDENCY_VERSION,
        "request_diagnostics_version": DIAGNOSTICS_VERSION,
        "reconciler_version": RECONCILER_VERSION, "construction_recipe_version": RECIPE_VERSION,
        "invocation_contract_version": INVOCATION_VERSION, "value_origin_version": VALUE_VERSION,
        "internal_invocation_proof_version": INTERNAL_INVOCATION_VERSION,
        "resource_invocation_scope_version": INVOCATION_SCOPE_VERSION,
        "agent_prompt_projection_version": PROMPT_PROJECTION_VERSION,
        "parameter_semantic_version": SEMANTIC_VERSION, "external_input_flow_version": INPUT_FLOW_VERSION,
        "terminal_schema_version": TERMINAL_VERSION, "semantic_proposal_version": PROPOSAL_VERSION, "tool_registry_version": TOOL_VERSION,
        "input_length_pair_version": PAIR_VERSION, "support_effect_version": EFFECT_VERSION,
        "requirement_mode": requirement_mode,
        "max_semantic_recoveries": 1, "max_provider_recoveries": 1, "max_protocol_recoveries": 1,
        "agent_prompt_digest": digest({"system": {"single": SYSTEM_PROMPT, "grouped": GROUP_PROMPT},
            "kind_prompts": KIND_PROMPTS, "source_detail": SOURCE_DETAIL_GUIDANCE,
            "owned_return_discovery": OWNED_RETURN_DISCOVERY,
            "common_contract_guidance": COMMON_CONTRACT_GUIDANCE,
            "contract_guidance_by_kind": CONTRACT_GUIDANCE_BY_KIND}),
        "terminal_schema_digest": digest([VALUE_SCHEMAS, DEPENDENCY_SCHEMA]),
        "tool_registry_digest": digest([TOOL_SCHEMAS, EXTRA_SCHEMAS]),
        "model": descriptor, "budget": budget.to_dict()}
    if investigation_backend is not None:
        backend_descriptor = deepcopy(investigation_backend.descriptor())
        from .dsh_config import BACKEND_NAME
        if (not isinstance(backend_descriptor, dict) or backend_descriptor.get("name") != BACKEND_NAME
                or backend_descriptor.get("budget") != budget.to_dict()):
            raise ValueError("DSH backend descriptor does not match the Context budget")
        configuration["agent_backend"] = backend_descriptor
    return configuration


def requirement_configuration(configuration, requirement):
    descriptor = {k: v for k, v in requirement.items() if k not in {"status", "evidence_ids", "resolution_attempt_failed"}}
    return {**configuration, "requirement_digest": digest(descriptor)}


def save_requirement(store, ft_id, run, configuration, *, publish_latest=True):
    directory = _owned(context_directory(store, ft_id) / "agent_runs" / run.result["requirement_id"], store.root)
    directory.mkdir(parents=True, exist_ok=True)
    attempts = [int(p.name.split("_")[-1]) for p in directory.glob("attempt_*") if p.name.split("_")[-1].isdigit()]
    history = _owned(directory / f"attempt_{max(attempts, default=0) + 1:04d}", store.root)
    save_run_documents(history, run, configuration)
    if publish_latest:
        save_run_documents(directory, run, configuration)
    return history


def save_revision_transaction(store, ft_id, runs, configurations, outcome, *, round_number):
    """Archive real attempts and publish accepted group projections atomically.

    A shared final marker authorizes every updated requirement. Readers reject
    pending groups, incomplete projections or a modified native attempt. Later
    committed transactions may supersede individual immutable members. Rejected groups
    keep the previous active projections and record their paid attempts only.
    """
    from ..semantic_discovery.agent import ValidationRun
    transaction_id = outcome.audit["transaction_id"]
    directory = context_directory(store, ft_id)
    destination = _owned(directory / "revision_transactions" / transaction_id, store.root)
    destination.mkdir(parents=True, exist_ok=False)
    marker_path = _owned(destination / "metadata.json", store.root)
    decision = deepcopy(outcome.audit)
    decision_digest = digest(decision)
    write_json(marker_path, {"schema_version": 1, "status": "pending", "decision_digest": decision_digest},
        sort_keys=True, allow_nan=False)
    attempts, archived = {}, {}
    for rid, run in sorted(runs.items()):
        raw = deepcopy(run)
        native = run.metadata.get("native_submission", {})
        if native.get("resolution") is not None:
            raw.result = deepcopy(native["resolution"])
        raw.metadata["result_origin"] = "native_submission" if native.get("resolution") is not None else "agent_fallback"
        raw.metadata["candidate_transaction_id"] = transaction_id
        history = save_requirement(store, ft_id, raw, configurations[rid], publish_latest=False)
        attempts[rid] = {"path": str(history.relative_to(directory)),
            "metadata_digest": digest(_load_json(history / "metadata.json")), "result_digest": digest(raw.result)}
        archived[rid] = raw

    # A batch can retire a claim in a different slot using globally issued
    # helper/creator evidence. Bind those proof witnesses to their authentic
    # immutable attempts without editing native traces or inventing tool calls.
    from .transaction_support import save_source_support
    witnesses = deepcopy(getattr(outcome, "source_witnesses", {}))
    if decision.get("source_witness_digest") != digest(witnesses):
        raise ValueError("transaction_source_witness_digest_changed")
    source_support, publication_rejection = None, None
    try:
        source_support = save_source_support(store, ft_id, destination, witnesses, attempts)
    except ValueError as error:
        if not str(error).startswith("source_support_origin_not_found:"):
            raise
        publication_rejection = {"code": "candidate_source_witness_not_archived",
            "detail": str(error), "evidence_ids": sorted(witnesses),
            "rule": "Re-expose the exact authorized proof evidence through a real native investigation; no new scope or budget is granted."}
    members = {}
    if decision["status"] == "committed" and not publication_rejection:
        changed = {rid for rid, run in runs.items() if rid in outcome.resolutions}
        changed.update(repair["requirement_id"] for repair in outcome.audits)
        staged = []
        for rid in sorted(changed):
            latest = _owned(directory / "agent_runs" / rid, store.root)
            result = outcome.resolutions[rid]
            if rid in archived:
                run = deepcopy(archived[rid])
                configuration = configurations[rid]
            else:
                documents = {name: _load_json(_owned(latest / (name + ".json"), store.root))
                    for name in ("result", "trace", "evidence", "metadata")}
                configuration = documents["metadata"]["configuration"]
                if any(digest(documents[name]) != documents["metadata"]["document_digests"][name]
                        for name in ("result", "trace", "evidence")):
                    raise ValueError("transaction baseline commit is invalid")
                run = ValidationRun(documents["result"], documents["trace"], documents["evidence"], documents["metadata"])
            run.result = deepcopy(result)
            issued = {record["evidence_id"] for record in run.evidence["records"]}
            referenced = {eid for fact in result["facts"] for eid in fact["evidence_ids"]}
            referenced.update(eid for dependency in result["discovered_api_dependencies"]
                for eid in dependency["evidence_ids"])
            if not referenced.issubset(issued):
                publication_rejection = {"code": "committed_projection_missing_issued_evidence",
                    "requirement_id": rid, "evidence_ids": sorted(referenced - issued)}
                break
            run.metadata["result_origin"] = "framework_committed_candidate"
            run.metadata["context_revision_transaction"] = {"transaction_id": transaction_id,
                "decision_digest": decision_digest, "result_digest": digest(result)}
            run.metadata.setdefault("framework_reconciliations", []).append({"round": round_number,
                "transaction_id": transaction_id, "audit": deepcopy(outcome.audit),
                "model_calls_delta": 0, "tool_calls_delta": 0})
            projection = _owned(destination / "projections" / rid, store.root)
            staged.append((rid, latest, projection, run, configuration))
        # Check every projection before touching any active latest. A missing
        # evidence carrier is a rejected candidate, not a partially published
        # group or an exception that bypasses the feedback scheduler.
        for rid, latest, projection, run, configuration in ([] if publication_rejection else staged):
            save_run_documents(projection, run, configuration)
            save_run_documents(latest, run, configuration)
            members[rid] = {"metadata_digest": digest(_load_json(latest / "metadata.json")),
                "result_digest": digest(run.result), "configuration_fingerprint": digest(configuration),
                "projection_path": str(projection.relative_to(directory))}
    marker = {"schema_version": 1, "status": "rejected" if publication_rejection else decision["status"],
        "transaction_id": transaction_id,
        "decision": decision, "decision_digest": decision_digest, "native_attempts": attempts,
        "member_projections": members, "source_support": source_support}
    if publication_rejection:
        marker["publication_rejection"] = publication_rejection
    write_json(marker_path, marker, sort_keys=True, allow_nan=False)
    return marker


def _valid_revision_transaction(store, ft_id, loaded, index):
    reference = loaded["metadata"].get("context_revision_transaction")
    if not reference:
        return True
    directory = context_directory(store, ft_id)
    transaction_id = reference.get("transaction_id", "")
    if (not transaction_id.startswith("context_revision_") or len(transaction_id) != len("context_revision_") + 24
            or any(c not in "0123456789abcdef" for c in transaction_id[-24:])):
        return False
    marker = _load_json(_owned(directory / "revision_transactions" / transaction_id / "metadata.json", store.root))
    if (marker.get("status") != "committed" or marker.get("transaction_id") != transaction_id
            or marker.get("decision_digest") != digest(marker.get("decision"))
            or marker["decision_digest"] != reference.get("decision_digest")
            or transaction_id != "context_revision_" + digest({key: value for key, value in
                marker["decision"].items() if key != "transaction_id"})[:24]
            or reference.get("result_digest") != digest(loaded["result"])
            or marker.get("source_support", {}).get("witness_digest") != marker["decision"].get("source_witness_digest")):
        return False
    from .transaction_support import validate_source_support
    if not validate_source_support(store, ft_id, directory / "revision_transactions" / transaction_id,
            marker.get("source_support"), index):
        return False
    for rid, member in marker["member_projections"].items():
        latest = _owned(directory / member["projection_path"], store.root)
        if latest != directory / "revision_transactions" / transaction_id / "projections" / rid:
            return False
        metadata = _load_json(_owned(latest / "metadata.json", store.root))
        result = _load_json(_owned(latest / "result.json", store.root))
        if (digest(metadata) != member["metadata_digest"] or digest(result) != member["result_digest"]
                or metadata.get("configuration_fingerprint") != member["configuration_fingerprint"]
                or metadata.get("context_revision_transaction", {}).get("transaction_id") != transaction_id):
            return False
        for name in ("result", "trace", "evidence"):
            if digest(_load_json(_owned(latest / (name + ".json"), store.root))) != metadata["document_digests"][name]:
                return False
    if loaded["result"].get("requirement_id") not in marker["member_projections"]:
        return False
    active_member = marker["member_projections"][loaded["result"]["requirement_id"]]
    if digest(loaded["metadata"]) != active_member["metadata_digest"]:
        return False
    for rid, attempt in marker["native_attempts"].items():
        history = _owned(directory / attempt["path"], store.root)
        if history.parent != directory / "agent_runs" / rid or not history.name.startswith("attempt_"):
            return False
        metadata = _load_json(_owned(history / "metadata.json", store.root))
        if digest(metadata) != attempt["metadata_digest"]:
            return False
        for name in ("result", "trace", "evidence"):
            document = _load_json(_owned(history / (name + ".json"), store.root))
            if digest(document) != metadata["document_digests"][name]:
                return False
        if digest(_load_json(history / "result.json")) != attempt["result_digest"]:
            return False
    return True


def save_reconciled_requirement(store, ft_id, row, configuration, result, audit, *, round_number,
                               source_evidence=None):
    """Commit a derived latest result without inventing another agent attempt.

    Archived native attempts stay unchanged. The latest marker keeps the same
    trace, issued evidence and call ownership, with an explicit framework audit.
    """
    from ..semantic_discovery.agent import ValidationRun
    directory = _owned(context_directory(store, ft_id) / 'agent_runs' / row['requirement_id'], store.root)
    documents = {name: _load_json(_owned(directory / (name + '.json'), store.root))
        for name in ('result', 'trace', 'evidence', 'metadata')}
    metadata = documents['metadata']
    if metadata['configuration'] != configuration or metadata['configuration_fingerprint'] != digest(configuration):
        raise ValueError('reconciliation configuration changed')
    if any(digest(documents[name]) != metadata['document_digests'][name]
            for name in ('result', 'trace', 'evidence')):
        raise ValueError('reconciliation input commit is invalid')
    if metadata.get('context_revision_transaction') or source_evidence is not None:
        from types import SimpleNamespace
        from .repair_transactions import proof_witness_records
        witnesses = proof_witness_records([audit], source_evidence or {})
        decision = {'status': 'committed', 'origin': 'framework_source_reconciliation',
            'round': round_number, 'requirement_id': row['requirement_id'],
            'previous_transaction_id': metadata.get('context_revision_transaction', {}).get('transaction_id'),
            'before_result_digest': digest(documents['result']), 'after_result_digest': digest(result),
            'source_audit': deepcopy(audit), 'source_witness_digest': digest(witnesses),
            'model_calls_delta': 0, 'tool_calls_delta': 0}
        decision['transaction_id'] = 'context_revision_' + digest(decision)[:24]
        outcome = SimpleNamespace(audit=decision, resolutions={row['requirement_id']: deepcopy(result)},
            audits=[{'requirement_id': row['requirement_id'], **deepcopy(audit)}], source_witnesses=witnesses)
        marker = save_revision_transaction(store, ft_id, {}, {}, outcome, round_number=round_number)
        return marker["status"] == "committed"
    metadata = deepcopy(metadata)
    metadata.setdefault('framework_reconciliations', []).append({'round': round_number,
        'before_result_digest': digest(documents['result']), 'after_result_digest': digest(result),
        'audit': deepcopy(audit), 'model_calls_delta': 0, 'tool_calls_delta': 0})
    metadata['result_origin'] = 'framework_reconciled_projection'
    run = ValidationRun(deepcopy(result), documents['trace'], documents['evidence'], metadata)
    save_run_documents(directory, run, configuration)
    return True


def load_requirement(store, ft_id, requirement, configuration, index, *, preserve_soft_unknown=False):
    directory = _owned(context_directory(store, ft_id) / "agent_runs" / requirement["requirement_id"], store.root)
    for name in ("metadata", "result", "trace", "evidence"):
        _owned(directory / f"{name}.json", store.root)
    loaded = load_run_documents(directory, configuration, index)
    statuses = {"resolved", "not_applicable"} | ({"unresolved"} if preserve_soft_unknown and not requirement["mandatory"] else set())
    try:
        if loaded and not _valid_revision_transaction(store, ft_id, loaded, index):
            return None
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if (loaded and not loaded["metadata"].get("resolution_attempt_failed")
            and not loaded["metadata"].get("submission_revoked")
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
        "resolutions": {"schema_version": 1, "resolutions": resolutions},
        "semantic_obligation_graph": run.completeness["semantic_obligation_graph"]}
    documents["subject_repair_history"] = {"schema_version": 1,
        "withdrawals": deepcopy(run.metadata.get("subject_repair_history", []))}
    documents['closure_feedback'] = deepcopy(run.metadata.get('closure_feedback', {}))
    documents['context_revision_history'] = {'schema_version': 1,
        'revisions': deepcopy(run.metadata.get('context_revision_history', []))}
    documents['context_revision_transactions'] = {'schema_version': 1,
        'transactions': deepcopy(run.metadata.get('context_revision_transactions', []))}
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
    from .callback_resources import VERSION as CALLBACK_RESOURCE_VERSION
    from .closure_feedback import VERSION as CLOSURE_FEEDBACK_VERSION
    from .repair_transactions import VERSION as TRANSACTION_VERSION
    from .transaction_support import VERSION as SOURCE_SUPPORT_VERSION
    if (configuration.get('policy_version') != POLICY_VERSION
            or configuration.get('callback_resource_reference_version') != CALLBACK_RESOURCE_VERSION
            or configuration.get('closure_feedback_version') != CLOSURE_FEEDBACK_VERSION
            or configuration.get('context_revision_transaction_version') != TRANSACTION_VERSION
            or configuration.get('native_submission_version') != 'native-typed-submission-v1'
            or configuration.get('context_transaction_source_support_version') != SOURCE_SUPPORT_VERSION):
        return None
    directory = context_directory(store, ft_id)
    try:
        metadata = _load_json(_owned(directory / "metadata.json", store.root))
        if metadata["configuration"] != configuration or metadata["configuration_fingerprint"] != digest(configuration):
            return None
        names = ("requirements", "facts", "api_closure", "harness_context", "completeness", "evidence", "resolutions")
        if configuration.get("semantic_obligation_graph_version"):
            names += ("semantic_obligation_graph",)
        if configuration.get('closure_feedback_version'):
            names += ('closure_feedback', 'context_revision_history')
        if configuration.get('context_revision_transaction_version'):
            names += ('context_revision_transactions',)
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
        if "semantic_obligation_graph" in documents and documents["semantic_obligation_graph"] != documents["completeness"].get("semantic_obligation_graph"):
            return None
        if configuration.get("argument_graph_version") and documents["argument_graph"] != documents["harness_context"].get("argument_graph"):
            return None
        if configuration.get("reconciler_version") and documents["canonical_construction"] != documents["harness_context"].get("canonical_construction"):
            return None
        if any(documents[name] != documents["harness_context"].get(name) for name in
                ("resource_contract", "invocation_contract", "parameter_semantic_contract", "external_input_flow") if name in documents):
            return None
        # A valid old Context and valid newer latest rows are each authentic,
        # but are not necessarily the same published snapshot. Never reuse a
        # complete Context whose active resolution has since changed.
        active_results = documents["resolutions"]["resolutions"]
        reqs = {req["requirement_id"]: req for req in documents["requirements"]["requirements"]}
        if set(active_results) - set(reqs):
            return None
        for rid, result in active_results.items():
            # Unresolved slots may retain facts contributing to a complete
            # source projection. Snapshot integrity covers those slots too,
            # independently of ordinary per-requirement resume eligibility.
            latest = load_run_documents(_owned(directory / "agent_runs" / rid, store.root),
                requirement_configuration(configuration, reqs[rid]), index)
            if not latest or not _valid_revision_transaction(store, ft_id, latest, index) or latest["result"] != result:
                return None
        return {**documents, "metadata": metadata}
    except (OSError, ValueError, KeyError, TypeError):
        return None
