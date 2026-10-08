"""Bounded closure/follow-up orchestration; never rerun resolved unrelated work."""
from copy import deepcopy

from ..semantic_discovery.models import canonical, digest
from ..semantic_discovery.tools import ToolBudgetExceeded
from .agent import HarnessContextAgent
from .api_closure import build_api_closure
from .completeness import HarnessContextCompletenessValidator, missing_requirement_tasks
from .evidence import build_context, validate_resolution_record
from .obligations import SemanticObligationGraphBuilder, VERSION as OBLIGATION_VERSION
from .models import ContextRun, POLICY_VERSION
from .requirements import HarnessRequirementBuilder, attach_basis, requirement
from .repairs import merge_resolution
from .repair_proofs import RepairProofEvaluator
from .closure_feedback import (build_closure_feedback, attach_closure_feedback, attach_rejected_candidates,
    VERSION as FEEDBACK_VERSION)
from .repair_transactions import (evaluate_revision, semantic_signature, MAX_REJECTED_REVISION_CORRECTIONS,
    VERSION as TRANSACTION_VERSION)
from .persistence import (save_requirement, save_reconciled_requirement, load_requirement,
    save_revision_transaction, requirement_configuration, save_context, context_directory)
from .scheduling import (optional_allocation, revisable_requirements, repair_routes,
    VERSION as SCHEDULING_VERSION)


def _attempt_failure_status(run):
    """Use explicit final failure, never a recovered error in the trace."""
    if run.metadata.get('submission_revoked'):
        return 'protocol_error'
    if run.metadata.get('resolution_attempt_failed'):
        return run.metadata['resolution_attempt_failed']
    status = run.metadata.get('execution_status')
    return status if status in {'provider_error', 'protocol_error', 'execution_failure'} else None


def _failed_attempt_result(run, requirement):
    """Preserve history separately while withholding a failed new proposal."""
    reason = (run.metadata.get('submission_revocation_reason') or
        _attempt_failure_status(run) or 'execution_failure')
    return {'requirement_id': requirement['requirement_id'], 'status': 'unresolved', 'facts': [],
        'discovered_api_dependencies': [], 'open_questions': [reason]}


def expand_requirements(ft, snapshot, rows, closure):
    builder = HarnessRequirementBuilder()
    known = {row["requirement_id"] for row in rows}
    existing = {row["requirement_id"]: row for row in rows}
    additions = []
    for support in closure["required_support_apis"]:
        additions.extend(builder.function_requirements(ft, snapshot, support["function_id"], depth=support["depth"],
                         required_by=support["required_by"], core=False))
        for parent in support["required_by"]:
            additions.append(requirement(ft["ft_id"], parent, "call_order", depth=max(0, support["depth"] - 1)))
    for row in attach_basis(additions, ft):
        if row["requirement_id"] not in known:
            rows.append(row)
            known.add(row["requirement_id"])
            existing[row["requirement_id"]] = row
        else:
            current = existing[row["requirement_id"]]
            parents = sorted(set(current["required_by"]) | set(row["required_by"]))
            if parents != current["required_by"] or row["dependency_depth"] < current["dependency_depth"]:
                current["required_by"] = parents
                current["dependency_depth"] = min(current["dependency_depth"], row["dependency_depth"])
                current["status"] = "open"


def investigation_priority(row, snapshot, report):
    """Rank exploration hints; this function proves or rejects no obligation.

    Hard dependencies come first. Among optional candidates, prefer a typed
    creation/release hint over an unrelated consumer. A callback bound to a
    project deallocator is a source reference hint too, not a release proof.
    Internal definitions remain readable evidence, not callable support APIs.
    """
    from .api_closure import callable_status
    from .requirements import context_parameters
    from .value_flow import body_tree
    from ..semantic_discovery.tools import _walk, _text
    from ..semantic_slicing.support_effects import bindings
    function = snapshot.functions[row["subject_function_id"]]
    hard = report["semantic_obligation_graph"]["frontier"]
    nodes = {n["obligation_id"]: n for n in report["semantic_obligation_graph"]["nodes"]}
    relevant = {nodes[n]["requirement_id"] for n in hard if n in nodes}
    if row["mandatory"] or row["requirement_id"] in relevant:
        return 0
    if callable_status(function) != "external_definition":
        return 3
    def release_hint(api, depth=0, seen=frozenset()):
        if depth > 2 or api["id"] in seen:
            return False
        source, body = body_tree(api)
        if body is None or body.has_error:
            return False
        names = {_text(n, source) for n in _walk(body) if n.type == "identifier"}
        if "free" in names and not any(f["name"] == "free" for f in snapshot.functions.values()):
            return True
        return any(release_hint(f, depth + 1, seen | {api["id"]})
            for f in snapshot.functions.values() if f["name"] in names and f.get("defined"))
    for parent in row["required_by"]:
        parent_function = snapshot.functions[parent]
        effects = bindings(parent_function, function, snapshot.functions, set(snapshot.functions))
        if effects.keys() & {"creation", "initialization", "cleanup"}:
            return 1
        subjects = [(p["base_type"], p.get("pointer_depth", 0)) for p in context_parameters(parent_function)]
        if parent_function.get("return_pointer_depth"):
            subjects.append((parent_function["return_base_type"], parent_function["return_pointer_depth"]))
        if any((p["base_type"], p.get("pointer_depth", 0)) in subjects for p in function["parameters"]) and release_hint(function):
            return 1
    return 2


class HarnessContextMiningLoop:
    def __init__(self, model, state, *, group_requirements=False, investigation_backend=None):
        self.model, self.state = model, state
        self.group_requirements = group_requirements
        self.investigation_backend = investigation_backend

    def run(self, ft, snapshot, tools, *, store=None, configuration=None, resume=False, on_requirement=None,
            on_checkpoint=None):
        # Artifacts must be keyed by the selected runtime, including its global
        # budget. Direct callers may not resume or publish under another backend.
        configured_backend = (configuration or {}).get('agent_backend')
        if self.investigation_backend is not None:
            descriptor = self.investigation_backend.descriptor()
            if store is not None and configured_backend != descriptor:
                raise ValueError('Context artifact configuration does not match its investigation backend')
            if descriptor.get('budget') is not None and descriptor['budget'] != self.state.budget.to_dict():
                raise ValueError('Context investigation backend budget does not match MiningState')
        elif configured_backend is not None:
            raise ValueError('Context artifact configuration selects a backend that was not supplied')
        def checkpoint(phase, **details):
            if on_checkpoint:
                on_checkpoint(phase, model_calls=self.state.model_calls,
                    tool_calls=self.state.tool_calls, source_chars=self.state.source_chars, **details)
        frozen_digest = digest(ft)
        execution_index = 1
        if store:
            from ..minimal_ft.persistence import _load_json, _owned
            try:
                previous = _load_json(_owned(context_directory(store, ft["ft_id"]) / "metadata.json", store.root))
                execution_index += previous.get("execution_index", 0)
            except (OSError, ValueError, TypeError):
                pass
        requirements = HarnessRequirementBuilder().build(ft, snapshot)
        rows, resolutions, facts = requirements["requirements"], {}, []
        agent = HarnessContextAgent(self.model, self.state, investigation_backend=self.investigation_backend)
        followups, followup_history, resumed, diagnostics = [], [], 0, {}
        execution_failures = {}
        termination, report = "completeness_budget_exhausted", None
        attempt_inputs, unchanged_skips, proved_skips, schedule_history = {}, [], [], []
        priority_hints = {}
        late_prerequisites = []
        proof_repairs = RepairProofEvaluator(ft, snapshot, self.state)
        repair_history, recoverable_rounds = [], []
        feedback_registries, revision_counts, revision_history = {}, {}, []
        correction_counts, rejection_feedback, transaction_history, seen_rejections = {}, [], [], set()
        allocation_history, optional_deferrals, revision_advances = [], [], []

        def closure_feedback(current_report, current_context):
            # Remember only choices already issued by real investigations.
            # Adding function IDs here disambiguates this diagnostic projection;
            # it neither issues new choices nor changes the terminal registry.
            signed = {key: [dict(choice, function_id=fid) if key == 'input_length_choices' else deepcopy(choice)
                for fid, registry in sorted(feedback_registries.items()) for choice in registry.get(key, [])]
                for key in ('input_length_choices', 'ownership_subjects', 'support_candidates', 'source_callback_bindings')}
            feedback = build_closure_feedback(current_report, rows, facts, signed=signed,
                evidence=self.state.evidence, canonical_construction=current_context.get('canonical_construction'),
                resource_identity=current_context.get('resource_identity'))
            return attach_rejected_candidates(feedback, rejection_feedback)

        def feedback_tasks(tasks, feedback, requirement_ids):
            result = deepcopy(tasks)
            present = {task['requirement_id'] for task in result}
            for row in rows:
                rid = row['requirement_id']
                items = [item for item in feedback['items'] if rid in item['repair_requirement_ids']]
                if rid not in requirement_ids or rid in present or not items:
                    continue
                task = {'requirement_id': rid, 'subject_function_id': row['subject_function_id'],
                    'kind': row['kind'], 'code': 'context_contract_revision',
                    'question': 'Revise the explicitly named contract fields; preserve independent facts.',
                    'obligation_ids': sorted({oid for item in items for oid in item['frontier_obligation_ids']}),
                    'missing_proofs': [], 'graph_holes': [], 'evidence_ids': [],
                    'blocked_roots': sorted({oid for item in items for oid in item['affected_roots']})}
                task['task_id'] = 'task_' + digest(task)[:24]
                result.append(task)
            return attach_closure_feedback(result, feedback)

        def ledger():
            return {'model_calls': self.state.model_calls, 'tool_calls': self.state.tool_calls,
                'source_chars': self.state.source_chars, 'tokens': deepcopy(self.state.tokens)}
        def failure_retry_allowed(rid):
            # A rejected semantic terminal can become answerable after another
            # subject issues the missing API/source. Provider/protocol retries
            # with identical inputs do not gain extra completeness passes.
            failure = execution_failures.get(rid)
            return (failure and failure['execution_status'] == 'protocol_error'
                and attempt_inputs.get(rid) != digest([sorted(self.state.evidence),
                    sorted(f['fact_id'] for f in facts)]))
        def record_repairs(audit, number):
            for withdrawal in audit.get("withdrawals", []):
                repair_history.append({"round": number, **deepcopy(withdrawal)})
        for number in range(1, self.state.budget.max_completeness_rounds + 1):
            targeted = {task["requirement_id"] for task in followups if task["requirement_id"]}
            processed = set()
            rejected_publications = set()
            while True:
                tools.investigation_model_limit = tools.investigation_tool_limit = None
                # Recompute before the first investigation as well as followups.
                # Closed framework/source projections consume no model calls.
                checkpoint('project_closure', round=number)
                projected_closure = build_api_closure(ft, rows, resolutions, snapshot, self.state)
                checkpoint('project_context', round=number)
                projected = build_context(ft, rows, facts, snapshot, self.state.evidence)
                projected["dependencies"] = deepcopy(projected_closure["unresolved_api_dependencies"])
                checkpoint('project_obligations', round=number)
                projected_report = HarnessContextCompletenessValidator().validate(projected, projected_closure,
                    ft, snapshot, rows, resolutions, self.state)
                proof_repairs.remember(projected, projected_report["semantic_obligation_graph"])
                if projected_report["status"] == "complete":
                    break  # Optional exploration cannot improve a closed Gate.
                frontier_tasks = missing_requirement_tasks(projected_report)
                feedback = closure_feedback(projected_report, projected)
                # One deliberate correction of an already submitted contract
                # may reuse unchanged evidence. In particular, a locally closed
                # input/length slot can block a different recipe root. Never
                # give provider failures a semantic retry or add a fourth pass.
                ready_revisions = revisable_requirements(feedback, attempt_inputs,
                    execution_failures, revision_counts)
                revisions = ready_revisions if number > 1 else set()
                correction_ids = {rid for rejection in rejection_feedback
                    if number > rejection['round'] and rejection['correction_allowed']
                    for rid in rejection['submitted_requirement_ids']
                    if rid in attempt_inputs and rid not in execution_failures
                    and correction_counts.get(rid, 0) < MAX_REJECTED_REVISION_CORRECTIONS}
                revisions.update(correction_ids)
                targeted.update(revisions)
                processed.difference_update(revisions)
                frontier_tasks = feedback_tasks(frontier_tasks, feedback, revisions)
                # A new support/cleanup proof can activate an as-yet unasked
                # mandatory prerequisite late in this pass. Queue only subjects
                # with no resolution or attempt; never purchase another retry of
                # a previously investigated subject or reset any global budget.
                activated = {task['requirement_id'] for task in frontier_tasks
                    if task.get('requirement_id') and task['requirement_id'] not in resolutions
                    and task['requirement_id'] not in attempt_inputs
                    and (number > 1 or task['requirement_id'] in processed)}
                newly_queued = activated - targeted
                for rid in sorted(newly_queued):
                    late_prerequisites.append({'round': number, 'requirement_id': rid,
                        'graph_digest': projected_report['semantic_obligation_graph_digest'],
                        'reason': 'uninvestigated_mandatory_frontier', 'within_existing_budget': True})
                targeted.update(activated)
                processed.difference_update(activated)
                pending = [row for row in rows if row["requirement_id"] not in processed and (
                    row["status"] in {"open", "unresolved"} or row["requirement_id"] in targeted)]
                if number > 1:
                    pending = [row for row in pending if row["requirement_id"] in targeted
                               and (row["requirement_id"] not in execution_failures
                                    or failure_retry_allowed(row["requirement_id"]))]
                if not pending:
                    break
                closed = set(projected_report["resolved_requirements"])
                for row in pending:
                    if row["requirement_id"] in closed and row["requirement_id"] not in revisions:
                        processed.add(row["requirement_id"])
                        proved_skips.append({"round": number, "requirement_id": row["requirement_id"],
                            "graph_digest": projected_report["semantic_obligation_graph_digest"]})
                pending = [row for row in pending if row["requirement_id"] not in closed or row['requirement_id'] in revisions]
                if not pending:
                    break
                fanout = {t["requirement_id"]: len(t["blocked_roots"]) for t in frontier_tasks}
                if number > 1:
                    input_digest = digest([sorted(self.state.evidence), sorted(f["fact_id"] for f in facts)])
                    unchanged = [row for row in pending if row['requirement_id'] not in revisions
                        and attempt_inputs.get(row["requirement_id"]) == input_digest]
                    for row in unchanged:
                        processed.add(row["requirement_id"])
                        unchanged_skips.append({"round": number, "requirement_id": row["requirement_id"],
                            "reason": "unchanged_evidence_and_facts", "input_digest": input_digest})
                    pending = [row for row in pending if row not in unchanged]
                    if not pending:
                        break
                def priority(row):
                    function = snapshot.functions[row["subject_function_id"]]
                    possible_input = any(p.get("is_pointer") and not (p.get("is_struct_like") or p.get("is_opaque_handle"))
                        for p in function["parameters"])
                    key = (row["subject_function_id"], tuple(row["required_by"]))
                    if row["mandatory"] or fanout.get(row["requirement_id"], 0):
                        rank = 0
                    else:
                        if key not in priority_hints:
                            priority_hints[key] = investigation_priority(row, snapshot, projected_report)
                        rank = priority_hints[key]
                    return (-1 if row['requirement_id'] in revisions else rank, -fanout.get(row["requirement_id"], 0), 0 if row["kind"] == "input_binding" and possible_input else
                        1 if row["kind"] == "input_binding" else 2 if row["mandatory"] else 3,
                        row["subject_function_id"], row["kind"])
                pending.sort(key=priority)
                first = pending[0]
                first_required = (first['mandatory'] or fanout.get(first['requirement_id'], 0)
                    or first['requirement_id'] in revisions)
                if (not first_required and ready_revisions
                        and number < self.state.budget.max_completeness_rounds):
                    # Do not spend the rest of a pass enumerating optional APIs
                    # while an already submitted mandatory contract has a
                    # precise correction agenda. The next existing pass owns
                    # revision; this does not create a new pass or retry.
                    revision_advances.append({'round': number,
                        'revision_requirement_ids': sorted(ready_revisions),
                        'graph_digest': projected_report['semantic_obligation_graph_digest'],
                        'budget': ledger(), 'reason': 'frontier_revision_before_optional_exploration'})
                    break
                linked = next((group for group in feedback.get('transaction_groups', [])
                    if first['requirement_id'] in revisions and first['requirement_id'] in group['requirement_ids']), None)
                # Linked correction is atomic in both ordinary requirement
                # modes. A single-mode run must not publish one half before
                # the companion native proposal is available for validation.
                grouped_batch = self.group_requirements or linked is not None
                if linked:
                    batch = [row for row in pending if row['requirement_id'] in linked['requirement_ids']]
                elif self.group_requirements:
                    batch = [row for row in pending if row['subject_function_id'] == first['subject_function_id']][:8]
                else:
                    batch = [first]
                # Grouped mode must not pull unrelated optional slots into an
                # otherwise mandatory/revision batch and spend protected calls.
                if not linked and first_required:
                    batch = [row for row in batch if row['mandatory']
                        or fanout.get(row['requirement_id'], 0) or row['requirement_id'] in revisions]
                optional_batch = not any(row['mandatory'] or fanout.get(row['requirement_id'], 0)
                    or row['requirement_id'] in revisions for row in batch)
                allocation = optional_allocation(self.state) if optional_batch else None
                if allocation and (not allocation['remaining_optional_model_calls']
                                   or not allocation['remaining_optional_tool_calls']):
                    processed.update(row['requirement_id'] for row in batch)
                    optional_deferrals.append({'round': number,
                        'requirement_ids': [row['requirement_id'] for row in batch],
                        'reason': 'preserve_existing_mandatory_and_revision_calls',
                        'allocation': allocation, 'budget': ledger()})
                    continue
                if len(batch) > 8:
                    # Do not silently split a declared atomic repair group.
                    processed.update(row['requirement_id'] for row in batch)
                    diagnostics[first['requirement_id']] = [{'code': 'linked_revision_group_exceeds_batch_limit',
                        'requirement_ids': [row['requirement_id'] for row in batch]}]
                    continue
                cached, configs = {}, {}
                for row in batch:
                    rid = row["requirement_id"]
                    processed.add(rid)
                    configs[rid] = requirement_configuration(configuration or {}, row)
                    prior = load_requirement(store, ft["ft_id"], row, configs[rid], tools.index, preserve_soft_unknown=True) if resume and store and rid not in targeted else None
                    if prior:
                        records = {record["evidence_id"]: record for record in prior["evidence"]["records"]}
                        discoveries = prior["metadata"].get("discoveries", {})
                        try:
                            from types import SimpleNamespace
                            cached_state = SimpleNamespace(evidence=records, discoveries=discoveries)
                            validate_resolution_record(prior["result"], row, snapshot, cached_state,
                                                       tools.initial_ids, tools.excluded)
                        except (ValueError, TypeError, KeyError):
                            prior = None
                    if prior:
                        self.state.evidence.update(records)
                        self.state.discoveries.update(deepcopy(discoveries))
                        if prior['metadata'].get('signed_proposal_registry'):
                            feedback_registries[row['subject_function_id']] = deepcopy(prior['metadata']['signed_proposal_registry'])
                        cached[rid] = prior["result"]
                        resumed += 1
                for row in batch:
                    rid = row['requirement_id']
                    if rid not in cached:
                        continue
                    resolutions[rid] = deepcopy(cached[rid])
                    row['status'] = cached[rid]['status']
                    row['evidence_ids'] = sorted({eid for f in cached[rid]['facts'] for eid in f['evidence_ids']})
                    facts = [f for f in facts if f['requirement_id'] != rid] + deepcopy(cached[rid]['facts'])
                    if cached[rid]['facts']:
                        # A compatible cached contract is an existing proposal,
                        # eligible for the same bounded, targeted revision as
                        # a native proposal produced in this run. Empty fallback
                        # slots gain no contract-revision permission.
                        attempt_inputs[rid] = digest([sorted(self.state.evidence),
                            sorted(f['fact_id'] for f in facts)])
                    if on_requirement:
                        on_requirement(row, cached[rid], True, self.state)
                investigated = [row for row in batch if row["requirement_id"] not in cached]
                revision_ids = sorted(row['requirement_id'] for row in investigated if row['requirement_id'] in revisions)
                revision_before = ledger()
                old_revision_fact_ids = sorted(f['fact_id'] for f in facts if f['requirement_id'] in revision_ids)
                submitted_revision_fact_ids = []
                for rid in revision_ids:
                    if rid in correction_ids:
                        correction_counts[rid] = correction_counts.get(rid, 0) + 1
                        revision_counts[rid] = max(1, revision_counts.get(rid, 0))
                    else:
                        revision_counts[rid] = revision_counts.get(rid, 0) + 1
                runs = {}
                if investigated:
                    if allocation:
                        tools.investigation_model_limit = allocation['model_limit']
                        tools.investigation_tool_limit = allocation['tool_limit']
                    allocation_history.append({'round': number,
                        'requirement_ids': [row['requirement_id'] for row in investigated],
                        'optional': optional_batch, 'allocation': allocation, 'budget_before': ledger()})
                    # One charged subject read per function. Agent bootstrap
                    # reuses that same existing cache, including in single mode.
                    checkpoint('bootstrap', subject_function_id=investigated[0]['subject_function_id'], round=number)
                    tools.activate(investigated[0], facts, requirement_ids=[r["requirement_id"] for r in investigated])
                    prelude_before = self.state.tool_calls
                    prelude_output, prelude_error = None, None
                    if self.state.tool_calls < self.state.budget.max_tool_calls:
                        try:
                            prelude_output = tools.bootstrap()
                        except (ValueError, OSError, ToolBudgetExceeded) as error:
                            prelude_error = (error.args[0] if isinstance(error, ToolBudgetExceeded)
                                else 'source_unavailable_or_invalid_query')
                    prelude_calls = self.state.tool_calls - prelude_before
                    prelude_events = ([{'kind': 'tool_call' if prelude_calls or prelude_output else 'prelude_stop',
                        'round': 0, 'tool_call_id': 'framework_batch_prelude', 'tool': 'get_function',
                        'arguments': {'function': investigated[0]['subject_function_id']},
                        'result_evidence_ids': (prelude_output or {}).get('evidence_ids', []),
                        'framework_prelude': True, 'tool_executed': bool(prelude_calls),
                        'evidence_reuse': (prelude_output or {}).get('bootstrap_reused', False),
                        'error': prelude_error}] if prelude_output is not None or prelude_error else [])
                    checkpoint('preview_context', round=number)
                    preview_closure = build_api_closure(ft, rows, resolutions, snapshot, self.state)
                    preview = build_context(ft, rows, facts, snapshot, self.state.evidence)
                    preview["dependencies"] = deepcopy(preview_closure["unresolved_api_dependencies"])
                    obligation_graph = SemanticObligationGraphBuilder().build(preview, preview_closure,
                        ft, snapshot, rows, resolutions, self.state)
                    preview_report = HarnessContextCompletenessValidator().validate_graph(obligation_graph, rows)
                    preview_feedback = closure_feedback(preview_report, preview)
                    tasks = [task for task in feedback_tasks(missing_requirement_tasks(preview_report),
                        preview_feedback, revision_ids)
                        if task["requirement_id"] in {r["requirement_id"] for r in investigated}]
                    schedule_history.append({"round": number, "requirement_ids": [r["requirement_id"] for r in investigated],
                        "graph_digest": obligation_graph["graph_digest"], "blocked_root_counts": fanout,
                        "missing_obligations": sorted({o for t in tasks for o in t["obligation_ids"]}),
                        'revision_requirement_ids': revision_ids,
                        'closure_feedback_digest': preview_feedback['frontier_digest']})
                    checkpoint('agent_investigation', subject_function_id=investigated[0]['subject_function_id'], round=number)
                    try:
                        investigated_runs = (agent.investigate_group(investigated, tools, facts, tasks, obligation_graph=obligation_graph)
                            if grouped_batch else [agent.investigate(investigated[0], tools, facts, tasks, obligation_graph=obligation_graph)])
                    finally:
                        tools.investigation_model_limit = tools.investigation_tool_limit = None
                    # The first cost owner also owns the framework subject read
                    # performed before the agent preview, including failed reads.
                    for owner_number, run in enumerate(investigated_runs):
                        run.trace['events'] = deepcopy(prelude_events) + run.trace.get('events', [])
                        run.metadata['framework_prelude_tool_calls'] = prelude_calls if owner_number == 0 else 0
                        if owner_number == 0:
                            run.metadata['tool_calls'] = run.metadata.get('tool_calls', 0) + prelude_calls
                        if grouped_batch:
                            run.metadata['group_tool_calls'] = run.metadata.get('group_tool_calls', 0) + prelude_calls
                    allocation_history[-1]['budget_after'] = ledger()
                    runs = {run.result["requirement_id"]: run for run in investigated_runs}
                    for run in investigated_runs:
                        if run.metadata.get('signed_proposal_registry'):
                            feedback_registries[investigated[0]['subject_function_id']] = deepcopy(run.metadata['signed_proposal_registry'])
                    input_digest = digest([sorted(self.state.evidence), sorted(f["fact_id"] for f in facts)])
                    for row in investigated:
                        attempt_inputs[row["requirement_id"]] = input_digest
                incoming = {}
                for row in investigated:
                    rid, run = row['requirement_id'], runs[row['requirement_id']]
                    diagnostics[rid] = [error for error in run.trace.get('validation_errors', [])
                        if error.get('requirement_id', rid) == rid]
                    native = run.metadata.get('native_submission', {})
                    failure_status = _attempt_failure_status(run)
                    if (not failure_status and native.get('resolution') is not None
                            and native.get('resolution_digest') == digest(native['resolution'])):
                        incoming[rid] = deepcopy(native['resolution'])
                    run.metadata['execution_index'] = execution_index
                    if failure_status:
                        run.metadata['resolution_attempt_failed'] = failure_status
                        row['resolution_attempt_failed'] = failure_status
                        execution_failures[rid] = {'requirement_id': rid,
                            'execution_status': failure_status,
                            'errors': deepcopy(run.metadata.get('execution_errors', []))}
                    else:
                        row.pop('resolution_attempt_failed', None)
                        execution_failures.pop(rid, None)
                transactional = bool(runs and any(rid in resolutions for rid in runs))
                transaction_status = None
                if transactional:
                    checkpoint('validate_candidate_group', round=number)
                    candidate = evaluate_revision(ft, snapshot, self.state, rows, resolutions, incoming,
                        feedback=preview_feedback, protected=proof_repairs.protected,
                        execution_failures={rid: execution_failures[rid] for rid in runs if rid in execution_failures})
                    transaction_status = candidate.audit['status']
                    candidate.audit.update(round=number, budget_before=revision_before, budget_after=ledger(),
                        revision_requirement_ids=revision_ids,
                        rejection_correction_requirement_ids=sorted(set(revision_ids) & correction_ids),
                        execution_index=execution_index, attempted_requirement_ids=sorted(runs))
                    # Even zero-call budget fallbacks have distinct scheduled
                    # batches. Bind the durable ID to the final whole audit.
                    candidate.audit['transaction_id'] = 'context_revision_' + digest(
                        {key: value for key, value in candidate.audit.items() if key != 'transaction_id'})[:24]
                    if store:
                        publication = save_revision_transaction(store, ft['ft_id'], runs, configs, candidate, round_number=number)
                        if publication.get('publication_rejection'):
                            transaction_status = 'rejected'
                            candidate.audit.update(status='rejected', candidate_validation_status='committed',
                                active_graph_digest=candidate.audit['before_graph_digest'])
                            candidate.audit['rejection_diagnostics'].append(deepcopy(publication['publication_rejection']))
                    transaction_history.append(deepcopy(candidate.audit))
                    if transaction_status == 'committed':
                        rows, resolutions, facts = candidate.requirements, candidate.resolutions, candidate.facts
                        for repair in candidate.audits:
                            record_repairs(repair, number)
                    elif transaction_status == 'rejected':
                        signature = digest([semantic_signature(incoming), candidate.audit['rejection_diagnostics']])
                        eligible = bool(incoming) and signature not in seen_rejections
                        seen_rejections.add(signature)
                        rejection_feedback.append({'transaction_id': candidate.audit['transaction_id'],
                            'round': number, 'submitted_requirement_ids': sorted(runs),
                            'native_submissions': deepcopy(incoming), 'submission_semantic_digest': semantic_signature(incoming),
                            'rejection_diagnostics': deepcopy(candidate.audit['rejection_diagnostics']),
                            'candidate_graph_digest': candidate.audit.get('candidate_graph_digest'),
                            'active_graph_digest': candidate.audit['active_graph_digest'],
                            'correction_allowed': eligible, 'rule': 'The candidate was rolled back. Correct the named linked slots '
                                'with source proof; this diagnostic is not an active fact or a new budget.'})
                    for row in rows:
                        rid = row['requirement_id']
                        if rid in runs and on_requirement:
                            result = resolutions.get(rid, {'requirement_id': rid, 'status': 'unresolved', 'facts': [],
                                'discovered_api_dependencies': [], 'open_questions': ['candidate_not_committed']})
                            on_requirement(row, result, False, self.state)
                    submitted_revision_fact_ids = [f['fact_id'] for rid, result in incoming.items()
                        if rid in revision_ids for f in result['facts']]
                for row in ([] if transactional else investigated):
                    rid = row["requirement_id"]
                    if rid in cached:
                        result = cached[rid]
                    else:
                        run = runs[rid]
                        diagnostics[rid] = [error for error in run.trace.get("validation_errors", [])
                                            if error.get("requirement_id", rid) == rid]
                        submitted_result = (_failed_attempt_result(run, row) if _attempt_failure_status(run)
                            else deepcopy(incoming.get(rid, run.result)))
                        result = deepcopy(submitted_result)
                        if rid in revision_ids:
                            submitted_revision_fact_ids.extend(f['fact_id'] for f in result['facts'])
                        checkpoint('reconcile_proposals', requirement_id=rid, round=number)
                        proof_repairs.configure(facts, rows, resolutions)
                        result, repair = merge_resolution(resolutions.get(rid), result, row, proof_evaluator=proof_repairs)
                        run.metadata["subject_local_repair"] = repair
                        run.metadata["execution_index"] = execution_index
                        if run.metadata.get("resolution_attempt_failed"):
                            row["resolution_attempt_failed"] = run.metadata["resolution_attempt_failed"]
                            execution_failures[rid] = {"requirement_id": rid,
                                "execution_status": run.metadata["resolution_attempt_failed"],
                                "errors": deepcopy(run.metadata.get("execution_errors", []))}
                        else:
                            row.pop("resolution_attempt_failed", None)
                            execution_failures.pop(rid, None)
                        if store:
                            archived = deepcopy(run)
                            archived.result = deepcopy(submitted_result)
                            save_requirement(store, ft["ft_id"], archived, configs[rid])
                            if archived.result != result:
                                if not save_reconciled_requirement(store, ft['ft_id'], row, configs[rid], result,
                                        repair, round_number=number, source_evidence=self.state.evidence):
                                    rejected_publications.add(digest([rid, result, repair]))
                                    result = deepcopy(archived.result)
                                    diagnostics.setdefault(rid, []).append({'code': 'source_reconciliation_publication_rejected'})
                                    repair = {**repair, 'withdrawals': []}
                        record_repairs(repair, number)
                    resolutions[rid] = result
                    if on_requirement:
                        on_requirement(row, result, rid in cached, self.state)
                    row["status"] = result["status"]
                    row["evidence_ids"] = sorted({eid for fact in result["facts"] for eid in fact["evidence_ids"]})
                    facts = [fact for fact in facts if fact["requirement_id"] != rid] + deepcopy(result["facts"])
                if revision_ids:
                    revised_closure = build_api_closure(ft, rows, resolutions, snapshot, self.state)
                    revised_context = build_context(ft, rows, facts, snapshot, self.state.evidence)
                    revised_context['dependencies'] = deepcopy(revised_closure['unresolved_api_dependencies'])
                    revised_report = HarnessContextCompletenessValidator().validate(revised_context, revised_closure,
                        ft, snapshot, rows, resolutions, self.state)
                    new_ids = sorted(f['fact_id'] for f in facts if f['requirement_id'] in revision_ids)
                    revision_history.append({'round': number, 'requirement_ids': revision_ids,
                        'feedback': deepcopy(preview_feedback), 'old_fact_ids': old_revision_fact_ids,
                        'submitted_fact_ids': sorted(submitted_revision_fact_ids),
                        'retained_fact_ids': new_ids,
                        'outcome': 'rejected' if transaction_status == 'rejected' else
                            'execution_failure' if any(rid in execution_failures for rid in revision_ids) else
                            'no_progress' if new_ids == old_revision_fact_ids else 'revalidated',
                        'before_graph_digest': projected_report['semantic_obligation_graph_digest'],
                        'after_graph_digest': revised_report['semantic_obligation_graph_digest'],
                        'before_open_roots': projected_report['semantic_obligation_graph']['open_roots'],
                        'after_open_roots': revised_report['semantic_obligation_graph']['open_roots'],
                        'generation_allowed': revised_report['generation_allowed'],
                        'budget_before': revision_before, 'budget_after': ledger()})
                checkpoint('expand_closure', round=number)
                closure = build_api_closure(ft, rows, resolutions, snapshot, self.state)
                expand_requirements(ft, snapshot, rows, closure)
            # A replacement may have lacked a creator/cleanup prerequisite at
            # submission time. Reconsider it after other slots supply proof,
            # without another model call. Each successful pass removes claims.
            checkpoint('reconsider_repairs', round=number)
            for _ in range(len(resolutions)):
                changed = False
                for row in rows:
                    rid = row["requirement_id"]
                    if rid not in resolutions:
                        continue
                    proof_repairs.configure(facts, rows, resolutions)
                    result, audit = merge_resolution(None, resolutions[rid], row, proof_evaluator=proof_repairs)
                    if not audit["withdrawals"]:
                        continue
                    publication_key = digest([rid, result, audit])
                    if publication_key in rejected_publications:
                        continue
                    if store and not save_reconciled_requirement(store, ft['ft_id'], row,
                            requirement_configuration(configuration or {}, row), result, audit, round_number=number,
                            source_evidence=self.state.evidence):
                        rejected_publications.add(publication_key)
                        diagnostics.setdefault(rid, []).append({'code': 'source_reconciliation_publication_rejected',
                            'rule': 'Keep the active claims and investigate the exact proof evidence through a native slot.'})
                        continue
                    resolutions[rid] = result
                    row["status"] = result["status"]
                    row["evidence_ids"] = sorted({e for f in result["facts"] for e in f["evidence_ids"]})
                    facts = [f for f in facts if f["requirement_id"] != rid] + deepcopy(result["facts"])
                    record_repairs(audit, number)
                    changed = True
                if not changed:
                    break
            checkpoint('final_context', round=number)
            closure = build_api_closure(ft, rows, resolutions, snapshot, self.state)
            context = build_context(ft, rows, facts, snapshot, self.state.evidence)
            context["dependencies"] = deepcopy(closure["unresolved_api_dependencies"])
            checkpoint('final_obligations', round=number)
            report = HarnessContextCompletenessValidator().validate(context, closure, ft, snapshot, rows, resolutions, self.state)
            proof_repairs.remember(context, report["semantic_obligation_graph"])
            if report["status"] == "complete":
                termination = "complete"
                break
            if report["status"] == "invalid":
                repairable = {"conflicting_argument_contract", "conflicting_ownership_facts",
                    "conflicting_input_contract", "conflicting_buffer_length_contract", "conflicting_return_contract"}
                if not report["validation_errors"] or any(e["code"] not in repairable for e in report["validation_errors"]):
                    termination = "invalid_context"
                    break
                recoverable_rounds.append({"round": number, "validation_errors": deepcopy(report["validation_errors"]),
                    "generation_allowed": False})
            followups = missing_requirement_tasks(report)
            for task in followups:
                task["validation_diagnostics"] = diagnostics.get(task["requirement_id"], [])
            followup_history.append({"round": number, "tasks": followups,
                "obligation_graph_digest": report["semantic_obligation_graph_digest"],
                "open_roots": report["semantic_obligation_graph"]["open_roots"]})
            if self.state.budget_stop:
                termination = self.state.budget_stop
                break
            if execution_failures and all(task.get("requirement_id") in execution_failures
                    and not failure_retry_allowed(task.get("requirement_id")) for task in followups):
                # Do not repeat identical rejected requests in another pass.
                termination = "execution_failure"
                break
        context["frozen"] = report["status"] == "complete"
        if report["status"] == "invalid" and termination == "completeness_budget_exhausted":
            termination = "invalid_context"
        if digest(ft) != frozen_digest:
            raise ValueError("Minimal FT mutated during context mining")
        requirements["requirements"] = sorted(rows, key=lambda row: row["requirement_id"])
        metrics = {"model_calls": self.state.model_calls, "tool_calls": self.state.tool_calls, "tokens": self.state.tokens,
            "source_chars": self.state.source_chars, "evidence_cache_hits": self.state.evidence_cache_hits, "discovered_functions": len(self.state.discoveries),
            "resolved_requirements": len(report["resolved_requirements"]), "hard_missing": len(report["hard_missing"]),
            "soft_unknowns": len(report["soft_unknowns"]), "closure_size": len(closure["core_apis"]) + len(closure["required_support_apis"]) + len(closure["optional_support_apis"]),
            "required_support_count": len(closure["required_support_apis"]), "optional_support_count": len(closure["optional_support_apis"]),
            "completeness_rounds": number, "resumed_requirements": resumed}
        metrics["execution_failed_requirements"] = len(execution_failures)
        metrics["unchanged_evidence_skips"] = len(unchanged_skips)
        metrics["proved_investigation_skips"] = len(proved_skips)
        metrics['late_prerequisite_activations'] = len(late_prerequisites)
        metrics["bootstrap_source_reads"] = tools.bootstrap_reads
        metrics["bootstrap_evidence_reuses"] = tools.bootstrap_reuses
        metrics["retired_semantic_proposals"] = len(repair_history)
        metrics["recoverable_invalid_rounds"] = len(recoverable_rounds)
        metrics['contract_revision_batches'] = len(revision_history)
        metrics['contract_revision_requirements'] = sum(len(batch['requirement_ids']) for batch in revision_history)
        metrics['contract_revision_unique_requirements'] = len({rid for batch in revision_history
            for rid in batch['requirement_ids']})
        metrics['rejected_revision_corrections'] = sum(correction_counts.values())
        metrics['context_revision_transactions'] = len(transaction_history)
        metrics['rejected_context_revision_transactions'] = sum(t['status'] == 'rejected' for t in transaction_history)
        metrics['optional_investigation_deferrals'] = sum(len(row['requirement_ids']) for row in optional_deferrals)
        metrics['frontier_revision_advances'] = len(revision_advances)
        graph = report["semantic_obligation_graph"]
        metrics["semantic_obligations"] = len(graph["nodes"])
        metrics["closed_obligation_roots"] = len(graph["closed_roots"])
        metrics["open_obligation_roots"] = len(graph["open_roots"])
        metrics["obligation_frontier"] = len(graph["frontier"])
        metadata = {"schema_version": 1, "policy_version": POLICY_VERSION, "ft_id": ft["ft_id"],
            "execution_index": execution_index,
            "termination": termination, "metrics": metrics, "followup_history": followup_history,
            "harness_generated": False, "model_decides_completeness": False}
        if self.investigation_backend is not None:
            metadata['agent_backend'] = deepcopy(self.investigation_backend.descriptor())
        metadata["execution_failures"] = sorted(execution_failures.values(), key=canonical)
        metadata["semantic_obligation_graph_version"] = OBLIGATION_VERSION
        metadata["unchanged_investigation_skips"] = unchanged_skips
        metadata["proved_investigation_skips"] = proved_skips
        metadata["investigation_schedule"] = schedule_history
        metadata['late_prerequisite_activations'] = late_prerequisites
        metadata["subject_repair_history"] = repair_history
        metadata["recoverable_invalid_rounds"] = recoverable_rounds
        metadata['closure_feedback_version'] = FEEDBACK_VERSION
        metadata['closure_feedback'] = closure_feedback(report, context)
        metadata['scheduling_version'] = SCHEDULING_VERSION
        metadata['investigation_allocations'] = allocation_history
        metadata['optional_investigation_deferrals'] = optional_deferrals
        metadata['frontier_revision_advances'] = revision_advances
        metadata['repair_routes'] = repair_routes(metadata['closure_feedback'])
        metadata['context_revision_history'] = revision_history
        metadata['context_revision_transaction_version'] = TRANSACTION_VERSION
        metadata['context_revision_transactions'] = transaction_history
        metadata['candidate_rejection_feedback'] = rejection_feedback
        metadata['rejected_revision_corrections'] = correction_counts
        run = ContextRun(requirements, context, closure, report, metadata)
        if store:
            save_context(store, run, configuration, self.state, resolutions)
        return run
