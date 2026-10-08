"""Validate a group of explicit revisions without mutating the active Context.

Only source-verified reconciliation can retire old claims. A failed or partial
candidate does not publish facts; evidence, discoveries and paid operations
belong to the live mining state and are never refunded by this transaction.
"""
from copy import deepcopy
from dataclasses import dataclass, field

from ..semantic_discovery.models import canonical, digest
from .api_closure import build_api_closure
from .completeness import HarnessContextCompletenessValidator
from .evidence import build_context, validate_resolution_record
from .repair_proofs import RepairProofEvaluator
from .repairs import merge_resolution, fact_conflicts

VERSION = "source-checked-context-transaction-v1"
MAX_REJECTED_REVISION_CORRECTIONS = 1


@dataclass
class RevisionOutcome:
    requirements: list
    resolutions: dict
    facts: list
    context: dict
    closure: dict
    report: dict
    audits: list
    audit: dict
    source_witnesses: dict = field(default_factory=dict)


def proof_witness_records(audits, evidence):
    """Copy issued records used by actual withdrawal proofs, without new reads."""
    ids = set()

    def visit(value):
        if isinstance(value, dict):
            ids.update(value.get("evidence_ids", []))
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    for audit in audits:
        visit(audit.get("withdrawals", []))
    if ids - set(evidence):
        raise ValueError("withdrawal_proof_references_unissued_evidence")
    return {eid: deepcopy(evidence[eid]) for eid in sorted(ids)}


def semantic_signature(resolutions):
    """New response/evidence IDs alone cannot buy another correction."""
    return digest({rid: {"status": result["status"], "claims": sorted([
        {key: deepcopy(f[key]) for key in ("requirement_id", "function_id", "predicate", "value")}
        for f in result["facts"]], key=canonical),
        "dependencies": sorted({canonical({key: deepcopy(value) for key, value in dependency.items()
            if key != "evidence_ids"}): {key: deepcopy(value) for key, value in dependency.items()
            if key != "evidence_ids"} for dependency in result["discovered_api_dependencies"]}.values(), key=canonical)}
        for rid, result in sorted(resolutions.items())})


def _union_dependency_evidence(result):
    # Both native records were already strictly parsed. The same semantic
    # dependency can cite newly issued evidence in a revision without becoming
    # two selections. Different roles/parents/necessity remain separate claims.
    dependencies = {}
    for row in result["discovered_api_dependencies"]:
        claim = {key: deepcopy(value) for key, value in row.items() if key != "evidence_ids"}
        entry = dependencies.setdefault(canonical(claim), {**claim, "evidence_ids": []})
        entry["evidence_ids"] = sorted(set(entry["evidence_ids"]) | set(row["evidence_ids"]))
    result["discovered_api_dependencies"] = sorted(dependencies.values(), key=canonical)


def _proof_signature(report):
    # A new evidence ID alone is no progress. A source-checked obligation
    # becoming proved is progress even when the typed claim did not change.
    return digest(sorted([{key: node.get(key) for key in ("obligation_id", "proof_status")}
        | {"local_status": node.get("local_proof", {}).get("status")}
        for node in report["semantic_obligation_graph"]["nodes"]], key=canonical))


def _project(ft, snapshot, state, requirements, resolutions):
    from .loop import expand_requirements
    rows, results = deepcopy(requirements), deepcopy(resolutions)

    def apply_statuses():
        for row in rows:
            result = results.get(row["requirement_id"])
            if result is not None:
                row["status"] = result["status"]
                row["evidence_ids"] = sorted({eid for f in result["facts"] for eid in f["evidence_ids"]})

    apply_statuses()
    closure = build_api_closure(ft, rows, results, snapshot, state)
    expand_requirements(ft, snapshot, rows, closure)
    apply_statuses()
    closure = build_api_closure(ft, rows, results, snapshot, state)
    facts = sorted([deepcopy(f) for result in results.values() for f in result["facts"]], key=lambda f: f["fact_id"])
    context = build_context(ft, rows, facts, snapshot, state.evidence)
    context["dependencies"] = deepcopy(closure["unresolved_api_dependencies"])
    report = HarnessContextCompletenessValidator().validate(context, closure, ft, snapshot, rows, results, state)
    return rows, results, facts, context, closure, report


def _frontier_failures(feedback, submitted_ids, report):
    nodes = {n["obligation_id"]: n for n in report["semantic_obligation_graph"]["nodes"]}
    failures = []
    for item in feedback.get("items", []):
        if not submitted_ids.intersection(item["repair_requirement_ids"]):
            continue
        for nid in item["frontier_obligation_ids"]:
            node = nodes.get(nid)
            # Unrelated downstream roots may need their own subsequent group.
            # The named prerequisite itself must have source-checked local
            # proof; a dependency-blocked root is not a new local omission.
            if node is None or node.get("local_proof", {}).get("status") != "proved":
                failures.append({"code": "linked_contract_still_unproved", "obligation_id": nid,
                    "requirement_ids": deepcopy(item["repair_requirement_ids"]),
                    "subject_function_id": item["subject_function_id"],
                    "subject_parameter": item.get("subject_parameter"),
                    "diagnostics": deepcopy(node.get("diagnostics", [])) if node else [],
                    "correction_targets": deepcopy(item["correction_targets"])})
    return sorted({canonical(row): row for row in failures}.values(), key=canonical)


def _reconcile_candidate(ft, snapshot, state, rows, candidate, protected):
    evaluator = RepairProofEvaluator(ft, snapshot, state)
    evaluator.protected = deepcopy(protected)
    staged = _project(ft, snapshot, state, rows, candidate)
    audits = []
    # All companion slots are already staged. Each successful pass removes a
    # claim, which bounds the fixed point independently of model-call budgets.
    limit = 1 + sum(len(result["facts"]) for result in candidate.values())
    for _ in range(limit):
        changed = False
        staged_rows, candidate, facts, _, _, _ = staged
        for row in staged_rows:
            rid = row["requirement_id"]
            if rid not in candidate:
                continue
            evaluator.configure(facts, staged_rows, candidate)
            result, repair = merge_resolution(None, candidate[rid], row, proof_evaluator=evaluator)
            if not repair["withdrawals"]:
                continue
            candidate[rid] = result
            audits.append({"requirement_id": rid, **deepcopy(repair)})
            changed = True
            staged = _project(ft, snapshot, state, staged_rows, candidate)
            staged_rows, candidate, facts, _, _, _ = staged
        if not changed:
            break
    return staged, audits


def evaluate_revision(ft, snapshot, state, requirements, resolutions, incoming, *,
                      feedback, protected, execution_failures=None):
    """Stage every slot, reconcile to a fixed point, and commit only progress.

    ``incoming`` contains parsed native submissions before local merging, not
    a model's claimed closure or an earlier merged result. Active arguments
    remain unchanged for every outcome. The caller may publish only a committed
    outcome; no-progress, rejected and execution-failure results use baseline.
    """
    # Derived checks use the same latest issued evidence for both projections.
    # Even an accidentally stateful proof helper cannot refund or mutate the
    # live provider ledger/cache while evaluating a candidate.
    view_state = deepcopy(state)
    baseline = _project(ft, snapshot, view_state, requirements, resolutions)
    rows, original, old_facts, old_context, old_closure, old_report = baseline
    known = {r["requirement_id"]: r for r in rows}
    submitted_ids = set(incoming)
    audit = {"version": VERSION, "submitted_requirement_ids": sorted(submitted_ids),
        "before_graph_digest": old_report["semantic_obligation_graph_digest"],
        "baseline_semantic_digest": semantic_signature(original),
        "native_submission_digest": digest(incoming), "rejection_diagnostics": [],
        "ledger": {"model_calls": state.model_calls, "tool_calls": state.tool_calls,
            "source_chars": state.source_chars, "tokens": deepcopy(state.tokens)},
        "rollback_scope": ["facts", "requirements", "resolutions", "uncommitted_withdrawals"],
        "retained_live_state": ["model_calls", "tool_calls", "source_chars", "tokens", "evidence",
            "discoveries", "budget_stop", "attempts", "issued_registries"]}

    def finish(status, projection, audits=()):
        audit["status"] = status
        audit["active_graph_digest"] = projection[-1]["semantic_obligation_graph_digest"]
        witnesses = proof_witness_records(audits, view_state.evidence) if status == "committed" else {}
        audit["source_witness_digest"] = digest(witnesses)
        audit["transaction_id"] = "context_revision_" + digest(audit)[:24]
        return RevisionOutcome(*projection, deepcopy(list(audits)), deepcopy(audit), witnesses)

    if execution_failures:
        audit["rejection_diagnostics"] = [{"code": "revision_execution_failure", "failures": deepcopy(execution_failures)}]
        return finish("execution_failure", baseline)
    if not incoming or submitted_ids - set(known):
        audit["rejection_diagnostics"] = [{"code": "native_revision_scope_invalid",
            "unknown_requirement_ids": sorted(submitted_ids - set(known))}]
        return finish("rejected", baseline)
    candidate = deepcopy(original)
    initial = {r["function_id"] for r in ft["core_functions"] + ft["support_candidates"]}
    try:
        for rid, result in incoming.items():
            validate_resolution_record(result, known[rid], snapshot, view_state, initial, set(ft["excluded_functions"]))
            candidate[rid], _ = merge_resolution(original.get(rid), result, known[rid])
            _union_dependency_evidence(candidate[rid])
    except (ValueError, TypeError, KeyError) as error:
        audit["rejection_diagnostics"] = [{"code": "native_revision_validation_failed",
            "detail": str(error)[:1000]}]
        return finish("rejected", baseline)

    try:
        staged, audits = _reconcile_candidate(ft, snapshot, view_state, rows, candidate, protected)
        for row in staged[0]:
            if row['requirement_id'] in staged[1]:
                validate_resolution_record(staged[1][row['requirement_id']], row, snapshot, view_state,
                    initial, set(ft['excluded_functions']))
    except (OSError, ValueError, TypeError, KeyError) as error:
        audit['rejection_diagnostics'] = [{'code': 'candidate_projection_failed', 'detail': str(error)[:1000]}]
        return finish('rejected', baseline)
    candidate_report = staged[-1]
    audit["candidate_graph_digest"] = candidate_report["semantic_obligation_graph_digest"]
    audit["candidate_semantic_digest"] = semantic_signature(staged[1])
    audit["candidate_hard_missing"] = deepcopy(candidate_report["hard_missing"])
    audit["candidate_withdrawals"] = [deepcopy(w) for repair in audits for w in repair["withdrawals"]]
    baseline_errors = {canonical(e) for e in old_report["validation_errors"]}
    new_errors = [deepcopy(e) for e in candidate_report["validation_errors"] if canonical(e) not in baseline_errors]
    if new_errors:
        audit["rejection_diagnostics"].append({"code": "candidate_introduced_validation_error", "errors": new_errors})
    baseline_conflicts = {canonical(e) for e in fact_conflicts(old_facts)}
    new_conflicts = [e for e in fact_conflicts(staged[2]) if canonical(e) not in baseline_conflicts]
    if new_conflicts:
        audit["rejection_diagnostics"].append({"code": "candidate_introduced_subject_conflict", "conflicts": new_conflicts})
    old_nodes = {n["obligation_id"]: n for n in old_report["semantic_obligation_graph"]["nodes"]}
    new_nodes = {n["obligation_id"]: n for n in candidate_report["semantic_obligation_graph"]["nodes"]}
    lost = [nid for nid, node in old_nodes.items() if node["proof_status"] == "proved"
        and (nid not in new_nodes or new_nodes[nid]["proof_status"] != "proved")]
    if lost:
        audit["rejection_diagnostics"].append({"code": "candidate_lost_proved_obligation", "obligation_ids": sorted(lost)})
    if (not audit["rejection_diagnostics"]
            and semantic_signature(staged[1]) == semantic_signature(original)
            and _proof_signature(candidate_report) == _proof_signature(old_report)):
        return finish("no_progress", baseline)
    audit["rejection_diagnostics"] += _frontier_failures(feedback, submitted_ids, candidate_report)
    if audit["rejection_diagnostics"]:
        return finish("rejected", baseline)
    return finish("committed", staged, audits)
