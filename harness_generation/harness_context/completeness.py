"""Generation gate: inspect only canonical semantic obligation closure."""
from copy import deepcopy

from ..semantic_discovery.models import digest, canonical
from .models import POLICY_VERSION
from .obligations import SemanticObligationGraphBuilder, close_obligations, VERSION


class HarnessContextCompletenessValidator:
    def validate(self, context, closure, ft, snapshot, requirements, resolutions, state):
        graph = SemanticObligationGraphBuilder().build(context, closure, ft, snapshot, requirements, resolutions, state)
        return self.validate_graph(graph, requirements)

    def validate_graph(self, graph, requirements):
        """Internal gate over a freshly recomputed graph, never a model proposal.

        Artifact readers must first rebuild and compare the whole proof graph.
        Closure is recomputed here as well; saved proof_status is not authority.
        """
        actual = close_obligations(graph["nodes"], graph["mandatory_roots"])
        errors = deepcopy(graph["validation_errors"]) + actual["diagnostics"]
        by_id = {n["obligation_id"]: n for n in actual["nodes"]}
        coverage = graph.get("required_coverage", [])
        if not coverage:
            errors.append({"code": "semantic_obligation_coverage_missing"})
        invocations = {n["subject_function_id"]: n for n in by_id.values() if n["predicate"] == "api_invocation_proved"}
        for row in coverage:
            nid, fid = row["obligation_id"], row["function_id"]
            invocation = invocations.get(fid)
            dependencies = {d["obligation_id"] for d in invocation["dependencies"]} if invocation else set()
            if nid not in by_id or not invocation or invocation["obligation_id"] not in actual["mandatory_roots"] or (
                    row["kind"] != "api_invocation" and nid not in dependencies):
                errors.append({"code": "semantic_obligation_coverage_gap", "coverage": row})
        if graph.get("version") != VERSION or graph.get("graph_digest") != digest({k: v for k, v in graph.items() if k != "graph_digest"}):
            errors.append({"code": "semantic_obligation_graph_digest_mismatch"})
        if any(graph.get(k) != actual[k] for k in actual):
            errors.append({"code": "semantic_obligation_closure_projection_mismatch"})
        hard = {}
        for nid in actual["open_roots"]:
            node = by_id.get(nid)
            if not node or node["kind"] == "integrity":
                continue
            diagnostics = node["diagnostics"] + [d for leaf in node["blocking_obligations"]
                for d in by_id.get(leaf, {}).get("diagnostics", [])]
            if not diagnostics:
                diagnostics = [{"requirement_id": node["requirement_id"], "subject_function_id": node["subject_function_id"],
                    "kind": node["kind"], "code": "semantic_obligation_dependency_unresolved",
                    "question": "Identify the missing proof on this obligation's dependency frontier; reuse established evidence."}]
            for diagnostic in diagnostics:
                row = {**deepcopy(diagnostic), "obligation_id": nid, "proof_status": node["proof_status"],
                    "blocking_obligations": node["blocking_obligations"]}
                hard[digest(row)] = row
        hard_rows = sorted(hard.values(), key=canonical)
        open_nodes = [by_id[n] for n in actual["open_roots"] if n in by_id]
        kinds = {n["kind"] for n in open_nodes}
        root_requirements = {n["requirement_id"]: n for n in actual["nodes"] if n["predicate"] == n["kind"] and n["requirement_id"]}
        return {"schema_version": 1, "artifact_kind": "harness_context_completeness", "policy_version": POLICY_VERSION,
            "ft_id": graph["ft_id"], "status": "invalid" if errors else "incomplete" if actual["open_roots"] else "complete",
            "generation_allowed": not errors and not actual["open_roots"], "hard_missing": hard_rows,
            "soft_unknowns": graph["soft_unknowns"], "validation_errors": sorted(errors, key=canonical),
            "semantic_obligation_graph": graph, "semantic_obligation_graph_version": VERSION,
            "semantic_obligation_graph_digest": graph["graph_digest"],
            "framework_satisfied_requirements": graph["framework_satisfied_requirements"],
            "argument_graph_version": graph["argument_graph_version"], "graph_failure_taxonomy": graph["graph_failure_taxonomy"],
            "execution_failed_requirements": sorted([{"requirement_id": r["requirement_id"],
                "resolution_attempt_failed": r["resolution_attempt_failed"]} for r in requirements if r.get("resolution_attempt_failed")], key=canonical),
            "resolved_requirements": sorted(rid for rid, n in root_requirements.items() if n["proof_status"] == "proved"),
            "unresolved_requirements": sorted(rid for rid, n in root_requirements.items() if n["proof_status"] != "proved"),
            "api_closure_complete": not {"api_closure", "invocation"} & kinds and not any(row["code"] == "required_api_unresolved" for row in hard_rows) and not errors,
            "lifecycle_complete": "lifecycle" not in kinds and not errors,
            "input_binding_complete": not {"input_binding", "buffer_length"} & kinds and not errors,
            "ownership_complete": "ownership" not in kinds and not errors,
            "ordering_sufficient": "call_order" not in kinds and not errors,
            "callback_complete": "callback" not in kinds and not errors}


CompletenessValidator = HarnessContextCompletenessValidator


def missing_requirement_tasks(report):
    """Coalesce missing leaf proofs by existing requirement, not by error row."""
    graph = report["semantic_obligation_graph"]
    nodes = {n["obligation_id"]: n for n in graph["nodes"]}
    grouped = {}
    for nid in graph["frontier"]:
        node = nodes.get(nid)
        if not node or not node["requirement_id"] or node["kind"] == "integrity":
            continue
        rid = node["requirement_id"]
        task = grouped.setdefault(rid, {"requirement_id": rid, "subject_function_id": node["subject_function_id"],
            "kind": node["kind"], "code": "semantic_obligation_proof_missing", "question": node["question"],
            "obligation_ids": [], "missing_proofs": [], "graph_holes": [], "evidence_ids": [], "blocked_roots": []})
        task["obligation_ids"].append(nid)
        task["missing_proofs"].append({"obligation_id": nid, "predicate": node["predicate"],
            "subject_parameter": node["subject_parameter"], "subject_field": node.get("subject_field"),
            "proof_status": node["proof_status"], "diagnostics": node["diagnostics"]})
        # A field node can be assigned to the argument requirement when no
        # state requirement exists; keep the wire predicate/slot independent.
        if node["requirement_id"]:
            root = next((n for n in graph["nodes"] if n["requirement_id"] == node["requirement_id"] and n["predicate"] == n["kind"]), None)
            if root:
                task["kind"] = root["kind"]
        task["evidence_ids"] += node["evidence_ids"]
        task["graph_holes"] += [hole for d in node["diagnostics"] for hole in d.get("graph_holes", [])]
        task["blocked_roots"] += [root for root in graph["open_roots"] if nid in nodes[root]["blocking_obligations"]]
    result = []
    for task in grouped.values():
        for key in ("obligation_ids", "evidence_ids", "blocked_roots"):
            task[key] = sorted(set(task[key]))
        task["graph_holes"] = sorted({canonical(h): h for h in task["graph_holes"]}.values(), key=canonical)
        task["missing_proofs"].sort(key=canonical)
        task["question"] = "Prove only these missing semantic obligations with exact issued source; identify evidence still missing. Do not design a harness. " + task["question"]
        task["task_id"] = "task_" + digest(task)[:24]
        result.append(task)
    return sorted(result, key=canonical)
