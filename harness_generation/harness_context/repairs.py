"""Subject-local repairs; only recomputed source proofs may retire proposals."""
from copy import deepcopy

from ..semantic_discovery.models import canonical
from .models import fact_id

VERSION = "source-verified-subject-repair-v7"
COLLECTIONS = {"argument_construction": "arguments", "ownership": "entries", "lifecycle": "resources",
    "state": "preconditions", "callback": "callbacks", "input_binding": "bindings", "buffer_length": "links",
    "call_order": "constraints"}


def subject_key(kind, row):
    if kind == "ownership":
        return (row.get("parameter"), row.get("return_value"), row.get("field"), row.get("subject_kind", "PointerParameter"))
    if kind == "lifecycle":
        return (row.get("subject_parameter"), row.get("return_value"))
    if kind in {"input_binding", "argument_construction", "state", "callback"}:
        return (row.get("parameter"),)
    if kind == "buffer_length":
        return (row.get("buffer_parameter"), row.get("length_parameter"))
    if kind == "call_order":
        return (row.get("before"), row.get("after"), row.get("resource_id"))
    if kind == "support_decision":
        # A support candidate is a relation: API, parent(s), and effect role.
        # Rejecting creation and rejecting initialization are independent
        # decisions, not contradictory answers about one undifferentiated API.
        return (row.get("reason"), tuple(sorted(row.get("required_by", []))))
    return ()


def _combine(old, new, kind, key=None):
    if canonical(old) == canonical(new):
        return deepcopy(old), False
    if old == "unknown":
        return deepcopy(new), False
    if new == "unknown":
        return deepcopy(old), False
    # Null API/identity or pointer-return semantics may be an explicit hole;
    # booleans and concrete enum values are never silently replaced.
    nullable = key in {"api", "release_api", "setup_api", "via_function_id", "resource_id"} or (
        kind == "return_semantics" and key in {"nullable", "owned", "error_cleanup"})
    if nullable and (old is None or new is None):
        return deepcopy(new if old is None else old), False
    if isinstance(old, dict) and isinstance(new, dict) and set(old) == set(new):
        merged, conflict = {}, False
        for name in old:
            merged[name], different = _combine(old[name], new[name], kind, name)
            conflict |= different
        return merged, conflict
    return deepcopy(old), True


def merge_resolution(previous, incoming, requirement, *, proof_evaluator=None):
    """Split collection facts by exact subject, preserve independent evidence.

    This cannot prove either claim. Compatible refinements union issued evidence;
    Without a framework proof evaluator, contradictory claims keep both facts.
    Source-supported selection is independent of submission order. Neither a
    model-written repair ID nor last-write-wins behavior is accepted.
    """
    result = deepcopy(incoming)
    kind, field = requirement["kind"], COLLECTIONS.get(requirement["kind"])
    old_facts = previous.get("facts", []) if previous else []
    by_subject = {}
    for fact in [*old_facts, *incoming["facts"]]:
        values = fact["value"].get(field, []) if field else [fact["value"]]
        extras = {k: deepcopy(v) for k, v in fact["value"].items() if k != field} if field else {}
        if field and not values:
            entry = {"row": None, "extras": extras, "evidence_ids": set(fact["evidence_ids"])}
            matches = [e for e in by_subject.setdefault(("__empty__",), []) if canonical(e["extras"]) == canonical(extras)]
            if matches:
                matches[0]['evidence_ids'] |= entry['evidence_ids']
            else:
                by_subject[("__empty__",)].append(entry)
        for row in values:
            key = subject_key(kind, row)
            candidates = by_subject.setdefault(key, [])
            for candidate in candidates:
                combined, conflict = _combine(candidate["row"], row, kind)
                conflict |= canonical(candidate['extras']) != canonical(extras)
                if not conflict:
                    candidate["row"] = combined
                    candidate["evidence_ids"] |= set(fact["evidence_ids"])
                    break
            else:
                candidates.append({"row": deepcopy(row), "extras": extras, "evidence_ids": set(fact["evidence_ids"])})
    merged = []
    for key in sorted(by_subject, key=canonical):
        for candidate in by_subject[key]:
            fact = {"requirement_id": requirement["requirement_id"], "function_id": requirement["subject_function_id"],
                "predicate": kind, "value": {**candidate["extras"], field: [candidate["row"]] if candidate["row"] is not None else []} if field else candidate["row"],
                "evidence_ids": sorted(candidate["evidence_ids"])}
            fact["fact_id"] = fact_id(fact)
            merged.append(fact)
    result["facts"] = sorted(merged, key=lambda f: f["fact_id"])
    dependencies = (previous or {}).get("discovered_api_dependencies", []) + incoming["discovered_api_dependencies"]
    result["discovered_api_dependencies"] = sorted({canonical(d): deepcopy(d) for d in dependencies}.values(), key=canonical)
    withdrawals = []
    if proof_evaluator is not None:
        result, withdrawals = proof_evaluator.reconcile(result, requirement)
    if previous and incoming["status"] == "unresolved" and not incoming["facts"]:
        result["status"] = previous["status"]
        if result["status"] != "unresolved":
            result["open_questions"] = []
    audit = {"version": VERSION, "retained_subjects": len({subject_key(kind, row)
        for f in old_facts for row in (f["value"].get(field, []) if field else [f["value"]])}),
        "merged_subjects": len(by_subject), "conflicts": fact_conflicts(result["facts"]),
        "withdrawals": withdrawals}
    return result, audit


def fact_conflicts(facts):
    groups, extras_by_requirement, conflicts = {}, {}, []
    for fact in facts:
        kind, field = fact["predicate"], COLLECTIONS.get(fact["predicate"])
        if field:
            extras = {k:v for k,v in fact['value'].items() if k != field}
            previous = extras_by_requirement.setdefault(fact['requirement_id'], extras)
            if canonical(previous) != canonical(extras):
                conflicts.append({'code':'subject_repair_conflict','requirement_id':fact['requirement_id'],
                    'subject_function_id':fact['function_id'],'kind':kind,'subject_parameter':None,'subject_key':['metadata']})
        for row in fact["value"].get(field, []) if field else [fact["value"]]:
            key = (fact["requirement_id"], *subject_key(kind, row))
            entry = groups.setdefault(key, [])
            if any(_combine(previous, row, kind)[1] for previous in entry):
                conflicts.append({"code": "subject_repair_conflict", "requirement_id": fact["requirement_id"],
                    "subject_function_id": fact["function_id"], "kind": kind,
                    "subject_parameter": row.get("parameter", row.get("subject_parameter")), "subject_key": list(key[1:])})
            entry.append(row)
    return sorted({canonical(c): c for c in conflicts}.values(), key=canonical)
