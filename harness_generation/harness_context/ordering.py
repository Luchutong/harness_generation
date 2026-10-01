"""Hard dependency graph with explicit provenance; suggestions stay soft."""
from ..semantic_discovery.models import canonical
from .value_flow import body_tree, complete_bodies
from ..semantic_discovery.tools import _walk, _text

VERSION = "provenance-ordering-v1"


def field_accesses(function, parameter, writes):
    source, body = body_tree(function)
    if body is None or body.has_error:
        return set()
    if parameter is None:
        returned = [n.named_children[0] for n in _walk(body) if n.type == "return_statement" and n.named_children and n.named_children[0].type == "identifier"]
        names = {_text(n, source) for n in returned}
        if len(names) != 1:
            return set()
        parameter = next(iter(names))
    result = set()
    for node in _walk(body):
        if node.type != "field_expression" or _text(node.child_by_field_name("argument"), source) != parameter:
            continue
        parent = node.parent
        is_write = parent.type == "assignment_expression" and parent.child_by_field_name("left") == node
        if is_write == writes:
            result.add(_text(node.child_by_field_name("field"), source))
    return result


def ordering_graph(context, snapshot, records):
    edges = []
    bodies = complete_bodies(snapshot, records)
    def add(before, after, strength, reason, row, resource=None):
        if before is None or after is None or before == after:
            return
        eids = set(row.get("evidence_ids", []))
        if strength == "hard":
            eids.update(bodies.get(before, ()))
            eids.update(bodies.get(after, ()))
            for binding in context.get("resource_identity", {}).get("bindings", []):
                if binding["resource_id"] == resource:
                    eids.update(binding["evidence_ids"])
        edges.append({"before": before, "after": after, "strength": strength, "reason": reason,
            "resource_id": resource, "evidence_ids": sorted(eids), "fact_id": row.get("fact_id")})
    resources = context["lifecycle_contract"]["resources"]
    arguments = context["argument_contract"]["arguments"]
    def dependence(before, after):
        producers = [(r["resource_id"], r["subject_parameter"]) for r in resources if r["function_id"] == before]
        producers += [(a["resource_id"], a["parameter"]) for a in arguments if a["function_id"] == before and a["resource_id"]]
        consumers = [(r["resource_id"], r["subject_parameter"]) for r in resources if r["function_id"] == after]
        return any(rid == other and field_accesses(snapshot.functions[before], parameter, True) & field_accesses(snapshot.functions[after], name, False)
            for rid, parameter in producers for other, name in consumers)
    for row in resources:
        fid, rid = row["function_id"], row["resource_id"]
        creation = row["creation"]["api"]
        if row["creation"]["kind"] == "creator_api" and creation in bodies and fid in bodies:
            add(creation, fid, "hard", "resource_producer_before_consumer", row, rid)
        if row["initialization"]["mandatory"] and row["initialization"]["api"] in bodies:
            initializer = row["initialization"]["api"]
            add(creation, initializer, "hard", "resource_producer_before_initializer", row, rid)
            if not row["return_value"]:
                add(initializer, fid, "hard", "resource_initialization_before_use", row, rid)
        if row["cleanup"]["mandatory"] and row["cleanup"]["api"] in bodies:
            add(fid, row["cleanup"]["api"], "hard", "resource_use_before_cleanup", row, rid)
    for row in context["callback_contract"]["callbacks"]:
        if row["mandatory"] and row.get("declaration_identity") and row["setup_api"] in bodies and dependence(row["setup_api"], row["function_id"]):
            add(row["setup_api"], row["function_id"], "hard", "callback_registration_before_use", row)
    for row in context["state_contract"]["preconditions"]:
        api, fid = row["api"], row["function_id"]
        if api in bodies and fid in bodies and row["kind"] in {"initialized", "input_fed", "reset"}:
            proven = dependence(api, fid) or any(e["before"] == api and e["after"] == fid and e["strength"] == "hard" for e in edges)
            add(api, fid, "hard" if proven else "soft", "state_precondition_data_dependence" if proven else "unproved_state_order", row)
    for row in context["input_contract"]["bindings"]:
        if row["source"] not in {"context", "derived"} or not row["via_function_id"]:
            continue
        before, after = row["via_function_id"], row["function_id"]
        producers = [r for r in resources if r["function_id"] == before]
        consumers = [r for r in resources if r["function_id"] == after and r["subject_parameter"] == row["parameter"]]
        for producer in producers:
            for consumer in consumers:
                if producer["resource_id"] != consumer["resource_id"] or before not in bodies or after not in bodies:
                    continue
                if field_accesses(snapshot.functions[before], producer["subject_parameter"], True) & field_accesses(snapshot.functions[after], consumer["subject_parameter"], False):
                    add(before, after, "hard", "input_state_write_before_read", row, producer["resource_id"])
    for row in context["ordering_contract"]["constraints"]:
        if row["kind"] in {"must_precede", "must_follow"} and row["after"]:
            before, after = (row["before"], row["after"]) if row["kind"] == "must_precede" else (row["after"], row["before"])
            add(before, after, "soft", "agent_ordering_suggestion", row, row["resource_id"])
    for row in context.get("argument_graph", {}).get("state_dependencies", []):
        if row["before"] in bodies and row["after"] in bodies:
            add(row["before"], row["after"], "hard", row["reason"], row, row["resource_id"])
    unique = {canonical(row): row for row in edges}
    edges = sorted(unique.values(), key=canonical)
    hard = [e for e in edges if e["strength"] == "hard"]
    cycles = cycle_edges(hard)
    return {"version": VERSION, "edges": edges, "hard_cycles": cycles,
        "soft_cycle_edges": cycle_edges(edges), "soft_policy": "diagnostic_only"}


def cycle_edges(edges):
    reach = {(e["before"], e["after"]) for e in edges}
    while True:
        expanded = reach | {(a, c) for a, b in reach for b2, c in reach if b == b2}
        if expanded == reach:
            break
        reach = expanded
    return [e for e in edges if (e["after"], e["before"]) in reach]
