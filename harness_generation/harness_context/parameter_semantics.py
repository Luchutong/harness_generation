"""Parameter relations constrain recipes; executable does not imply suitable."""
from ..semantic_discovery.models import canonical
from ..semantic_discovery.tools import _text
from .value_flow import body_tree, complete_bodies
from .argument_graph import parameter_id

VERSION = "parameter-semantic-relations-v2"


def mandatory_upper_bounds(function, snapshot):
    """A leading literal guard with a known nonreturning C operation.

    Error returns, assertions/macros, unknown calls, nested guards and mutable
    preceding statements are not mandatory bounds. No project API spelling is
    used, and shadowed libc identifiers are never treated as intrinsics.
    """
    source, body = body_tree(function)
    if body is None or body.has_error or not body.named_children:
        return []
    guard = body.named_children[0]
    if guard.type != "if_statement" or guard.child_by_field_name("alternative") is not None:
        return []
    condition = guard.child_by_field_name("condition")
    while condition is not None and condition.type == "parenthesized_expression" and len(condition.named_children) == 1:
        condition = condition.named_children[0]
    if condition is None or condition.type != "binary_expression":
        return []
    left, right = condition.child_by_field_name("left"), condition.child_by_field_name("right")
    op = _text(condition.child_by_field_name("operator"), source)
    if left.type == "number_literal" and right.type == "identifier":
        left, right = right, left
        op = {"<": ">", "<=": ">="}.get(op)
    if left.type != "identifier" or right.type != "number_literal" or op not in {">", ">="}:
        return []
    consequence = guard.child_by_field_name("consequence")
    if consequence.type == "compound_statement" and len(consequence.named_children) == 1:
        consequence = consequence.named_children[0]
    if consequence.type != "expression_statement" or len(consequence.named_children) != 1:
        return []
    call = consequence.named_children[0]
    if call.type != "call_expression":
        return []
    target = _text(call.child_by_field_name("function"), source)
    if (target not in {"abort", "__builtin_trap"}
            or any(p["name"] == target for p in function.get("parameters", []))
            or any(f["name"] == target for f in snapshot.functions.values())
            or call.child_by_field_name("arguments").named_children):
        return []
    try:
        upper = int(_text(right, source), 0) - (op == ">=")
    except ValueError:
        return []
    parameter = _text(left, source)
    return [{"parameter": parameter, "upper_bound": upper, "proof_kind": "leading_nonreturning_guard"}] if upper >= 0 else []


def project_parameter_relations(context, snapshot, records):
    bodies = complete_bodies(snapshot, records)
    rows = []
    for fid in sorted(bodies):
        function = snapshot.functions[fid]
        bounds = {b["parameter"]: b for b in mandatory_upper_bounds(function, snapshot)}
        for i, p in enumerate(function["parameters"]):
            links = [l for l in context["buffer_length_contract"]["links"]
                if l["function_id"] == fid and l["length_parameter"] == p["name"]]
            if not links and p["name"] not in bounds:
                continue
            rows.append({"parameter_id": parameter_id(fid, i), "function_id": fid, "parameter": p["name"],
                "measures": sorted({l["buffer_parameter"] for l in links}),
                "relations": sorted({l["relation"] for l in links}),
                "units": sorted({"elements" if l["relation"] == "elements" else "bytes"
                    for l in links if l["relation"] in {"bytes", "elements", "derived", "capacity"}}),
                "mandatory_upper_bound": bounds.get(p["name"], {}).get("upper_bound"),
                "bound_proof": bounds.get(p["name"]),
                "evidence_ids": sorted(set(bodies[fid]) | {e for l in links for e in l["evidence_ids"]})})
    context["parameter_semantic_contract"] = {"version": VERSION, "parameters": sorted(rows, key=canonical)}
