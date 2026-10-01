"""Conservative value identity over issued, complete C bodies.

This is intentionally a straight-line analysis. Branches, escapes, casts,
ambiguous symbols and multiple origins remain unknown, rather than aliasing by
type. Origins include the call site, so two calls to one creator stay distinct.
"""
from collections import defaultdict

from tree_sitter import Language, Parser
import tree_sitter_c

from ..semantic_discovery.models import canonical, digest
from ..semantic_discovery.tools import _walk, _text

VERSION = "resource-value-flow-v1"


def body_tree(function):
    source = ("void __flow__(void) " + function.get("body", "")).encode()
    root = Parser(Language(tree_sitter_c.language())).parse(source).root_node
    body = next((n for n in _walk(root) if n.type == "compound_statement"), None)
    return source, body


def complete_bodies(snapshot, records):
    result = defaultdict(set)
    for eid, record in records.items():
        if record.get("truncated") or record.get("tool") not in {
                "get_function", "read_source_range", "find_resource_flows", "find_function_argument_usages"}:
            continue
        for fid in {record.get("function_id"), record.get("caller_id")}:
            function = snapshot.functions.get(fid)
            if function and function.get("defined") and function.get("body") and function["body"] in record.get("content", ""):
                result[fid].add(eid)
        if record.get("tool") == "read_source_range":
            for fid, function in snapshot.functions.items():
                if function["file"] == record.get("source") and function.get("body") and function["body"] in record.get("content", ""):
                    result[fid].add(eid)
    return result


def unique_callee(snapshot, name, caller):
    matches = [f for f in snapshot.functions.values() if f["name"] == name and f.get("defined")]
    local = [f for f in matches if f["file"] == caller["file"]]
    matches = local if len(local) == 1 else matches
    return matches[0] if len(matches) == 1 else None


def resource_flows(snapshot, records):
    bodies = complete_bodies(snapshot, records)
    observations, unresolved = [], []
    for caller_id in sorted(bodies):
        caller = snapshot.functions[caller_id]
        source, body = body_tree(caller)
        if body is None or body.has_error:
            continue
        if any(n.type in {"if_statement", "switch_statement", "for_statement", "while_statement",
                         "do_statement", "goto_statement", "conditional_expression", "preproc_if"} for n in _walk(body)):
            unresolved.append({"caller_id": caller_id, "reason": "nonlinear_value_flow", "evidence_ids": sorted(bodies[caller_id])})
            continue
        env = {}
        def key(node):
            if node is None:
                return None
            if node.type == "identifier":
                return _text(node, source)
            if node.type == "field_expression":
                base = key(node.child_by_field_name("argument"))
                field = node.child_by_field_name("field")
                return (base + "." + _text(field, source)) if base and field else None
            return None
        def origin(callee, node, kind="return", parameter=None):
            type_name = callee.get("return_base_type") if kind == "return" else next(
                p["base_type"] for p in callee["parameters"] if p["name"] == parameter)
            data = {"function_id": callee["id"], "kind": kind, "parameter": parameter,
                    "type": type_name, "pointer_depth": callee.get("return_pointer_depth", 0) if kind == "return" else next(
                        p.get("pointer_depth", 0) - 1 for p in callee["parameters"] if p["name"] == parameter),
                    "caller_id": caller_id, "call_offset": node.start_byte}
            return {"resource_id": "resource_" + digest(data)[:24], "origin": data}
        def emit(callee, parameter, value, node, returned=False):
            if value:
                declared = next((p for p in callee.get("parameters", []) if p["name"] == parameter), None)
                is_output = value["origin"]["kind"] == "out_parameter" and callee["id"] == value["origin"]["function_id"] and parameter == value["origin"]["parameter"]
                if not returned and not is_output and declared and (declared.get("base_type") != value["origin"]["type"]
                        or declared.get("pointer_depth", 0) != value["origin"]["pointer_depth"]):
                    unresolved.append({"caller_id": caller_id, "function_id": callee["id"], "parameter": parameter,
                        "reason": "value_flow_type_mismatch", "evidence_ids": sorted(bodies[caller_id])})
                    return
                observations.append({**value, "function_id": callee["id"], "parameter": parameter,
                    "return_value": returned, "caller_id": caller_id, "call_offset": node.start_byte,
                    "evidence_ids": sorted(bodies[caller_id])})
        def evaluate(node):
            if node is None:
                return None
            if node.type == "parenthesized_expression":
                return evaluate(node.named_children[0]) if len(node.named_children) == 1 else None
            if key(node):
                return env.get(key(node))
            if node.type != "call_expression":
                return None
            target = node.child_by_field_name("function")
            if target is None or target.type != "identifier":
                env.clear()  # unknown indirect calls can mutate escaped state
                return None
            callee = unique_callee(snapshot, _text(target, source), caller)
            args = node.child_by_field_name("arguments").named_children
            if not callee or len(args) != len(callee.get("parameters", [])):
                # Library calls/unknown callees cannot supply a project origin.
                for arg in args:
                    if arg.type == "pointer_expression":
                        env.clear()
                return None
            for param, arg in zip(callee["parameters"], args):
                emit(callee, param["name"], evaluate(arg), node)
                if arg.type == "pointer_expression" and _text(arg, source).startswith("&") and param.get("pointer_depth", 0) > 1:
                    # Only an evidenced allocation into THIS exact out parameter.
                    callee_source, callee_body = body_tree(callee)
                    assigns = [n for n in _walk(callee_body) if n.type == "assignment_expression"] if callee_body else []
                    proven = callee["id"] in bodies and any(
                        _text(n.child_by_field_name("left"), callee_source).replace(" ", "") == "*" + param["name"]
                        and n.child_by_field_name("right").type == "call_expression" for n in assigns)
                    proven = proven and not any(n.type in {"if_statement", "for_statement", "while_statement", "switch_statement"} for n in _walk(callee_body))
                    local = key(arg.named_children[0]) if arg.named_children else None
                    if local:
                        env[local] = origin(callee, node, "out_parameter", param["name"]) if proven else None
                        emit(callee, param["name"], env[local], node)
            if callee.get("return_pointer_depth", 0):
                value = origin(callee, node)
                emit(callee, None, value, node, True)
                return value
            return None
        for statement in body.named_children:
            if statement.type == "declaration":
                for decl in statement.named_children:
                    if decl.type != "init_declarator":
                        if decl.type in {"identifier", "pointer_declarator"}:
                            names = [n for n in _walk(decl) if n.type == "identifier"]
                            for name in names:
                                env.pop(_text(name, source), None)
                        continue
                    target = decl.child_by_field_name("declarator")
                    names = [n for n in _walk(target) if n.type == "identifier"]
                    if len(names) == 1:
                        env[_text(names[0], source)] = evaluate(decl.child_by_field_name("value"))
            elif statement.type == "expression_statement" and statement.named_children:
                expression = statement.named_children[0]
                if expression.type == "assignment_expression":
                    target = key(expression.child_by_field_name("left"))
                    value = evaluate(expression.child_by_field_name("right"))
                    if target:
                        env[target] = value
                    else:
                        env.clear()
                else:
                    evaluate(expression)
            elif statement.type != "comment":
                # Stop at returns/unknown blocks; no paths beyond this point.
                break
    return {"version": VERSION, "observations": sorted(observations, key=canonical),
            "unresolved": unresolved}
