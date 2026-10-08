"""Conservative value identity over issued, complete C bodies.

Tracks bounded branch paths and keeps distinct origins rather than aliasing by
type. Loops, escapes, casts and ambiguous symbols remain unknown. Origins
include the call site, so two calls to one creator stay distinct.
"""
from collections import defaultdict

from tree_sitter import Language, Parser
import tree_sitter_c

from ..semantic_discovery.models import canonical, digest
from ..semantic_discovery.tools import _walk, _text

VERSION = "resource-value-flow-v3"
PATH_LIMIT = 32


def body_tree(function):
    source = ("void __flow__(void) " + function.get("body", "")).encode()
    root = Parser(Language(tree_sitter_c.language())).parse(source).root_node
    body = next((n for n in _walk(root) if n.type == "compound_statement"), None)
    return source, body


def complete_bodies(snapshot, records):
    from ..source_evidence import complete_bodies as coverage
    return coverage(snapshot.functions, records, snapshot.artifacts.source_hashes)


def unique_callee(snapshot, name, caller):
    matches = [f for f in snapshot.functions.values() if f["name"] == name and f.get("defined")]
    local = [f for f in matches if f["file"] == caller["file"]]
    matches = local if len(local) == 1 else matches
    return matches[0] if len(matches) == 1 else None


def resource_flows(snapshot, records):
    bodies = complete_bodies(snapshot, records)
    observations, unresolved = [], []
    unknown_sites = set()
    for caller_id in sorted(bodies):
        caller = snapshot.functions[caller_id]
        source, body = body_tree(caller)
        if body is None or body.has_error:
            continue
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
        conditional_sites = set()
        def emit(callee, parameter, value, node, returned=False):
            if value is None and parameter is not None:
                unknown_sites.add((caller_id, callee['id'], parameter, node.start_byte))
            if value:
                declared = next((p for p in callee.get("parameters", []) if p["name"] == parameter), None)
                is_output = value["origin"]["kind"] == "out_parameter" and callee["id"] == value["origin"]["function_id"] and parameter == value["origin"]["parameter"]
                if not returned and not is_output and declared and (declared.get("base_type") != value["origin"]["type"]
                        or declared.get("pointer_depth", 0) != value["origin"]["pointer_depth"]):
                    unresolved.append({"caller_id": caller_id, "function_id": callee["id"], "parameter": parameter,
                        "reason": "value_flow_type_mismatch", "evidence_ids": sorted(bodies[caller_id])})
                    return
                observations.append({**value, **({'conditional': True} if node.start_byte in conditional_sites else {}),
                    "function_id": callee["id"], "parameter": parameter,
                    "return_value": returned, "caller_id": caller_id, "call_offset": node.start_byte,
                    "evidence_ids": sorted(bodies[caller_id])})
        def evaluate(node, env):
            if node is None:
                return None
            if node.type == "parenthesized_expression":
                return evaluate(node.named_children[0], env) if len(node.named_children) == 1 else None
            if key(node):
                return env.get(key(node))
            if node.type != "call_expression":
                if any(n.type in {'call_expression', 'assignment_expression', 'update_expression'} for n in _walk(node)):
                    env.clear()  # hidden evaluation order/conditional mutations
                return None
            target = node.child_by_field_name("function")
            if target is None or target.type != "identifier":
                env.clear()  # unknown indirect calls can mutate escaped state
                return None
            name = _text(target, source)
            if name in env:
                env.clear()  # local function-pointer shadow is not a project API
                return None
            callee = unique_callee(snapshot, name, caller)
            args = node.child_by_field_name("arguments").named_children
            if not callee or len(args) != len(callee.get("parameters", [])):
                # Library calls/unknown callees cannot supply a project origin.
                for arg in args:
                    if arg.type == "pointer_expression":
                        env.clear()
                return None
            for param, arg in zip(callee["parameters"], args):
                emit(callee, param["name"], evaluate(arg, env), node)
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
        def process(statement, env):
            if statement is None:
                return [env]
            if statement.type in {'compound_statement', 'else_clause'}:
                # C block declarations can shadow an outer pointer. Restore
                # only those declared names, retaining assignments to outer
                # variables and keeping branch-specific origins separate.
                declared = set()
                if statement.type == 'compound_statement':
                    for child in statement.named_children:
                        if child.type != 'declaration':
                            continue
                        for item in child.named_children:
                            target = item.child_by_field_name('declarator') if item.type == 'init_declarator' else item
                            if target.type in {'identifier', 'pointer_declarator', 'array_declarator'}:
                                names = [n for n in _walk(target) if n.type == 'identifier']
                                if len(names) == 1:
                                    declared.add(_text(names[0], source))
                saved = {name: value for name, value in env.items()
                    if any(name == local or name.startswith(local + '.') for local in declared)}
                states = [env]
                for child in statement.named_children:
                    states = [state for current in states for state in process(child, current)]
                    if len(states) > PATH_LIMIT:
                        unresolved.append({'caller_id': caller_id, 'reason': 'value_flow_path_limit',
                            'evidence_ids': sorted(bodies[caller_id])})
                        return [{}]
                    if not states:
                        break
                for state in states:
                    for name in list(state):
                        if any(name == local or name.startswith(local + '.') for local in declared):
                            state.pop(name)
                    state.update(saved)
                return states
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
                        env[_text(names[0], source)] = evaluate(decl.child_by_field_name("value"), env)
            elif statement.type == "expression_statement" and statement.named_children:
                expression = statement.named_children[0]
                if expression.type == "assignment_expression":
                    target = key(expression.child_by_field_name("left"))
                    value = evaluate(expression.child_by_field_name("right"), env)
                    if target:
                        env[target] = value
                    else:
                        env.clear()
                else:
                    intrinsic_exit = False
                    if expression.type == 'call_expression':
                        target = expression.child_by_field_name('function')
                        name = _text(target, source)
                        intrinsic_exit = (target.type == 'identifier' and name not in env
                            and name in {'exit', 'abort', '__builtin_trap'}
                            and not any(f['name'] == name and f.get('defined') for f in snapshot.functions.values()))
                    evaluate(expression, env)
                    if intrinsic_exit:
                        return []
            elif statement.type == 'if_statement':
                evaluate(statement.child_by_field_name('condition'), env)
                for branch in (statement.child_by_field_name('consequence'), statement.child_by_field_name('alternative')):
                    if branch:
                        conditional_sites.update(n.start_byte for n in _walk(branch) if n.type == 'call_expression')
                return process(statement.child_by_field_name('consequence'), dict(env)) + process(
                    statement.child_by_field_name('alternative'), dict(env))
            elif statement.type == 'return_statement':
                if statement.named_children:
                    evaluate(statement.named_children[0], env)
                return []
            elif statement.type not in {'comment', 'empty_statement'}:
                # Unsupported iterations/control cannot preserve identities into
                # later code. Continue with an empty environment so unrelated
                # resource calls after the block can still be investigated.
                unresolved.append({'caller_id': caller_id, 'reason': 'nonlinear_value_flow',
                    'evidence_ids': sorted(bodies[caller_id])})
                return [{}]
            return [env]
        process(body, {p['name']: None for p in caller.get('parameters', [])})
    proven = []
    for row in observations:
        site = row['caller_id'], row['function_id'], row['parameter'], row['call_offset']
        if not row['return_value'] and site in unknown_sites:
            unresolved.append({'caller_id': row['caller_id'], 'function_id': row['function_id'],
                'parameter': row['parameter'], 'call_offset': row['call_offset'],
                'reason': 'value_origin_unproved_on_reaching_path', 'evidence_ids': row['evidence_ids']})
        else:
            proven.append(row)
    return {"version": VERSION,
            "observations": sorted({canonical(r): r for r in proven}.values(), key=canonical),
            "unresolved": sorted({canonical(r): r for r in unresolved}.values(), key=canonical)}
