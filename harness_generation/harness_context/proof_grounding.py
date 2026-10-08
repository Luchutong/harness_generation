"""Bounded source checks for claims that citation validity alone cannot prove.

Only issued complete bodies participate. Straight-line aliases and branch path
intersection distinguish may-write/may-release from a definite same-object
effect. Unknown calls/control flow do not acquire a positive proof by default.
This is a validator/projection, not another agent contract or tool.
"""
from copy import deepcopy

from ..semantic_discovery.models import canonical
from ..semantic_discovery.tools import _walk, _text
from .value_flow import body_tree, complete_bodies, unique_callee

VERSION = "source-obligation-grounding-v10"
LIMIT = 32


def analyze(function, snapshot, issued, *, depth=0, _field_values=None, _zero_objects=(), _invocation=(),
            _nonnull_parameters=None):
    source, body = body_tree(function)
    if body is None or body.has_error or function["id"] not in issued or depth > 2:
        return {"available": False, "paths": [], "reads": [], "guards": {},
            "callback_bindings": [], "source_function_ids": []}
    reads, guards = set(), {}
    local_symbols = set()
    pointer_names = {p['name'] for p in function['parameters'] if p.get('is_pointer')}
    for statement in _walk(body):
        if statement.type != 'declaration':
            continue
        for declarator in statement.named_children:
            if declarator.type == 'init_declarator':
                declarator = declarator.child_by_field_name('declarator')
            if declarator.type in {'identifier','pointer_declarator','function_declarator','array_declarator','parenthesized_declarator'}:
                local_symbols.update(_text(n, source) for n in _walk(declarator) if n.type == 'identifier')
                if any(n.type == 'pointer_declarator' for n in _walk(declarator)):
                    pointer_names.update(_text(n, source) for n in _walk(declarator) if n.type == 'identifier')
    nonnull = {"parameter:" + p["name"] for p in function["parameters"] if p.get("is_pointer")
        and (_nonnull_parameters is None or p['name'] in _nonnull_parameters)}
    initial = {"env": {p["name"]: "parameter:" + p["name"] for p in function["parameters"]},
        "writes": {}, "zero": set(_zero_objects), "released": set(), "release_counts": {},
        "escapes": set(), "uncertain": False,
        "ended": False, "returned": None, "outputs": {}, "retentions": set(),
        "field_values": dict(_field_values or {}), "object_types": {
            "parameter:" + p["name"]: p["base_type"] for p in function["parameters"]
            if p.get("is_struct_like") and p.get("pointer_depth", 0) <= 1},
        "callback_calls": [], "traversals": [], "source_function_ids": {function["id"]}}

    def intrinsic(name, state):
        return name not in state['env'] and name not in local_symbols and not any(
            f['name'] == name and f.get('defined') for f in snapshot.functions.values())

    def value(node, state):
        if node is None:
            return None
        if node.type in {"parenthesized_expression", "cast_expression"}:
            result = value(node.named_children[-1], state) if node.named_children else None
            # A function pointer cast is not an exact declared ABI binding.
            return None if node.type == "cast_expression" and result and result.startswith("function:") else result
        if node.type == "identifier":
            name = _text(node, source)
            if name in state["env"]:
                return state["env"][name]
            callee = unique_callee(snapshot, name, function) if name not in local_symbols else None
            if callee:
                return "function:" + callee["id"]
            return "literal:0" if name == "NULL" else "external:" + name
        if node.type == "pointer_expression" and node.named_children:
            # Dereferencing a stored pointer is a different subject. Only an
            # address expression preserves the local object/function identity.
            if not _text(node, source).lstrip().startswith("&"):
                return None
            operand = node.named_children[-1]
            if operand.type != 'identifier':
                return None
            origin = value(operand, state)
            # &pointer is its storage cell, not the pointee being released;
            # &aggregate and &project_function retain their exact identities.
            return 'address:' + origin if origin and _text(operand, source) in pointer_names else origin
        if node.type == "field_expression":
            key = field(node, state)
            return state["field_values"].get(key, "literal:0" if key and key[0] in state["zero"] else None)
        if node.type == "number_literal":
            number = literal(node)
            return "literal:" + str(number) if number is not None else None
        if node.type == "call_expression":
            name = _text(node.child_by_field_name("function"), source)
            if name in {"malloc", "calloc"} and intrinsic(name, state):
                origin = "local:" + function["id"] + ":" + str(node.start_byte)
                nonnull.add(origin)
                if name == "calloc":
                    state["zero"].add(origin)
                return origin
        return None

    def field(node, state):
        if node is None or node.type != "field_expression":
            return None
        argument = node.child_by_field_name("argument")
        base = value(argument, state)
        if argument.type == "field_expression":
            parent = field(argument, state)
            base = parent[0] if parent else None
            name = parent[1] + "." if parent else ""
        else:
            name = ""
        return (base, name + _text(node.child_by_field_name("field"), source)) if base else None

    def inspect_reads(node, state):
        for n in _walk(node):
            target = field(n, state)
            if target and target[0] in state['released']:
                state['uncertain'] = True  # A release effect cannot certify use after free.
            if not target or not target[0].startswith("parameter:"):
                continue
            parent = n.parent
            if parent and parent.type == "field_expression" and parent.child_by_field_name("argument") == n:
                continue
            if target not in state["writes"] and target[0] not in state["zero"]:
                reads.add((target[0].removeprefix("parameter:"), target[1]))

    def literal(node):
        text = _text(node, source).strip()
        try:
            return int(text, 0)
        except ValueError:
            return None

    def expression(node, state):
        if node is None:
            return
        if node.type == "assignment_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            expression(right, state)
            inspect_reads(right, state)
            target = field(left, state)
            if target:
                if target[0] in state['released']:
                    state['uncertain'] = True
                direct = _text(node.child_by_field_name("operator"), source) == "="
                if not direct:
                    inspect_reads(left, state)
                state["writes"][target] = literal(right) if direct else None
                origin = value(right, state)
                state["field_values"][target] = origin if direct else None
                if origin and not target[0].startswith("local:"):
                    state["escapes"].add(origin)
                    state["retentions"].add((origin, target[0], target[1]))
            elif left.type == "identifier":
                name = _text(left, source)
                origin = value(right, state)
                if name not in state["env"] and origin:
                    state["escapes"].add(origin)
                    state["retentions"].add((origin, "external:" + name, ""))
                state["env"][name] = origin or "unknown:" + name
            elif left.type == "pointer_expression" and _text(left, source).lstrip().startswith("*"):
                destination = value(left.named_children[-1], state) if left.named_children else None
                origin = value(right, state)
                if destination and origin:
                    state["outputs"][destination] = origin
            return
        if node.type == "call_expression":
            inspect_reads(node, state)
            target = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments").named_children
            if any(n.type in {"call_expression", "assignment_expression", "update_expression"}
                   for arg in args for n in _walk(arg)):
                state["uncertain"] = True  # argument evaluation/order is not modeled
            name = _text(target, source)
            if target.type == "identifier" and (name in state['env'] or name in local_symbols):
                state['uncertain'] = True
                return
            callee = unique_callee(snapshot, name, function) if target.type == "identifier" else None
            if target.type == 'identifier' and callee is None and any(
                    f['name'] == name and f.get('defined') for f in snapshot.functions.values()):
                state['uncertain'] = True  # ambiguous project symbol is not a libc intrinsic
                return
            site = (*_invocation, function["id"] + ":" + str(node.start_byte))
            if target.type == "field_expression":
                from .callbacks import callback_declarations, function_callback_abi
                from .evidence import callback_abis
                key, reference = field(target, state), value(target, state)
                bound = snapshot.functions.get(reference.removeprefix("function:")) if reference and reference.startswith("function:") else None
                base = state["object_types"].get(key[0]) if key else None
                declared = callback_declarations({"id": function["id"], "parameters": [
                    {"name": "object", "base_type": base, "declaration": ""}]}, snapshot) if base else []
                declarations = [d for d in declared if d.get("field_path", d["field"]) == key[1]]
                exact = (bound and bound["id"] in issued and len(declarations) == 1 and "." not in key[1]
                    and callback_abis(declarations[0]["signature"]) == function_callback_abi(bound["signature"])
                    and len(args) == len(bound["parameters"]))
                row = {"function_id": function["id"], "invocation_sites": list(site),
                    "callee_expression": name, "owner_origin": key[0] if key else None,
                    "field": key[1] if key else None, "target_function_ids": [bound["id"]] if exact else [],
                    "argument_origins": [value(a, state) for a in args],
                    "status": "proved" if exact and not state["uncertain"] else "missing",
                    "code": "exact_object_field_callback" if exact else "callback_binding_unreproduced"}
                state["callback_calls"].append(row)
                if not exact:
                    state["uncertain"] = True
                    return
                callee = bound
            if callee:
                mapping = {"parameter:" + p["name"]: value(a, state) for p, a in zip(callee["parameters"], args)}
                if any(origin in state['released'] for origin in mapping.values()):
                    state['uncertain'] = True
                reverse = {v: k for k, v in mapping.items() if v}
                # Two formals aliasing the same table need an alias-aware callee
                # environment; independent formal subjects cannot prove this.
                object_args = [v for v in mapping.values() if v in state["object_types"]]
                if len(object_args) != len(set(object_args)):
                    state["uncertain"] = True
                    return
                fields, zero_objects = {}, set()
                for p, arg in zip(callee["parameters"], args):
                    actual, formal = value(arg, state), "parameter:" + p["name"]
                    if not (p.get("is_struct_like") and p.get("pointer_depth", 0) == 1
                            and state["object_types"].get(actual) == p["base_type"]):
                        continue
                    for (origin, member), stored in state["field_values"].items():
                        if origin == actual:
                            fields[formal, member] = reverse.get(stored, stored)
                    if actual in state["zero"]:
                        zero_objects.add(formal)
                        from .callbacks import callback_declarations
                        for d in callback_declarations(callee, snapshot):
                            if d["parameter"] == p["name"] and d["field"]:
                                fields.setdefault((formal, d.get("field_path", d["field"])), "literal:0")
                summary = analyze(callee, snapshot, issued, depth=depth + 1,
                    _field_values=fields, _zero_objects=zero_objects, _invocation=site,
                    _nonnull_parameters={p['name'] for p, arg in zip(callee['parameters'], args)
                        if value(arg, state) in nonnull})
                paths = summary["paths"]
                if not paths:
                    state["uncertain"] = True
                    return
                state["source_function_ids"].update(summary["source_function_ids"])
                for proof in summary.get('traversal_proofs', []):
                    row = deepcopy(proof)
                    row['root_origin'] = mapping.get(row['root_origin'], row['root_origin'])
                    state['traversals'].append(row)
                for callback in summary["callback_bindings"]:
                    row = deepcopy(callback)
                    row["owner_origin"] = mapping.get(row["owner_origin"], row["owner_origin"])
                    row["argument_origins"] = [mapping.get(v, v) for v in row["argument_origins"]]
                    state["callback_calls"].append(row)
                for param, arg in zip(callee["parameters"], args):
                    origin = value(arg, state)
                    expected = "parameter:" + param["name"]
                    if not origin:
                        continue
                    for p, f in summary["reads"]:
                        if p == param["name"] and origin.startswith("parameter:") and (origin, f) not in state["writes"]:
                            reads.add((origin.removeprefix("parameter:"), f))
                    common = set.intersection(*[set(k for k in p["writes"] if k[0] == expected) for p in paths])
                    for _, member in common:
                        values = {p["writes"][(expected, member)] for p in paths}
                        state["writes"][(origin, member)] = next(iter(values)) if len(values) == 1 else None
                    members = {member for path in paths for identity, member in path["field_values"] if identity == expected}
                    for member in members:
                        values = {path["field_values"].get((expected, member)) for path in paths}
                        stored = next(iter(values)) if len(values) == 1 else None
                        state["field_values"][origin, member] = mapping.get(stored, stored)
                    if all(expected in p["released"] for p in paths):
                        state["released"].add(origin)
                    counts = [p['release_counts'].get(expected, (0, 0)) for p in paths]
                    low, high = state['release_counts'].get(origin, (0, 0))
                    state['release_counts'][origin] = (low + min(c[0] for c in counts),
                        high + max(c[1] for c in counts))
                    if any(expected in p["escapes"] for p in paths):
                        state["escapes"].add(origin)
                    for path in paths:
                        for retained, destination, member in path["retentions"]:
                            if retained != expected:
                                continue
                            mapped = next((value(a, state) for cp, a in zip(callee["parameters"], args)
                                if destination == "parameter:" + cp["name"]), None)
                            state["retentions"].add((origin, mapped or destination, member))
                state["uncertain"] |= any(p["uncertain"] for p in paths)
            elif name == "free" and len(args) == 1 and target.type == "identifier":
                origin = value(args[0], state)
                if origin and not origin.startswith('unknown:'):
                    state["released"].add(origin)
                    low, high = state['release_counts'].get(origin, (0, 0))
                    state['release_counts'][origin] = (low + 1, high + 1)
                else:
                    state['uncertain'] = True  # unknown pointee is not a wrong-object witness
            elif name in {"memcpy", "memset"}:
                state["uncertain"] = True
            elif name not in {"malloc", "calloc", "realloc", "strlen", "memcpy", "memset", "__builtin_trap", "abort", "exit"}:
                # Unknown callees are not positive field/release evidence.
                state["uncertain"] = True
            return
        # Side effects hidden in short-circuit/conditional/comma syntax are
        # outside this transfer function, and must invalidate positive proofs.
        if any(n.type in {"call_expression", "assignment_expression", "update_expression"} for n in _walk(node)):
            state["uncertain"] = True
        inspect_reads(node, state)

    def owned_traversal(statement, state):
        """Inductive postorder release of a valid owned backlinked tree.

        The ordinary valid-object premise includes finite, uniquely owned
        children with reciprocal backlinks. This rule proves the incoming root
        is consumed once; it does not certify arbitrary external heap graphs.
        Each descent decreases its guarded child count. All other case paths
        save the current object, advance to its backlink and release the saved
        object through the ordinary exact call/ABI transfer function.
        """
        def unwrap(node):
            while node is not None and node.type == 'parenthesized_expression' and len(node.named_children) == 1:
                node = node.named_children[0]
            return node
        def children(node):
            return [n for n in node.named_children if n.type not in {'comment', 'empty_statement'}
                and not (n.type == 'expression_statement' and not n.named_children)]
        def assignment(node):
            rows = children(node)
            expression_node = rows[0] if node.type == 'expression_statement' and len(rows) == 1 else None
            if expression_node is not None and expression_node.type == 'assignment_expression' and _text(
                    expression_node.child_by_field_name('operator'), source) == '=':
                return expression_node.child_by_field_name('left'), expression_node.child_by_field_name('right')
            return None, None
        condition = unwrap(statement.child_by_field_name('condition'))
        block = statement.child_by_field_name('body')
        if condition is None or condition.type != 'identifier' or block.type != 'compound_statement':
            return None
        cursor = _text(condition, source)
        origin = state['env'].get(cursor)
        if not origin or not origin.startswith('parameter:') or origin not in nonnull or state['uncertain']:
            return None
        stages = children(block)
        if len(stages) != 4 or stages[0].type != 'switch_statement':
            return None
        saved, old = assignment(stages[1]); advanced, link = assignment(stages[2])
        if (saved is None or saved.type != 'identifier' or _text(old, source) != cursor
                or advanced is None or _text(advanced, source) != cursor or link.type != 'field_expression'
                or _text(link.child_by_field_name('argument'), source) != cursor):
            return None
        backlink = field(link, state)
        if not backlink or state['writes'].get(backlink) != 0:
            return None  # The root must be isolated before walking descendants.
        parameter = next((p for p in function['parameters'] if origin == 'parameter:' + p['name']), None)
        layouts = [s for s in snapshot.artifacts.structs if parameter and parameter['base_type'] in {s['name'], *s.get('aliases', [])}]
        if len(layouts) != 1:
            return None
        from .callbacks import parse_declaration
        layout_source, layout = parse_declaration(layouts[0]['declaration'])
        aliases = {layouts[0]['name'], *layouts[0].get('aliases', [])}
        members = [n for n in _walk(layout) if n.type == 'field_declaration'
            and _text(n.child_by_field_name('type'), layout_source) in aliases
            and any(c.type == 'pointer_declarator' and len(c.named_children) == 1
                and c.named_children[0].type == 'field_identifier'
                and _text(c.named_children[0], layout_source) == backlink[1] for c in n.named_children)]
        if len(members) != 1:
            return None
        save_name = _text(saved, source)
        if save_name == cursor or save_name not in state['env']:
            return None
        tail = children(stages[3])
        if len(tail) != 1 or tail[0].type != 'call_expression':
            return None
        args = tail[0].child_by_field_name('arguments').named_children
        if sum(a.type == 'identifier' and _text(a, source) == save_name for a in args) != 1:
            return None
        switch = stages[0]
        discriminant = unwrap(switch.child_by_field_name('condition'))
        if discriminant is None or discriminant.type != 'field_expression' or not field(discriminant, state) or field(discriminant, state)[0] != origin:
            return None
        cases = children(switch.child_by_field_name('body'))
        if not cases or any(c.type != 'case_statement' for c in cases) or not any(c.child_by_field_name('value') is None for c in cases):
            return None
        outcomes, ranks = [], []
        for case in cases:
            label = case.child_by_field_name('value')
            rows = [n for n in children(case) if n != label]
            prefix = rows[:-1] if rows and rows[-1].type == 'break_statement' else None
            if prefix is None:
                if len(rows) != 3 or rows[0].type != 'if_statement' or rows[2].type != 'continue_statement':
                    return None
                guard = rows[0]
                test = unwrap(guard.child_by_field_name('condition'))
                if test.type != 'unary_expression' or _text(test.child_by_field_name('operator'), source) != '!' or guard.child_by_field_name('alternative'):
                    return None
                count = test.child_by_field_name('argument')
                count_key = field(count, state)
                if not count_key or count_key[0] != origin:
                    return None
                yes = guard.child_by_field_name('consequence')
                zero_path = children(yes) if yes.type == 'compound_statement' else [yes]
                if not zero_path or zero_path[-1].type != 'break_statement':
                    return None
                destination, child = assignment(rows[1])
                subscripts = [n for n in _walk(child) if n.type == 'subscript_expression'] if child else []
                updates = [n for n in _walk(child) if n.type == 'update_expression'] if child else []
                container = field(subscripts[0].child_by_field_name('argument'), state) if len(subscripts) == 1 else None
                selected = child
                while selected is not None and selected.type == 'field_expression':
                    selected = selected.child_by_field_name('argument')
                if (destination is None or _text(destination, source) != cursor or len(subscripts) != 1 or len(updates) != 1
                        or selected != subscripts[0] or unwrap(subscripts[0].child_by_field_name('index')) != updates[0]
                        or _text(updates[0].child_by_field_name('operator'), source) != '--'
                        or not _text(updates[0], source).lstrip().startswith('--')
                        or field(updates[0].child_by_field_name('argument'), state) != count_key
                        or not container or container[0] != origin or container[1].rsplit('.', 1)[:-1] != count_key[1].rsplit('.', 1)[:-1]
                        or any(n.type in {'call_expression', 'assignment_expression', 'conditional_expression'} for n in _walk(child))):
                    return None
                ranks.append(count_key[1])
                prefix = zero_path[:-1]
            path = deepcopy(state)
            for row in prefix:
                expr = children(row)
                if row.type != 'expression_statement' or len(expr) != 1 or expr[0].type != 'call_expression':
                    return None
                # Owned payload allocations are separate from the root object.
                # Resolve the callback normally; never treat a callback spelling
                # or a pointer type alone as a deallocation effect.
                for arg in expr[0].child_by_field_name('arguments').named_children:
                    member = field(arg, path)
                    if member and member[0] == origin:
                        if member == backlink:
                            return None
                        path['field_values'].setdefault(member, 'owned_member:' + origin + ':' + member[1])
                expression(expr[0], path)
            for stage in stages[1:]:
                for expr in children(stage):
                    expression(expr, path)
            if (path['uncertain'] or path['release_counts'].get(origin) != (1, 1) or origin in path['escapes']
                    or path['env'].get(cursor) != 'literal:0'):
                return None
            path['traversals'].append({'kind': 'owned_backlinked_postorder', 'root_origin': origin,
                'backlink_field': backlink[1], 'decreasing_child_counts': sorted(set(ranks)),
                'loop_offset': statement.start_byte, 'scope': 'valid_owned_tree_root_consumed_once'})
            outcomes.append(path)
        return outcomes

    def process(statement, state):
        if state["ended"]:
            return [state]
        if statement.type in {"compound_statement", "else_clause"}:
            states = [state]
            for child in statement.named_children:
                states = [n for s in states for n in process(child, s)]
                if len(states) > LIMIT:
                    state["uncertain"] = True
                    return [state]
            return states
        if statement.type == "declaration":
            for decl in statement.named_children:
                initialized = decl.type == "init_declarator"
                declarator = decl.child_by_field_name("declarator") if initialized else decl
                if declarator.type not in {"identifier", "pointer_declarator", "array_declarator", "parenthesized_declarator", "function_declarator"}:
                    continue
                names = [n for n in _walk(declarator) if n.type == "identifier"]
                if len(names) != 1:
                    state["uncertain"] = True
                    continue
                name, rhs = _text(names[0], source), decl.child_by_field_name("value") if initialized else None
                if rhs is not None and rhs.type != "initializer_list":
                    expression(rhs, state)
                pointer = any(n.type == "pointer_declarator" for n in _walk(declarator))
                typename = _text(statement.child_by_field_name("type"), source)
                aggregate = any(typename in {s["name"], *s.get("aliases", [])} for s in snapshot.artifacts.structs)
                origin = value(rhs, state) if pointer or not aggregate else None
                if origin is None:
                    origin = "local:" + function["id"] + ":" + str(decl.start_byte)
                state["env"][name] = origin
                if aggregate and (not pointer or initialized and origin.startswith("local:") and origin not in state["object_types"]):
                    state["object_types"][origin] = typename
                    if not pointer:
                        nonnull.add(origin)  # Address of a real local aggregate.
                if aggregate and pointer and not initialized:
                    # A declaration is not a use of indeterminate storage.
                    # Keep it unknown until assignment; never give it a local
                    # aggregate identity or an assumed non-null pointee.
                    state['env'][name] = 'unknown:' + name
                    state['object_types'].pop(origin, None)
                if aggregate and rhs is not None and not pointer:
                    if rhs.type == "initializer_list":
                        if len(rhs.named_children) == 1 and literal(rhs.named_children[0]) == 0:
                            state["zero"].add(origin)
                        else:
                            for item in rhs.named_children:
                                designator = item.child_by_field_name("designator")
                                assigned = item.child_by_field_name("value")
                                fields = [n for n in _walk(designator) if n.type == "field_identifier"] if designator else []
                                if item.type != "initializer_pair" or len(fields) != 1 or assigned is None:
                                    state["uncertain"] = True
                                    continue
                                expression(assigned, state)
                                key = origin, _text(fields[0], source)
                                state["field_values"][key] = value(assigned, state)
                                state["writes"][key] = literal(assigned)
                    else:
                        state["uncertain"] = True  # aggregate copies are not pointer aliases
                if pointer and rhs is not None and origin.startswith(("parameter:", "local:")):
                    nonnull.add(origin)
            return [state]
        if statement.type == "if_statement":
            condition = statement.child_by_field_name("condition")
            while condition.type == "parenthesized_expression" and condition.named_children:
                condition = condition.named_children[0]
            expression(condition, state)
            yes, no = statement.child_by_field_name("consequence"), statement.child_by_field_name("alternative")
            # A null guard is evaluated under the same non-null object premise
            # as a field read or a returned creator object, not under all flags.
            text = _text(condition, source).replace(" ", "")
            origin = value(condition, state)
            for name in list(state["env"]):
                identity = state["env"][name]
                if text in {name, name + "!=NULL", name + "!=0"}:
                    origin = identity
                    if identity in nonnull:
                        return process(yes, state)
                if text in {"!" + name, name + "==NULL", name + "==0"} and identity in nonnull:
                    exits = any(n.type == "return_statement" for n in _walk(yes))
                    if exits:
                        return process(no, state) if no else [state]
            # Explicit nonreturning guard gives a required field value.
            fatal = any(n.type == "call_expression" and _text(n.child_by_field_name("function"), source) in {"__builtin_trap", "abort", "exit"}
                and intrinsic(_text(n.child_by_field_name("function"), source), state) for n in _walk(yes))
            if fatal and condition.type == "binary_expression":
                left, right = condition.child_by_field_name("left"), condition.child_by_field_name("right")
                target = field(left, state)
                if target and target[0].startswith("parameter:") and _text(condition.child_by_field_name("operator"), source) == "!=" and literal(right) is not None:
                    guards[(target[0].removeprefix("parameter:"), target[1])] = literal(right)
            return process(yes, deepcopy(state)) + (process(no, deepcopy(state)) if no else [deepcopy(state)])
        if statement.type == "expression_statement":
            for child in statement.named_children:
                expression(child, state)
            return [state]
        if statement.type == "return_statement":
            if statement.named_children:
                expression(statement.named_children[0], state)
                state["returned"] = value(statement.named_children[0], state)
                if state["returned"] and state["returned"].startswith("parameter:"):
                    state["escapes"].add(state["returned"])
                    state["retentions"].add((state["returned"], "return", ""))
            state["ended"] = True
            return [state]
        if statement.type == 'while_statement':
            traversal = owned_traversal(statement, state)
            if traversal is not None:
                return traversal
        if statement.type not in {"comment", "empty_statement"}:
            inspect_reads(statement, state)
            state["uncertain"] = True
        return [state]

    paths = process(body, initial)
    bindings = []
    sites = {tuple(r["invocation_sites"]) for path in paths for r in path["callback_calls"]}
    for site in sorted(sites):
        occurrences = [[r for r in path["callback_calls"] if tuple(r["invocation_sites"]) == site] for path in paths]
        calls = [r for group in occurrences for r in group]
        row = deepcopy(calls[0])
        targets = sorted({t for r in calls for t in r["target_function_ids"]})
        arguments = {canonical(r["argument_origins"]) for r in calls}
        definite = (all(len(group) == 1 for group in occurrences) and len(targets) == 1
            and len(arguments) == 1 and all(r["status"] == "proved" for r in calls)
            and not any(p["uncertain"] for p in paths))
        row.update(target_function_ids=targets, status="proved" if definite else "missing",
            code="exact_object_field_callback" if definite else "callback_binding_conditional_or_unreproduced",
            source_function_ids=sorted(set().union(*(p["source_function_ids"] for p in paths))))
        bindings.append(row)
    return {"available": True, "paths": paths, "reads": sorted(reads), "guards": guards,
        "callback_bindings": bindings,
        "traversal_proofs": sorted({canonical(r): r for p in paths for r in p['traversals']}.values(), key=canonical),
        "source_function_ids": sorted(set().union(*(p["source_function_ids"] for p in paths)))}


def field_proofs(context, snapshot, records, closure):
    """Cover caller state, or the exact owned CORE-return cleanup binding."""
    issued = complete_bodies(snapshot, records)
    active = set(context["core_apis"]) | {r["function_id"] for r in closure["required_support_apis"]}
    arguments = {(r["function_id"], r["parameter"]): r for r in context["canonical_construction"]["parameters"]}
    conditions = context["state_contract"]["preconditions"]
    rows = []
    for fid in sorted(active):
        function = snapshot.functions[fid]
        reader = analyze(function, snapshot, issued)
        supplied_results = {}
        for source in context.get('construction_contract', {}).get('sources', []):
            producer = source.get('creator_api')
            parameter = source.get('parameter')
            selection = arguments.get((fid, parameter), {})
            recipe = selection.get('recipe') or {}
            rid = recipe.get('resource_id')
            if (source.get('kind') != 'cleanup_consumption' or not source.get('verified')
                    or source.get('function_id') != fid or producer not in context['core_apis']
                    or not source.get('observed_pair_origins') or source.get('resource_id') != rid
                    or selection.get('status') != 'resolved' or recipe.get('kind') != 'resource_reference'
                    or recipe.get('producer_api') != producer or producer not in issued or fid not in issued):
                continue
            # The harness supplies an exact owned CORE result to its observed
            # cleanup API. Fields produced inside the target are target state,
            # not caller initialization. Explicit setup/guard obligations still
            # require the ordinary field proof, including on this cleanup input.
            if any(c['function_id'] == fid and c['parameter'] == parameter and c['kind'] != 'none'
                    for c in conditions) or any(p == parameter for p, _ in reader['guards']):
                continue
            resources = [r for r in context.get('lifecycle_contract', {}).get('resources', [])
                if r['function_id'] == producer and r['return_value'] and r['resource_id'] == rid
                and r['cleanup'] == {'mandatory': True, 'api': fid}]
            owners = [o for o in context.get('ownership_contract', {}).get('entries', [])
                if o['function_id'] == producer and o['return_value'] and o['resource_id'] == rid
                and o['ownership'] == 'owned' and o['release_api'] == fid and o['lifetime'] == 'until_release']
            if len(resources) != 1 or len(owners) != 1 or resources[0]['initialization']['mandatory']:
                continue
            supplied_results[parameter] = (source, owners[0])
        recorded_results = set()
        for parameter, field in reader["reads"]:
            declared = next(p for p in function["parameters"] if p["name"] == parameter)
            # Extents/data buffers and callback ABI fields have independent
            # construction proofs; do not invent context state for raw bytes.
            if not (declared.get("is_struct_like") or declared.get("is_opaque_handle")):
                continue
            if parameter in supplied_results:
                if parameter not in recorded_results:
                    source, owner = supplied_results[parameter]
                    rows.append({'function_id': fid, 'parameter': parameter, 'field': None,
                        'fields': sorted(f for p, f in reader['reads'] if p == parameter),
                        'status': 'proved', 'code': 'source_observed_core_return_cleanup',
                        'proof_scope': 'harness_cleanup_input_binding', 'writer_api': source['creator_api'],
                        'resource_id': source['resource_id'], 'construction_source': source['construction_id'],
                        'evidence_ids': sorted(set(source['evidence_ids']) | set(owner['evidence_ids']) | issued[fid] | issued[source['creator_api']])})
                    recorded_results.add(parameter)
                continue
            row = {"function_id": fid, "parameter": parameter, "field": field, "status": "missing",
                "code": "state_field_initialization_unproven", "evidence_ids": sorted(issued[fid]), "writer_api": None}
            selection = arguments.get((fid, parameter), {})
            recipe = selection.get("recipe") or {}
            row["resource_id"] = recipe.get("resource_id")
            proposals = [c for c in conditions if c["function_id"] == fid and c["parameter"] == parameter and c["kind"] != "unknown"]
            writer = next((c["api"] for c in proposals if c["kind"] != "none" and c["api"]), None)
            if not writer and recipe.get("kind") in {"creator_call", "out_parameter_call"}:
                writer = recipe.get("producer_api")
            expected = reader["guards"].get((parameter, field))
            if not writer and recipe.get("kind") in {"stack_zero_init", "stack_object", "field_initialization"}:
                zero = recipe.get("kind") == "stack_zero_init"
                setup = recipe.get("field_initializers", recipe.get("fields", []))
                initialized = zero or any(x.get("field") == field for x in setup if isinstance(x, dict))
                if initialized and (expected is None or zero and expected == 0):
                    row.update(status="proved", code="construction_field_initialized")
            if writer in snapshot.functions and writer in issued:
                row["writer_api"] = writer
                row["evidence_ids"] = sorted(set(row["evidence_ids"]) | issued[writer])
                producer = snapshot.functions[writer]
                proof = analyze(producer, snapshot, issued)
                candidates = [p for p in producer["parameters"] if p.get("base_type") == declared["base_type"] and p.get("pointer_depth") == declared.get("pointer_depth")]
                targets = []
                for p in candidates:
                    chosen = arguments.get((writer, p["name"]), {}).get("recipe") or {}
                    if row["resource_id"] and chosen.get("resource_id") and chosen["resource_id"] != row["resource_id"]:
                        continue
                    targets.append("parameter:" + p["name"])
                if producer.get("return_base_type") == declared["base_type"] and producer.get("return_pointer_depth"):
                    targets += sorted({p["returned"] for p in proof["paths"] if p["returned"] and not p["returned"].startswith("external:")})
                output = recipe.get("out_parameter") if recipe.get("kind") == "out_parameter_call" and recipe.get("producer_api") == writer else None
                if output:
                    targets += sorted({p["outputs"].get("parameter:" + output) for p in proof["paths"]
                        if p["outputs"].get("parameter:" + output)})
                if len(set(targets)) == 1:
                    target = targets[0]
                    paths = [p for p in proof["paths"] if not producer.get("return_pointer_depth") or p["returned"] == target]
                    values = [p["writes"].get((target, field), 0 if target in p["zero"] else "absent") for p in paths]
                    if output and not all(p["outputs"].get("parameter:" + output) == target for p in paths):
                        row.update(code="out_parameter_export_not_definite")
                        rows.append(row)
                        continue
                    definite = bool(values) and all(v != "absent" and (expected is None or v == expected) for v in values)
                    if definite and not any(p["uncertain"] for p in paths):
                        row.update(status="proved", code="same_object_definite_field_initialization")
                    elif values and all(v == "absent" for v in values) and not any(p["uncertain"] for p in paths):
                        row.update(status="contradicted", code="initializer_field_or_object_mismatch")
                    elif expected is not None and values and all(v not in {expected, "absent", None} for v in values):
                        row.update(status="contradicted", code="initializer_field_value_mismatch")
                    else:
                        row.update(code="initializer_conditional_or_unreproduced_write")
                elif not targets:
                    row.update(status="contradicted", code="initializer_object_mismatch")
                else:
                    row.update(code="initializer_object_ambiguous")
            rows.append(row)
    return sorted(rows, key=canonical)


def cleanup_checks(context, snapshot, records):
    """Separate actual release counterexamples from unsupported analysis.

    Missing effect evidence still blocks closure; it cannot retire a proposal
    as false during local repair. This is an existing ownership projection.
    """
    issued = complete_bodies(snapshot, records)
    rows = []
    for entry in context["ownership_contract"]["entries"]:
        api = entry.get("release_api")
        if not api or api not in snapshot.functions or entry["ownership"] != "owned":
            continue
        function = snapshot.functions[entry["function_id"]]
        declared = next((p for p in function["parameters"] if p["name"] == entry["parameter"]), None)
        base = function.get("return_base_type") if entry["return_value"] else declared.get("base_type") if declared else None
        target = snapshot.functions[api]
        params = [p for p in target["parameters"] if p.get("base_type") == base and p.get("is_pointer")]
        connection = None
        # An erased callback subject is not the cleanup's declared User*.
        # Its exact allocated caller origin can bridge that difference; a
        # shared model resource label or void* type alone cannot do so.
        if not params and base == 'void' and entry.get('field') is None:
            from .resource_identity import exact_cleanup_connection
            connection = exact_cleanup_connection(context, snapshot, records,
                entry['function_id'], entry['parameter'], entry['return_value'], api)
            if connection:
                params = [p for p in target['parameters'] if p['name'] == connection['cleanup_parameter']]
        release = analyze(target, snapshot, issued,
            _nonnull_parameters={params[0]['name']} if len(params) == 1 else set())
        paths = release["paths"]
        origin = "parameter:" + params[0]["name"] if len(params) == 1 else None
        counterexample = origin and any(not p['uncertain'] and (
            p['release_counts'].get(origin, (0, 0))[1] == 0
            or p['release_counts'].get(origin, (0, 0))[0] > 1) for p in paths)
        definite = origin and bool(paths) and all(not p["uncertain"]
            and p['release_counts'].get(origin) == (1, 1) and origin not in p['escapes'] for p in paths)
        row = {"function_id": entry["function_id"], "kind": "ownership", "parameter": entry["parameter"],
            "fact_id": entry.get("fact_id"), "evidence_ids": sorted(set(entry["evidence_ids"]) |
                set(connection['evidence_ids'] if connection else []) |
                set().union(*(issued[f] for f in release["source_function_ids"]))),
            "status": "contradicted" if counterexample else "proved" if definite else "missing",
            "code": "cleanup_object_or_path_conflict" if counterexample else "same_object_definite_release" if definite else "cleanup_effect_unproven"}
        if connection:
            row['source_witness'] = connection
        rows.append(row)
    return sorted(rows, key=canonical)


def contradictions(context, snapshot, records):
    issued = complete_bodies(snapshot, records)
    failures = []
    def fail(row, kind, code, parameter=None, detail=None):
        failures.append({"function_id": row["function_id"], "kind": kind, "code": code,
            "parameter": parameter, "fact_id": row.get("fact_id"), "evidence_ids": row["evidence_ids"],
            **({"detail": detail} if detail is not None else {})})
    for entry in context["ownership_contract"]["entries"]:
        fid, parameter = entry["function_id"], entry["parameter"]
        summary = analyze(snapshot.functions[fid], snapshot, issued)
        if parameter and entry["field"] is None and entry["lifetime"] == "during_call" and any("parameter:" + parameter in p["escapes"] for p in summary["paths"]):
            origin = "parameter:" + parameter
            retentions = sorted({(destination, member) for path in summary["paths"]
                for value, destination, member in path["retentions"] if value == origin}, key=canonical)
            fail(entry, "ownership", "ownership_escape_lifetime_conflict", parameter, detail={
                "observed_lifetime": entry["lifetime"], "observed_ownership": entry["ownership"],
                "source_retentions": [{"destination": destination, "field": member}
                    for destination, member in retentions],
                "source_paths_uncertain": any(path["uncertain"] for path in summary["paths"]),
                "repair_rule": "A pointer retained after this call cannot use during_call lifetime. Prove its actual recipient and bound; changing lifetime does not prove ownership, nonescape, or cleanup."})
    failures += [{k: v for k, v in row.items() if k != "status"} for row in cleanup_checks(context, snapshot, records)
        if row["status"] == "contradicted"]
    for callback in context["callback_contract"]["callbacks"]:
        userdata = callback.get("userdata")
        if not userdata or "." in userdata:
            continue
        summary = analyze(snapshot.functions[callback["function_id"]], snapshot, issued)
        if callback["lifetime"] == "during_call" and any("parameter:" + userdata in p["escapes"] for p in summary["paths"]):
            fail(callback, "callback", "callback_userdata_escape_lifetime_conflict", userdata)
    return sorted({canonical(f): f for f in failures}.values(), key=canonical)
