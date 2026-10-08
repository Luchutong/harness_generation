"""Framework-owned identities, leaving model facts and their hashes untouched."""
from collections import defaultdict

from ..semantic_discovery.models import canonical, digest
from .value_flow import complete_bodies, resource_flows, body_tree, unique_callee
from ..semantic_discovery.tools import _walk, _text

VERSION = "resource-identity-v7"


def endpoint(row):
    return (row["function_id"], row.get("subject_parameter", row.get("parameter")),
            row.get("return_value", False))


def releases_parameter(function, name, snapshot, bodies, depth=0):
    return bool(parameter_release_proof(function, name, snapshot, bodies, depth=depth))


def parameter_release_proof(function, name, snapshot, bodies, *, depth=0):
    """One exact parameter, once on every supported non-null path.

    Uses the same source transfer function as ownership checks, including
    verified field callbacks. A may-release, missing body or escaped parameter
    cannot become a canonical cleanup consumption binding.
    """
    from .proof_grounding import analyze
    summary = analyze(function, snapshot, bodies, depth=depth, _nonnull_parameters={name})
    origin = 'parameter:' + name
    paths = summary['paths']
    if not paths or any(p['uncertain'] or p['release_counts'].get(origin) != (1, 1)
            or origin in p['escapes'] for p in paths):
        return None
    return summary


def allocated_return(function, snapshot):
    source, body = body_tree(function)
    if body is None or body.has_error:
        return False
    allocated = set()
    for declaration in _walk(body):
        if declaration.type != "init_declarator":
            continue
        value = declaration.child_by_field_name("value")
        while value is not None and value.type in {"cast_expression", "parenthesized_expression"}:
            value = value.child_by_field_name("value") if value.type == "cast_expression" else value.named_children[0]
        name = _text(value.child_by_field_name("function"), source) if value is not None and value.type == "call_expression" else None
        if name in {"malloc", "calloc"} and not any(f["name"] == name for f in snapshot.functions.values()):
            allocated.update(_text(n, source) for n in _walk(declaration.child_by_field_name("declarator")) if n.type == "identifier")
    if any(n.type == "assignment_expression" and _text(n.child_by_field_name("left"), source) in allocated for n in _walk(body)):
        return False
    for node in _walk(body):
        if node.type == "return_statement" and node.named_children:
            value = node.named_children[0]
            while value.type in {"cast_expression", "parenthesized_expression"}:
                value = value.child_by_field_name("value") if value.type == "cast_expression" else value.named_children[0]
            if value.type == "call_expression":
                name = _text(value.child_by_field_name("function"), source)
                if name in {"malloc", "calloc"} and not any(f["name"] == name for f in snapshot.functions.values()):
                    return True
    return any(n.type == "return_statement" and n.named_children and n.named_children[0].type == "identifier"
               and _text(n.named_children[0], source) in allocated for n in _walk(body))


def allocated_export_proof(function, snapshot, bodies, parameter=None):
    """Every supported non-null exported value is a fresh, unreleased allocation."""
    from .proof_grounding import analyze
    if function['id'] not in bodies:
        return None
    proof = analyze(function, snapshot, bodies)
    paths = proof['paths']
    if not paths or any(p['uncertain'] for p in paths):
        return None
    values = [p['outputs'].get('parameter:' + parameter) if parameter else p['returned'] for p in paths]
    source, body = body_tree(function)
    allocations = {'local:' + function['id'] + ':' + str(n.start_byte) for n in _walk(body)
        if n.type == 'call_expression' and _text(n.child_by_field_name('function'), source) in {'malloc', 'calloc'}}
    nonnull = [(p, value) for p, value in zip(paths, values) if value != 'literal:0']
    if not nonnull or any(value not in allocations or value in p['released']
            for p, value in nonnull):
        return None
    # An absent out write is different from an explicit nullable returned value.
    if parameter and any(value is None for value in values):
        return None
    return proof


def exclusive_return_export_proof(function, snapshot, bodies):
    """A fresh return with no extra stored or passed pointer alias.

    Fresh allocation alone permits retained aliases. Array/dereference stores
    are not fully represented in the bounded effect interpreter, so this
    positive certificate also rejects their source forms. Local pointer aliases
    are tracked conservatively; unknown callee retention is never assumed safe.
    This guard does not assert that rejected source actually escapes.
    """
    proof = allocated_export_proof(function, snapshot, bodies)
    if not proof or any(p['returned'] != 'literal:0' and (p['returned'] in p['escapes']
            or p['returned'] in p['outputs'].values()
            or any(origin == p['returned'] for origin, _, _ in p['retentions'])) for p in proof['paths']):
        return None
    source, body = body_tree(function)
    exports = {p['returned'] for p in proof['paths'] if p['returned'] != 'literal:0'}
    allocation_offsets = {int(origin.rsplit(':', 1)[-1]) for origin in exports}
    declarations = [n for n in _walk(body) if n.type == 'init_declarator']
    # Use only actual declaration declarators, never field/type/RHS identifiers.
    local_names, retained_names = set(), set()
    for declaration in _walk(body):
        if declaration.type != 'declaration':
            continue
        retained = declaration.parent != body or any(child.type == 'storage_class_specifier' and _text(child, source) in
            {'static', 'extern', '_Thread_local', 'thread_local'} for child in declaration.named_children)
        for item in declaration.named_children:
            declarator = item.child_by_field_name('declarator') if item.type == 'init_declarator' else item
            if declarator.type in {'identifier', 'pointer_declarator', 'array_declarator', 'parenthesized_declarator'}:
                names = {_text(n, source) for n in _walk(declarator) if n.type == 'identifier'}
                (retained_names if retained else local_names).update(names)
    aliases = set()
    def contains_export(expression):
        return expression is not None and any(
            n.type == 'identifier' and _text(n, source) in aliases
            or n.type == 'call_expression' and n.start_byte in allocation_offsets
            for n in _walk(expression))
    assignments = [n for n in _walk(body) if n.type == 'assignment_expression']
    for _ in range(len(declarations) + len(assignments) + 1):
        previous = set(aliases)
        for node in declarations + assignments:
            value = node.child_by_field_name('value' if node.type == 'init_declarator' else 'right')
            if not contains_export(value):
                continue
            target = node.child_by_field_name('declarator' if node.type == 'init_declarator' else 'left')
            if node.type == 'assignment_expression':
                if target.type != 'identifier' or _text(target, source) not in local_names:
                    return None
                aliases.add(_text(target, source))
            else:
                if any(n.type == 'array_declarator' for n in _walk(target)) or not any(
                        n.type == 'pointer_declarator' for n in _walk(target)):
                    return None
                names = {_text(n, source) for n in _walk(target) if n.type == 'identifier'}
                if names & retained_names or not names <= local_names:
                    return None
                aliases.update(names)
        if previous == aliases:
            break
    for node in _walk(body):
        if node.type == 'call_expression' and any(contains_export(arg)
                for arg in node.child_by_field_name('arguments').named_children):
            return None
    return proof


def exclusive_parameter_use_proof(function, parameter, snapshot, bodies, *, depth=0):
    """Prove a pointer parameter is neither consumed nor retained through aliases.

    The effect interpreter does not represent every array/address store. This
    additional source guard tracks pointer aliases independently and rejects
    writes into non-local storage, pointer mutation and unverified callee use.
    Field reads and writes of unrelated values remain ordinary object accesses.
    Rejected syntax is unresolved; it does not assert an actual escape.
    """
    from .proof_grounding import analyze
    if depth > 2 or function['id'] not in bodies or parameter not in {
            p['name'] for p in function['parameters'] if p.get('is_pointer')}:
        return None
    summary = analyze(function, snapshot, bodies, _nonnull_parameters={parameter})
    origin = 'parameter:' + parameter
    if not summary['paths'] or any(p['uncertain'] or origin in p['escapes'] or origin in p['released']
            or p['release_counts'].get(origin, (0, 0)) != (0, 0) for p in summary['paths']):
        return None
    source, body = body_tree(function)
    automatic = set()
    declarations = [n for n in _walk(body) if n.type == 'init_declarator']
    assignments = [n for n in _walk(body) if n.type == 'assignment_expression']
    for declaration in _walk(body):
        if declaration.type != 'declaration' or declaration.parent != body or any(child.type == 'storage_class_specifier'
                and _text(child, source) in {'static', 'extern', '_Thread_local', 'thread_local'}
                for child in declaration.named_children):
            continue
        for item in declaration.named_children:
            declarator = item.child_by_field_name('declarator') if item.type == 'init_declarator' else item
            if any(n.type == 'pointer_declarator' for n in _walk(declarator)) and not any(
                    n.type == 'array_declarator' for n in _walk(declarator)):
                automatic.update(_text(n, source) for n in _walk(declarator) if n.type == 'identifier')
    aliases = {parameter}

    def contains_alias(node):
        if node is None:
            return False
        if node.type == 'identifier':
            return _text(node, source) in aliases
        if node.type == 'pointer_expression' and _text(node, source).lstrip().startswith('&'):
            # An interior address can retain the containing allocation too.
            return any(n.type == 'identifier' and _text(n, source) in aliases for n in _walk(node))
        # A field value is distinct from its containing object's address.
        if node.type in {'field_expression', 'subscript_expression', 'call_expression', 'sizeof_expression'}:
            return False
        return any(contains_alias(child) for child in node.named_children)

    def exact_alias(node):
        while node is not None and node.type in {'cast_expression', 'parenthesized_expression'}:
            node = node.child_by_field_name('value') if node.type == 'cast_expression' else node.named_children[0]
        return node is not None and node.type == 'identifier' and _text(node, source) in aliases

    for _ in range(len(declarations) + len(assignments) + 1):
        previous = set(aliases)
        for node in declarations + assignments:
            value = node.child_by_field_name('value' if node.type == 'init_declarator' else 'right')
            if not contains_alias(value):
                continue
            if not exact_alias(value):
                return None
            target = node.child_by_field_name('declarator' if node.type == 'init_declarator' else 'left')
            if node.type == 'assignment_expression':
                name = _text(target, source)
                if (target.type != 'identifier' or name not in automatic
                        or _text(node.child_by_field_name('operator'), source) != '='):
                    return None
                aliases.add(name)
            else:
                names = {_text(n, source) for n in _walk(target) if n.type == 'identifier'}
                if len(names) != 1 or not names <= automatic:
                    return None
                aliases.update(names)
        if previous == aliases:
            break
    for node in _walk(body):
        if node.type == 'assignment_expression':
            target = node.child_by_field_name('left')
            if target.type == 'identifier' and _text(target, source) in aliases and (
                    _text(node.child_by_field_name('operator'), source) != '=' or
                    not contains_alias(node.child_by_field_name('right'))):
                return None
        elif node.type == 'update_expression' and contains_alias(node.child_by_field_name('argument')):
            return None
        elif node.type == 'return_statement' and any(contains_alias(child) for child in node.named_children):
            return None
        elif node.type == 'call_expression':
            arguments = node.child_by_field_name('arguments').named_children
            protected = [i for i, argument in enumerate(arguments) if contains_alias(argument)]
            if not protected:
                continue
            target = node.child_by_field_name('function')
            callee = unique_callee(snapshot, _text(target, source), function) if target.type == 'identifier' else None
            if not callee or callee['id'] not in bodies or len(arguments) != len(callee['parameters']):
                return None
            for index in protected:
                if not exact_alias(arguments[index]) or not exclusive_parameter_use_proof(callee, callee['parameters'][index]['name'],
                        snapshot, bodies, depth=depth + 1):
                    return None
    return summary


def _cleanup_source_view(context, snapshot, records):
    """An authenticated argument graph containing no model semantics."""
    from .argument_graph import GraphBuilder
    empty = {'facts': [], 'core_apis': list(context.get('core_apis', [])),
        'input_contract': {'bindings': []}, 'buffer_length_contract': {'links': []},
        'argument_contract': {'arguments': []}, 'lifecycle_contract': {'resources': []},
        'ownership_contract': {'entries': []}, 'state_contract': {'preconditions': []}}
    ft = {'ft_id': 'cleanup_source_' + digest(snapshot.source_fingerprint)[:24],
        'core_functions': [{'function_id': fid} for fid in empty['core_apis']],
        'support_candidates': [], 'excluded_functions': []}
    builder = GraphBuilder(empty, ft, [], snapshot, records)
    return builder, builder.build()


def _exclusive_local_cleanup_chain(function, builder, graph, middle, cleanup, origin):
    """Reject unanalysed calls, aliases and extra uses of the held pointer."""
    source, body = body_tree(function)
    if body is None or body.has_error:
        return False
    nodes = {n['node_id']: n for n in graph['nodes']}
    local = nodes.get(cleanup['source_node'], {})
    if (local.get('node_type') != 'LocalValue' or local.get('function_id') != function['id']
            or middle and middle['source_node'] != cleanup['source_node']):
        return False
    offsets = [origin['call_offset']] + ([middle['call_offset']] if middle else []) + [cleanup['call_offset']]
    if offsets != sorted(set(offsets)):
        return False
    calls = sorted((n for n in _walk(body) if n.type == 'call_expression'), key=lambda n: n.start_byte)
    if ([n.start_byte for n in calls] != offsets or
            sorted(c['call_offset'] for c in builder.calls if c['caller_id'] == function['id']) != offsets):
        return False
    references = sorted((n for n in _walk(body) if n.type == 'identifier'
        and _text(n, source) == local.get('name')), key=lambda n: n.start_byte)
    if len(references) != len(offsets) or references[0].start_byte >= offsets[0]:
        return False
    if any(not call.start_byte < ref.start_byte < call.end_byte
            for call, ref in zip(calls[1:], references[1:])):
        return False
    declaration = references[0].parent
    while declaration is not None and declaration.type not in {'init_declarator', 'compound_statement'}:
        declaration = declaration.parent
    value = declaration.child_by_field_name('value') if declaration is not None and declaration.type == 'init_declarator' else None
    return value is not None and value.type == 'call_expression' and value.start_byte == offsets[0]


def exact_cleanup_connection(context, snapshot, records, function_id, parameter, return_value, cleanup_api, *, _view=None):
    """Prove a fresh caller origin reaches one exact cleanup slot.

    Declared ``void *`` endpoints may be bridged only by a certified forwarding
    edge. Model resource labels, ownership claims and lifecycle choices are not
    used. This proves an API connection, never ownership or support necessity.
    The narrow caller shape excludes additional calls/aliases which the source
    argument graph cannot yet propagate through all callee effects.
    """
    from .proof_grounding import analyze
    if cleanup_api not in snapshot.functions or function_id not in snapshot.functions:
        return None
    if not return_value and parameter not in {p['name'] for p in snapshot.functions[function_id]['parameters']}:
        return None
    builder, graph = _view or _cleanup_source_view(context, snapshot, records)
    bodies = builder.bodies
    if function_id not in bodies or cleanup_api not in bodies:
        return None
    nodes = {n['node_id']: n for n in graph['nodes']}
    resolved = {c['target_parameter']: c for c in graph['dependency_graph']['resolved_parameters']}
    parameters = {(n['function_id'], n['name']): n['node_id'] for n in nodes.values() if n['node_type'] == 'Parameter'}

    def trace(fid, name):
        candidate = resolved.get(parameters.get((fid, name)))
        evidence, source_ids, seen = set(), set(), set()
        while candidate and candidate.get('basis') in {'callback_parameter_forwarding', 'internal_parameter_forwarding'}:
            if candidate['target_parameter'] in seen:
                return None
            seen.add(candidate['target_parameter'])
            target, source_node = nodes[candidate['target_parameter']], nodes.get(candidate['source_node'], {})
            internal = candidate['basis'] == 'internal_parameter_forwarding'
            descriptors = [d for d in graph.get('internal_invocations' if internal else 'callback_dispatches', [])
                if d['proof_status'] == 'proven' and d['function_id'] == target['function_id']
                and d['via_function_id'] == source_node.get('function_id')
                and {'parameter': target['name'], 'via_parameter': source_node.get('name')} in d['parameter_forwarding']
                and (not internal or d['invocation_proof_id'] == candidate.get('invocation_proof_id'))]
            if len(descriptors) != 1:
                return None
            evidence.update(descriptors[0]['evidence_ids'])
            source_ids.update((target['function_id'], source_node['function_id']))
            candidate = resolved.get(candidate['source_node'])
        if not candidate or candidate.get('basis') != 'call_site_value_flow' or not candidate.get('resource_id'):
            return None
        return candidate, evidence, source_ids

    def nonconsuming(fid, name):
        return exclusive_parameter_use_proof(snapshot.functions[fid], name, snapshot, bodies)

    if return_value:
        origins = [n['origin'] for n in graph['resource_origins']
            if n['origin']['function_id'] == function_id and n['origin']['kind'] == 'return']
        if len(origins) != 1:
            return None
        origin = origins[0]
        rid = next(n['resource_id'] for n in graph['resource_origins'] if n['origin'] == origin)
        subjects = [(None, set(), set(), None)]
        # A callback target's all-path effect proof closes its thin dispatcher.
        for (fid, name), pid in parameters.items():
            forwarded = trace(fid, name)
            if not forwarded or forwarded[0]['resource_id'] != rid or fid == cleanup_api:
                continue
            via = nodes[forwarded[0]['target_parameter']]['function_id']
            if fid not in context.get('core_apis', []) and via not in context.get('core_apis', []):
                continue
            summary = nonconsuming(fid, name)
            if summary:
                subjects.append((*forwarded, summary))
    else:
        forwarded = trace(function_id, parameter)
        summary = nonconsuming(function_id, parameter)
        if not forwarded or not summary:
            return None
        rid = forwarded[0]['resource_id']
        origins = [n['origin'] for n in graph['resource_origins'] if n['resource_id'] == rid]
        if len(origins) != 1:
            return None
        origin = origins[0]
        subjects = [(*forwarded, summary)]
    creator, caller = origin.get('function_id'), origin.get('caller_id')
    if origin.get('kind') != 'return' or creator not in bodies or caller not in bodies:
        return None
    allocation = exclusive_return_export_proof(snapshot.functions[creator], snapshot, bodies)
    if not allocation:
        return None
    slots = [(name, resolved[pid]) for (fid, name), pid in parameters.items() if fid == cleanup_api
        and pid in resolved and resolved[pid].get('resource_id') == rid
        and resolved[pid].get('basis') == 'call_site_value_flow']
    if len(slots) != 1:
        return None
    cleanup_parameter, cleanup = slots[0]
    declared = next(p for p in snapshot.functions[cleanup_api]['parameters'] if p['name'] == cleanup_parameter)
    if declared.get('base_type') != origin.get('type') or declared.get('pointer_depth') != origin.get('pointer_depth'):
        return None
    release = parameter_release_proof(snapshot.functions[cleanup_api], cleanup_parameter, snapshot, bodies)
    if not release or cleanup.get('caller_id') != caller:
        return None
    for middle, evidence, forwarding_ids, summary in subjects:
        if middle and (middle['caller_id'] != caller or middle['resource_id'] != rid):
            continue
        if not _exclusive_local_cleanup_chain(snapshot.functions[caller], builder, graph, middle, cleanup, origin):
            continue
        source_ids = {function_id, cleanup_api, creator, caller} | forwarding_ids \
            | set(allocation['source_function_ids']) | set(release['source_function_ids'])
        if summary:
            source_ids.update(summary['source_function_ids'])
        if not source_ids <= bodies.keys():
            continue
        certificate = {'version': 'source-cleanup-connection-v2',
            'source_fingerprint': snapshot.source_fingerprint,
            'kind': 'source_exact_cleanup_connection', 'proof_status': 'proven',
            'function_id': function_id, 'parameter': parameter, 'return_value': return_value,
            'cleanup_api': cleanup_api, 'cleanup_parameter': cleanup_parameter,
            'creator_api': creator, 'resource_id': rid, 'caller_id': caller,
            'creator_call_offset': origin['call_offset'], 'cleanup_call_offset': cleanup['call_offset'],
            'source_function_ids': sorted(source_ids),
            'evidence_ids': sorted(evidence | set(cleanup['evidence_ids']) | set().union(*(bodies[fid] for fid in source_ids)))}
        certificate['proof_id'] = 'cleanup_connection_' + digest(certificate)[:24]
        return certificate
    return None


def project_callback_identities(context, graph, snapshot):
    """Carry one certified caller origin into its exact indirect endpoint.

    Only the graph's synchronous forwarding certificate and a resolved source
    origin authorize normalization. Shared types and model resource labels do
    not contribute to this proof, and competing origins remain unresolved.
    """
    nodes = {n['node_id']: n for n in graph['nodes']}
    resolved = defaultdict(list)
    for candidate in graph['dependency_graph']['resolved_parameters']:
        resolved[candidate['target_parameter']].append(candidate)
    certificates = defaultdict(list)
    for candidate in graph['construction_candidates']:
        if (candidate.get('basis') not in {'callback_parameter_forwarding', 'internal_parameter_forwarding'}
                or candidate.get('proof_status') != 'proven'):
            continue
        source, target = nodes.get(candidate['source_node']), nodes.get(candidate['target_parameter'])
        if not source or not target or source['node_type'] != 'Parameter' or target['node_type'] != 'Parameter':
            continue
        internal = candidate['basis'] == 'internal_parameter_forwarding'
        dispatch = [d for d in graph.get('internal_invocations' if internal else 'callback_dispatches', []) if d['proof_status'] == 'proven'
            and d['via_function_id'] == source['function_id'] and d['function_id'] == target['function_id']
            and {'parameter': target['name'], 'via_parameter': source['name']} in d['parameter_forwarding']
            and (not internal or d['invocation_proof_id'] == candidate.get('invocation_proof_id'))]
        origins = {p['resource_id'] for p in resolved[source['node_id']] if p.get('resource_id')}
        if len(dispatch) != 1 or len(origins) != 1 or not resolved[target['node_id']]:
            continue
        certificates[(target['function_id'], target['name'], False)].append((next(iter(origins)), candidate))
    bindings = context['resource_identity']['bindings']
    for subject, rows in certificates.items():
        origins = {rid for rid, _ in rows}
        existing = {b['resource_id'] for b in bindings if endpoint(b) == subject
            and b['reason'] != 'distinct_subject'}
        if len(origins) != 1 or existing - origins:
            continue
        rid = next(iter(origins))
        producer_ids = {o['origin']['function_id'] for o in graph['resource_origins'] if o['resource_id'] == rid}
        evidence = sorted({e for _, candidate in rows for e in candidate['evidence_ids']})
        for section, field in (('argument_contract', 'arguments'), ('ownership_contract', 'entries'),
                ('lifecycle_contract', 'resources')):
            for row in context[section][field]:
                if endpoint(row) == subject and row.get('field') is None:
                    if section == 'argument_contract' and row['construction'] == 'creator_api' and row['api'] not in producer_ids:
                        continue  # Origin normalization cannot correct a different creator claim.
                    row['resource_id'] = rid
        bindings[:] = [b for b in bindings if endpoint(b) != subject]
        bindings.append({'function_id': subject[0], 'parameter': subject[1], 'return_value': False,
            'resource_id': rid, 'reason': 'source_' + rows[0][1]['basis'], 'evidence_ids': evidence,
            'candidate_ids': sorted(c['candidate_id'] for _, c in rows)})
    bindings.sort(key=canonical)


def resolve_resources(context, snapshot, records, *, allowed=None):
    resources = context["lifecycle_contract"]["resources"]
    flow = resource_flows(snapshot, records)
    observed = defaultdict(dict)
    for row in flow["observations"]:
        observed[endpoint(row)][row["resource_id"]] = row
    mapping, bindings, unresolved = {}, [], list(flow["unresolved"])
    planned = {s['creator_api']: s for s in context.get('construction_contract', {}).get('sources', [])
        if s['kind'] == 'cleanup_consumption' and s.get('binding_scope') == 'single_harness_invocation'}
    for row in resources:
        subject = endpoint(row)
        values = observed.get(subject, {})
        if row['return_value'] and row['function_id'] in planned:
            proof = planned[row['function_id']]
            rid, reason, eids = proof['resource_id'], 'single_harness_owned_return_binding', proof['evidence_ids']
        elif len(values) == 1:
            proof = next(iter(values.values()))
            rid, reason, eids = proof["resource_id"], "source_value_flow", proof["evidence_ids"]
        else:
            origin = {"function_id": subject[0], "kind": "return" if subject[2] else "parameter",
                      "parameter": subject[1], "type": row["type"]}
            rid, reason, eids = "resource_" + digest(origin)[:24], "distinct_subject", row["evidence_ids"]
            if len(values) > 1:
                unresolved.append({"function_id": subject[0], "parameter": subject[1],
                    "reason": "multiple_runtime_origins", "origins": sorted(values), "evidence_ids": sorted({e for v in values.values() for e in v["evidence_ids"]})})
        mapping[subject] = rid
        bindings.append({"function_id": subject[0], "parameter": subject[1], "return_value": subject[2],
                         "resource_id": rid, "reason": reason, "evidence_ids": sorted(eids)})
    for proof in planned.values():
        mapping[proof['function_id'], proof['parameter'], False] = proof['resource_id']
    # Explicit construction of a harness argument, not type-based aliasing:
    # a single requested creator invocation feeds a single constructed subject.
    # Multiple consumers are NOT collapsed without source value-flow proof.
    bodies = complete_bodies(snapshot, records)
    release_bodies = {api: eids for api, eids in bodies.items() if allowed is None or api in allowed}
    constructed = defaultdict(set)
    arguments = context["argument_contract"]["arguments"]
    for row in resources:
        if row["creation"]["kind"] != "creator_api" or row["return_value"]:
            continue
        api = row["creation"]["api"]
        matching = [a for a in arguments if a["function_id"] == row["function_id"]
            and a["parameter"] == row["subject_parameter"] and a["construction"] == "creator_api" and a["api"] == api]
        producer = snapshot.functions.get(api, {})
        parameter = next(p for p in snapshot.functions[row["function_id"]]["parameters"] if p["name"] == row["subject_parameter"])
        if matching and api in bodies and producer.get("return_pointer_depth") == parameter.get("pointer_depth") and producer.get("return_base_type") == row["type"]:
            constructed[(api, row["type"])].add(mapping[endpoint(row)])
    for row in resources:
        if not row["return_value"]:
            continue
        subject = endpoint(row)
        candidates = constructed.get((row["function_id"], row["type"]), set())
        if not observed.get(subject) and len(candidates) == 1:
            mapping[subject] = next(iter(candidates))
            for binding in bindings:
                if endpoint(binding) == subject:
                    binding.update(resource_id=mapping[subject], reason="unique_harness_creator_binding")
        elif not observed.get(subject) and len(candidates) > 1:
            unresolved.append({"function_id": subject[0], "parameter": None,
                "reason": "creator_invocation_multiplicity", "origins": sorted(candidates), "evidence_ids": row["evidence_ids"]})
    raw_aliases = defaultdict(set)
    raw_subjects = defaultdict(set)
    for row in resources:
        raw_aliases[row["resource_id"]].add(mapping[endpoint(row)])
        raw_subjects[row["resource_id"]].add(row["function_id"])
    # Proved use endpoints can bind construction/ownership without requiring
    # redundant lifecycle rows for cleanup/consumer SUPPORT APIs.
    for subject, values in observed.items():
        if len(values) == 1 and subject not in mapping:
            mapping[subject] = next(iter(values))
    # A unique owned producer + explicit release contract + actual deallocation
    # body fixes the harness cleanup binding. This does not equate arbitrary
    # same-type API parameters or infer ownership from a function's spelling.
    for argument in arguments:
        subject = endpoint(argument)
        if observed.get(subject):
            continue
        fid, name = subject[:2]
        function = snapshot.functions[fid]
        parameter = next(p for p in function["parameters"] if p["name"] == name)
        release = parameter_release_proof(function, name, snapshot, release_bodies)
        if not release:
            continue
        if any(p['name'] != name and p.get('pointer_depth') == parameter.get('pointer_depth')
                and p.get('base_type') == parameter.get('base_type')
                and releases_parameter(function, p['name'], snapshot, release_bodies)
                for p in function['parameters']):
            continue
        producers = [r for r in resources if r["return_value"] and r["cleanup"]["mandatory"] and r["cleanup"]["api"] == fid
            and r["type"] == parameter.get("base_type") and r["function_id"] in bodies and allocated_return(snapshot.functions[r["function_id"]], snapshot)
            and snapshot.functions[r["function_id"]].get("return_pointer_depth", 0) == parameter.get("pointer_depth", 0)
            and (argument["api"] is None or argument["api"] == r["function_id"])
            and any(o["function_id"] == r["function_id"] and o["return_value"] and o["ownership"] == "owned" and o["release_api"] == fid
                    for o in context["ownership_contract"]["entries"])]
        origins = {mapping[endpoint(r)] for r in producers}
        if len(origins) == 1:
            mapping[subject] = next(iter(origins))
            bindings.append({"function_id": fid, "parameter": name, "return_value": False,
                "resource_id": mapping[subject], "reason": "unique_owned_return_release_binding",
                "evidence_ids": sorted(set().union(*(bodies[api] for api in release['source_function_ids']))
                    | {e for r in producers for e in r["evidence_ids"]})})
            argument.update(construction="derived", api=None)
    for section, field in (("lifecycle_contract", "resources"), ("argument_contract", "arguments"),
                           ("ownership_contract", "entries"), ("ordering_contract", "constraints")):
        for row in context[section][field]:
            if section == 'ownership_contract' and row.get('subject_kind') == 'PointerParameter' and any(
                    p['name'] == row['parameter'] and p.get('pointer_depth', 0) >= 2
                    for p in snapshot.functions[row['function_id']]['parameters']):
                continue  # Pointer storage is distinct from the produced pointee.
            raw = row.get("resource_id")
            subject = endpoint(row)
            if row.get("field") is not None:
                continue
            if raw is None:
                # Only a proven flow into a real lifecycle resource; raw input
                # observations are not constructed objects.
                if section in {"argument_contract", "ownership_contract"} and mapping.get(subject) in set(mapping[endpoint(r)] for r in resources):
                    row["resource_id"] = mapping[subject]
                continue
            candidates = raw_aliases.get(raw, set())
            if subject in mapping:
                row["resource_id"] = mapping[subject]
            elif len(candidates) == 1:
                # A model ID alone cannot connect unrelated endpoints. Only
                # reuse within a subject already proved by lifecycle/flow.
                same_subject = row["function_id"] in raw_subjects[raw]
                if same_subject:
                    row["resource_id"] = next(iter(candidates))
            # Unknown IDs deliberately survive: phantom-resource Gate rejects.
    # Cleanup proofs were projected before identity normalization. Keep their
    # exact consumer slot and certificate reference aligned with that mapping.
    for source in context.get('construction_contract', {}).get('sources', []):
        if source['kind'] != 'cleanup_consumption':
            continue
        normalized = mapping.get((source['function_id'], source['parameter'], False))
        if normalized is None or normalized == source['resource_id']:
            continue
        old = source['construction_id']
        source['resource_id'] = normalized
        source['construction_id'] = 'construction_' + digest({k:v for k,v in source.items() if k != 'construction_id'})[:24]
        for argument in arguments:
            if argument.get('construction_source') == old:
                argument['construction_source'] = source['construction_id']
    reuse_projections = []
    groups = defaultdict(list)
    for row in resources:
        groups[row["resource_id"]].append(row)
    for rid, group in groups.items():
        reuse = {r["reuse"] for r in group}
        origins = [o for o in flow["observations"] if o["resource_id"] == rid and o["return_value"]]
        released = any(o["resource_id"] == rid and any(o["function_id"] == r["cleanup"]["api"] for r in group) for o in flow["observations"])
        if reuse == {"per_input", "per_context"} and released and origins and all(allocated_return(snapshot.functions[o["function_id"]], snapshot) for o in origins):
            # Both contracts allow one freshly allocated context per input. The
            # straight-line caller allocates and releases it in this invocation.
            for row in group:
                row["reuse"] = "per_input"
            reuse_projections.append({"resource_id": rid, "scope": "per_input", "reason": "fresh_local_create_release_interval",
                "evidence_ids": sorted({e for o in flow["observations"] if o["resource_id"] == rid for e in o["evidence_ids"]})})
    return {"version": VERSION, "bindings": sorted(bindings, key=canonical), "reuse_projections": reuse_projections,
            "value_flow": flow, "unresolved": sorted(unresolved, key=canonical)}
