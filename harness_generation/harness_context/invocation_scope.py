"""A finite fresh-resource scope, independently reproducible from issued source.

This reconciles two reuse labels only inside a proved local creation/use/release
scope. It supplies neither ownership facts nor missing lifecycle obligations.
Branches other than an exact non-null guard and arbitrary resource aliases are
deliberately outside this certificate.
"""
from copy import deepcopy
import re

from ..semantic_discovery.models import canonical, digest
from ..semantic_discovery.tools import _text, _walk
from .internal_invocations import _non_escaping_arguments, repeated_invocations, unwrap
from .resource_identity import allocated_export_proof, parameter_release_proof
from .value_flow import body_tree, unique_callee

VERSION = "finite-resource-invocation-scope-v1"


def _statements(body):
    return [n for n in body.named_children if n.type != 'comment']


def _nonnull_guard(node, name, source):
    node = unwrap(node)
    if node is not None and node.type == 'identifier':
        return _text(node, source) == name
    if node is not None and node.type == 'binary_expression':
        left, right = unwrap(node.child_by_field_name('left')), unwrap(node.child_by_field_name('right'))
        return (left is not None and left.type == 'identifier' and _text(left, source) == name
            and _text(node.child_by_field_name('operator'), source) == '!='
            and right is not None and _text(right, source) in {'0', 'NULL'})
    return False


def _ordinary_nonretaining(function, parameter, snapshot, bodies):
    """Narrow direct consumer: pointer field reads/writes and memory intrinsics."""
    if function['id'] not in bodies or not _non_escaping_arguments(function, snapshot, {parameter}, set()):
        return None
    source, body = body_tree(function)
    shadowed = {f['name'] for f in snapshot.functions.values() if f.get('defined')} | {
        p['name'] for p in function['parameters']}
    for declaration in (n for n in _walk(body) if n.type == 'declaration'):
        for declarator in declaration.named_children:
            if declarator.type == 'init_declarator':
                declarator = declarator.child_by_field_name('declarator')
            if declarator is not None and (declarator.type.endswith('declarator') or declarator.type == 'identifier'):
                shadowed.update(_text(n, source) for n in _walk(declarator) if n.type == 'identifier')
    for node in _walk(body):
        if node.type in {'while_statement', 'for_statement', 'do_statement', 'switch_statement',
                         'goto_statement', 'preproc_if', 'preproc_ifdef'}:
            return None
        if node.type == 'call_expression':
            target = node.child_by_field_name('function')
            if (target is None or target.type != 'identifier' or _text(target, source) in shadowed
                    or _text(target, source) not in {'memcpy', 'memmove', 'memset'}):
                return None
    return {'function_id': function['id'], 'parameter': parameter,
            'kind': 'source_nonretaining_parameter', 'source_function_ids': [function['id']]}


def _fresh_export_is_exclusive(function, proof):
    """Close pointer stores outside the transfer engine's field vocabulary.

    The returned fresh object may initialize its fields, but its address must
    not also be published to a subscript, out slot, global, or another callee.
    Only the explicit return exports this address in this bounded pattern.
    """
    allocations = {p['returned'] for p in proof['paths'] if p['returned'] != 'literal:0'}
    if any(value in allocations for p in proof['paths'] for value in p['outputs'].values()):
        return False
    protected = {name for p in proof['paths'] for name, value in p['env'].items() if value in allocations}
    source, body = body_tree(function)
    for node in _walk(body):
        if node.type != 'identifier' or _text(node, source) not in protected:
            continue
        parent = node.parent
        # sizeof has no evaluated pointer use, and the allocation declarator
        # introduces storage rather than exporting an address.
        ancestor = parent
        unevaluated = False
        while ancestor is not None and ancestor != body:
            if ancestor.type == 'sizeof_expression':
                unevaluated = True
                break
            ancestor = ancestor.parent
        if unevaluated or parent.type == 'pointer_declarator':
            continue
        if parent.type == 'field_expression' and parent.child_by_field_name('argument') == node:
            # &r->field publishes an address within the resource as well.
            ancestor = parent.parent
            if ancestor.type == 'pointer_expression' and _text(ancestor, source).lstrip().startswith('&'):
                return False
            continue
        if parent.type == 'return_statement' and len(parent.named_children) == 1:
            continue
        if parent.type in {'parenthesized_expression', 'binary_expression'}:
            # Exact local non-null guards are not an escape.
            ancestor = parent
            while ancestor is not None and ancestor.type in {'parenthesized_expression', 'binary_expression'}:
                ancestor = ancestor.parent
            if ancestor is not None and ancestor.type == 'if_statement' and _nonnull_guard(
                    ancestor.child_by_field_name('condition'), _text(node, source), source):
                continue
        return False
    return True


def _consumer_proof(function, parameter, snapshot, bodies, descriptors):
    ordinary = _ordinary_nonretaining(function, parameter, snapshot, bodies)
    if ordinary:
        return ordinary, []
    rebuilt = repeated_invocations(function, snapshot, bodies)
    matches = [d for d in rebuilt if d in descriptors and any(
        p['via_parameter'] == parameter for p in d['parameter_forwarding'])]
    if len(matches) != 1:
        return None
    descriptor = matches[0]
    # A certified loop has exactly one call. Check every other occurrence of
    # this pointer too: a local alias, return, address escape or pointer-valued
    # store outside that call cannot hide behind the forwarding descriptor.
    source, body = body_tree(function)
    call = next(n for n in _walk(body) if n.type == 'call_expression')
    arguments = call.child_by_field_name('arguments').named_children
    forwarded = {a.start_byte for a in arguments if a.type == 'identifier' and _text(a, source) == parameter}
    for node in _walk(body):
        if node.type == 'identifier' and _text(node, source) == parameter and node.start_byte not in forwarded:
            return None
    child = snapshot.functions[descriptor['function_id']]
    # Repeated invocations already check all protected helper arguments. This
    # stricter consumer boundary additionally excludes unknown/retaining calls
    # that do not mention the root directly, and loops inside the reader.
    for binding in descriptor['parameter_forwarding']:
        if binding['via_parameter'] == parameter and not _ordinary_nonretaining(child, binding['parameter'], snapshot, bodies):
            return None
    return ({'function_id': function['id'], 'parameter': parameter,
             'kind': 'source_internal_nonretaining_parameter',
             'invocation_proof_id': descriptor['invocation_proof_id'],
             'source_function_ids': [function['id'], child['id']]}, [descriptor])


def prove_finite_resource_scope(context, resource_id, rows, snapshot, bodies):
    """Prove fresh create→use→exact cleanup in one source caller invocation.

    `bodies` is the authenticated complete-body map. The Plan can independently
    rebuild this certificate from its source_evidence map and frozen snapshot.
    Original rows remain intact; a conflict in any other definition stays hard.
    """
    if not rows or snapshot is None:
        return None
    definitions = {canonical({k: r[k] for k in ('type', 'creation', 'cleanup')}) for r in rows}
    if len(definitions) != 1 or {r['reuse'] for r in rows} != {'per_context', 'per_input'}:
        return None
    definition = rows[0]
    creation, cleanup = definition['creation'], definition['cleanup']
    if creation['kind'] != 'creator_api' or not cleanup['mandatory'] or not creation['api'] or not cleanup['api']:
        return None
    graph = context.get('argument_graph', {})
    origins = [r['origin'] for r in graph.get('resource_origins', []) if r['resource_id'] == resource_id]
    if len(origins) != 1:
        return None
    origin = origins[0]
    creator = snapshot.functions.get(creation['api'])
    caller = snapshot.functions.get(origin.get('caller_id'))
    if (not creator or not caller or origin.get('kind') != 'return'
            or origin['function_id'] != creator['id'] or origin.get('pointer_depth') != 1
            or origin.get('type') != definition['type']
            or resource_id != 'resource_' + digest(origin)[:24]
            or creator['id'] not in bodies or caller['id'] not in bodies):
        return None
    fresh = allocated_export_proof(creator, snapshot, bodies)
    if not fresh or any(p['returned'] in p['escapes'] or any(t[0] == p['returned'] for t in p['retentions'])
                        for p in fresh['paths']) or not _fresh_export_is_exclusive(creator, fresh):
        return None
    source, body = body_tree(caller)
    if body is None or body.has_error or not caller['file'].endswith('.c'):
        return None
    statements = _statements(body)
    if len(statements) != 2 or statements[0].type != 'declaration' or statements[1].type != 'if_statement':
        return None
    declaration, guard = statements
    if re.search(r'\b(?:static|extern|volatile)\b', _text(declaration, source)):
        return None
    initializers = [n for n in declaration.named_children if n.type == 'init_declarator']
    if len(initializers) != 1 or any(n.type.endswith('declarator') and n.type != 'init_declarator'
                                   for n in declaration.named_children):
        return None
    initial = initializers[0]
    declarator = initial.child_by_field_name('declarator')
    names = [_text(n, source) for n in _walk(declarator) if n.type == 'identifier']
    value = unwrap(initial.child_by_field_name('value'))
    if (len(names) != 1 or declarator.type != 'pointer_declarator'
            or value is None or value.type != 'call_expression' or value.start_byte != origin['call_offset']):
        return None
    local = names[0]
    target = value.child_by_field_name('function')
    if (target is None or target.type != 'identifier'
            or _text(target, source) in {p['name'] for p in caller['parameters']}
            or unique_callee(snapshot, _text(target, source), caller) != creator
            or len([n for n in _walk(declaration) if n.type == 'call_expression']) != 1
            or local in {p['name'] for p in caller['parameters']}):
        return None
    if (guard.child_by_field_name('alternative') is not None
            or not _nonnull_guard(guard.child_by_field_name('condition'), local, source)):
        return None
    branch = guard.child_by_field_name('consequence')
    if branch is None or branch.type != 'compound_statement':
        return None
    uses = _statements(branch)
    if len(uses) < 2:
        return None
    endpoints = {(creator['id'], None, True)}
    certificates, internal, cleanup_binding = [], [], None
    sources = set(fresh['source_function_ids']) | {caller['id']}
    parameter_names = {p['name'] for p in caller['parameters']}
    for index, statement in enumerate(uses):
        if statement.type != 'expression_statement' or len(statement.named_children) != 1:
            return None
        call = unwrap(statement.named_children[0])
        if call is None or call.type != 'call_expression' or len([n for n in _walk(call) if n.type == 'call_expression']) != 1:
            return None
        target = call.child_by_field_name('function')
        if target is None or target.type != 'identifier' or _text(target, source) in parameter_names | {local}:
            return None
        callee = unique_callee(snapshot, _text(target, source), caller) if target is not None and target.type == 'identifier' else None
        if not callee or callee['id'] not in bodies:
            return None
        arguments = call.child_by_field_name('arguments').named_children
        if len(arguments) != len(callee['parameters']):
            return None
        positions = []
        for i, argument in enumerate(arguments):
            argument = unwrap(argument)
            if argument.type == 'identifier' and _text(argument, source) == local:
                positions.append(i)
            elif argument.type == 'identifier' and _text(argument, source) in parameter_names:
                pass
            elif argument.type != 'number_literal':
                return None
        if len(positions) != 1:
            return None
        parameter = callee['parameters'][positions[0]]
        if parameter.get('pointer_depth') != 1 or parameter.get('base_type') != definition['type']:
            return None
        subject = (callee['id'], parameter['name'], False)
        endpoints.add(subject)
        if index == len(uses) - 1:
            if callee['id'] != cleanup['api']:
                return None
            release = parameter_release_proof(callee, parameter['name'], snapshot, bodies)
            if not release:
                return None
            sources.update(release['source_function_ids'])
            cleanup_binding = {'function_id': callee['id'], 'parameter': parameter['name'], 'call_offset': call.start_byte}
        else:
            if callee['id'] in {creator['id'], cleanup['api']}:
                return None
            proof = _consumer_proof(callee, parameter['name'], snapshot, bodies, graph.get('internal_invocations', []))
            if not proof:
                return None
            certificate, children = proof
            certificates.append({**certificate, 'call_offset': call.start_byte})
            internal.extend(children)
            sources.update(certificate['source_function_ids'])
            for d in children:
                endpoints.update((d['function_id'], p['parameter'], False) for p in d['parameter_forwarding']
                                 if p['via_parameter'] == parameter['name'])
    # Every lifecycle subject must be one exact source endpoint. A matching type
    # or a model-supplied shared resource ID alone never establishes this.
    if any((r['function_id'], r['subject_parameter'], r['return_value']) not in endpoints for r in rows):
        return None
    proof = {'version': VERSION, 'resource_id': resource_id, 'proof_status': 'proven',
        'effective_reuse': 'per_input', 'scope': 'fresh_create_use_cleanup_within_one_invocation',
        'origin': deepcopy(origin), 'creator_id': creator['id'], 'caller_id': caller['id'],
        'source_fingerprint': snapshot.source_fingerprint,
        'local_parameter': local, 'nonnull_guard': True, 'cleanup_binding': cleanup_binding,
        'consumer_bindings': sorted(certificates, key=canonical),
        'internal_invocation_ids': sorted({d['invocation_proof_id'] for d in internal}),
        'observed_reuse': sorted([{'function_id': r['function_id'], 'parameter': r['subject_parameter'],
            'return_value': r['return_value'], 'reuse': r['reuse'], 'fact_id': r['fact_id']} for r in rows], key=canonical),
        'resource_bindings': sorted([{'function_id': r['function_id'], 'parameter': r['subject_parameter'],
            'return_value': r['return_value'], 'resource_id': resource_id} for r in rows], key=canonical),
        'source_evidence': {fid: sorted(bodies[fid]) for fid in sorted(sources)},
        'evidence_ids': sorted({e for fid in sources for e in bodies[fid]})}
    return {**proof, 'scope_proof_id': 'invocation_scope_' + digest(proof)[:24]}
