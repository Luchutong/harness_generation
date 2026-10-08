"""Bounded source effects for exact support subjects, independent of API names.

An effect is an admissible relation, not a proof that a call is mandatory.
Only supplied complete bodies participate; signatures alone issue no effects.
"""
from ..semantic_discovery.tools import _walk, _text
from .core_proofs import tree, accesses

VERSION = "subject-support-effects-v3"


def releases(function, parameter, functions, issued, depth=0):
    if function['id'] not in issued or depth > 2:
        return False
    source, body = tree(function)
    if body is None or body.has_error:
        return False
    for node in _walk(body):
        if node.type != 'call_expression':
            continue
        target = node.child_by_field_name('function')
        if target.type != 'identifier':
            continue
        name = _text(target, source)
        args = node.child_by_field_name('arguments').named_children
        matches = [f for f in functions.values() if f['name'] == name and f.get('defined')]
        if name == 'free' and not matches and len(args) == 1 and _text(args[0], source) == parameter:
            return True
        local = [f for f in matches if f['file'] == function['file']]
        matches = local if len(local) == 1 else matches
        if len(matches) == 1:
            callee = matches[0]
            for p, arg in zip(callee['parameters'], args):
                if _text(arg, source) == parameter and releases(callee, p['name'], functions, issued, depth + 1):
                    return True
    return False


def bindings(parent, api, functions, issued, *, release_summary=None):
    if parent['id'] not in issued or api['id'] not in issued:
        return {}
    source, body = tree(api)
    if body is None or body.has_error:
        return {}
    reads, _ = accesses(parent)
    _, writes = accesses(api)
    subjects = [dict(parameter=p['name'], type=p['base_type'], pointer_depth=p.get('pointer_depth', 0), subject_kind='PointerParameter')
        for p in parent.get('parameters', []) if p.get('is_pointer') or p.get('is_struct_like')]
    parent_source, parent_body = tree(parent)
    for p in parent.get('parameters', []):
        if p.get('pointer_depth', 0) >= 2 and parent_body is not None and any(
                n.type == 'assignment_expression' and _text(n.child_by_field_name('left'), parent_source).replace(' ', '') == '*' + p['name']
                for n in _walk(parent_body)):
            subjects.append(dict(parameter=p['name'], type=p['base_type'], pointer_depth=p['pointer_depth'] - 1, subject_kind='OutParameterPointee'))
    if parent.get('return_pointer_depth'):
        subjects.append(dict(parameter=None, type=parent['return_base_type'], pointer_depth=parent['return_pointer_depth'], subject_kind='PointerReturn'))
    rows = {}
    def add(reason, subject, effect, api_parameter=None, fields=()):
        rows.setdefault(reason, []).append({**subject, 'api_parameter': api_parameter,
            'effect': effect, 'fields': sorted(fields)})
    def compatible(subject, base, depth):
        return depth == subject['pointer_depth'] and (subject['type'] == base or subject['type'] == 'void' and depth == 1)
    has_return = any(n.type == 'return_statement' and n.named_children for n in _walk(body))
    for subject in subjects:
        if (subject['subject_kind'] != 'PointerReturn' and has_return
                and api.get('return_pointer_depth')
                and compatible(subject, api.get('return_base_type'), api['return_pointer_depth'])):
            # Returned storage is an actual construction mechanism. Necessity,
            # aliasing, ownership and invocation identity remain Context work.
            add('creation', subject, 'pointer_return')
            add('initialization', subject, 'pointer_return')
        for p in api.get('parameters', []):
            # The parent's return object is produced by the parent's own call.
            # A same-type producer (including an internal delegate) cannot
            # establish a separate harness invocation to construct that output.
            # Creators for actual input subjects remain admissible; returned
            # subjects still participate in cleanup effects below.
            if (subject['subject_kind'] != 'PointerReturn' and p.get('pointer_depth', 0) >= 2
                    and compatible(subject, p['base_type'], p['pointer_depth'] - 1)):
                if any(n.type == 'assignment_expression' and
                    _text(n.child_by_field_name('left'), source).replace(' ', '') == '*' + p['name'] for n in _walk(body)):
                    add('creation', subject, 'out_parameter_write', p['name'])
                    add('initialization', subject, 'out_parameter_write', p['name'])
            if not compatible(subject, p['base_type'], p.get('pointer_depth', 0)):
                continue
            grounded_release = (release_summary and release_summary['paths']
                and all(not path['uncertain'] and path['release_counts'].get('parameter:' + p['name']) == (1, 1)
                    for path in release_summary['paths']))
            if releases(api, p['name'], functions, issued) or grounded_release:
                add('cleanup', subject, 'parameter_release', p['name'])
            fields = set(writes.get(p['name'], {})) & set(reads.get(subject['parameter'], ()))
            if fields:
                for reason in ('initialization', 'configuration', 'other'):
                    add(reason, subject, 'observed_field_write', p['name'], fields)
    return rows
