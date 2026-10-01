"""Source-issued byte-buffer/extent choices, without parameter-name rules."""
from ..semantic_discovery.models import canonical, digest
from ..semantic_discovery.tools import _walk, _text
from .value_flow import body_tree

VERSION = 'input-length-pairs-v1'
BYTE_TYPES = {'char', 'signed char', 'unsigned char', 'uint8_t', 'int8_t'}


def buffer_pairs(function):
    source, body = body_tree(function)
    if body is None or body.has_error:
        return []
    pointers = {p['name'] for p in function['parameters'] if p.get('pointer_depth') == 1 and p['base_type'] in BYTE_TYPES}
    scalars = {p['name'] for p in function['parameters'] if not p.get('is_pointer') and not p.get('is_struct_like')}
    pairs = set()
    for n in _walk(body):
        if n.type != 'subscript_expression':
            continue
        buffer = _text(n.child_by_field_name('argument'), source)
        if buffer not in pointers:
            continue
        index = n.child_by_field_name('index')
        lengths = {_text(i, source) for i in _walk(index) if i.type == 'identifier'} & scalars
        # A direct scalar truth test guarding the buffer read supplies a
        # candidate extent. Arbitrary arithmetic comparisons do not.
        parent = n.parent
        while parent is not None and parent != body:
            if parent.type in {'conditional_expression', 'if_statement'}:
                condition = parent.child_by_field_name('condition')
                while condition is not None and condition.type == 'parenthesized_expression' and len(condition.named_children) == 1:
                    condition = condition.named_children[0]
                if condition is not None and condition.type == 'identifier' and _text(condition, source) in scalars:
                    lengths.add(_text(condition, source))
            parent = parent.parent
        pairs.update((buffer, length) for length in lengths)
    rows = [dict(function_id=function['id'], buffer_parameter=b, length_parameter=l, units='bytes',
        source_relation='indexed_or_guarded_buffer_read') for b, l in sorted(pairs)]
    return [{**r, 'binding_id': 'input_pair_' + digest(r)[:24]} for r in rows]


def constrain_pairs(value, kind, function):
    """Source access relations are proposals, never proof of extent units.

    A scalar guarding/indexing a buffer can be a flag or an offset. Do not
    force it to become the length just because it is the only source candidate.
    """
    if kind not in {'input_binding', 'buffer_length'}:
        return
    field = 'bindings' if kind == 'input_binding' else 'links'
    value['properties'][field]['description'] = (
        'Select an actual input/extent binding. input_length_choices are source hints, '
        'not proofs of length units; flags and offsets are not automatically extents.')


def project_pairs(context):
    """One projection records agreement and contradiction; never overwrite facts."""
    rows, diagnostics = [], []
    for b in context['input_contract']['bindings']:
        if b['source'] != 'fuzz_data' or b['size_parameter'] is None:
            continue
        matching = [l for l in context['buffer_length_contract']['links'] if l['function_id'] == b['function_id']
            and l['buffer_parameter'] == b['parameter']]
        agreed = [l for l in matching if l['length_parameter'] == b['size_parameter'] and
            (l['relation'] == b['size_relation'] or l['relation'] in {'derived', 'capacity'}) and
            l['requires_nul_termination'] == b['nul_terminated'] and l['binary_zero_allowed'] == b['binary_zero_allowed']]
        identity = dict(function_id=b['function_id'], buffer_parameter=b['parameter'], length_parameter=b['size_parameter'])
        rows.append({**identity, 'status': 'resolved' if len(matching) == len(agreed) == 1 else 'conflict',
            'units': b['size_relation'], 'evidence_ids': sorted(set(b['evidence_ids']) | {e for l in matching for e in l['evidence_ids']})})
        if len(matching) != 1 or len(agreed) != 1:
            diagnostics.append({**identity, 'code': 'input_length_binding_conflict'})
    context['input_length_binding'] = {'version': VERSION, 'bindings': sorted(rows, key=canonical), 'diagnostics': diagnostics}
