"""Check canonical argument provenance in generated C; never evaluate C."""
from copy import deepcopy
import re
from collections import defaultdict

from ..semantic_discovery.tools import _walk, _text


def _simple_pointer_type(node):
    """Accept one ordinary pointer type, without references or nested templates."""
    if node is None or node.type != 'type_descriptor':
        return False
    base = node.child_by_field_name('type')
    pointer = node.child_by_field_name('declarator')
    return bool(base is not None and base.type in {'primitive_type', 'sized_type_specifier', 'type_identifier'}
                and pointer is not None and pointer.type == 'abstract_pointer_declarator'
                and pointer.child_by_field_name('declarator') is None
                and all(child.type == 'type_qualifier' for child in pointer.named_children))


def native_pointer_cast_argument(node, source):
    """Recognize native C++ pointer casts rather than accepting template calls."""
    if node is None or node.type != 'call_expression':
        return None
    target = node.child_by_field_name('function')
    if target is None or target.type != 'template_function':
        return None
    name = target.child_by_field_name('name')
    types = target.child_by_field_name('arguments')
    arguments = node.child_by_field_name('arguments')
    if (name is None or name.type != 'identifier'
            or _text(name, source) not in {'static_cast', 'reinterpret_cast', 'const_cast'}
            or types is None or len(types.named_children) != 1
            or not _simple_pointer_type(types.named_children[0])
            or arguments is None or len(arguments.named_children) != 1):
        return None
    return arguments.named_children[0]


def _natural_byte_parameter(parameter, plan):
    """Prove alignment 1 without losing alignment attributes on source aliases."""
    byte_types = {'char', 'signed char', 'unsigned char'}
    if (parameter.get('is_pointer') is not True or parameter.get('pointer_depth') != 1
            or parameter.get('is_struct_like') or parameter.get('is_opaque_handle')
            or re.sub(r'\s+', ' ', parameter.get('base_type', '').strip()) not in byte_types):
        return False
    spelling = re.fullmatch(r'\s*(?:(?:const|volatile)\s+)*([A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)?)'
                            r'\s*\*\s*(?:(?:const|volatile)\s*)*', parameter.get('type', ''))
    if spelling is None:
        return False
    pointee = re.sub(r'\s+', ' ', spelling[1].strip())
    if pointee in byte_types:
        return True
    # Resolved base_type alone does not preserve an alias's aligned attribute.
    # Only the frozen, unadorned source declaration certifies a byte typedef.
    definitions = []
    for declaration in plan.get('type_declarations', []):
        match = re.fullmatch(r'\s*typedef\s+(char|signed\s+char|unsigned\s+char)'
                             r'\s+([A-Za-z_]\w*)\s*;\s*', declaration)
        if match and match[2] == pointee:
            definitions.append(re.sub(r'\s+', ' ', match[1]))
    return len(definitions) == 1 and definitions[0] == parameter['base_type'].strip()


def validate_recipe_bindings(entry, source, plan):
    expected = defaultdict(list)
    for invocation in plan['call_sequence'] + plan['cleanup_sequence']:
        if invocation.get('invocation_kind') not in {'callback', 'internal'}:
            expected[invocation['symbol']].append(invocation)
    errors, counts, env = [], defaultdict(int), {}
    parameters = entry.child_by_field_name('declarator').child_by_field_name('parameters')
    named = [p for p in parameters.named_children if p.type == 'parameter_declaration'] if parameters else []
    names = [[_text(n, source) for n in _walk(p.child_by_field_name('declarator')) if n.type == 'identifier'] for p in named]
    if len(names) != 2 or any(len(n) != 1 for n in names):
        return ['canonical_fuzz_parameters_unavailable']
    env[names[0][0]], env[names[1][0]] = {'op': 'fuzz_bytes'}, {'op': 'fuzz_size'}
    root = entry
    while root.parent is not None:
        root = root.parent
    global_variables = set()
    for declaration in _walk(root):
        if declaration.type != 'declaration':
            continue
        ancestor = declaration.parent
        inside_function = False
        while ancestor is not None:
            if ancestor.type in {'function_definition', 'lambda_expression'}:
                inside_function = True
                break
            ancestor = ancestor.parent
        if inside_function:
            continue
        for declarator in declaration.named_children:
            if declarator.type == 'init_declarator':
                declarator = declarator.child_by_field_name('declarator')
            if declarator is None or declarator.type not in {'identifier', 'pointer_declarator', 'array_declarator', 'function_declarator'}:
                continue
            functions = [n for n in _walk(declarator) if n.type == 'function_declarator']
            if any(n.child_by_field_name('declarator') is not None and n.child_by_field_name('declarator').type == 'identifier' for n in functions):
                continue  # A declaration of the intrinsic's function ABI.
            current = declarator
            while current is not None and current.type != 'identifier':
                if current.type == 'parenthesized_declarator' and len(current.named_children) == 1:
                    current = current.named_children[0]
                else:
                    current = current.child_by_field_name('declarator')
            if current is not None:
                global_variables.add(_text(current, source))

    def scalar(node):
        result = value(node)
        return result if result and result.get('op') != 'fuzz_bytes' and result.get('op') else None

    def capacity_covers(capacity, extent, extra=0):
        if not capacity or not extent:
            return False
        if not extra and capacity == extent:
            return True
        if capacity.get('op') == 'add':
            for base, padding in ((capacity['left'], capacity['right']), (capacity['right'], capacity['left'])):
                if base == extent and padding.get('op') == 'constant' and padding['value'] >= extra:
                    return True
        return (capacity.get('op') == extent.get('op') == 'constant'
                and capacity['value'] >= extent['value'] + extra)

    def origin(observed, extent):
        if observed == {'op': 'fuzz_bytes'}:
            return True
        return bool(observed and observed.get('buffer_id') is not None and observed.get('live')
                    and observed.get('copied_from') == {'op': 'fuzz_bytes'}
                    and observed.get('copied_extent') == extent
                    and capacity_covers(observed.get('capacity'), extent))

    def input_matches(observed, argument, invocation):
        binding = argument.get('input_binding') or {}
        extent = {'op': 'fuzz_size'}
        length = next((a for a in invocation['arguments'] if a.get('parameter') == binding.get('size_parameter')), None)
        if length:
            recipe = length.get('canonical_recipe') or {}
            if recipe.get('kind') == 'derived_scalar':
                extent = recipe['expression']
        if binding.get('alignment') == 'explicit':
            return False  # The current Plan schema contains no alignment byte count.
        if not origin(observed, extent):
            return False
        copied = bool(observed and observed.get('buffer_id') is not None)
        api = next((a for a in plan['api_declarations'] if a['function_id'] == invocation['function_id']), None)
        parameter = next((p for p in (api or {}).get('parameters', [])
                          if p.get('name') == argument.get('parameter')), {})
        # Generated code cannot supply its own alias or an assumed alignment.
        byte_aligned = _natural_byte_parameter(parameter, plan)
        needs_aligned_copy = binding.get('alignment') == 'natural' and not byte_aligned
        if binding.get('transform') == 'copy' or binding.get('mutable') or needs_aligned_copy:
            if not copied:
                return False
        if binding.get('transform') == 'nul_terminate' or binding.get('nul_terminated'):
            if not copied or not capacity_covers(observed.get('capacity'), extent, 1):
                return False
            if observed.get('nul_at') != extent and not observed.get('zero_initialized'):
                return False
        return True

    def invalidate_bytes(observed):
        if observed and observed.get('address'):
            env[observed['address']] = None
        if observed == {'op': 'fuzz_bytes'}:
            for name, current in list(env.items()):
                if current == {'op': 'fuzz_bytes'}:
                    env[name] = None
        elif observed and observed.get('buffer_id') is not None:
            observed.update(copied_from=None, copied_extent=None, nul_at=None, zero_initialized=False)

    def value(node):
        if node is None:
            return None
        if node.type in {'identifier', 'null_literal', 'null'}:
            name = _text(node, source)
            if name in {'NULL', 'nullptr'}:
                return {'op': 'constant', 'value': 0}
            if name in env:
                return env[name]
            api = next((a for a in plan['api_declarations'] if a['symbol'] == name), None)
            return {'callback_api': api['function_id']} if api else None
        if node.type == 'number_literal':
            try:
                return {'op': 'constant', 'value': int(re.sub(r'[uUlL]+$', '', _text(node, source)), 0)}
            except ValueError:
                return None
        if node.type == 'char_literal' and _text(node, source) in {"'\\0'", "'\\x00'"}:
            return {'op': 'constant', 'value': 0}
        if node.type == 'parenthesized_expression' and len(node.named_children) == 1:
            return value(node.named_children[0])
        if node.type == 'cast_expression':
            inner = value(node.child_by_field_name('value'))
            return inner if (_simple_pointer_type(node.child_by_field_name('type')) and inner
                             and (inner.get('resource_id') or inner.get('buffer_id') is not None
                                  or inner == {'op': 'fuzz_bytes'})) else None
        if node.type == 'pointer_expression' and _text(node, source).startswith('&'):
            target = node.named_children[0] if node.named_children else None
            if target is not None and target.type == 'identifier':
                name = _text(target, source)
                return {'address': name, 'stored': env.get(name)}
            return None
        if node.type == 'binary_expression':
            left, right = value(node.child_by_field_name('left')), value(node.child_by_field_name('right'))
            operator = _text(node.child_by_field_name('operator'), source)
            if left and right and operator in {'+', '-'}:
                return {'op': 'add' if operator == '+' else 'subtract', 'left': left, 'right': right}
            return None
        if node.type == 'conditional_expression':
            condition = node.child_by_field_name('condition')
            yes, no = node.child_by_field_name('consequence'), node.child_by_field_name('alternative')
            if condition.type == 'binary_expression' and _text(condition.child_by_field_name('operator'), source) in {'<', '<='}:
                left, right = condition.child_by_field_name('left'), condition.child_by_field_name('right')
                if value(left) == value(yes) and value(right) == value(no) and value(left) and value(right):
                    return {'op': 'min', 'left': value(left), 'right': value(right)}
            return None
        if node.type != 'call_expression':
            return None
        cast_argument = native_pointer_cast_argument(node, source)
        if cast_argument is not None:
            inner = value(cast_argument)
            return inner if inner and (inner.get('resource_id') or inner.get('buffer_id') is not None
                                      or inner == {'op': 'fuzz_bytes'}) else None
        target = node.child_by_field_name('function')
        name = _text(target, source).removeprefix('std::').removeprefix('::')
        args = node.child_by_field_name('arguments').named_children
        actual = [value(arg) for arg in args]
        # Project APIs named like libc and local function-pointer shadows never
        # certify allocation or copying as an intrinsic.
        if name in expected and (name in env or name in global_variables):
            errors.append('canonical_api_shadowed')
            return None
        memory_helpers = {'malloc', 'calloc', 'realloc', 'free', 'memcpy', 'memmove', 'memset',
                          'memcmp', 'strlen', 'strnlen', 'strcmp', 'strncmp'}
        if name in memory_helpers and name not in expected and (name in env or name in global_variables):
            errors.append('canonical_memory_helper_shadowed')
            for observed in actual:
                invalidate_bytes(observed)
            return None
        intrinsic = name not in expected and name not in env and name not in global_variables and target.type in {'identifier', 'qualified_identifier'}
        if intrinsic and name in {'malloc', 'calloc'}:
            capacity = actual[0] if name == 'malloc' and len(actual) == 1 else None
            if name == 'calloc' and len(actual) == 2:
                if actual[0] == {'op': 'constant', 'value': 1}:
                    capacity = actual[1]
                elif actual[1] == {'op': 'constant', 'value': 1}:
                    capacity = actual[0]
            return {'buffer_id': node.start_byte, 'capacity': capacity, 'live': True,
                    'copied_from': None, 'copied_extent': None, 'nul_at': None,
                    'zero_initialized': name == 'calloc'}
        if intrinsic and name in {'memcpy', 'memmove'} and len(actual) == 3:
            destination, original, extent = actual
            if destination and destination.get('buffer_id') is not None:
                previous_nul = destination.get('nul_at')
                if origin(original, extent) and capacity_covers(destination.get('capacity'), extent):
                    destination.update(copied_from={'op': 'fuzz_bytes'}, copied_extent=extent,
                                       nul_at=previous_nul if previous_nul == extent else None)
                else:
                    invalidate_bytes(destination)
            else:
                invalidate_bytes(destination)
            return destination
        if intrinsic and name in {'free', 'realloc'} and actual:
            if actual[0] and actual[0].get('buffer_id') is not None:
                actual[0]['live'] = False
            else:
                invalidate_bytes(actual[0])
            return None
        if intrinsic and name == 'memset' and actual:
            invalidate_bytes(actual[0])
            return actual[0]
        if name not in expected or counts[name] >= len(expected[name]):
            return None
        invocation = expected[name][counts[name]]
        counts[name] += 1
        for observed, argument in zip(actual, invocation['arguments']):
            recipe = argument.get('canonical_recipe', {})
            kind = recipe.get('kind')
            if kind is None:
                binding = argument.get('input_binding') or {}
                if binding.get('source') == 'fuzz_data':
                    kind = 'fuzz_bytes'
                elif any(b.get('source') == 'fuzz_data' for b in argument.get('length_for', [])):
                    kind = 'fuzz_size'
            if kind in {'creator_call', 'out_parameter_call', 'resource_reference'}:
                if not observed or observed.get('resource_id') != recipe.get('resource_id'):
                    errors.append('canonical_resource_binding_mismatch')
            elif kind == 'out_parameter_storage':
                if not observed or not observed.get('address') or observed.get('stored') != {'op': 'constant', 'value': 0}:
                    errors.append('canonical_out_storage_mismatch')
                else:
                    env[observed['address']] = {'resource_id': recipe['resource_id']}
            elif kind == 'fuzz_bytes' and not input_matches(observed, argument, invocation):
                errors.append('canonical_fuzz_bytes_binding_mismatch')
                if (argument.get('input_binding') or {}).get('alignment') == 'explicit':
                    errors.append('canonical_explicit_alignment_unprovable')
            elif kind == 'fuzz_size' and observed != {'op': 'fuzz_size'}:
                errors.append('canonical_fuzz_size_binding_mismatch')
            elif kind == 'derived_scalar' and observed != recipe['expression']:
                errors.append('canonical_scalar_recipe_mismatch')
            elif kind == 'stack_zero_init' and (not observed or not (observed.get('stored') or {}).get('zero_object')):
                errors.append('canonical_zero_initialization_missing')
            elif kind == 'constant' and observed != {'op': 'constant', 'value': int(recipe['value'])}:
                errors.append('canonical_constant_recipe_mismatch')
            elif kind == 'callback_object' and recipe.get('producer_api') and observed != {'callback_api': recipe['producer_api']}:
                errors.append('canonical_callback_binding_mismatch')
        return {'resource_id': invocation['return_resource']} if invocation['return_resource'] else None

    def declarator_name(node):
        if node is None:
            return None
        if node.type == 'identifier':
            return _text(node, source)
        if node.type == 'parenthesized_declarator' and len(node.named_children) == 1:
            return declarator_name(node.named_children[0])
        return declarator_name(node.child_by_field_name('declarator'))

    def nonempty_extent(condition):
        while condition is not None:
            if condition.type == 'parenthesized_expression' and len(condition.named_children) == 1:
                condition = condition.named_children[0]
            elif condition.type == 'condition_clause' and len(condition.named_children) == 1:
                condition = condition.child_by_field_name('value')
            else:
                break
        if condition is None:
            return None
        result = scalar(condition)
        if result and result.get('op') == 'fuzz_size':
            return result
        if condition.type == 'binary_expression':
            left, right = scalar(condition.child_by_field_name('left')), scalar(condition.child_by_field_name('right'))
            operator = _text(condition.child_by_field_name('operator'), source)
            zero = {'op': 'constant', 'value': 0}
            if right == zero and operator in {'>', '!='} and left and left.get('op') == 'fuzz_size':
                return left
            if left == zero and operator in {'<', '!='} and right and right.get('op') == 'fuzz_size':
                return right
        return None

    def visit(node):
        if node is None:
            return
        if node.type == 'init_declarator':
            declarator, initializer = node.child_by_field_name('declarator'), node.child_by_field_name('value')
            name = declarator_name(declarator)
            if name:
                zero = initializer is not None and initializer.type == 'initializer_list' and re.fullmatch(r'\{\s*(?:0\s*)?\}', _text(initializer, source))
                env[name] = None  # C declaration scope begins before its initializer.
                env[name] = {'zero_object': True} if zero else value(initializer)
            return
        if node.type == 'declaration':
            for child in node.named_children:
                if child.type == 'init_declarator':
                    visit(child)
                elif child == node.child_by_field_name('declarator'):
                    functions = [n for n in _walk(child) if n.type == 'function_declarator']
                    if any(n.child_by_field_name('declarator') is not None and n.child_by_field_name('declarator').type == 'identifier' for n in functions):
                        continue
                    name = declarator_name(child)
                    if name:
                        env[name] = None
            return
        if node.type == 'assignment_expression':
            left, right = node.child_by_field_name('left'), node.child_by_field_name('right')
            observed = value(right)
            operator = _text(node.child_by_field_name('operator'), source)
            if left.type == 'identifier':
                env[_text(left, source)] = observed if operator == '=' else None
            elif left.type == 'subscript_expression':
                buffer = value(left.child_by_field_name('argument'))
                index_node = left.child_by_field_name('index')
                indices = left.child_by_field_name('indices')
                if index_node is None and indices is not None and len(indices.named_children) == 1:
                    index_node = indices.named_children[0]
                index = scalar(index_node)
                if buffer and buffer.get('buffer_id') is not None and operator == '=' and observed == {'op': 'constant', 'value': 0}:
                    buffer['nul_at'] = index
                    if buffer.get('copied_extent') != index:
                        invalidate_bytes(buffer)
                        buffer['nul_at'] = index
                else:
                    invalidate_bytes(buffer)
            elif left.type == 'pointer_expression':
                invalidate_bytes(value(left.named_children[0] if left.named_children else None))
            return
        if node.type == 'update_expression':
            target = node.child_by_field_name('argument')
            while target is not None and target.type == 'parenthesized_expression' and len(target.named_children) == 1:
                target = target.named_children[0]
            if target is not None and target.type == 'pointer_expression':
                invalidate_bytes(value(target.named_children[0] if target.named_children else None))
            elif target is not None and target.type == 'subscript_expression':
                invalidate_bytes(value(target.child_by_field_name('argument')))
            for identifier in _walk(node):
                if identifier.type == 'identifier':
                    env[_text(identifier, source)] = None
            return
        if node.type == 'call_expression':
            value(node)
            return
        if node.type == 'if_statement':
            visit(node.child_by_field_name('condition'))
            before = deepcopy(env)
            visit(node.child_by_field_name('consequence'))
            after_yes = deepcopy(env)
            env.clear(); env.update(deepcopy(before))
            visit(node.child_by_field_name('alternative'))
            after_no = deepcopy(env)
            # A branch ending in an unconditional return contributes no state
            # to the following call sites. Still visit it above so its actual
            # API arguments and mutations are checked; only the join changes.
            def returns(branch):
                if branch is None:
                    return False
                # A trailing return does not dominate a jump out of the
                # branch. This interpreter has no label/loop/exception CFG;
                # retain both environments whenever one of those transfers
                # could bypass the return, including transfers in a nested
                # statement. A label can also admit an external entry path.
                if any(n.type in {'goto_statement', 'labeled_statement', 'break_statement',
                                  'continue_statement', 'throw_statement', 'try_statement'}
                       for n in _walk(branch)):
                    return False
                if branch.type == 'return_statement':
                    return True
                if branch.type == 'compound_statement':
                    return bool(branch.named_children) and returns(branch.named_children[-1])
                if branch.type == 'else_clause' and len(branch.named_children) == 1:
                    return returns(branch.named_children[0])
                if branch.type == 'if_statement':
                    return returns(branch.child_by_field_name('consequence')) and returns(branch.child_by_field_name('alternative'))
                return False
            yes_returns = returns(node.child_by_field_name('consequence'))
            no_returns = returns(node.child_by_field_name('alternative'))
            if yes_returns != no_returns:
                env.clear()
                env.update(after_no if yes_returns else after_yes)
                return
            # A copy guarded only by nonempty input is also an exact copy on
            # the zero-byte path. No terminator, allocation or side effect is
            # inferred for that path.
            extent = nonempty_extent(node.child_by_field_name('condition'))
            if extent and node.child_by_field_name('alternative') is None:
                for name, copied in after_yes.items():
                    original = after_no.get(name)
                    if not copied or not original or copied.get('buffer_id') is None:
                        continue
                    base_keys = ('buffer_id', 'capacity', 'live', 'zero_initialized', 'nul_at')
                    if (all(copied.get(k) == original.get(k) for k in base_keys)
                            and origin(copied, extent) and original.get('copied_from') is None):
                        original.update(copied_from={'op': 'fuzz_bytes'}, copied_extent=extent)
            env.clear()
            for name in set(after_yes) | set(after_no):
                env[name] = after_yes.get(name) if after_yes.get(name) == after_no.get(name) else None
            return
        if node.type in {'for_statement', 'while_statement', 'do_statement', 'switch_statement'}:
            before = deepcopy(env)
            for child in node.named_children:
                visit(child)
            after = deepcopy(env)
            env.clear()
            for name in set(before) | set(after):
                env[name] = after.get(name) if before.get(name) == after.get(name) else None
            return
        for child in node.named_children:
            visit(child)
    visit(entry.child_by_field_name('body'))
    return sorted(set(errors))
