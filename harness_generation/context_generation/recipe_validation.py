"""Check new recipe bindings in generated C; no evaluation of C expressions."""
import re
from collections import defaultdict

from ..semantic_discovery.tools import _walk, _text


def validate_recipe_bindings(entry, source, plan):
    if not plan.get('construction_recipes'):
        return []
    expected=defaultdict(list)
    for invocation in plan['call_sequence']+plan['cleanup_sequence']:
        expected[invocation['symbol']].append(invocation)
    errors=[]; counts=defaultdict(int); env={}
    parameters=entry.child_by_field_name('declarator').child_by_field_name('parameters')
    named=[p for p in parameters.named_children if p.type=='parameter_declaration']
    if len(named)!=2:
        return []
    names=[[_text(n,source) for n in _walk(p.child_by_field_name('declarator')) if n.type=='identifier'] for p in named]
    if any(len(n)!=1 for n in names):
        return []
    env[names[1][0]]={'op':'fuzz_size'}

    def value(node):
        if node is None:
            return None
        if node.type in {'identifier','null_literal','null'}:
            name=_text(node,source)
            return {'op':'constant','value':0} if name in {'NULL','nullptr'} else env.get(name)
        if node.type=='number_literal':
            try:return {'op':'constant','value':int(re.sub(r'[uUlL]+$','',_text(node,source)),0)}
            except ValueError:return None
        if node.type=='parenthesized_expression' and len(node.named_children)==1:
            return value(node.named_children[0])
        if node.type=='cast_expression':
            inner=value(node.child_by_field_name('value'))
            return inner if inner and inner.get('resource_id') else None
        if node.type=='pointer_expression' and _text(node,source).startswith('&'):
            target=node.named_children[0] if node.named_children else None
            if target is not None and target.type=='identifier':
                name=_text(target,source)
                return {'address':name,'stored':env.get(name)}
            return None
        if node.type=='binary_expression':
            left,right=value(node.child_by_field_name('left')),value(node.child_by_field_name('right'))
            operator=_text(node.child_by_field_name('operator'),source)
            if left and right and operator in {'+','-'}:
                return {'op':'add' if operator=='+' else 'subtract','left':left,'right':right}
            return None
        if node.type=='conditional_expression':
            condition=node.child_by_field_name('condition')
            yes,no=node.child_by_field_name('consequence'),node.child_by_field_name('alternative')
            if condition.type=='binary_expression' and _text(condition.child_by_field_name('operator'),source) in {'<','<='}:
                left,right=condition.child_by_field_name('left'),condition.child_by_field_name('right')
                if value(left)==value(yes) and value(right)==value(no) and value(left) and value(right):
                    return {'op':'min','left':value(left),'right':value(right)}
            return None
        if node.type=='call_expression':
            name=_text(node.child_by_field_name('function'),source).removeprefix('::')
            args=node.child_by_field_name('arguments').named_children
            actual=[value(arg) for arg in args]
            if name not in expected or counts[name]>=len(expected[name]):
                return None
            invocation=expected[name][counts[name]];counts[name]+=1
            for observed,argument in zip(actual,invocation['arguments']):
                recipe=argument.get('canonical_recipe',{});kind=recipe.get('kind')
                if kind in {'creator_call','out_parameter_call','resource_reference'}:
                    if not observed or observed.get('resource_id')!=recipe.get('resource_id'):
                        errors.append('canonical_resource_binding_mismatch')
                elif kind=='out_parameter_storage':
                    if not observed or not observed.get('address') or observed.get('stored')!={'op':'constant','value':0}:
                        errors.append('canonical_out_storage_mismatch')
                    else:
                        env[observed['address']]={'resource_id':recipe['resource_id']}
                elif kind=='derived_scalar' and observed!=recipe['expression']:
                    errors.append('canonical_scalar_recipe_mismatch')
                elif kind=='stack_zero_init' and (not observed or not (observed.get('stored') or {}).get('zero_object')):
                    errors.append('canonical_zero_initialization_missing')
                elif kind=='constant' and observed!={'op':'constant','value':int(recipe['value'])}:
                    errors.append('canonical_constant_recipe_mismatch')
            return {'resource_id':invocation['return_resource']} if invocation['return_resource'] else None
        return None

    def visit(node):
        if node.type=='init_declarator':
            declarator=node.child_by_field_name('declarator'); initializer=node.child_by_field_name('value')
            ids=[n for n in _walk(declarator) if n.type=='identifier']
            if len(ids)==1:
                zero=initializer is not None and initializer.type=='initializer_list' and re.fullmatch(r'\{\s*(?:0\s*)?\}',_text(initializer,source))
                env[_text(ids[0],source)]={'zero_object':True} if zero else value(initializer)
            return
        if node.type=='assignment_expression':
            left=node.child_by_field_name('left');right=node.child_by_field_name('right')
            if left.type=='identifier':
                env[_text(left,source)]=value(right) if _text(node.child_by_field_name('operator'),source)=='=' else None
            else:
                value(right)
            return
        if node.type=='update_expression':
            for identifier in _walk(node):
                if identifier.type=='identifier':env[_text(identifier,source)]=None
            return
        if node.type=='call_expression':
            value(node);return
        for child in node.named_children:
            visit(child)
    visit(entry.child_by_field_name('body'))
    return sorted(set(errors))
