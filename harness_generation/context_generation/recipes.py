"""Lower canonical, finite construction recipes into Plan data, never source guesses."""
import re
from copy import deepcopy

from ..harness_context.reconciliation import scalar_bounds, VERSION, RECIPE_VERSION
from ..semantic_discovery.models import digest


def scalar_expression(expression):
    if scalar_bounds(expression) is None:
        raise ValueError('invalid scalar IR')
    op=expression['op']
    if op=='fuzz_size':
        return 'size'
    if op=='constant':
        return str(expression['value'])
    left,right=scalar_expression(expression['left']),scalar_expression(expression['right'])
    if op=='min':
        return f'(({left}) < ({right}) ? ({left}) : ({right}))'
    return f'(({left}) {"+" if op=="add" else "-"} ({right}))'


def parameter_type(parameter):
    declaration=parameter.get('declared_type',parameter.get('declaration',''))
    name=parameter.get('name',parameter.get('parameter'))
    value=re.sub(r'\b'+re.escape(name)+r'\b','',declaration).strip()
    return re.sub(r'\b(?:const|volatile|restrict)\b','',value).strip()


def lower_recipes(context, active, snapshot):
    contract=context['canonical_construction']
    if contract['version']!=VERSION or contract['recipe_version']!=RECIPE_VERSION:
        raise ValueError('unsupported canonical construction version')
    if contract['input_contract_digest']!=digest(context['input_contract']):
        raise ValueError('derived argument input contract changed after canonical selection')
    selected={r['parameter_id']:r for r in contract['parameters']}
    targets={r['parameter_id'] for r in contract['parameters'] if r['function_id'] in active}
    pending=list(targets)
    while pending:
        pid=pending.pop();row=selected[pid]
        if row['status']!='resolved' or not row['recipe']:
            raise ValueError('Plan requires resolved canonical construction')
        for dep in row['recipe']['dependencies']:
            if dep not in targets:
                targets.add(dep);pending.append(dep)
    program=[]
    for pid in sorted(targets):
        row=selected[pid];recipe=deepcopy(row['recipe'])
        parameter=snapshot.functions[row['function_id']]['parameters'][row['parameter_index']]
        recipe.update(parameter_id=pid,function_id=row['function_id'],parameter=row['parameter'],
            declared_type=row['declared_type'],pointer_depth=parameter.get('pointer_depth',0),
            dependency_recipes=[selected[dep]['recipe']['recipe_id'] for dep in recipe['dependencies']],
            evidence_ids=row['evidence_ids'],proof_digest=row['proof_digest'])
        kind=recipe['kind'];rid=recipe.get('resource_id')
        if rid:
            recipe['resource_variable']='hg_'+rid
        if kind=='derived_scalar':
            bounds=scalar_bounds(recipe['expression'])
            if bounds is None or list(bounds)!=recipe['bounds'] or bounds[1] is None:
                raise ValueError('scalar bounds do not reproduce')
            recipe['storage_variable']='hg_scalar_'+pid[-12:]
            recipe['c_expression']=scalar_expression(recipe['expression'])
            recipe['storage_type']=parameter_type(parameter)
            recipe['binding_expression']=recipe['storage_variable']
        elif kind in {'stack_zero_init','stack_storage'}:
            recipe['storage_variable']='hg_object_'+pid[-12:]
            c_type=parameter_type(parameter)
            if '*' in c_type:
                c_type=c_type.rsplit('*',1)[0].strip()
            recipe['storage_type']=c_type
            recipe['binding_expression']=('&' if parameter.get('pointer_depth',0) else '')+recipe['storage_variable']
            recipe['initialization']='all_zero' if kind=='stack_zero_init' else 'storage_only'
        elif kind=='out_parameter_storage':
            if parameter.get('pointer_depth',0)<2 or not rid:
                raise ValueError('out storage requires exact pointer cell and resource')
            recipe['storage_type']=parameter_type(parameter).rsplit('*',1)[0].strip()
            recipe['binding_expression']='&'+recipe['resource_variable']
        elif kind in {'creator_call','out_parameter_call','resource_reference'}:
            if not rid or recipe.get('producer_api') and recipe['producer_api'] not in active:
                raise ValueError('recipe producer is outside required API closure')
            recipe['binding_expression']=recipe['resource_variable']
        elif kind=='constant':
            if type(recipe.get('value')) not in {int,bool}:
                raise ValueError('constant recipe is not numeric')
            recipe['binding_expression']=str(int(recipe['value']))
        elif kind=='fuzz_size':
            recipe['binding_expression']='size'
        elif kind=='fuzz_bytes':
            recipe['input_source']='data'
        program.append(recipe)
    return program
