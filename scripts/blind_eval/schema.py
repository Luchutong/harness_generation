"""Validate the JSON Schema subset used by our annotation document.

No production validator or model is invoked. Unsupported schema keywords must
not be relied upon; schema uses types, enums, bounds and structural constraints.
"""
from pathlib import Path
import json

SCHEMA=Path(__file__).resolve().parents[2]/'benchmarks/blind/ground_truth.schema.json'


def validate(value,schema,path='$'):
    kind=('null' if value is None else 'boolean' if type(value) is bool else 'integer' if type(value) is int
          else 'string' if isinstance(value,str) else 'array' if isinstance(value,list) else 'object' if isinstance(value,dict) else 'unknown')
    allowed=schema.get('type');allowed=[allowed] if isinstance(allowed,str) else allowed
    if allowed and kind not in allowed:raise ValueError(f'annotation_type:{path}')
    if 'enum' in schema and value not in schema['enum']:raise ValueError(f'annotation_enum:{path}')
    if 'const' in schema and value!=schema['const']:raise ValueError(f'annotation_const:{path}')
    if kind=='object':
        props=schema.get('properties',{});extra=schema.get('additionalProperties',True)
        if not set(schema.get('required',[]))<=value.keys():raise ValueError(f'annotation_required:{path}')
        if extra is False and set(value)-set(props):raise ValueError(f'annotation_unknown_field:{path}')
        for key,item in value.items():
            if key in props:validate(item,props[key],path+'.'+key)
            elif isinstance(extra,dict):validate(item,extra,path+'.'+key)
    elif kind=='array':
        if len(value)<schema.get('minItems',0):raise ValueError(f'annotation_min_items:{path}')
        if schema.get('uniqueItems') and len({json.dumps(v,sort_keys=True) for v in value})!=len(value):raise ValueError(f'annotation_duplicate:{path}')
        for i,item in enumerate(value):validate(item,schema.get('items',{}),path+f'[{i}]')
    elif kind=='integer' and value<schema.get('minimum',value):raise ValueError(f'annotation_minimum:{path}')
    return value


def validate_annotation(value):return validate(value,json.loads(SCHEMA.read_text()))
