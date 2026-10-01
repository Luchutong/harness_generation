"""Signed CORE/proposal boundaries; all model submissions here are offline."""
from copy import deepcopy

import pytest

from harness_generation.harness_context.proposals import registry, ownership_subjects
from harness_generation.harness_context.requirements import HarnessRequirementBuilder
from harness_generation.harness_context.terminal import terminal_schema, expand_submission, derive_selections
from harness_generation.harness_context.models import validate_shape
from harness_generation.semantic_slicing.core_proofs import inclusion_proofs
from test_harness_context import setup, CONTEXT, owner
from test_semantic_slicing import fixture, run, queries, tool, terminal, DIRECT


@pytest.mark.parametrize('reason', ['core_processing', 'external_input_injection', 'wrapper_delegation'])
def test_nonanchor_wrapper_cannot_become_core_by_changing_reason(tmp_path, reason):
    sample = fixture(tmp_path, DIRECT)
    ids = sample[-1]
    result, _, _ = run(sample, [queries(tool('find_callers', 'callers', function=ids['parse']),
        tool('get_function', 'anchor', function=ids['parse'])),
        queries(tool('get_function', 'wrapper', function=ids['wrapper'])),
        terminal({ids['parse']:('core','accepted_anchor'), ids['wrapper']:('core',reason)})])
    assert result.result['run_status'] == 'invalid'
    assert result.result['core_functions'] == [ids['parse']]


def test_shared_type_and_unobserved_field_do_not_prove_core(tmp_path):
    source = CONTEXT + '\nvoid unrelated(Context *object,unsigned v) {object->ready=v;}\n'
    sample = fixture(tmp_path, source)
    functions = {f['id']:f for f in sample[1].functions}
    ids = sample[-1]
    records = {fid:{'tool':'get_function','function_id':fid,'content':f['body']} for fid,f in functions.items()}
    assert inclusion_proofs(ids['parse'], ids['unrelated'], functions, records) == []


def activated(tmp_path, source=CONTEXT, kind='lifecycle'):
    p = setup(tmp_path, source)
    req = next(r for r in HarnessRequirementBuilder().build(p[1], p[3])['requirements'] if r['kind']==kind)
    tools = p[5]; tools.activate(req); tools.bootstrap()
    return p, req, tools


def value_schema(req, tools):
    return terminal_schema([req], registry(tools), tools.snapshot)['properties']['resolutions']['properties']['r0']['properties']['facts']['items']['properties']['value']


def test_only_complete_source_can_issue_support_choices(tmp_path):
    p, req, tools = activated(tmp_path)
    creator = p[0][-1]['create']
    tools.execute('find_initializers', {'type':'Context'})
    tools.execute('get_function_signature', {'function':creator})
    assert not [c for c in registry(tools)['support_candidates'] if c['function_id']==creator]
    tools.execute('get_function', {'function':creator})
    selected = [c for c in registry(tools)['support_candidates'] if c['function_id']==creator and c['reason']=='creation']
    assert len(selected)==1 and selected[0]['necessity_proven'] is False
    before = selected[0]['candidate_id']
    tools.execute('get_function', {'function':creator})
    assert next(c for c in registry(tools)['support_candidates'] if c['function_id']==creator and c['reason']=='creation')['candidate_id']==before


def test_api_field_changes_only_after_source_is_issued(tmp_path):
    p, req, tools = activated(tmp_path)
    creator=p[0][-1]['create']
    def choices():
        rows = value_schema(req, tools)['properties']['resources']['items']['anyOf']
        return next(r['properties']['creation']['properties']['api']['enum'] for r in rows if r['properties']['subject_parameter']['enum'] == ['ctx'])
    assert creator not in choices()
    tools.execute('find_initializers', {'type':'Context'})
    assert creator not in choices()
    tools.execute('get_function', {'function':creator})
    assert creator in choices()


@pytest.mark.parametrize('bad_subject', [None, 'size', 'parse', 'ownership_subject_forged'])
def test_wire_ownership_rejects_unsiged_and_scalar_subjects(tmp_path, bad_subject):
    p, req, tools = activated(tmp_path, kind='ownership')
    row={'entries':[{'subject_id':bad_subject,'resource_id':None,'ownership':'borrowed','release_api':None,'lifetime':'during_call'}]}
    with pytest.raises(ValueError):
        validate_shape(row, value_schema(req,tools))


def test_parameter_and_api_enums_are_independent(tmp_path):
    p, req, tools = activated(tmp_path, kind='input_binding')
    schema=value_schema(req,tools)['properties']['bindings']['items']['properties']
    assert 'data' in schema['parameter']['enum'] and p[0][-1]['parse'] not in schema['parameter']['enum']
    assert p[0][-1]['parse'] in schema['via_function_id']['enum'] and 'data' not in schema['via_function_id']['enum']


def test_scalar_return_has_no_ownership_or_pointer_return_predicate(tmp_path):
    p, req, tools=activated(tmp_path, kind='return_semantics')
    subjects=ownership_subjects(p[0][-1]['parse'], p[3])
    assert not any(s['return_value'] or s['parameter']=='size' for s in subjects)
    schema=value_schema(req,tools)
    with pytest.raises(ValueError):
        validate_shape(dict(success='always',nullable=False,owned=False,error_cleanup=False),schema)
    validate_shape(dict(success='always',nullable=None,owned=None,error_cleanup=False),schema)


def test_out_storage_pointee_and_pointer_field_are_distinct_signed_subjects(tmp_path):
    source='typedef struct Object {unsigned number; void *ref;} Object; int parse(Object **out,Object *ctx,int n) {*out=ctx;return n;}'
    p=setup(tmp_path,source)
    subjects=ownership_subjects(p[0][-1]['parse'],p[3])
    kinds={s['subject_kind'] for s in subjects if s['parameter']=='out' and s['field'] is None}
    assert kinds=={'PointerParameter','OutParameterPointee'}
    assert not any(s['parameter']=='n' or s['field']=='number' for s in subjects)
    assert any(s['subject_kind']=='ResourceObject' and s['parameter']=='ctx' and s['field']=='ref' for s in subjects)
    assert len({s['subject_id'] for s in subjects})==len(subjects)


def test_support_selection_preserves_optional_actions_and_rejects_foreign_candidate(tmp_path):
    p, req, tools=activated(tmp_path)
    ids=p[0][-1]
    tools.execute('find_cleanup_candidates', {'type':'Context'})
    tools.execute('get_function', {'function':ids['destroy']})
    signed=registry(tools)
    fact={'function_id':ids['parse'],'predicate':'lifecycle','value':{'resources':[{
        'creation':{'api':None},'initialization':{'api':None,'mandatory':False},
        'cleanup':{'api':ids['destroy'],'mandatory':False}}]}}
    selection=derive_selections([fact],req,signed)
    assert len(selection)==1 and selection[0]['necessity']=='optional' and selection[0]['candidate_id']
    fact['value']['resources'][0]['cleanup']['api']=ids['create']
    with pytest.raises(ValueError,match='support_activation_candidate_not_signed'):
        derive_selections([fact],req,signed)


def test_native_wire_forbids_free_dependency_payload_even_when_unresolved(tmp_path):
    _, req, tools=activated(tmp_path)
    value={'resolutions':{'r0':{'status':'unresolved','facts':[],
        'discovered_api_dependencies':[{'function_id':'invented'}],'open_questions':['missing']}}}
    with pytest.raises(ValueError):
        expand_submission(value,[req],registry(tools),tools.snapshot)
