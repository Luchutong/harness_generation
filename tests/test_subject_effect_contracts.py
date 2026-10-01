"""Proposal constraints and contract composition; model facts are offline fixtures."""
from copy import deepcopy
import json
import shutil

import pytest

from harness_generation.harness_context.proposals import registry, merge_registry, registry_update
from harness_generation.harness_context.terminal import derive_selections, terminal_schema, expand_submission
from harness_generation.harness_context.models import validate_shape
from harness_generation.harness_context.input_pairs import project_pairs
from harness_generation.harness_context.value_roles import subject_origins
from harness_generation.semantic_slicing.proposals import choices, terminal_schema as slice_schema
from harness_generation.semantic_slicing.models import validate_submission
from harness_generation.semantic_discovery.models import canonical
from harness_generation.context_generation import HarnessPlanBuilder
from harness_generation.cli import main
from harness_generation.llm import FakeLLM
from test_semantic_slicing import fixture, DIRECT
from test_harness_context import setup, mine, direct_specs, assert_gate
from test_proposal_boundaries import activated, value_schema


def test_slice_source_choices_preserve_wrapper_as_evidence(tmp_path):
    sample = fixture(tmp_path, DIRECT)
    from harness_generation.semantic_slicing import SemanticSliceTools
    from harness_generation.semantic_slicing.frontier import build_frontier
    artifacts, catalog, candidate, validation, ids = sample[1:]
    tools = SemanticSliceTools(artifacts, catalog, build_frontier(sample[0], artifacts, catalog, candidate, validation))
    tools._frontier({'candidate_id': validation['candidate_id'], 'function_id': ids['parse']})
    tools.execute('find_callers', {'function': ids['parse']})
    for fid in (ids['parse'], ids['wrapper']):
        tools.execute('get_function', {'function': fid})
    signed = choices(tools)
    wrapper = [c for c in signed if c['function_id'] == ids['wrapper']]
    assert {c['role'] for c in wrapper} == {'exclude', 'unresolved'}
    rows = [next(c for c in signed if c['function_id'] == fid and c['role'] == role)
        for fid, role in ((ids['parse'], 'core'), (ids['wrapper'], 'exclude'))]
    wire = {'classification': [{'choice_id': c['choice_id'], 'open_questions': []} for c in rows]}
    validate_shape(wire, slice_schema(tools)['function']['parameters'])
    assert [c['role'] for c in validate_submission(canonical(wire), tools)['classification']] == ['core', 'exclude']
    wire['classification'][1]['choice_id'] = 'slice_choice_forged'
    with pytest.raises(ValueError, match='slice_role_choice_not_issued'):
        validate_submission(canonical(wire), tools)


def test_support_effect_binds_exact_target_parameter(tmp_path):
    source = '''typedef struct State {unsigned mode;unsigned other;} State;
int parse(State *left, State *right) {return left->mode+right->other;}
void set(State *object) {object->mode=1;}
void usage(State *left,State *right) {parse(left,right);}
'''
    p, req, tools = activated(tmp_path, source, kind='state')
    ids = p[0][-1]
    tools.execute('find_callers', {'function': ids['parse']})
    tools.execute('get_function', {'function': ids['usage']})
    tools.execute('find_type_usages', {'type': 'State'})
    tools.execute('get_function', {'function': ids['set']})
    tools.bootstrap()
    signed = registry(tools)
    assert not any(c['function_id'] == ids['usage'] for c in signed['support_candidates'])
    proposal = {'function_id': ids['parse'], 'predicate': 'state', 'value': {'preconditions': [
        {'parameter': 'left', 'kind': 'initialized', 'api': ids['set']}]}}
    assert derive_selections([proposal], req, signed)
    proposal['value']['preconditions'][0]['parameter'] = 'right'
    with pytest.raises(ValueError, match='subject_effect_mismatch'):
        derive_selections([proposal], req, signed)
    with pytest.raises(ValueError):
        validate_shape(proposal['value'], value_schema(req, tools))


def test_pointer_cell_cannot_select_pointee_resource(tmp_path):
    source = '''typedef struct State {unsigned mode;} State;
int acquire(State **out) {*out=calloc(1,sizeof(State));return 1;}
int parse(State *s) {return s->mode;}
void usage(void) {State *s;acquire(&s);parse(s);}
'''
    p, req, tools = activated(tmp_path, source, kind='ownership')
    ids = p[0][-1]
    tools.execute('find_resource_flows', {'function': ids['parse']})
    tools.execute('find_callees', {'function': ids['usage']})
    tools.execute('get_function', {'function': ids['acquire']})
    from harness_generation.harness_context.proposals import ownership_subjects
    subjects = ownership_subjects(ids['acquire'], p[3])
    catalog = registry(tools)['origin_catalog']
    rid = next(r for r, v in catalog.items() if v['origin']['kind'] == 'out_parameter')
    cell = next(s for s in subjects if s['subject_kind'] == 'PointerParameter')
    pointee = next(s for s in subjects if s['subject_kind'] == 'OutParameterPointee')
    assert rid not in subject_origins(cell, p[3], catalog)
    assert rid in subject_origins(pointee, p[3], catalog)


@pytest.mark.parametrize('name,length', [('data','size'), ('opaque_bytes','extent')])
def test_input_and_length_wire_choose_same_source_pair(tmp_path, name, length):
    source = f'typedef unsigned long size_t; int parse(const unsigned char *{name},size_t {length}){{return {length}?{name}[0]:0;}}'
    p, req, tools = activated(tmp_path, source, kind='input_binding')
    tools.bootstrap()
    fid = p[0][-1]['parse']
    value = direct_specs(fid, data=name, size=length)[fid, 'input_binding']['value']
    validate_shape(value, value_schema(req, tools))
    assert any(c['buffer_parameter'] == name and c['length_parameter'] == length for c in registry(tools)['input_length_choices'])
    value['bindings'][0]['size_parameter'] = 'invented_extent'
    with pytest.raises(ValueError):
        validate_shape(value, value_schema(req, tools))


def test_input_pair_projection_preserves_conflicting_facts(tmp_path):
    fid = 'fixture:parse'
    specs = direct_specs(fid)
    context = {'input_contract': {'bindings': [dict(function_id=fid, evidence_ids=['ev_a'], **specs[fid,'input_binding']['value']['bindings'][0])]},
        'buffer_length_contract': {'links': [dict(function_id=fid, evidence_ids=['ev_a'], **specs[fid,'buffer_length']['value']['links'][0])]}}
    project_pairs(context)
    assert not context['input_length_binding']['diagnostics']
    context['buffer_length_contract']['links'][0]['binary_zero_allowed'] = False
    before = deepcopy(context['buffer_length_contract'])
    project_pairs(context)
    assert context['input_length_binding']['diagnostics'][0]['code'] == 'input_length_binding_conflict'
    assert context['buffer_length_contract'] == before


def test_group_length_reuses_input_selection_and_rejects_duplicate_extent(tmp_path):
    p, req, tools = activated(tmp_path, kind='input_binding')
    from harness_generation.harness_context.requirements import HarnessRequirementBuilder
    other = next(r for r in HarnessRequirementBuilder().build(p[1], p[3])['requirements'] if r['kind'] == 'buffer_length')
    tools.bootstrap()
    fid = p[0][-1]['parse']
    specs = direct_specs(fid)
    inputs = specs[fid,'input_binding']['value']
    lengths = deepcopy(specs[fid,'buffer_length']['value'])
    for row in lengths['links']:
        for key in ('length_parameter', 'requires_nul_termination', 'binary_zero_allowed'):
            row.pop(key)
    signed = registry(tools, [req, other])
    wire = {'resolutions': {'r'+str(i): {'status': 'resolved', 'facts': [{'value': v, 'evidence_ids': signed['evidence_ids']}],
        'discovered_api_dependencies': [], 'open_questions': []} for i, v in enumerate((inputs, lengths))}}
    expanded = expand_submission(wire, [req, other], signed, p[3])
    link = expanded['resolutions'][1]['facts'][0]['value']['links'][0]
    assert link['length_parameter'] == inputs['bindings'][0]['size_parameter']
    assert link['binary_zero_allowed'] == inputs['bindings'][0]['binary_zero_allowed']
    wire['resolutions']['r1']['facts'][0]['value']['links'][0]['length_parameter'] = 'different_extent'
    with pytest.raises(ValueError):
        expand_submission(wire, [req, other], signed, p[3])


def test_native_fact_evidence_is_scoped_to_its_complete_subject(tmp_path):
    p, req, tools = activated(tmp_path, kind='return_semantics')
    tools.execute('find_type_usages', {'type': 'Context'})
    foreign = tools.execute('get_function', {'function': p[0][-1]['create']})
    own = tools.bootstrap()
    signed = registry(tools)
    slot = {'status': 'resolved', 'facts': [{'value': dict(success='always',nullable=None,owned=None,error_cleanup=False),
        'evidence_ids': signed['subject_evidence_ids']}], 'discovered_api_dependencies': [], 'open_questions': []}
    validate_shape({'resolutions': {'r0':slot}}, terminal_schema([req], signed, p[3]))
    # Supporting API evidence can supplement, but cannot replace the subject.
    slot['facts'][0]['evidence_ids'] += foreign['evidence_ids']
    from harness_generation.harness_context.agent import parse_group_resolution
    parse_group_resolution(canonical({'resolutions': {'r0':slot}}), [req], tools)
    slot['facts'][0]['evidence_ids'] = foreign['evidence_ids']
    with pytest.raises(ValueError):
        parse_group_resolution(canonical({'resolutions': {'r0':slot}}), [req], tools)


def test_construction_and_state_api_roles_are_discriminated(tmp_path):
    p, req, tools = activated(tmp_path, kind='argument_construction')
    ids = p[0][-1]
    tools.execute('find_type_usages', {'type': 'Context'})
    tools.execute('get_function', {'function': ids['create']})
    tools.bootstrap()
    value = {'arguments': [{'parameter':'ctx', 'construction':'creator_api', 'api':ids['create'], 'resource_id':None, 'constant':None}]}
    validate_shape(value, value_schema(req, tools))
    value['arguments'][0]['construction'] = 'input'
    with pytest.raises(ValueError):
        validate_shape(value, value_schema(req, tools))
    from harness_generation.harness_context.requirements import HarnessRequirementBuilder
    state_req = next(r for r in HarnessRequirementBuilder().build(p[1], p[3])['requirements'] if r['kind'] == 'state')
    state = {'preconditions': [{'parameter':'ctx', 'kind':'initialized', 'api':ids['create']}]}
    validate_shape(state, value_schema(state_req, tools))
    state['preconditions'][0]['kind'] = 'input_fed'
    with pytest.raises(ValueError):
        validate_shape(state, value_schema(state_req, tools))


def test_registry_delta_replays_without_repeating_source_registry(tmp_path):
    p, req, tools = activated(tmp_path)
    tools.bootstrap()
    full = registry_update(tools)
    # bootstrap already emitted the initial registry; reset only transport state.
    tools._proposal_registry_sent = None
    full = registry_update(tools)
    assert 'origin_catalog' not in full['signed_proposal_registry']
    assert registry_update(tools) == {}
    tools.execute('find_type_usages', {'type': 'Context'})
    update = tools.execute('get_function', {'function': p[0][-1]['create']})
    merged = merge_registry(full['signed_proposal_registry'], update)
    # The intervening signature query adds evidence IDs only, not API effects.
    assert merged['support_candidates'] == registry(tools)['support_candidates']
    assert 'signed_proposal_registry_delta' in update and 'signed_proposal_registry' not in update


def test_parse_anchor_bounded_adapter_from_excluded_caller_compiles(tmp_path):
    source = '''#include <stdlib.h>
#include <stddef.h>
int parse(const unsigned char *src,size_t cb) {if(cb>16) abort();return cb?src[cb-1]:0;}
void usage(const unsigned char *raw,size_t extent) {size_t prefix=extent<16?extent:16;parse(raw,prefix);}
'''
    prepared = setup(tmp_path, source, roles={'parse': ('core','accepted_anchor'), 'usage': ('exclude','unrelated_behavior')}, discover_callers=True)
    ids = prepared[0][-1]
    specs = direct_specs(ids['parse'], data='src', size='cb')
    run, _ = mine(prepared, specs, persist=True)
    assert_gate(run)
    assert run.context['core_apis'] == [ids['parse']]
    plan = HarnessPlanBuilder().build(prepared[1], run.context, run.closure, prepared[3], run.completeness)
    scalar = next(r for r in plan['construction_recipes'] if r['kind'] == 'derived_scalar')
    assert scalar['bounds'] == [0,16]
    assert ids['usage'] not in {c['function_id'] for c in plan['call_sequence']}
    if shutil.which('clang') and shutil.which('clang++'):
        code = '''#include <stdint.h>
#include <stddef.h>
extern "C" int parse(const unsigned char *src,size_t cb);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size){
if(size>1048576)return 0;size_t cb=size<16?size:16;parse(data,cb);return 0;}
'''
        assert main(['context-generate','--artifacts',str(prepared[0][0].root),'--build','--runtime'],llm=FakeLLM([code])) == 0
