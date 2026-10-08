"""Internal reader coverage requires exact source flow, never API spelling."""
from copy import deepcopy
import shutil

import pytest

from harness_generation.context_generation.recipes import lower_recipes
from harness_generation.harness_context.argument_graph import build_argument_graph, parameter_id
from harness_generation.harness_context.input_contracts import project_internal_inputs
from harness_generation.harness_context.input_flow import project_input_flow
from harness_generation.harness_context.reconciliation import GraphContractReconciler
from test_argument_graph import graph_fixture, construction
from test_harness_context import (setup, mine, assert_gate, argument, owner, order,
                                 lifecycle_value, resource_id, direct_specs, binding)


SOURCE = '''#include <stddef.h>
#include <stdlib.h>
#include <string.h>
typedef struct Reader { const unsigned char *bytes; size_t extent; size_t cursor; } Reader;
Reader *open_bytes(const unsigned char *bytes, size_t extent) {
    Reader *r = malloc(sizeof(*r)); if(r) {r->bytes=bytes;r->extent=extent;r->cursor=0;} return r;
}
size_t take(Reader *r, unsigned char *destination, size_t capacity) {
    size_t n=r->extent-r->cursor; if(n>capacity)n=capacity;
    if(n)memcpy(destination,r->bytes+r->cursor,n);r->cursor+=n;return n;
}
int parse(Reader *r) {
    unsigned char temporary[4];unsigned sum=0;size_t n;
    while((n=take(r,temporary,sizeof(temporary))))for(size_t i=0;i<n;i++)sum+=temporary[i];return sum&255;
}
void release(Reader *r) { free(r); }
void example(const unsigned char *data,size_t size) {
    Reader *r=open_bytes(data,size); if(r){parse(r);release(r);}
}
'''


def fixture(tmp_path, source=SOURCE):
    return graph_fixture(tmp_path, source, bindings=[('open_bytes', 'bytes', 'extent')])


def graph_and_contract(f):
    graph = build_argument_graph(*f[:5])
    contract = GraphContractReconciler().reconcile(f[0], graph, f[2], f[3])
    return graph, contract


def row(contract, f, name, parameter):
    return next(r for r in contract['parameters'] if r['function_id'] == f[-1][name] and r['parameter'] == parameter)


def test_guarded_creator_and_internal_loop_preserve_same_origin_and_capacity(tmp_path):
    f = fixture(tmp_path)
    graph, contract = graph_and_contract(f)
    descriptor, = graph['internal_invocations']
    assert descriptor['function_id'] == f[-1]['take'] and descriptor['via_function_id'] == f[-1]['parse']
    assert descriptor['multiplicity'] == 'source_loop' and descriptor['calls_per_invocation'] == {'min': 1, 'max': None}
    assert descriptor['parameter_forwarding'] == [{'parameter': 'r', 'via_parameter': 'r'}]
    reader = row(contract, f, 'take', 'r')
    parser = row(contract, f, 'parse', 'r')
    cleanup = row(contract, f, 'release', 'r')
    assert reader['status'] == parser['status'] == cleanup['status'] == 'resolved'
    assert reader['recipe']['resource_id'] == parser['recipe']['resource_id'] == cleanup['recipe']['resource_id']
    assert cleanup['recipe']['kind'] == 'resource_reference'
    destination = row(contract, f, 'take', 'destination')
    assert destination['recipe']['kind'] == 'stack_array_storage'
    assert destination['recipe']['array_elements'] == 4 and destination['recipe']['element_type'] == 'unsigned char'
    assert destination['recipe']['storage_scope'] == 'internal_invocation'
    assert row(contract, f, 'take', 'capacity')['recipe']['value'] == 4
    assert graph['unresolved_ownership']  # Invocation provenance does not prove owned/free facts.
    assert graph_and_contract(f) == (graph, contract)


@pytest.mark.parametrize('before,after', [
    ('take(r,temporary,sizeof(temporary))', 'take(n ? r : 0,temporary,sizeof(temporary))'),
    ('sum+=temporary[i];', 'sum+=temporary[i];take(r,temporary,sizeof(temporary));'),
    ('sizeof(temporary)', '4'),
    ('sum+=temporary[i];', 'sum+=temporary[i];unknown(temporary);'),
    ('sum+=temporary[i];', 'sum+=temporary[i];r=0;'),
    ('temporary[4]', 'temporary[extent]'),
    ('temporary[4]', 'temporary[5000]'),
    ('unsigned char temporary[4]', 'unsigned char *temporary'),
    ('if(n)memcpy(destination,r->bytes+r->cursor,n);', 'global=destination;if(n)memcpy(destination,r->bytes+r->cursor,n);'),
    ('if(n)memcpy(destination,r->bytes+r->cursor,n);', 'unknown(destination);if(n)memcpy(destination,r->bytes+r->cursor,n);'),
    ('size_t n=r->extent-r->cursor;', 'r++;size_t n=r->extent-r->cursor;'),
    ('size_t n=r->extent-r->cursor;', '++r;size_t n=r->extent-r->cursor;'),
    ('size_t n=r->extent-r->cursor;', '(r)++;size_t n=r->extent-r->cursor;'),
    ('size_t n=r->extent-r->cursor;', 'r+=1;size_t n=r->extent-r->cursor;'),
    ('size_t n=r->extent-r->cursor;', '(r)+=1;size_t n=r->extent-r->cursor;'),
    ('size_t n=r->extent-r->cursor;', '(r)=r+1;size_t n=r->extent-r->cursor;'),
    ('size_t n=r->extent-r->cursor;', 'destination++;size_t n=r->extent-r->cursor;'),
    ('size_t n=r->extent-r->cursor;', '(destination)+=1;size_t n=r->extent-r->cursor;'),
    ('size_t n=r->extent-r->cursor;', 'void (*memcpy)(void*,const void*,size_t)=capture;size_t n=r->extent-r->cursor;'),
])
def test_unknown_flow_does_not_certify_internal_schedule(tmp_path, before, after):
    f = fixture(tmp_path, SOURCE.replace(before, after))
    graph, _ = graph_and_contract(f)
    assert graph['internal_invocations'] == []
    assert construction(graph, f[-1]['take'], 0) is None


def test_partial_or_changed_source_cannot_certify_internal_schedule(tmp_path):
    f = fixture(tmp_path)
    for change in ('remove', 'mutate'):
        records = deepcopy(f[4])
        eid = next(e for e, record in records.items() if record['function_id'] == f[-1]['take'])
        if change == 'remove':
            del records[eid]
        else:
            records[eid]['content'] += ' /* invented source */'
        graph = build_argument_graph(*f[:4], records)
        assert graph['internal_invocations'] == []


def test_local_memory_intrinsic_spelling_does_not_hide_a_known_retaining_callback(tmp_path):
    source = SOURCE.replace('#include <string.h>', '''#include <string.h>
void *captured;
static void capture(void *destination, const void *input, size_t size) { captured=destination; }
''').replace('size_t n=r->extent-r->cursor;',
            'void (*memcpy)(void*,const void*,size_t)=capture;size_t n=r->extent-r->cursor;')
    f = fixture(tmp_path, source)
    graph, _ = graph_and_contract(f)
    assert graph['internal_invocations'] == []
    assert construction(graph, f[-1]['take'], 0) is None


@pytest.mark.parametrize('guard', ['if(r)', 'if(r != 0)'])
def test_nonnull_source_guard_proves_only_the_exact_creator_subject(tmp_path, guard):
    f = fixture(tmp_path, SOURCE.replace('if(r){parse(r);release(r);}', guard+'{parse(r);release(r);}'))
    graph, contract = graph_and_contract(f)
    assert row(contract, f, 'parse', 'r')['status'] == 'resolved'
    assert construction(graph, f[-1]['parse'], 0)['source_kind'] == 'creator_return'


@pytest.mark.parametrize('replacement', [
    'if(size){parse(r);release(r);}',
    'if(r){parse(r);release(r);}else{parse(r);}',
    'if(r){if(size)parse(r);release(r);}',
    'if(r){unknown(&r);parse(r);release(r);}',
    'if(r){r=0;parse(r);release(r);}',
])
def test_other_control_flow_does_not_become_a_creator_binding(tmp_path, replacement):
    f = fixture(tmp_path, SOURCE.replace('if(r){parse(r);release(r);}', replacement))
    graph, contract = graph_and_contract(f)
    assert row(contract, f, 'parse', 'r')['status'] != 'resolved'


def test_internal_reader_input_is_the_same_evidenced_creator_context(tmp_path):
    f = fixture(tmp_path)
    graph, contract = graph_and_contract(f)
    context, _, requirements, snapshot, _, ids = f
    context['argument_graph'] = graph
    context['canonical_construction'] = contract
    rid = row(contract, f, 'parse', 'r')['recipe']['resource_id']
    eids = sorted(f[4])
    for name, returned in [('open_bytes', True), ('parse', False), ('take', False)]:
        context['lifecycle_contract']['resources'].append({'function_id': ids[name], 'subject_parameter': None if returned else 'r',
            'return_value': returned, 'resource_id': rid, 'evidence_ids': eids})
    context['input_contract']['bindings'][0].update(via_function_id=None)
    context['input_contract']['bindings'].append({'function_id': ids['parse'], 'parameter': 'r', 'size_parameter': None,
        'source': 'context', 'via_function_id': ids['open_bytes'], 'transform': 'none', 'evidence_ids': eids,
        'size_relation': 'none', 'fact_id': 'observed_context'})
    requirements = [*requirements, {'requirement_id': 'reader_input', 'subject_function_id': ids['take'], 'kind': 'input_binding'}]
    satisfied = project_internal_inputs(context, requirements)
    assert satisfied[0]['requirement_id'] == 'reader_input'
    context['ordering_graph'] = {'edges': []}
    project_input_flow(context, snapshot)
    assert set(context['external_input_flow']['reachable_functions']) >= {ids['open_bytes'], ids['parse'], ids['take']}
    assert any(r['function_id'] == ids['take'] and r['proof_kinds'] == ['source_internal_parameter_forwarding']
               for r in context['external_input_flow']['indirect_invocation_paths'])
    assert all(r['function_id'] == ids['open_bytes'] for r in context['external_input_flow']['roots'])


def test_internal_forwarding_never_joins_distinct_contexts(tmp_path):
    f = fixture(tmp_path)
    graph, contract = graph_and_contract(f)
    context = f[0]
    context['argument_graph'] = graph
    context['canonical_construction'] = contract
    row(contract, f, 'take', 'r')['recipe']['resource_id'] = 'different_instance'
    context['input_contract']['bindings'].append({'function_id': f[-1]['parse'], 'parameter': 'r', 'size_parameter': None,
        'source': 'context', 'via_function_id': f[-1]['open_bytes'], 'transform': 'none', 'evidence_ids': sorted(f[4])})
    assert project_internal_inputs(context, [{'requirement_id':'reader_input','subject_function_id':f[-1]['take'],'kind':'input_binding'}]) == []
    assert not any(b['function_id'] == f[-1]['take'] for b in context['input_contract']['bindings'])


def test_byte_array_lowering_retains_extent_and_does_not_allocate_one_element(tmp_path):
    f = fixture(tmp_path)
    graph, contract = graph_and_contract(f)
    f[0]['canonical_construction'] = contract
    recipes = lower_recipes(f[0], {f[-1]['parse'], f[-1]['take'], f[-1]['open_bytes']}, f[3])
    recipe, = [r for r in recipes if r['kind'] == 'stack_array_storage']
    assert recipe['array_elements'] == 4
    assert recipe['binding_expression'] == recipe['storage_variable']
    assert recipe['storage_type'] == 'unsigned char'


def stream_specs(ids):
    """Independent source-grounded contracts, retaining every mandatory fact."""
    parse, read, create, cleanup = (ids[name] for name in ('parse', 'take', 'open_bytes', 'release'))
    rid = resource_id(parse, 'r')
    specs = {}
    for fid, via in ((parse, create), (read, parse)):
        specs[fid, 'input_binding'] = {'value': {'bindings': [{'parameter': 'r', 'source': 'context',
            'transform': 'none', 'size_parameter': None, 'size_relation': 'none', 'nul_terminated': False,
            'binary_zero_allowed': True, 'mutable': True, 'alignment': 'none', 'via_function_id': via}]}}
        specs[fid, 'argument_construction'] = {'value': {'arguments': [argument('r', 'creator_api', create, rid)]}}
        specs[fid, 'lifecycle'] = {'value': lifecycle_value(fid, rid, 'Reader', 'r', create, cleanup),
            'dependencies': [{'function_id': create, 'necessity': 'required', 'reason': 'creation'},
                             {'function_id': cleanup, 'necessity': 'required', 'reason': 'cleanup'}]}
        specs[fid, 'ownership'] = {'value': {'entries': [owner('r', resource=rid)]}}
        specs[fid, 'state'] = {'value': {'preconditions': [{'parameter': 'r', 'kind': 'initialized', 'api': create}]}}
        specs[fid, 'return_semantics'] = {'value': {'success': 'always', 'nullable': None, 'owned': None, 'error_cleanup': False}}
        specs[fid, 'call_order'] = {'value': {'constraints': [order(create, fid), order(fid, cleanup)]}}
    specs[read, 'argument_construction']['value']['arguments'] += [argument('destination', 'stack'),
        {**argument('capacity', 'constant'), 'constant': 4}]
    specs[read, 'buffer_length'] = {'value': {'applicable': True, 'links': [{'buffer_parameter': 'destination',
        'length_parameter': 'capacity', 'relation': 'capacity', 'element_type': 'unsigned char',
        'requires_nul_termination': False, 'binary_zero_allowed': True}]}}
    specs[read, 'ownership']['value']['entries'].append(owner('destination'))
    specs.update(direct_specs(create, data='bytes', size='extent'))
    specs[create, 'lifecycle'] = {'value': lifecycle_value(create, rid, 'Reader', None, create, cleanup)}
    specs[create, 'ownership']['value']['entries'].append(owner(returned=True, ownership='owned', release=cleanup, resource=rid))
    specs[create, 'return_semantics'] = {'value': {'success': 'nonnull', 'nullable': True, 'owned': True, 'error_cleanup': False}}
    specs[create, 'call_order'] = {'value': {'constraints': [order(create, cleanup)]}}
    specs[cleanup, 'argument_construction'] = {'value': {'arguments': [argument('r', 'derived')]}}
    specs[cleanup, 'ownership'] = {'value': {'entries': [owner('r', ownership='transferred')]}}
    for fid, reason in ((create, 'creation'), (cleanup, 'cleanup')):
        specs[fid, 'support_decision'] = {'value': {'decision': 'required', 'reason': reason, 'required_by': [parse, read]},
            'dependencies': [{'function_id': fid, 'necessity': 'required', 'reason': reason, 'required_by': parent}
                             for parent in (parse, read)]}
    return specs


def stream_context(tmp_path, *, omit=None, grouped=False, change_specs=None):
    prepared = setup(tmp_path, SOURCE, roles={'parse': ('core', 'accepted_anchor'), 'take': ('core', 'core_processing'),
        'open_bytes': ('support', 'resource_creation'), 'release': ('support', 'resource_cleanup')}, discover_callers=True)
    specs = stream_specs(prepared[0][-1])
    if omit:
        specs.pop((prepared[0][-1][omit[0]], omit[1]))
    if change_specs:
        change_specs(specs, prepared[0][-1])
    if grouped:
        from harness_generation.harness_context import HarnessContextMiningLoop
        from test_context_grouping import GroupedFixtureModel
        model = GroupedFixtureModel(specs, query_type='Reader', initial_ids=prepared[5].initial_ids)
        run = HarnessContextMiningLoop(model, prepared[4], group_requirements=True).run(
            prepared[1], prepared[3], prepared[5])
    else:
        run, _ = mine(prepared, specs, query_type='Reader')
    return prepared, run


STREAM_HARNESS = '''#include <stdint.h>
#include <stddef.h>
typedef struct Reader { const unsigned char *bytes; size_t extent; size_t cursor; } Reader;
extern "C" Reader *open_bytes(const unsigned char *bytes, size_t extent);
extern "C" size_t take(Reader *r, unsigned char *destination, size_t capacity);
extern "C" int parse(Reader *r);
extern "C" void release(Reader *r);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 1048576) return 0;
    Reader *r = open_bytes(data, size);
    if (r) { (void)parse(r); release(r); }
    return 0;
}
'''


@pytest.mark.parametrize('grouped', [False, True], ids=['atomic', 'grouped'])
def test_full_context_gate_plan_and_code_preserve_internal_reader_scope(tmp_path, grouped):
    from harness_generation.context_generation import HarnessPlanBuilder
    from harness_generation.context_generation.validation import validate_code
    prepared, run = stream_context(tmp_path, grouped=grouped)
    assert_gate(run)
    assert run.completeness['hard_missing'] == [] and run.completeness['validation_errors'] == []
    ids = prepared[0][-1]
    assert set(run.context['external_input_flow']['reachable_functions']) >= {ids[n] for n in ('open_bytes', 'parse', 'take')}
    plan = HarnessPlanBuilder().build(prepared[1], run.context, run.closure, prepared[3], run.completeness)
    assert plan == HarnessPlanBuilder().build(prepared[1], run.context, run.closure, prepared[3], run.completeness)
    reader, = [call for call in plan['call_sequence'] if call['function_id'] == ids['take']]
    assert reader['invocation_kind'] == 'internal' and reader['via_function_id'] == ids['parse']
    assert reader['multiplicity'] == 'source_loop' and reader['calls_per_input'] is None
    assert reader['storage_lifetime'] == 'via_invocation'
    creator, = [call for call in plan['call_sequence'] if call['role'] == 'create']
    assert reader['arguments'][0]['resource_id'] == creator['return_resource']
    assert all(root['function_id'] == ids['open_bytes'] for root in run.context['external_input_flow']['roots'])
    destination, = [a for a in reader['arguments'] if a['parameter'] == 'destination']
    assert destination['canonical_recipe']['kind'] == 'stack_array_storage'
    assert destination['canonical_recipe']['array_elements'] == 4
    capacity, = [a for a in reader['arguments'] if a['parameter'] == 'capacity']
    assert capacity['canonical_recipe']['kind'] == 'constant' and capacity['canonical_recipe']['value'] == 4
    assert validate_code(STREAM_HARNESS, plan)['status'] == 'valid'
    extra = STREAM_HARNESS.replace('(void)parse(r);', 'unsigned char extra[4];take(r,extra,sizeof(extra));(void)parse(r);')
    assert validate_code(extra, plan)['status'] == 'invalid'
    changed = deepcopy(run.context)
    changed['argument_graph']['internal_invocations'][0]['local_arguments'][0]['elements'] = 8
    from harness_generation.context_generation import PlanError
    with pytest.raises(PlanError):
        HarnessPlanBuilder().build(prepared[1], changed, run.closure, prepared[3], run.completeness)


@pytest.mark.parametrize('omit', [('open_bytes', 'ownership'), ('take', 'ownership'), ('parse', 'lifecycle')])
def test_internal_certificate_never_satisfies_missing_mandatory_semantics(tmp_path, omit):
    _, run = stream_context(tmp_path, omit=omit)
    assert run.completeness['generation_allowed'] is False
    assert run.context['frozen'] is False
    assert run.completeness['hard_missing']


def test_grouped_output_storage_cannot_be_reclassified_as_a_fuzz_input(tmp_path):
    def wrong(specs, ids):
        specs[ids['take'], 'input_binding']['value']['bindings'].append(binding('destination', 'capacity'))
        specs[ids['take'], 'argument_construction']['value']['arguments'][1]['construction'] = 'input'
    _, run = stream_context(tmp_path, grouped=True, change_specs=wrong)
    assert run.completeness['generation_allowed'] is False
    assert run.completeness['hard_missing']


def test_grouped_explicit_input_link_with_wrong_units_is_still_blocked(tmp_path):
    def wrong(specs, ids):
        specs[ids['open_bytes'], 'buffer_length']['value']['links'][0]['relation'] = 'elements'
        specs[ids['open_bytes'], 'buffer_length']['value']['links'][0]['element_type'] = 'unsigned char'
    _, run = stream_context(tmp_path, grouped=True, change_specs=wrong)
    assert run.completeness['generation_allowed'] is False
    assert any(gap['kind'] in {'input_binding', 'buffer_length'} for gap in run.completeness['hard_missing'])


def test_internal_reader_compiles_and_replays_six_sanitized_inputs(tmp_path):
    if not shutil.which('clang') or not shutil.which('clang++'):
        pytest.skip('clang toolchain unavailable')
    from harness_generation.context_generation import HarnessPlanBuilder
    from harness_generation.context_generation.build import build_and_run
    from harness_generation.target_build import TargetBuildConfig
    prepared, run = stream_context(tmp_path)
    assert_gate(run)
    plan = HarnessPlanBuilder().build(prepared[1], run.context, run.closure, prepared[3], run.completeness)
    harness = tmp_path / 'harness.cpp'
    harness.write_text(STREAM_HARNESS)
    recipe = TargetBuildConfig(project_root=tmp_path / 'project', source_files=(tmp_path / 'project' / 'api.c',))
    build, replay = build_and_run(harness, tmp_path / 'build', plan, recipe, runtime=True)
    assert build['status'] == 'passed', build
    assert replay['status'] == 'passed' and len(replay['cases']) == 6, replay
    assert all(case['success'] for case in replay['cases'])
