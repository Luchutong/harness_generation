"""Source-preserving pointer casts and byte alignment do not weaken bindings."""
from copy import deepcopy

import pytest

from harness_generation.context_generation.validation import validate_code
from test_context_generation import ready, DIRECT_CODE


def call(code, expression='data', extent='size'):
    return code.replace('parse(data, size)', f'parse({expression}, {extent})')


@pytest.mark.parametrize('keyword', ['static_cast', 'reinterpret_cast', 'const_cast'])
def test_native_single_pointer_cast_preserves_exact_fuzz_source(tmp_path, keyword):
    _, _, plan = ready(tmp_path)
    result = validate_code(call(DIRECT_CODE, f'{keyword}<const unsigned char*>(data)'), plan)
    assert result['status'] == 'valid'
    assert result['observed_calls'] == {'parse': 1}
    assert result['validator'] == 'frozen_plan_code_v8'


@pytest.mark.parametrize('expression', [
    'reinterpret_cast<const unsigned char*>(data+1)',
    'reinterpret_cast<const unsigned char*>(NULL)',
    'reinterpret_cast<const unsigned char*>(unrelated)',
    'reinterpret_cast<unsigned long>(data)',
    'static_cast<size_t>(size)',
    'const_cast<unsigned long>(data)',
    'dynamic_cast<const unsigned char*>(data)',
    'unknown_cast<const unsigned char*>(data)',
    'reinterpret_cast<const unsigned char*, int>(data)',
    'reinterpret_cast<const unsigned char*>(data,size)',
    'reinterpret_cast<const unsigned char**>(data)',
    'reinterpret_cast<const unsigned char&>(data)',
    'reinterpret_cast<Unknown<unsigned char>*>(data)',
    'std::reinterpret_cast<const unsigned char*>(data)',
    '(unsigned long)data',
])
def test_casts_cannot_create_source_or_authorize_unknown_template_calls(tmp_path, expression):
    _, _, plan = ready(tmp_path)
    code = DIRECT_CODE.replace('(void)parse(data, size);',
        f'const unsigned char unrelated[1]={{0}};(void)parse({expression}, size);')
    result = validate_code(code, plan)
    assert result['status'] == 'invalid'
    assert 'canonical_fuzz_bytes_binding_mismatch' in result['errors']


@pytest.mark.parametrize('extent', ['0', '1', 'size+1', 'size/2', 'static_cast<size_t>(size)'])
def test_pointer_cast_keeps_original_exact_extent_contract(tmp_path, extent):
    _, _, plan = ready(tmp_path)
    result = validate_code(call(DIRECT_CODE,
        'reinterpret_cast<const unsigned char*>(data)', extent), plan)
    assert 'canonical_fuzz_size_binding_mismatch' in result['errors']


@pytest.mark.parametrize('byte_type', ['char', 'signed char', 'unsigned char'])
@pytest.mark.parametrize('typedef', [False, True])
def test_natural_byte_alignment_uses_authenticated_frozen_parameter(tmp_path, byte_type, typedef):
    _, _, original = ready(tmp_path)
    plan = deepcopy(original)
    parameter = plan['api_declarations'][0]['parameters'][0]
    parameter.update(base_type=byte_type, type=f'const {byte_type} *')
    if typedef:
        parameter.update(type='const byte_alias *', declaration='const byte_alias * data')
        plan['type_declarations'].append(f'typedef {byte_type} byte_alias;')
    plan['call_sequence'][0]['arguments'][0]['input_binding']['alignment'] = 'natural'
    result = validate_code(DIRECT_CODE, plan)
    assert result['status'] == 'valid'
    assert original['call_sequence'][0]['arguments'][0]['input_binding']['alignment'] == 'none'


@pytest.mark.parametrize('metadata', [
    {'base_type': 'uint32_t'}, {'base_type': 'unsigned int'}, {'base_type': 'wchar_t'},
    {'base_type': 'unknown_alias'}, {'base_type': ''}, {'pointer_depth': 2}, {'is_pointer': False},
])
def test_natural_nonbyte_or_unresolved_parameter_still_requires_copy(tmp_path, metadata):
    _, _, original = ready(tmp_path)
    plan = deepcopy(original)
    plan['api_declarations'][0]['parameters'][0].update(metadata)
    plan['call_sequence'][0]['arguments'][0]['input_binding']['alignment'] = 'natural'
    # Even a generated declaration cannot authenticate the source alias.
    code = DIRECT_CODE.replace('#include <stddef.h>',
        '#include <stddef.h>\ntypedef unsigned char unknown_alias;')
    result = validate_code(code, plan)
    assert 'canonical_fuzz_bytes_binding_mismatch' in result['errors']


@pytest.mark.parametrize('declarations', [[],
    ['typedef unsigned char byte_alias __attribute__((aligned(16)));'],
    ['typedef unsigned char byte_alias;','typedef unsigned char byte_alias;'],
    ['typedef unsigned int byte_alias;'],
])
def test_natural_resolved_alias_needs_frozen_unadorned_single_byte_typedef(tmp_path, declarations):
    _, _, original = ready(tmp_path)
    plan = deepcopy(original)
    plan['api_declarations'][0]['parameters'][0].update(base_type='unsigned char',type='const byte_alias *')
    plan['type_declarations'] += declarations
    plan['call_sequence'][0]['arguments'][0]['input_binding']['alignment'] = 'natural'
    code = DIRECT_CODE.replace('#include <stddef.h>',
        '#include <stddef.h>\ntypedef unsigned char byte_alias;')
    assert 'canonical_fuzz_bytes_binding_mismatch' in validate_code(code,plan)['errors']


@pytest.mark.parametrize('binding', [
    {'transform': 'copy'}, {'mutable': True}, {'nul_terminated': True}, {'alignment': 'explicit'},
])
def test_byte_alignment_never_bypasses_copy_mutability_terminator_or_explicit_contract(tmp_path, binding):
    _, _, original = ready(tmp_path)
    plan = deepcopy(original)
    plan['call_sequence'][0]['arguments'][0]['input_binding'].update({'alignment': 'natural', **binding})
    result = validate_code(call(DIRECT_CODE, 'reinterpret_cast<const unsigned char*>(data)'), plan)
    assert 'canonical_fuzz_bytes_binding_mismatch' in result['errors']


def test_pointer_cast_cannot_change_resource_identity(tmp_path):
    _, _, original = ready(tmp_path, 'context')
    plan = deepcopy(original)
    # The real shared plan uses the creator resource for both parse and cleanup.
    SHARED_CODE = '''#include <stdint.h>
#include <stddef.h>
typedef struct Context { int ready; int calls; } Context;
extern "C" Context *create(void);
extern "C" void destroy(Context *ctx);
extern "C" int parse(Context *ctx, const unsigned char *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
 Context *ctx=create(); if(ctx) { parse(ctx,data,size); destroy(ctx); } return 0;
}
'''
    assert validate_code(SHARED_CODE, plan)['status'] == 'valid'
    same_resource = SHARED_CODE.replace('Context *ctx=create()',
        'Context *ctx=reinterpret_cast<Context*>(create())')
    assert validate_code(same_resource, plan)['status'] == 'valid'
    code = SHARED_CODE.replace('parse(ctx,data,size)', 'parse(reinterpret_cast<Context*>(data),data,size)')
    result = validate_code(code, plan)
    assert 'canonical_resource_binding_mismatch' in result['errors']


def test_cast_alias_write_still_invalidates_original_fuzz_bytes(tmp_path):
    _, _, plan = ready(tmp_path)
    code = DIRECT_CODE.replace('(void)parse(data, size);',
        '*const_cast<unsigned char*>(data)=0;(void)parse(data,size);')
    assert 'canonical_fuzz_bytes_binding_mismatch' in validate_code(code, plan)['errors']


def test_natural_nonbyte_parameter_can_use_exact_live_malloc_copy(tmp_path):
    _, _, original = ready(tmp_path)
    plan = deepcopy(original)
    plan['api_declarations'][0]['parameters'][0]['base_type'] = 'unsigned int'
    plan['call_sequence'][0]['arguments'][0]['input_binding']['alignment'] = 'natural'
    code = DIRECT_CODE.replace('#include <stddef.h>',
        '#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>').replace('(void)parse(data, size);',
        'unsigned char *copy=static_cast<unsigned char*>(malloc(size));'
        'if(copy){if(size)memcpy(copy,data,size);parse(copy,size);free(copy);}')
    assert validate_code(code, plan)['status'] == 'valid'
    assert validate_code(code.replace('memcpy(copy,data,size)', 'memcpy(copy,data+1,size)'), plan)['status'] == 'invalid'
