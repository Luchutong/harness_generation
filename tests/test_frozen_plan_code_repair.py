"""One code correction keeps the exact FrozenPlan, original failures and costs."""
from copy import deepcopy
import hashlib
import json
import os
import re
from pathlib import Path
import shutil

import pytest

from harness_generation.context_generation.cli import main
from harness_generation.context_generation.code_repair import translate
from harness_generation.context_generation.stage4 import ContextStage4Generator
from harness_generation.context_generation.validation import validate_code
from harness_generation.llm import LLMError, LLMGeneration
from harness_generation.semantic_discovery.models import digest
from test_context_generation import ready, DIRECT_CODE


BAD_CODE = DIRECT_CODE.replace('(void)parse(data, size);', '(void)parse(data, size);\n    (void)parse(data, size);')
# Tree-sitter establishes valid syntax but the C++ compiler rejects the name.
COMPILE_BAD_CODE = DIRECT_CODE.replace('return 0;\n}', 'return undeclared_compiler_value;\n}')
RUNTIME_BAD_CODE = DIRECT_CODE.replace('return 0;\n}',
    'volatile int zero=0; volatile int value=1/zero; (void)value; return 0;\n}')


class ScriptedCodeLLM:
    provider = 'explicit-offline-code-repair-test'
    model = 'same-frozen-model'

    def __init__(self, steps):
        self.steps = list(steps)
        self.calls = []

    def generate(self, prompt):
        number = len(self.calls) + 1
        self.calls.append(deepcopy(prompt.to_dict()))
        if not self.steps:
            raise AssertionError('Unregistered hidden code model attempt')
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        if callable(step):
            step = step(prompt)
        return LLMGeneration(step, self.model, prompt.prompt_version, self.provider,
            response_id=f'offline-code-response-{number}', finish_reason='stop',
            usage={'prompt_tokens': number * 17, 'completion_tokens': number * 23,
                   'total_tokens': number * 40},
            metadata={'max_tokens': 8192, 'temperature': 0.2, 'timeout': 120})


def read(path):
    return json.loads(path.read_text())


def hashes(paths, base):
    return {p.relative_to(base).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(paths) if p.is_file()}


def original_inputs(store):
    return hashes([p for p in store.root.rglob('*') if p.is_file()
                   and 'context_generations' not in p.parts], store.root)


def generation_directory(store):
    return next((store.root / 'context_generations').glob('*/*/*/metadata.json')).parent


def assert_attempt_integrity(directory, metadata, expected_statuses):
    assert metadata['model_calls'] == len(expected_statuses)
    attempts = metadata['model_attempts']
    assert len(attempts) == len(expected_statuses)
    assert [r['status'] for r in attempts] == expected_statuses
    plan = read(directory / 'harness_plan.json')
    for number, record in enumerate(attempts, 1):
        assert record['attempt'] == number and record['model_call'] is True
        assert record['plan_digest'] == digest(plan)
        attempt_dir = directory / 'code_attempts' / f'attempt_{number:04d}'
        assert read(attempt_dir / 'attempt.json') == record
        assert not (attempt_dir / 'metadata.json').exists()
        for name, sha in record['file_digests'].items():
            assert hashlib.sha256((directory/name).read_bytes()).hexdigest() == sha
    assert len(list(directory.rglob('metadata.json'))) == 1
    return attempts, plan


@pytest.mark.skipif(not shutil.which('clang') or not shutil.which('clang++'), reason='clang unavailable')
def test_invalid_code_then_explicit_corrected_code_same_plan_replays_six_inputs(tmp_path):
    store, frozen, plan = ready(tmp_path)
    before = original_inputs(store)
    project_before = hashes(frozen[-1].project_root.rglob("*"),frozen[-1].project_root)
    def corrected(prompt):
        assert prompt.parameters['harness_plan'] == plan
        assert prompt.parameters['repair_data']['previous_code']==BAD_CODE.strip()+'\n'
        assert 'required_invocation_count_mismatch' in prompt.content
        assert 'UNTRUSTED' in prompt.content.upper()
        return DIRECT_CODE
    llm = ScriptedCodeLLM([BAD_CODE, corrected])
    assert main(['--artifacts',str(store.root),'--max-code-repairs','1','--build','--runtime'],llm=llm)==0
    directory = generation_directory(store)
    metadata = read(directory/'metadata.json')
    attempts, saved_plan = assert_attempt_integrity(directory,metadata,['invalid_code','passed'])
    assert metadata['code_repairs']==1 and metadata['configuration']['max_code_repairs']==1
    assert saved_plan==plan and original_inputs(store)==before
    assert hashes(frozen[-1].project_root.rglob("*"),frozen[-1].project_root)==project_before
    assert len(llm.calls)==2 and all(c['parameters']['harness_plan']==plan for c in llm.calls)
    first=directory/'code_attempts/attempt_0001'
    assert (first/'harness.cpp').read_text()==BAD_CODE.strip()+'\n'
    assert read(first/'code_validation.json')['status']=='invalid'
    assert (directory/'harness.cpp').read_text()==DIRECT_CODE.strip()+'\n'
    assert read(directory/'code_validation.json')['status']=='valid'
    runtime=read(directory/'build/runtime.json')
    assert runtime['status']=='passed' and len(runtime['cases'])==6
    from harness_generation.context_generation.build import SMOKE_INPUTS
    assert [(directory/'build'/f'input_{n}.bin').read_bytes() for n in range(6)]==list(SMOKE_INPUTS)
    responses=[(p,read(p)) for p in directory.rglob('response.json')]
    assert len(responses)==2
    assert {str(p.relative_to(directory)) for p,_ in responses}=={'response.json','code_attempts/attempt_0002/response.json'}
    assert read(directory/'response.json')['content']==BAD_CODE
    assert read(directory/'code_attempts/attempt_0002/response.json')['content']==DIRECT_CODE
    assert len({r['response_id'] for _,r in responses})==2
    assert sum(r['usage']['total_tokens'] for _,r in responses)==120
    assert all(r['metadata']=={'max_tokens':8192,'temperature':0.2,'timeout':120} for _,r in responses)
    assert all(r['usage_known'] for r in attempts)
    assert attempts[0]['response_path']=='response.json'
    assert attempts[1]['response_path']=='code_attempts/attempt_0002/response.json'


@pytest.mark.skipif(not shutil.which('clang') or not shutil.which('clang++'), reason='clang unavailable')
def test_compile_failed_then_corrected_code_gets_exact_compiler_diagnostics(tmp_path):
    store,_,plan=ready(tmp_path)
    assert validate_code(COMPILE_BAD_CODE,plan)['status']=='valid'
    def correct(prompt):
        assert prompt.parameters['harness_plan']==plan
        assert 'undeclared_compiler_value' in prompt.content and 'compile_failed' in prompt.content
        assert 'error:' in prompt.content
        return DIRECT_CODE
    llm=ScriptedCodeLLM([COMPILE_BAD_CODE,correct])
    assert main(['--artifacts',str(store.root),'--max-code-repairs','1','--build','--runtime'],llm=llm)==0
    d=generation_directory(store);attempts,_=assert_attempt_integrity(d,read(d/'metadata.json'),['compile_failed','passed'])
    archived=read(d/'code_attempts/attempt_0001/build/build.json')
    assert not archived['success'] and any(c.get('return_code')!=0 for c in archived['commands'])
    assert read(d/'build/build.json')['success'] and read(d/'build/runtime.json')['status']=='passed'
    assert len(llm.calls)==2 and attempts[0]['usage_known']


def test_second_invalid_translation_stops_at_two_and_keeps_both_failures(tmp_path):
    store,_,plan=ready(tmp_path)
    llm=ScriptedCodeLLM([BAD_CODE,BAD_CODE,DIRECT_CODE])
    assert main(['--artifacts',str(store.root),'--max-code-repairs','1'],llm=llm)==1
    d=generation_directory(store);m=read(d/'metadata.json')
    assert_attempt_integrity(d,m,['invalid_code','invalid_code'])
    assert m['status']=='invalid_code' and m['code_repairs']==1 and len(llm.calls)==2
    assert validate_code((d/'harness.cpp').read_text(),plan)['status']=='invalid'
    assert len(list(d.rglob('response.json')))==2 and len(llm.steps)==1


@pytest.mark.parametrize('binding',['parse(data, 0)','parse(data+1, size)'])
def test_second_attempt_cannot_replace_original_fuzz_data_or_extent_binding(tmp_path,binding):
    store,_,plan=ready(tmp_path)
    changed=DIRECT_CODE.replace('parse(data, size)',binding)
    assert validate_code(changed,plan)['status']=='invalid'
    llm=ScriptedCodeLLM([BAD_CODE,changed,DIRECT_CODE])
    assert main(['--artifacts',str(store.root),'--max-code-repairs','1'],llm=llm)==1
    d=generation_directory(store);m=read(d/'metadata.json')
    assert_attempt_integrity(d,m,['invalid_code','invalid_code'])
    assert read(d/'harness_plan.json')==plan and len(llm.calls)==2


@pytest.mark.parametrize('content',['','x'*131073])
def test_response_usage_survives_empty_or_oversized_code_without_hidden_repair(tmp_path,content):
    store,_,_=ready(tmp_path)
    llm=ScriptedCodeLLM([content,DIRECT_CODE])
    assert main(['--artifacts',str(store.root),'--max-code-repairs','1'],llm=llm)==1
    d=generation_directory(store);m=read(d/'metadata.json')
    attempts,_=assert_attempt_integrity(d,m,['generation_failed'])
    assert len(llm.calls)==1 and m['code_repairs']==0
    response=read(d/'response.json')
    assert response['content']==content and response['usage']['total_tokens']==40
    assert attempts[0]['usage_known'] and attempts[0]['response_path']=='response.json'
    assert not (d/'harness.cpp').exists()


def test_first_valid_response_never_spends_registered_optional_repair(tmp_path):
    store,_,_=ready(tmp_path)
    llm=ScriptedCodeLLM([DIRECT_CODE,BAD_CODE])
    assert main(['--artifacts',str(store.root),'--max-code-repairs','1'],llm=llm)==0
    d=generation_directory(store);m=read(d/'metadata.json')
    assert_attempt_integrity(d,m,['passed'])
    assert len(llm.calls)==1 and m['code_repairs']==0


@pytest.mark.parametrize('error',['OpenAI-compatible endpoint returned HTTP 401',
                                  'OpenAI-compatible request failed: TimeoutError', 'unknown provider failure'])
def test_second_provider_failure_preserves_first_cost_and_unknown_second_usage(tmp_path,error):
    store,_,_=ready(tmp_path)
    llm=ScriptedCodeLLM([BAD_CODE,LLMError(error),DIRECT_CODE])
    assert main(['--artifacts',str(store.root),'--max-code-repairs','1'],llm=llm)==1
    d=generation_directory(store);m=read(d/'metadata.json')
    attempts,_=assert_attempt_integrity(d,m,['invalid_code','generation_failed'])
    assert len(llm.calls)==m['model_calls']==2 and m['status']=='generation_failed'
    assert attempts[0]['usage_known'] is True and attempts[1]['usage_known'] is False
    assert attempts[1]['response_path'] is None and attempts[1]['error_category']
    assert len(list(d.rglob('response.json')))==1 and read(d/'response.json')['usage']['total_tokens']==40
    assert not (d/'harness.cpp').exists() and not (d/'code_validation.json').exists()
    assert (d/'code_attempts/attempt_0001/harness.cpp').read_text()==BAD_CODE.strip()+'\n'
    assert not (d/'code_attempts/attempt_0002/harness.cpp').exists()


@pytest.mark.parametrize('error',['OpenAI-compatible endpoint returned HTTP 403',
                                  'OpenAI-compatible request failed: TimeoutError'])
def test_initial_provider_failure_never_requests_code_correction(tmp_path,error):
    store,_,_=ready(tmp_path)
    llm=ScriptedCodeLLM([LLMError(error),DIRECT_CODE])
    assert main(['--artifacts',str(store.root),'--max-code-repairs','1'],llm=llm)==1
    d=generation_directory(store);m=read(d/'metadata.json')
    assert_attempt_integrity(d,m,['generation_failed'])
    assert len(llm.calls)==1 and m['code_repairs']==0 and not list(d.rglob('response.json'))


@pytest.mark.skipif(not shutil.which('clang') or not shutil.which('clang++'), reason='clang unavailable')
def test_runtime_failure_never_repairs_or_changes_fixtures(tmp_path):
    store,_,_=ready(tmp_path)
    llm=ScriptedCodeLLM([RUNTIME_BAD_CODE,DIRECT_CODE])
    assert main(['--artifacts',str(store.root),'--max-code-repairs','1','--build','--runtime'],llm=llm)==1
    d=generation_directory(store);m=read(d/'metadata.json')
    assert_attempt_integrity(d,m,['runtime_failed'])
    assert len(llm.calls)==1 and m['code_repairs']==0
    runtime=read(d/'build/runtime.json');assert runtime['status']=='failed' and len(runtime['cases'])==6


@pytest.mark.parametrize('mode',['harness','plan_only','blocked'])
def test_existing_code_plan_only_and_blocked_inputs_never_generate_or_repair(tmp_path,mode):
    store,_,plan=ready(tmp_path)
    llm=ScriptedCodeLLM([DIRECT_CODE])
    args=['--artifacts',str(store.root),'--max-code-repairs','1']
    if mode=='harness':
        harness=tmp_path/'explicit_existing.cpp';harness.write_text(BAD_CODE)
        args+=['--harness',str(harness)]
    elif mode=='plan_only':args+=['--plan-only']
    else:
        p=store.root/'harness_contexts'/plan['ft_id']/'harness_context.json';c=read(p);c['frozen']=False;p.write_text(json.dumps(c))
    result=main(args,llm=llm)
    assert result==(0 if mode=='plan_only' else 1) and llm.calls==[]
    assert not list((store.root/'context_generations').rglob('code_attempts'))


def test_default_zero_cap_keeps_single_attempt_and_explicit_one_is_not_resumed_as_zero(tmp_path):
    store,_,_=ready(tmp_path)
    llm=ScriptedCodeLLM([BAD_CODE,DIRECT_CODE])
    assert main(['--artifacts',str(store.root)],llm=llm)==1
    d=generation_directory(store);m=read(d/'metadata.json')
    assert_attempt_integrity(d,m,['invalid_code'])
    assert m['configuration']['max_code_repairs']==0 and m['code_repairs']==0 and len(llm.calls)==1
    assert main(['--artifacts',str(store.root),'--resume','--max-code-repairs','1'],llm=llm)==0
    assert len(llm.calls)==2


@pytest.mark.parametrize('value',['-1','2'])
def test_cli_rejects_unregistered_code_repair_caps_before_any_call(tmp_path,value):
    llm=ScriptedCodeLLM([])
    with pytest.raises(SystemExit):main(['--artifacts',str(tmp_path),'--max-code-repairs',value],llm=llm)
    assert llm.calls==[]


def test_same_plan_cannot_be_mutated_by_generator_callback(tmp_path):
    _,_,plan=ready(tmp_path)
    original=deepcopy(plan)
    def mutate(prompt):
        prompt.parameters['harness_plan']['input_policy']['max_bytes']+=1
        return DIRECT_CODE
    llm=ScriptedCodeLLM([mutate,DIRECT_CODE])
    directory=tmp_path/'isolated_translation';directory.mkdir()
    status,calls,error,attempts=translate(directory,plan,ContextStage4Generator(llm),max_code_repairs=1)
    assert status=='generation_failed' and calls==1 and len(llm.calls)==1
    assert attempts[0]['plan_digest']==digest(original) and attempts[0]['error_category']=='ValueError'
    assert not (directory/'harness.cpp').exists()




@pytest.mark.parametrize('replacement', [
    'parse(data+1, size)', 'parse(NULL, size)', 'parse(data, 0)',
    'parse(data, 1)', 'parse(data, size+1)', 'parse(data, size/2)',
    'parse(data, (size_t)0)',
])
@pytest.mark.parametrize('empty_recipes', [False, True])
def test_exact_fuzz_arguments_are_checked_without_construction_collection(tmp_path,replacement,empty_recipes):
    _,_,original=ready(tmp_path)
    plan=deepcopy(original)
    if empty_recipes:
        plan['construction_recipes']=[]
        for argument in plan['call_sequence'][0]['arguments']:
            argument.pop('canonical_recipe',None)
    validation=validate_code(DIRECT_CODE.replace('parse(data, size)',replacement),plan)
    assert validation['status']=='invalid'
    assert any(e in validation['errors'] for e in ['canonical_fuzz_bytes_binding_mismatch',
                                                  'canonical_fuzz_size_binding_mismatch'])
    assert validate_code(DIRECT_CODE,plan)['status']=='valid'
    assert original['construction_recipes']


@pytest.mark.parametrize('before,invocation', [
    ('data++;', 'parse(data,size)'),
    ('size++;', 'parse(data,size)'),
    ('const unsigned char *input=data; input=NULL;', 'parse(input,size)'),
    ('size_t extent=size; extent=0;', 'parse(data,extent)'),
    ('memset((void*)data,0,size);', 'parse(data,size)'),
    ('unsigned char unrelated[1]={0};', 'parse(unrelated,size)'),
])
def test_fuzz_parameter_alias_rebinding_and_write_invalidation_are_rejected(tmp_path,before,invocation):
    _,_,plan=ready(tmp_path)
    code=DIRECT_CODE.replace('#include <stddef.h>','#include <stddef.h>\n#include <string.h>')
    code=code.replace('(void)parse(data, size);',before+'(void)'+invocation+';')
    assert validate_code(code,plan)['status']=='invalid'


def test_renamed_entry_parameters_and_exact_local_aliases_preserve_fuzz_binding(tmp_path):
    _,_,plan=ready(tmp_path)
    code=re.sub(r'\bdata\b','bytes',DIRECT_CODE)
    code=re.sub(r'\bsize\b','extent',code)
    code=code.replace('(void)parse(bytes, extent);',
        'const uint8_t *alias=bytes; size_t count=extent; (void)parse(alias,count);')
    assert validate_code(code,plan)['status']=='valid'


def copied_code(body):
    return DIRECT_CODE.replace('#include <stddef.h>',
        '#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>').replace('(void)parse(data, size);',body)


@pytest.mark.parametrize('allocator',['malloc(size)','calloc(1,size)','calloc(size,1)'])
def test_exact_copy_supports_mutability_and_natural_alignment(tmp_path,allocator):
    _,_,original=ready(tmp_path)
    plan=deepcopy(original)
    binding=plan['call_sequence'][0]['arguments'][0]['input_binding']
    binding.update(transform='copy',mutable=True,alignment='natural')
    code=copied_code(f'unsigned char *copy=(unsigned char*){allocator}; '
        'if(copy){ if(size)memcpy(copy,data,size);parse(copy,size);free(copy); }')
    assert validate_code(code,plan)['status']=='valid'
    assert validate_code(DIRECT_CODE,plan)['status']=='invalid'
    assert original['call_sequence'][0]['arguments'][0]['input_binding']['transform']=='direct'


NUL_CODE='''#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
extern "C" int parse(const char *text);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data,size_t size) {
 if(size>1048576)return 0;
 char *text=(char*)malloc(size+1);
 if(text){if(size)memcpy(text,data,size);text[size]=0;parse(text);free(text);}
 return 0;
}
'''


@pytest.mark.skipif(not shutil.which('clang') or not shutil.which('clang++'),reason='clang unavailable')
@pytest.mark.parametrize('language',['c','c++'])
def test_nonempty_copy_nul_transform_keeps_real_frozen_plan_and_six_fixtures(tmp_path,language):
    store,_,plan=ready(tmp_path,'nul')
    before=original_inputs(store)
    code=NUL_CODE if language=='c++' else NUL_CODE.replace('extern "C" ','')
    llm=ScriptedCodeLLM([code])
    assert main(['--artifacts',str(store.root),'--language',language,
                 '--max-code-repairs','1','--build','--runtime'],llm=llm)==0
    directory=generation_directory(store);metadata=read(directory/'metadata.json')
    assert_attempt_integrity(directory,metadata,['passed'])
    assert original_inputs(store)==before and len(llm.calls)==1
    replay=read(directory/'build/runtime.json')
    assert replay['status']=='passed' and len(replay['cases'])==6


@pytest.mark.parametrize('old,new',[
    ('if(size)memcpy(text,data,size);',''),
    ('if(size)memcpy(text,data,size);','memcpy(text,data+1,size);'),
    ('if(size)memcpy(text,data,size);','memcpy(text,data,size-1);'),
    ('if(size)memcpy(text,data,size);','if(size>1)memcpy(text,data,size);'),
    ('text[size]=0;',''),
    ('text[size]=0;','text[0]=0;'),
    ('text[size]=0;','text[size]=1;'),
    ('parse(text);free(text);','free(text);parse(text);'),
    ('malloc(size+1)','malloc(size)'),
    ('if(size)memcpy(text,data,size);','if(0)memcpy(text,data,size);'),
    ('if(size)memcpy(text,data,size);','memcpy(text,data,size);memset(text,0,size);'),
    ('if(size)memcpy(text,data,size);','void *(*memcpy)(void*,const void*,size_t)=NULL; memcpy(text,data,size);'),
    ('char *text=(char*)malloc(size+1);','void *(*malloc)(size_t)=NULL;char *text=(char*)malloc(size+1);'),
])
def test_nul_copy_requires_original_source_complete_extent_and_live_terminated_copy(tmp_path,old,new):
    _,_,plan=ready(tmp_path,'nul')
    validation=validate_code(NUL_CODE.replace(old,new),plan)
    assert validation['status']=='invalid' and 'canonical_fuzz_bytes_binding_mismatch' in validation['errors']


def test_global_function_pointer_shadow_cannot_certify_a_copy(tmp_path):
    _,_,plan=ready(tmp_path,'nul')
    code=NUL_CODE.replace('extern "C" int parse',
        'void *(*memcpy)(void*,const void*,size_t)=NULL;\nextern "C" int parse')
    assert 'canonical_fuzz_bytes_binding_mismatch' in validate_code(code,plan)['errors']


def test_planned_bounded_length_and_matching_copy_keep_explicit_scalar_ir(tmp_path):
    _,_,original=ready(tmp_path)
    plan=deepcopy(original)
    extent={'op':'min','left':{'op':'fuzz_size'},'right':{'op':'constant','value':16}}
    plan['call_sequence'][0]['arguments'][1]['canonical_recipe']={'kind':'derived_scalar','expression':extent}
    code=copied_code('size_t prefix=size<16?size:16;unsigned char *copy=(unsigned char*)malloc(prefix);'
        'if(copy){memcpy(copy,data,prefix);parse(copy,prefix);free(copy);}')
    assert validate_code(code,plan)['status']=='valid'
    assert validate_code(code.replace('parse(copy,prefix)','parse(copy,16)'),plan)['status']=='invalid'
    assert validate_code(code.replace('memcpy(copy,data,prefix)','memcpy(copy,data,size)'),plan)['status']=='invalid'
    assert validate_code(DIRECT_CODE.replace('parse(data, size)','parse(data, (size<16?size:16))'),plan)['status']=='valid'


def test_second_empty_response_keeps_known_usage_and_archived_first_failure(tmp_path):
    store,_,_=ready(tmp_path)
    llm=ScriptedCodeLLM([BAD_CODE,'',DIRECT_CODE])
    assert main(['--artifacts',str(store.root),'--max-code-repairs','1'],llm=llm)==1
    directory=generation_directory(store);metadata=read(directory/'metadata.json')
    attempts,_=assert_attempt_integrity(directory,metadata,['invalid_code','generation_failed'])
    assert len(llm.calls)==2 and all(a['usage_known'] for a in attempts)
    responses=[read(p) for p in directory.rglob('response.json')]
    assert len(responses)==2 and sum(r['usage']['total_tokens'] for r in responses)==120
    assert read(directory/'response.json')['content']==BAD_CODE
    assert read(directory/'code_attempts/attempt_0002/response.json')['content']==''
    assert not (directory/'harness.cpp').exists()


@pytest.mark.skipif(not shutil.which('clang') or not shutil.which('clang++'),reason='clang unavailable')
def test_provider_error_after_compile_failure_keeps_failed_build_and_clears_final_build(tmp_path):
    store,_,_=ready(tmp_path)
    llm=ScriptedCodeLLM([COMPILE_BAD_CODE,LLMError('HTTP 401'),DIRECT_CODE])
    assert main(['--artifacts',str(store.root),'--max-code-repairs','1','--build','--runtime'],llm=llm)==1
    directory=generation_directory(store);metadata=read(directory/'metadata.json')
    attempts,_=assert_attempt_integrity(directory,metadata,['compile_failed','generation_failed'])
    assert not read(directory/'code_attempts/attempt_0001/build/build.json')['success']
    assert not (directory/'build').exists() and not (directory/'harness.cpp').exists()
    assert attempts[1]['usage_known'] is False and attempts[1]['response_path'] is None
    assert len(llm.calls)==2 and len(list(directory.rglob('response.json')))==1


@pytest.mark.parametrize('prefix,error',[
    ('auto parse=[](const unsigned char*,size_t){return 0;};','canonical_api_shadowed'),
    ('int (*parse)(const unsigned char*,size_t)=NULL;','canonical_api_shadowed'),
    ('auto memcmp=[](const void *a,const void*,size_t){*((unsigned char*)a)=0;return 0;};memcmp(data,data,size);','canonical_memory_helper_shadowed'),
])
def test_local_api_and_memory_intrinsic_shadow_cannot_certify_fuzz_inputs(tmp_path,prefix,error):
    _,_,plan=ready(tmp_path)
    code=copied_code(prefix+'parse(data,size);')
    result=validate_code(code,plan)
    assert result['status']=='invalid' and error in result['errors']


@pytest.mark.parametrize('copy', [False, True])
def test_explicit_alignment_without_byte_contract_stays_unprovable(tmp_path,copy):
    _,_,original=ready(tmp_path)
    plan=deepcopy(original)
    plan['call_sequence'][0]['arguments'][0]['input_binding']['alignment']='explicit'
    code=(copied_code('unsigned char *copy=(unsigned char*)malloc(size);'
        'if(copy){memcpy(copy,data,size);parse(copy,size);free(copy);}') if copy else DIRECT_CODE)
    validation=validate_code(code,plan)
    assert validation['status']=='invalid'
    assert 'canonical_explicit_alignment_unprovable' in validation['errors']
    assert original['call_sequence'][0]['arguments'][0]['input_binding']['alignment']=='none'


def test_zero_initialized_nul_copy_needs_no_invented_terminator_write(tmp_path):
    _,_,plan=ready(tmp_path,'nul')
    code=NUL_CODE.replace('malloc(size+1)','calloc(1,size+1)').replace('text[size]=0;','')
    assert validate_code(code,plan)['status']=='valid'
    assert validate_code(code.replace('calloc(1,size+1)','calloc(1,size)'),plan)['status']=='invalid'


def test_same_api_function_prototype_is_not_a_function_pointer_shadow(tmp_path):
    _,_,plan=ready(tmp_path)
    code=DIRECT_CODE.replace('(void)parse(data, size);',
        'int parse(const unsigned char*,size_t);(void)parse(data,size);')
    assert validate_code(code,plan)['status']=='valid'


@pytest.mark.parametrize('body',[
    'const unsigned char *data=NULL;size_t size=0;parse(data,size);',
    'size_t n=n;parse(src,n);',
    'const uint8_t *src=src;parse(src,n);',
])
def test_actual_entry_names_cannot_be_replaced_by_inner_local_input_names(tmp_path,body):
    _,_,plan=ready(tmp_path)
    code=re.sub(r'\bdata\b','src',DIRECT_CODE)
    code=re.sub(r'\bsize\b','n',code)
    code=code.replace('(void)parse(src, n);','{'+body+'}')
    assert validate_code(code,plan)['status']=='invalid'


@pytest.mark.parametrize('prefix',[
    '*(&size)=0;', 'size_t *n=&size;*n=0;', 'size_t *n=&size;(*n)++;',
    'memset(&size,0,sizeof size);', '*(&data)=NULL;', 'free((void*)data);',
])
def test_indirect_parameter_mutation_or_release_cannot_keep_original_source_provenance(tmp_path,prefix):
    _,_,plan=ready(tmp_path)
    code=copied_code(prefix+'parse(data,size);')
    assert validate_code(code,plan)['status']=='invalid'


@pytest.mark.parametrize('mutation',[
    'realloc(copy,size);',
    'for(size_t i=0;i<0;i++){memcpy(copy,data,size);}',
    'switch(size){case 1:memcpy(copy,data,size);break;default:break;}',
])
def test_copy_is_not_certified_after_reallocation_or_conditional_loop_copy(tmp_path,mutation):
    _,_,plan=ready(tmp_path)
    copy='memcpy(copy,data,size);'+mutation if mutation.startswith('realloc') else mutation
    code=copied_code('unsigned char *copy=(unsigned char*)malloc(size);if(copy){'+copy+'parse(copy,size);free(copy);}')
    assert validate_code(code,plan)['status']=='invalid'
