"""Only reachable branch state may describe later frozen byte bindings."""
import pytest

from harness_generation.context_generation.validation import validate_code
from test_context_generation import ready, DIRECT_CODE


def copied_code(branch, *, source='data'):
    return DIRECT_CODE.replace('#include <stddef.h>', '#include <stddef.h>\n#include <stdlib.h>\n#include <string.h>').replace(
        '(void)parse(data, size);',
        'unsigned char *copy=(unsigned char*)malloc(size); if(!copy)return 0;'
        f'if(size)memcpy(copy,{source},size);' + branch + '(void)parse(copy,size);free(copy);')


@pytest.mark.parametrize('branch', [
    'if(size==0){free(copy);return 0;}',
    'if(size>0){}else{free(copy);return 0;}',
    'if(size==0){if(data==NULL){free(copy);return 0;}else{free(copy);return 0;}}',
])
def test_returning_release_branch_cannot_invalidate_later_live_copy(tmp_path, branch):
    _, _, plan = ready(tmp_path)
    result = validate_code(copied_code(branch), plan)
    assert result['status']=='valid'
    assert result['observed_calls']=={'parse':1}


@pytest.mark.parametrize('branch', [
    'if(size==0){free(copy);}',
    'if(size==0){free(copy);if(data==NULL)return 0;}',
    'if(size==0){free(copy);return 0;}free(copy);',
    'if(size==0){free(copy);return 0;}copy[0]=0;',
])
def test_freed_mutated_or_nonterminating_branch_still_fails_binding(tmp_path, branch):
    _, _, plan = ready(tmp_path)
    result = validate_code(copied_code(branch), plan)
    assert 'canonical_fuzz_bytes_binding_mismatch' in result['errors']


def test_returning_branch_never_repairs_wrong_copy_origin(tmp_path):
    _, _, plan = ready(tmp_path)
    result = validate_code(copied_code('if(size==0){free(copy);return 0;}', source='data+1'),plan)
    assert 'canonical_fuzz_bytes_binding_mismatch' in result['errors']


@pytest.mark.parametrize('branch', [
    'if(size){free(copy);goto target;return 0;}target:',
    'if(size){free(copy);if(copy)goto target;return 0;}target:',
    'if(size){}else{free(copy);goto target;return 0;}target:',
    'if(size){free(copy);unused_label:return 0;}',
    'while(size){if(copy){free(copy);break;return 0;}break;}',
    'int flag=1;while(flag){if(copy){free(copy);flag=0;continue;return 0;}}',
    'try{if(size){free(copy);throw 1;return 0;}}catch(...){}',
])
def test_unmodeled_jump_never_prunes_a_potentially_reaching_mutation(tmp_path, branch):
    _, _, plan = ready(tmp_path)
    result = validate_code(copied_code(branch),plan)
    assert 'canonical_fuzz_bytes_binding_mismatch' in result['errors']


def test_goto_before_unreachable_return_cannot_hide_replaced_direct_fuzz_pointer(tmp_path):
    _, _, plan = ready(tmp_path)
    code = DIRECT_CODE.replace('(void)parse(data, size);',
        'if(size){data=NULL;goto target;return 0;}target:(void)parse(data,size);')
    result = validate_code(code,plan)
    assert 'canonical_fuzz_bytes_binding_mismatch' in result['errors']


def test_nested_straight_return_keeps_later_live_copy_valid(tmp_path):
    _, _, plan = ready(tmp_path)
    branch = 'if(size==0){if(data==NULL){free(copy);return 0;}free(copy);return 0;}'
    result = validate_code(copied_code(branch),plan)
    assert result['status']=='valid'
