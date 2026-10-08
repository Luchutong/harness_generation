"""API identities survive error guards; ambiguous paths never become aliases."""
import pytest

from harness_generation.harness_context.value_flow import resource_flows
from test_proof_reliability import analysis_fixture


SOURCE = '''#include <stdlib.h>
typedef struct Item {unsigned n;} Item;
Item *parse(const unsigned char *p,unsigned n){return calloc(1,sizeof(Item));}
void release(Item *p){free(p);}
void usage(const unsigned char *bytes,unsigned extent,int flag){BODY}
'''


def inspect(tmp_path, body):
    snapshot, ids, records, _ = analysis_fixture(tmp_path, SOURCE.replace('BODY', body))
    return resource_flows(snapshot, records), ids


@pytest.mark.parametrize('guard', ['if(flag)return;', 'if(flag){abort();}', 'if(flag){exit(1);}'])
def test_preceding_error_guards_do_not_remove_later_creator_and_cleanup(tmp_path, guard):
    flow, ids = inspect(tmp_path, guard+'Item *result=parse(bytes,extent);release(result);')
    created, = [o for o in flow['observations'] if o['function_id']==ids['parse'] and o['return_value']]
    consumed, = [o for o in flow['observations'] if o['function_id']==ids['release']]
    assert created['resource_id']==consumed['resource_id']


def test_nullable_guard_and_unrelated_scalar_branch_preserve_return_identity(tmp_path):
    flow, ids = inspect(tmp_path, 'Item *result=parse(bytes,extent);if(!result)return;if(flag)extent=0;release(result);')
    consumed, = [o for o in flow['observations'] if o['function_id']==ids['release']]
    created, = [o for o in flow['observations'] if o['function_id']==ids['parse'] and o['return_value']]
    assert consumed['resource_id']==created['resource_id']


def test_conditional_reassignment_preserves_two_distinct_possible_objects(tmp_path):
    flow, ids = inspect(tmp_path, 'Item *a=parse(bytes,extent),*b=parse(bytes,extent);Item *p=a;if(flag)p=b;release(p);')
    created = {o['resource_id'] for o in flow['observations'] if o['function_id']==ids['parse'] and o['return_value']}
    consumed = {o['resource_id'] for o in flow['observations'] if o['function_id']==ids['release']}
    assert len(created)==2 and consumed==created


def test_unknown_reaching_path_cannot_be_discarded_in_favor_of_known_origin(tmp_path):
    flow, ids = inspect(tmp_path, 'Item *p=parse(bytes,extent);if(flag)p=0;release(p);')
    assert not any(o['function_id']==ids['release'] for o in flow['observations'])
    assert any(u['function_id']==ids['release'] for u in flow['unresolved'] if 'function_id' in u)


def test_inner_shadow_does_not_replace_the_outer_resource(tmp_path):
    flow, ids = inspect(tmp_path, 'Item *p=parse(bytes,extent);if(flag){Item *p=parse(bytes,extent);release(p);}release(p);')
    returns = sorted([o for o in flow['observations'] if o['return_value']],key=lambda o:o['call_offset'])
    cleanup = sorted([o for o in flow['observations'] if o['function_id']==ids['release']],key=lambda o:o['call_offset'])
    assert len(returns)==len(cleanup)==2
    assert cleanup[0]['resource_id']==returns[1]['resource_id']
    assert cleanup[1]['resource_id']==returns[0]['resource_id']


def test_unmodeled_loop_drops_identity_after_mutation(tmp_path):
    flow, ids = inspect(tmp_path, 'Item *p=parse(bytes,extent);while(flag){p=parse(bytes,extent);flag--;}release(p);')
    assert not any(o['function_id']==ids['release'] for o in flow['observations'])


def test_unreachable_call_after_return_is_not_an_observed_lifecycle(tmp_path):
    flow, ids = inspect(tmp_path, 'Item *p=parse(bytes,extent);return;release(p);')
    assert not any(o['function_id']==ids['release'] for o in flow['observations'])
