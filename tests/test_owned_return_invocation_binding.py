"""Usage examples keep their own identities while one new harness has one return."""
import pytest

from test_context_generation import ready
from test_harness_context import OWNED


@pytest.mark.parametrize('guarded', [False, True])
@pytest.mark.parametrize('delegated', [False, True])
def test_independent_examples_bind_one_core_result_to_its_cleanup(tmp_path, guarded, delegated):
    source = '#include <stdlib.h>\n' + OWNED
    if delegated:
        source = source.replace('Node *parse(', 'Node *allocate(')
        source += 'Node *parse(const unsigned char *data,size_t size){return allocate(data,size);}\n'
    for name in ('first', 'second'):
        source += 'void '+name+'(const unsigned char *data,size_t size){'
        source += 'if(!size)return;' if guarded else ''
        source += 'Node *n=parse(data,size);node_free(n);}\n'
    _, frozen, plan = ready(tmp_path, 'owned', source_override=source)
    context = frozen[1]
    source = next(s for s in context['construction_contract']['sources'] if s['kind']=='cleanup_consumption')
    assert source['binding_scope']=='single_harness_invocation'
    assert len(source['observed_pair_origins'])==2
    # The original example instances remain distinct in source value flow.
    assert len({o['resource_id'] for o in context['resource_identity']['value_flow']['observations']
        if o['function_id']==source['creator_api'] and o['return_value']})==2
    assert len(plan['call_sequence'])==1 and len(plan['cleanup_sequence'])==1
    assert plan['call_sequence'][0]['return_resource']==plan['cleanup_sequence'][0]['arguments'][0]['resource_id']
    assert plan['cleanup_sequence'][0]['arguments'][0]['canonical_recipe']['kind']=='resource_reference'
