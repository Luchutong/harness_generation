"""Acquire exact cleanup implementation dependencies before asking for facts."""
import pytest

from harness_generation.harness_context import ContextBudget, HarnessRequirementBuilder
from harness_generation.harness_context.construction import prepare_local_evidence
from harness_generation.harness_context.proposals import registry
from harness_generation.harness_context.value_flow import complete_bodies
from test_harness_context import setup
from test_owned_traversal_proofs import SOURCE


@pytest.mark.parametrize('depth,proved', [(2, True), (1, False)])
def test_guarded_return_cleanup_pair_and_void_delegate_use_existing_depth_budget(tmp_path, depth, proved):
    source=SOURCE+'''void usage(const unsigned char *bytes,unsigned extent){
 if(!extent)return;Node *result=parse(bytes,extent);if(!result)return;finish(result);
}'''
    prepared=setup(tmp_path,source,budget=ContextBudget(max_dependency_depth=depth))
    ids,tools,state=prepared[0][-1],prepared[5],prepared[4]
    req=next(r for r in HarnessRequirementBuilder().build(prepared[1],prepared[3])['requirements'] if r['kind']=='ownership')
    tools.activate(req);tools.bootstrap();prepare_local_evidence(tools)
    bodies=complete_bodies(prepared[3],state.evidence)
    assert (ids['walk'] in bodies and ids['discard'] in bodies)==proved
    signed=registry(tools)
    assert any(r['function_id']==ids['finish'] and r['reason']=='cleanup' for r in signed['support_candidates'])==proved
    assert state.model_calls==0 and state.tool_calls<=state.budget.max_tool_calls
    assert state.source_chars<=state.budget.max_source_chars
    assert all(d['depth']<=depth for d in state.discoveries.values())


def test_return_consumer_depth_survives_cross_predicate_activation(tmp_path):
    source=SOURCE+'''void usage(const unsigned char *bytes,unsigned extent){
 if(!extent)return;Node *result=parse(bytes,extent);if(!result)return;finish(result);
}'''
    prepared=setup(tmp_path,source)
    tools,state=prepared[5],prepared[4]
    requirements=HarnessRequirementBuilder().build(prepared[1],prepared[3])['requirements']
    for kind in ('buffer_length','ownership','lifecycle'):
        req=next(r for r in requirements if r['kind']==kind)
        tools.activate(req);tools.bootstrap();prepare_local_evidence(tools)
        assert tools.depth(prepared[0][-1]['finish']) == 1
        if kind in {'ownership','lifecycle'}:
            assert any(r['function_id']==prepared[0][-1]['finish'] and r['reason']=='cleanup'
                for r in registry(tools)['support_candidates'])
    assert state.model_calls==0
