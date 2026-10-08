"""Source-scope cleanup investigation without ownership defaults or extra budget."""
from copy import deepcopy

import pytest

from harness_generation.harness_context import HarnessRequirementBuilder, ContextBudget
from harness_generation.harness_context.proposals import registry
from harness_generation.semantic_discovery.models import digest
from harness_generation.semantic_discovery.tools import ToolBudgetExceeded
from test_harness_context import setup, OWNED, CONTEXT, owner

from harness_generation.harness_context import investigation as proposal


def agenda(prepared,kind='lifecycle',facts=()):
    requirement=next(r for r in HarnessRequirementBuilder().build(prepared[1],prepared[3])['requirements'] if r['kind']==kind)
    tools=prepared[5];tools.activate(requirement,facts);tools.bootstrap()
    signed=registry(tools,[requirement])
    view=dict(proved=[],missing_evidence=[],blocked=[])
    return proposal.proof_agenda([requirement],facts,[],tools,signed,view,{'parameters':[]})['slots'][0],requirement


def test_pointer_return_cleanup_discovery_precedes_creator_internals(tmp_path):
    prepared=setup(tmp_path,OWNED)
    before=prepared[4].model_calls
    slot,_=agenda(prepared)
    assert slot['query_options'][0]['tool']=='find_cleanup_candidates'
    assert slot['query_options'][0]['arguments']=={'type':'Node'}
    assert all(q['tool']!='find_initializers' for q in slot['query_options'])
    assert prepared[4].model_calls==before==0


def test_outside_scope_then_legal_discovery_then_exact_body_with_existing_caps(tmp_path):
    budget=ContextBudget(max_total_model_calls=4,max_tool_calls=8,max_source_chars=96000)
    prepared=setup(tmp_path,OWNED,budget=budget)
    slot,_=agenda(prepared);tools=prepared[5];cleanup=prepared[0][-1]['node_free']
    before_calls=prepared[4].tool_calls
    assert tools.execute('get_function',{'function':cleanup})['error']=='outside_requirement_scope_use_discovery_tool'
    query=slot['query_options'][0]
    result=tools.execute(query['tool'],query['arguments'])
    assert cleanup in [row['function_id'] for row in result['project_functions']]
    definition=tools.execute('get_function',{'function':cleanup})
    assert definition['evidence_ids'] and cleanup in tools.scope_ids
    assert prepared[4].tool_calls-before_calls==3 and prepared[4].tool_calls <= budget.max_tool_calls
    assert prepared[4].source_chars < budget.max_source_chars
    assert not any(row['necessity_proven'] for row in registry(tools)['support_candidates'])
    assert budget.max_total_model_calls==4 and budget.max_source_chars==96000


def test_owned_unknown_release_fact_is_not_changed_by_agenda(tmp_path):
    prepared=setup(tmp_path,OWNED);fid=prepared[0][-1]['parse']
    facts=[dict(function_id=fid,predicate='ownership',evidence_ids=[],value={'entries':[owner(returned=True,ownership='owned')]})]
    before=digest(facts)
    slot,_=agenda(prepared,'ownership',facts)
    assert slot['query_options'][0]['tool']=='find_cleanup_candidates'
    assert digest(facts)==before and facts[0]['value']['entries'][0]['release_api'] is None


def test_explicit_borrowed_return_does_not_gain_owned_cleanup_priority(tmp_path):
    prepared=setup(tmp_path,OWNED);fid=prepared[0][-1]['parse']
    facts=[dict(function_id=fid,predicate='ownership',evidence_ids=[],value={'entries':[owner(returned=True,ownership='borrowed')]})]
    slot,_=agenda(prepared,'lifecycle',facts)
    assert not any(q['tool']=='find_cleanup_candidates' for q in slot['query_options'])


def test_scalar_consumer_keeps_original_creation_query(tmp_path):
    prepared=setup(tmp_path,CONTEXT)
    slot,_=agenda(prepared)
    assert any(q['tool']=='find_initializers' and q['arguments']=={'type':'Context'} for q in slot['query_options'])
    assert not any(q['tool']=='find_cleanup_candidates' for q in slot['query_options'])


def test_already_read_cleanup_reuses_complete_source_and_skips_creator_hunt(tmp_path):
    prepared=setup(tmp_path,OWNED);tools=prepared[5]
    slot,requirement=agenda(prepared)
    tools.execute('find_cleanup_candidates',{'type':'Node'})
    tools.execute('get_function',{'function':prepared[0][-1]['node_free']})
    charged=prepared[4].source_chars
    slot,_=agenda(prepared)
    assert any(c['reason']=='cleanup' for c in slot['candidate_effects'])
    assert not any(q['tool'] in {'find_cleanup_candidates','find_initializers'} for q in slot['query_options'])
    assert prepared[4].source_chars==charged


def test_budget_exhaustion_remains_an_error_without_extra_read_or_facts(tmp_path):
    budget=ContextBudget(max_total_model_calls=4,max_tool_calls=3,max_source_chars=96000)
    prepared=setup(tmp_path,OWNED,budget=budget);slot,_=agenda(prepared)
    prepared[4].tool_calls=budget.max_tool_calls
    query=slot['query_options'][0]
    before=deepcopy(prepared[4].evidence)
    with pytest.raises(ToolBudgetExceeded):prepared[5].execute(query['tool'],query['arguments'])
    assert prepared[4].evidence==before
    assert prepared[4].tool_calls==budget.max_tool_calls
