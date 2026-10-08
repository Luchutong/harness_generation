"""Scope/subject feedback guides agents without issuing facts or permissions."""
from copy import deepcopy

import pytest

from harness_generation.harness_context import ContextBudget, HarnessRequirementBuilder
from harness_generation.harness_context.investigation import proof_agenda
from harness_generation.harness_context.proposals import registry
from harness_generation.harness_context.prompt_projection import agenda_view, terminal_guidance
from harness_generation.harness_context.source_queries import SourceDetails
from harness_generation.semantic_discovery.models import digest
from harness_generation.semantic_discovery.tools import ToolBudgetExceeded
from test_harness_context import setup, OWNED, CALLBACK


def active(prepared, kind='lifecycle', facts=()):
    req=next(r for r in HarnessRequirementBuilder().build(prepared[1],prepared[3])['requirements'] if r['kind']==kind)
    tools=prepared[5];tools.activate(req,facts);tools.bootstrap()
    return req,tools


def slot(prepared,req,facts=()):
    tools=prepared[5]
    return proof_agenda([req],facts,[],tools,registry(tools,[req]),
                        dict(proved=[],missing_evidence=[],blocked=[]),{'parameters':[]})['slots'][0]


def excluded_owned(tmp_path,source=OWNED,budget=None,extra_exclusions=()):
    return setup(tmp_path,source,roles={'parse':('core','accepted_anchor'),
        'node_free':('exclude','diagnostic_only'),**{n:('exclude','diagnostic_only') for n in extra_exclusions}},budget=budget)


def exclude_for_scope_adapter(prepared,name):
    # Unit-level adapter policy input. Unrelated signatures are outside the
    # Slice fixture's frontier; this does not assert a validated Slice/Gate.
    fid=prepared[0][-1][name]
    prepared[1]['excluded_functions'].append(fid)
    prepared[5].excluded.add(fid)


@pytest.mark.parametrize('tool',['get_function','get_function_signature'])
def test_exact_excluded_read_names_blocker_without_evidence_or_scope(tmp_path,tool):
    p=excluded_owned(tmp_path);_,tools=active(p);fid=p[0][-1]['node_free']
    before=(deepcopy(p[1]),deepcopy(p[4].evidence),deepcopy(p[4].discoveries),set(tools.scope_ids),p[4].source_chars,p[4].tool_calls)
    output=tools.execute(tool,{'function':fid})
    assert output['error']=='upstream_excluded' and output['evidence_ids']==[]
    assert output['function_id']==fid and 'Discovery does not remove' in output['rule']
    assert (p[1],p[4].evidence,p[4].discoveries,tools.scope_ids,p[4].source_chars)==before[:5]
    assert p[4].tool_calls==before[5]+1


def test_ordinary_out_of_scope_function_can_still_be_discovered_then_read(tmp_path):
    p=setup(tmp_path,OWNED);_,tools=active(p);fid=p[0][-1]['node_free']
    assert tools.execute('get_function',{'function':fid})['error']=='outside_requirement_scope_use_discovery_tool'
    output=tools.execute('find_cleanup_candidates',{'type':'Node'})
    assert fid in {r['function_id'] for r in output['project_functions']}
    assert tools.execute('get_function',{'function':fid})['evidence_ids']
    assert not output['upstream_scope_feedback']['all_cleanup_shaped_signatures_excluded']


def test_excluded_cleanup_feedback_is_only_signature_diagnostic(tmp_path):
    p=excluded_owned(tmp_path);_,tools=active(p);fid=p[0][-1]['node_free']
    output=tools.execute('find_cleanup_candidates',{'type':'Node'});feedback=output['upstream_scope_feedback']
    assert feedback['all_cleanup_shaped_signatures_excluded']
    conflict,=feedback['excluded_structural_candidates']
    assert conflict['function_id']==fid and conflict['signature'].startswith('void node_free')
    assert conflict['type_links'][0]['parameter']=='node' and conflict['diagnostic_only']
    assert 'evidence_id' not in conflict and 'resource_id' not in conflict and 'callable_status' not in conflict
    assert fid not in tools.scope_ids and fid not in p[4].discoveries
    assert fid not in {r.get('function_id') for r in output['evidence']}
    assert fid not in {r['function_id'] for r in output['project_functions']}
    signed=registry(tools)
    assert fid not in signed['issued_function_ids']
    assert fid not in {r['function_id'] for r in signed['support_candidates']}


def test_signature_conflicts_are_bounded_and_do_not_claim_effects(tmp_path):
    source=OWNED+'\n'+'\n'.join(f'void release_{i}(Node *n) {{ (void)n; }}' for i in range(4))
    p=excluded_owned(tmp_path,source,ContextBudget(max_references_per_query=1),[f'release_{i}' for i in range(4)])
    _,tools=active(p)
    feedback=tools.execute('find_cleanup_candidates',{'type':'Node'})['upstream_scope_feedback']
    assert feedback['excluded_match_count']==5 and feedback['truncated']
    assert len(feedback['excluded_structural_candidates'])==1
    assert 'not cleanup/necessity proof' in feedback['rule']
    assert not any(c['necessity_proven'] for c in registry(tools)['support_candidates'])


def test_unknown_type_never_leaks_excluded_signature_diagnostics(tmp_path):
    p=excluded_owned(tmp_path);_,tools=active(p)
    assert tools.execute('find_cleanup_candidates',{'type':'Foreign'})['error']=='outside_requirement_scope'
    assert tools.cleanup_scope_feedback('Foreign') is None


@pytest.mark.parametrize('source_mention', ['comment', 'parameter', 'field'])
def test_known_body_or_subject_names_do_not_authorize_excluded_type_diagnostics(tmp_path,source_mention):
    source=OWNED+'\ntypedef struct Foreign { int value; } Foreign;\nvoid foreign_free(Foreign *p) { free(p); }'
    if source_mention=='comment':
        source=source.replace('return node;', '/* Foreign is a comment, not this subject type. */ return node;')
    elif source_mention=='parameter':
        source=source.replace('size_t size)', 'size_t size,int Foreign)')
    else:
        source=source.replace('int value; } Node;', 'int value; int Foreign; } Node;')
    p=excluded_owned(tmp_path,source);exclude_for_scope_adapter(p,'foreign_free');_,tools=active(p)
    assert 'Foreign' in tools.known_symbols
    before=deepcopy(p[4].evidence)
    assert tools.cleanup_scope_feedback('Foreign') is None
    output=tools.execute('find_cleanup_candidates',{'type':'Foreign'})
    assert output.get('upstream_scope_feedback') is None
    assert p[0][-1]['foreign_free'] not in tools.scope_ids
    assert not output['evidence'] and p[4].evidence==before


def test_associated_struct_field_type_authorizes_only_structural_diagnostics(tmp_path):
    source=OWNED.replace('int value; } Node;', 'int value; struct Foreign *child; } Node;')
    source+='\nstruct Foreign { int value; };\nvoid foreign_free(struct Foreign *p) { free(p); }'
    p=excluded_owned(tmp_path,source);exclude_for_scope_adapter(p,'foreign_free');_,tools=active(p)
    feedback=tools.cleanup_scope_feedback('Foreign')
    assert feedback is not None and feedback['excluded_match_count']==1
    assert feedback['excluded_structural_candidates'][0]['function_id']==p[0][-1]['foreign_free']
    assert p[0][-1]['foreign_free'] not in tools.scope_ids


@pytest.mark.parametrize('return_type,body',[('void','(void)n;'),('int','return n->value;')])
def test_allowed_pointer_signature_prevents_all_excluded_claim(tmp_path,return_type,body):
    p=excluded_owned(tmp_path,OWNED+f'\n{return_type} touch(Node *n) {{ {body} }}')
    req,tools=active(p)
    feedback=tools.execute('find_cleanup_candidates',{'type':'Node'})['upstream_scope_feedback']
    assert not feedback['all_cleanup_shaped_signatures_excluded']
    assert 'upstream_scope_blockers' not in slot(p,req)


def test_all_excluded_agenda_records_blocker_and_never_requeries_or_mutates(tmp_path):
    p=excluded_owned(tmp_path);req,tools=active(p)
    before=(digest(p[1]),deepcopy(p[4].evidence),deepcopy(p[4].discoveries),p[4].source_chars,p[4].tool_calls,p[4].model_calls)
    first=slot(p,req);second=slot(p,req)
    assert first==second
    assert not any(q['tool']=='find_cleanup_candidates' for q in first['query_options'])
    blocker,=first['upstream_scope_blockers']
    assert blocker['query']=={'type':'Node'} and 'upstream exclusion' in blocker['next_action']
    assert (digest(p[1]),p[4].evidence,p[4].discoveries,p[4].source_chars,p[4].tool_calls,p[4].model_calls)==before
    assert agenda_view({'slots':[first]})['slots'][0]['upstream_scope_blockers']==first['upstream_scope_blockers']


def test_budget_exhaustion_still_prevents_excluded_read(tmp_path):
    p=excluded_owned(tmp_path,budget=ContextBudget(max_tool_calls=1));_,tools=active(p)
    with pytest.raises(ToolBudgetExceeded):tools.execute('get_function',{'function':p[0][-1]['node_free']})
    assert p[4].tool_calls==1


def test_excluded_caller_remains_readable_source_only_after_existing_discovery(tmp_path):
    source=OWNED+'\nvoid usage(const unsigned char *b,size_t n) { Node *v=parse(b,n);node_free(v); }'
    p=setup(tmp_path,source,roles={'parse':('core','accepted_anchor'),
        'usage':('exclude','unrelated_behavior')},discover_callers=True);_,tools=active(p)
    output=tools.execute('find_resource_flows',{'function':p[0][-1]['parse']})
    caller=p[0][-1]['usage']
    assert caller in tools.scope_ids
    assert tools.execute('get_function',{'function':caller})['evidence_ids']
    assert caller not in registry(tools)['issued_function_ids']


DIRECT_CALLBACK='''typedef unsigned long size_t;
typedef int (*Handler)(void *,const unsigned char *,size_t);
int parse(const unsigned char *data,size_t size,Handler handler,void *user) { return handler(user,data,size); }
'''


def test_callback_feedback_identifies_actual_userdata_parameter_and_does_not_bind_resource(tmp_path):
    p=setup(tmp_path,DIRECT_CALLBACK);req,tools=active(p,'callback');before=deepcopy(p[4].evidence)
    result=slot(p,req)['callback_userdata_feedback'];row,=result['candidates']
    assert row['userdata_identity']==row['userdata_parameter']=='user'
    assert row['callback_parameter']=='handler' and row['argument_index']==0
    assert row['syntactic_only'] and 'resource_id' not in row and 'evidence_id' not in row
    assert 'not a resource ID' in result['rule'] and p[4].evidence==before


def test_callback_member_feedback_keeps_exact_member_identity(tmp_path):
    p=setup(tmp_path,CALLBACK);fid=p[0][-1]['parse']
    row,=SourceDetails(p[3],fid).callback_userdata_feedback(6)['candidates']
    assert row['userdata_identity']=='ctx.userdata' and row['userdata_parameter'] is None
    assert row['callback_field']=='consume'


def test_callback_feedback_skips_shadowed_parameter_instead_of_guessing_alias(tmp_path):
    source=DIRECT_CALLBACK.replace('return handler(user,data,size);','{ void *user=0;return handler(user,data,size); }')
    p=setup(tmp_path,source)
    assert not SourceDetails(p[3],p[0][-1]['parse']).callback_userdata_feedback(6)['candidates']


def test_callback_feedback_never_guesses_computed_userdata(tmp_path):
    source=DIRECT_CALLBACK.replace('handler(user,data,size)','handler((char*)user+size,data,size)')
    p=setup(tmp_path,source)
    assert not SourceDetails(p[3],p[0][-1]['parse']).callback_userdata_feedback(6)['candidates']


def test_length_feedback_names_declared_scalar_and_preserves_missing_link(tmp_path):
    p=setup(tmp_path,OWNED);fid=p[0][-1]['parse']
    req,tools=active(p,'buffer_length')
    facts=[{'requirement_id':req['requirement_id'],'function_id':fid,'predicate':'buffer_length','evidence_ids':[],
            'value':{'applicable':True,'links':[{'buffer_parameter':'data','length_parameter':None,'relation':'bytes'}]}}]
    original=deepcopy(facts);feedback=slot(p,req,facts)['length_link_feedback']
    assert feedback['declared_scalar_parameters'][0]['parameter']=='size'
    assert feedback['submitted_buffer_length_links'][0]['length_parameter'] is None
    assert 'derived scalar argument alone' in feedback['rule'] and 'candidates only' in feedback['rule']
    assert facts==original and p[4].model_calls==0


def test_scalar_flag_is_presented_only_as_candidate_not_a_length_contract(tmp_path):
    source=OWNED.replace('size_t size)', 'size_t size,int mode)')
    p=setup(tmp_path,source);req,_=active(p,'argument_construction');feedback=slot(p,req)['length_link_feedback']
    assert {r['parameter'] for r in feedback['declared_scalar_parameters']}=={'size','mode'}
    assert not feedback['submitted_buffer_length_links'] and 'replace a flag' in feedback['rule']
    assert not p[4].model_calls


def test_terminal_guidance_exposes_scope_userdata_and_length_rules():
    rules=' '.join(terminal_guidance([
        {'kind': 'callback'}, {'kind': 'buffer_length'}])['contracts'])
    assert 'upstream_excluded' in rules and 'length_parameter' in rules
    assert 'callback.userdata' in rules and 'do not substitute a resource ID' in rules
