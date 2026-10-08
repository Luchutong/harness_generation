"""Exact source feedback stays descriptive; explicit model facts close the gate."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from harness_generation.context_generation import HarnessPlanBuilder
from harness_generation.harness_context.agent import HarnessContextAgent
from harness_generation.harness_context import prompt_projection, proof_grounding
from harness_generation.harness_context.models import fact_id
from harness_generation.harness_context.tools import HarnessContextTools
from harness_generation.entry_candidates import CandidateCatalog
from harness_generation.semantic_discovery import FakeAgentModel, AgentModelResponse, AgentToolCall
from harness_generation.semantic_discovery.models import canonical, digest
from harness_generation.semantic_discovery.tools import RepositoryIndex
from test_argument_graph import graph_fixture
from test_callback_resource_references import load_prepared, rebuild
from test_context_generation import ready
from test_harness_context import owner


def unknown_owned(tmp_path, *, alignment='unknown', binary_zero_allowed=True):
    store,_,_=ready(tmp_path,'owned')
    prepared=load_prepared(store.root)
    fid=next(fid for fid,f in prepared[1].functions.items() if f['name']=='parse')
    req=next(r for r in prepared[2] if r['kind']=='input_binding' and r['subject_function_id']==fid)
    result=prepared[3][req['requirement_id']]
    fact=result['facts'][0]
    fact['value']['bindings'][0].update(alignment=alignment,binary_zero_allowed=binary_zero_allowed)
    fact['fact_id']=fact_id(fact)
    context,closure,report=rebuild(prepared)
    return store,prepared,req,context,closure,report


@pytest.mark.parametrize('alignment,zero,fields',[
    ('unknown',True,['alignment']),('none',None,['binary_zero_allowed']),
    ('unknown',None,['alignment','binary_zero_allowed'])])
def test_feedback_identifies_only_exact_unknown_input_fields(tmp_path,alignment,zero,fields):
    _,prepared,req,context,_,report=unknown_owned(tmp_path,alignment=alignment,binary_zero_allowed=zero)
    before=digest(context['facts'])
    gaps=[g for g in report['hard_missing'] if g['code']=='input_constraints_unresolved']
    assert gaps and all(g['subject_parameter']=='data' and g['requirement_id']==req['requirement_id'] for g in gaps)
    assert all(g['detail']['unknown_fields']==fields for g in gaps)
    assert all(g['detail']['observed_constraints']['alignment']==alignment for g in gaps)
    assert all(g['detail']['observed_constraints']['binary_zero_allowed']==zero for g in gaps)
    assert prompt_projection.diagnostic_view(gaps[0])['detail']==gaps[0]['detail']
    assert digest(context['facts'])==before and not report['generation_allowed']


def test_explicit_model_correction_closes_owned_gate_plan_without_alignment_default(tmp_path):
    store,prepared,req,context,closure,report=unknown_owned(tmp_path)
    before=digest(context['facts'])
    original=prepared[3][req['requirement_id']]
    corrected=deepcopy(original['facts'][0]['value'])
    corrected['bindings'][0]['alignment']='none'
    catalog=CandidateCatalog((),prepared[1].source_fingerprint)
    tools=HarnessContextTools(prepared[1],catalog,prepared[0],prepared[4],
        index=RepositoryIndex(prepared[1].artifacts,catalog,functions_path=store.functions))
    wire={'resolutions':{'r0':{'status':'resolved','facts':[{'value':corrected,
        'evidence_ids':original['facts'][0]['evidence_ids']}],'discovered_api_dependencies':[],'open_questions':[]}}}
    model=FakeAgentModel([AgentModelResponse(tool_calls=(AgentToolCall('explicit_fix',
        'submit_requirement_resolution',canonical(wire)),))])
    run=HarnessContextAgent(model,prepared[4]).investigate(req,tools,facts=context['facts'])
    assert run.result['status']=='resolved' and prepared[4].model_calls==1
    prepared[3][req['requirement_id']]=run.result
    fixed,closed,actual=rebuild(prepared)
    assert actual['generation_allowed'] and not actual['hard_missing'] and not actual['validation_errors']
    plan=HarnessPlanBuilder().build(prepared[0],fixed,closed,prepared[1],actual)
    assert plan['frozen'] and digest(context['facts'])==before
    assert next(b for b in context['input_contract']['bindings'] if b['parameter']=='data')['alignment']=='unknown'
    assert next(b for b in fixed['input_contract']['bindings'] if b['parameter']=='data')['alignment']=='none'


SOURCE='''typedef unsigned long size_t;
typedef struct State { const unsigned char *bytes; size_t count; } State;
void supply(State *s,const unsigned char *src,size_t cb) { s->bytes=src;s->count=cb; }
int parse(State *s) { return s->count?s->bytes[0]:0; }
'''


def test_retention_feedback_preserves_exact_recipient_and_does_not_invent_ownership(tmp_path):
    fixture=graph_fixture(tmp_path,SOURCE)
    _,_,_,snapshot,records,ids=fixture
    eids=[eid for eid,r in records.items() if r['function_id']==ids['supply']]
    entry={**owner('src'), 'function_id':ids['supply'],'fact_id':'fact_borrowed','evidence_ids':eids}
    context={'ownership_contract':{'entries':[entry]},'callback_contract':{'callbacks':[]}}
    before=deepcopy(context)
    conflicts=proof_grounding.contradictions(context,snapshot,records)
    failure=next(c for c in conflicts if c['code']=='ownership_escape_lifetime_conflict')
    detail=failure['detail']
    assert detail['observed_lifetime']=='during_call' and detail['observed_ownership']=='borrowed'
    assert detail['source_retentions']==[{'destination':'parameter:s','field':'bytes'}]
    assert prompt_projection.diagnostic_view(failure)['detail']==detail
    assert context==before and 'facts' not in context and 'input_contract' not in context
    # A longer lifetime alone does not create a cleanup/ownership certificate.
    entry['lifetime']='until_context_cleanup'
    assert not proof_grounding.contradictions(context,snapshot,records)
    assert entry['ownership']=='borrowed' and entry['release_api'] is None


def test_retention_feedback_handles_mixed_none_and_string_member_names(monkeypatch):
    entry={'function_id':'f','parameter':'src','field':None,'lifetime':'during_call',
        'ownership':'borrowed','evidence_ids':['ev_source'],'fact_id':'fact_source'}
    context={'ownership_contract':{'entries':[entry]},'callback_contract':{'callbacks':[]}}
    summary={'paths':[{'escapes':{'parameter:src'},'retentions':{('parameter:src','parameter:dst',None),
        ('parameter:src','parameter:dst','bytes')},'uncertain':False}]}
    monkeypatch.setattr(proof_grounding,'complete_bodies',lambda *_:{'f':{'ev_source'}})
    monkeypatch.setattr(proof_grounding,'analyze',lambda *_:summary)
    monkeypatch.setattr(proof_grounding,'cleanup_checks',lambda *_:[])
    before=deepcopy(context)
    failure,=proof_grounding.contradictions(context,SimpleNamespace(functions={'f':{}}),{})
    assert len(failure['detail']['source_retentions'])==2
    assert failure['code']=='ownership_escape_lifetime_conflict' and context==before


def test_context_input_without_feeder_reports_exact_binding_and_does_not_supply_api(tmp_path):
    store,_,_=ready(tmp_path,'context')
    prepared=load_prepared(store.root)
    fid=next(fid for fid,f in prepared[1].functions.items() if f['name']=='parse')
    req=next(r for r in prepared[2] if r['kind']=='input_binding' and r['subject_function_id']==fid)
    result=prepared[3][req['requirement_id']]
    fact=result['facts'][0]
    row=deepcopy(fact['value']['bindings'][0])
    row.update(parameter='ctx',source='context',transform='none',via_function_id=None,
        size_parameter=None,size_relation='none',binary_zero_allowed=None)
    fact['value']['bindings']=[row];fact['fact_id']=fact_id(fact)
    before=digest(fact)
    context,closure,report=rebuild(prepared)
    gaps=[g for g in report['hard_missing'] if g['code']=='core_fuzz_input_path_unresolved' and g['subject_function_id']==fid]
    assert gaps and all(g['subject_parameter']=='ctx' for g in gaps)
    assert all(g['detail']['observed_bindings']==[{'parameter':'ctx','source':'context','transform':'none',
        'via_function_id':None,'size_parameter':None}] for g in gaps)
    assert all(g['detail']['missing_contract']=='source_proven_fuzz_input_path' for g in gaps)
    assert prompt_projection.diagnostic_view(gaps[0])['detail']==gaps[0]['detail']
    assert digest(fact)==before and row['via_function_id'] is None and not report['generation_allowed']


def test_unresolved_input_fed_state_reports_exact_parameter_and_observed_api(tmp_path):
    store,_,_=ready(tmp_path,'context')
    prepared=load_prepared(store.root)
    fid=next(fid for fid,f in prepared[1].functions.items() if f['name']=='parse')
    req=next(r for r in prepared[2] if r['kind']=='state' and r['subject_function_id']==fid)
    result=prepared[3][req['requirement_id']]
    fact=result['facts'][0]
    entry=next(p for p in fact['value']['preconditions'] if p['parameter']=='ctx')
    entry.update(kind='input_fed',api=None);fact['fact_id']=fact_id(fact)
    before=digest(fact)
    context,closure,report=rebuild(prepared)
    gaps=[g for g in report['hard_missing'] if g['code']=='state_precondition_unresolved' and g.get('subject_parameter')=='ctx']
    assert gaps and all(g['detail']['observed_kind']=='input_fed' and g['detail']['observed_api'] is None for g in gaps)
    assert all(g['detail']['missing_contract']=='source_proven_state_api_or_field_effect' for g in gaps)
    assert prompt_projection.diagnostic_view(gaps[0])['detail']==gaps[0]['detail']
    assert digest(fact)==before and entry['api'] is None and not report['generation_allowed']
