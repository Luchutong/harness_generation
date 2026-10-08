"""Strict source certificate and chronology-independent borrowed lifetime retirement."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from harness_generation.minimal_ft.models import ProjectSnapshot
from harness_generation.harness_context.models import fact_id
from harness_generation.harness_context.repairs import merge_resolution,fact_conflicts
from harness_generation.harness_context.value_flow import complete_bodies
from test_evidence_repairs import shared_context,target,patch

from harness_generation.harness_context.repair_proofs import RepairProofEvaluator as Evaluator

_BASE_PREPARED = None

def prepare(tmp_path):
    global _BASE_PREPARED
    if _BASE_PREPARED is None:
        _BASE_PREPARED=shared_context(tmp_path)
    ft,snapshot,reqs,resolutions,state,gate=_BASE_PREPARED
    copied_artifacts=replace(snapshot.artifacts,functions=deepcopy(snapshot.artifacts.functions))
    prepared=(deepcopy(ft),ProjectSnapshot.from_artifacts(copied_artifacts),deepcopy(reqs),deepcopy(resolutions),deepcopy(state),deepcopy(gate))
    req=target(prepared,'feed','ownership')
    original=deepcopy(prepared[3][req['requirement_id']])
    bad=patch(original,'entries','data',lifetime='during_call')
    good=patch(original,'entries','data',lifetime='until_release')
    previous=deepcopy(original)
    previous['facts']=[f for f in previous['facts'] if f['value']['entries'][0]['parameter']!='data']+bad['facts']
    previous['facts'].sort(key=lambda f:f['fact_id'])
    prepared[3][req['requirement_id']]=previous
    evaluator=Evaluator(prepared[0],prepared[1],prepared[4]).configure(
        [f for r in prepared[3].values() for f in r['facts']],prepared[2],prepared[3])
    candidate=deepcopy(previous)
    candidate['facts']=[f for f in previous['facts'] if f['value']['entries'][0]['parameter']!='data']+good['facts']
    candidate['facts'].sort(key=lambda f:f['fact_id'])
    context,closure,graph=evaluator._projection(candidate,req)
    assert not graph['validation_errors']
    fid=req['subject_function_id'];row=good['facts'][0]['value']['entries'][0]
    assert evaluator._borrowed_source_proof(row,fid,context,graph)
    return prepared,req,previous,good,evaluator,context,graph

def replace_body(prepared,name,body):
    snapshot,state=prepared[1],prepared[4]
    fid=next(fid for fid,f in snapshot.functions.items() if f['name']==name)
    snapshot.functions[fid]['body']=body
    # New synthetic authenticated body observations, never edit native artifacts.
    # Drop broad range records so a stale old source range cannot authenticate it.
    state.evidence={eid:r for eid,r in state.evidence.items() if r.get('tool')!='read_source_range'}
    for r in state.evidence.values():
        if r.get('function_id')==fid and r.get('tool')=='get_function':
            r['content']=body;r['truncated']=False
    assert fid in complete_bodies(snapshot,state.evidence)
    return fid

@pytest.mark.parametrize('reverse',[False,True])
def test_strict_until_release_retirement_is_order_independent_and_preserves_other_subjects(tmp_path,reverse):
    prepared,req,previous,good,evaluator,context,graph=prepare(tmp_path)
    merged,audit=merge_resolution(good,previous,req,proof_evaluator=evaluator) if reverse else merge_resolution(previous,good,req,proof_evaluator=evaluator)
    assert len(audit['withdrawals'])==1 and not audit['conflicts']
    event=audit['withdrawals'][0]
    assert event['reason']=='source_disproved' and event['previous_proof']['status']=='contradicted'
    assert event['replacement_proof']['source_witness']['lifetime_bound']=='until_release'
    assert all(f in merged['facts'] for f in previous['facts'] if f['value']['entries'][0]['parameter']!='data')
    assert not fact_conflicts(merged['facts'])

@pytest.mark.parametrize('corruption',['explicit_owned','static','unknown_lifetime','different_release_api','different_resource_id'])
def test_retirement_cannot_cover_explicit_ownership_or_uncertain_different_subject_claim(tmp_path,corruption):
    prepared,req,previous,good,evaluator,context,graph=prepare(tmp_path)
    changed=deepcopy(previous)
    fact=next(f for f in changed['facts'] if f['value']['entries'][0]['parameter']=='data')
    row=fact['value']['entries'][0]
    if corruption=='explicit_owned':row['ownership']='owned'
    elif corruption=='static':row['lifetime']='static'
    elif corruption=='unknown_lifetime':row['lifetime']='unknown'
    elif corruption=='different_release_api':row['release_api']=next(fid for fid,f in prepared[1].functions.items() if f['name']=='destroy')
    else:row['resource_id']='resource_foreign'
    fact['fact_id']=fact_id(fact);changed['facts'].sort(key=lambda f:f['fact_id'])
    evaluator.configure([f for r in prepared[3].values() for f in r['facts']],prepared[2],{**prepared[3],req['requirement_id']:changed})
    merged,audit=merge_resolution(changed,good,req,proof_evaluator=evaluator)
    assert not audit['withdrawals'],corruption
    if corruption!='unknown_lifetime':
        assert any(f['value']['entries'][0]==row for f in merged['facts'])
    # Existing unknown-enum compatible refinement is independent of retirement.

@pytest.mark.parametrize('case',[ 'source_global_export','source_array_alias_export','source_out_export','source_unknown_callee',
    'source_pointer_arithmetic','recipient_array_escape','producer_global_escape','producer_array_alias_escape',
    'cleanup_unknown_callee','cleanup_parameter_array_escape','cleanup_member_free','cleanup_member_read','cleanup_conditional_release'])
def test_source_escape_unknown_effect_or_member_cleanup_never_certifies_longer_borrow(tmp_path,case):
    prepared,req,previous,good,evaluator,context,graph=prepare(tmp_path)
    snapshot=prepared[1]
    feed=snapshot.functions[req['subject_function_id']]['body']
    if case=='source_global_export':replace_body(prepared,'feed',feed.replace('{','{ saved=data;',1))
    elif case=='source_array_alias_export':replace_body(prepared,'feed',feed.replace('{','{ const unsigned char *alias=data; saved[0]=alias;',1))
    elif case=='source_out_export':replace_body(prepared,'feed',feed.replace('{','{ *out=data;',1))
    elif case=='source_unknown_callee':replace_body(prepared,'feed',feed.replace('{','{ unknown(data);',1))
    elif case=='source_pointer_arithmetic':replace_body(prepared,'feed',feed.replace('=data','=data+1'))
    elif case=='recipient_array_escape':replace_body(prepared,'feed',feed.replace('{','{ saved[0]=ctx;',1))
    elif case=='producer_global_escape':replace_body(prepared,'create','{ Context *p=calloc(1,sizeof(Context)); saved=p; return p; }')
    elif case=='producer_array_alias_escape':replace_body(prepared,'create','{ Context *p=calloc(1,sizeof(Context)); Context *alias=p; saved[0]=alias; return p; }')
    elif case=='cleanup_unknown_callee':replace_body(prepared,'destroy','{ unknown(ctx);free(ctx); }')
    elif case=='cleanup_parameter_array_escape':replace_body(prepared,'destroy','{ saved[0]=ctx;free(ctx); }')
    elif case=='cleanup_member_free':replace_body(prepared,'destroy','{ free((void*)ctx->data);free(ctx); }')
    elif case=='cleanup_member_read':replace_body(prepared,'destroy','{ if(ctx->data) free(ctx);else free(ctx); }')
    else:replace_body(prepared,'destroy','{ if(flag) free(ctx); }')
    fid=req['subject_function_id'];row=good['facts'][0]['value']['entries'][0]
    assert evaluator._borrowed_source_proof(row,fid,context,graph) is None,case
    merged,audit=merge_resolution(previous,good,req,proof_evaluator=evaluator)
    assert not audit['withdrawals'],case
    assert fact_conflicts(merged['facts'])

@pytest.mark.parametrize('case',['recipient_wrong_rid','cleanup_wrong_rid','cleanup_unknown','cleanup_optional',
    'producer_borrowed','producer_owner_release_mismatch','resource_reuse_unknown','missing_source_body'])
def test_exact_resource_owner_cleanup_and_complete_body_are_required(tmp_path,case):
    prepared,req,previous,good,evaluator,context,graph=prepare(tmp_path)
    fid=req['subject_function_id'];row=good['facts'][0]['value']['entries'][0]
    creator=next(k for k,v in prepared[1].functions.items() if v['name']=='create')
    cleanup=next(k for k,v in prepared[1].functions.items() if v['name']=='destroy')
    if case=='recipient_wrong_rid':
        next(r for r in context['canonical_construction']['parameters'] if r['function_id']==fid and r['parameter']=='ctx')['recipe']['resource_id']='resource_wrong'
    elif case=='cleanup_wrong_rid':
        next(r for r in context['canonical_construction']['parameters'] if r['function_id']==cleanup)['recipe']['resource_id']='resource_wrong'
    elif case=='cleanup_unknown':
        for r in context['lifecycle_contract']['resources']:r['cleanup']['api']=None
    elif case=='cleanup_optional':
        for r in context['lifecycle_contract']['resources']:r['cleanup']['mandatory']=False
    elif case in ('producer_borrowed','producer_owner_release_mismatch'):
        owner=next(r for r in context['ownership_contract']['entries'] if r['function_id']==creator and r['return_value'])
        if case=='producer_borrowed':owner['ownership']='borrowed'
        else:owner['release_api']=None
    elif case=='resource_reuse_unknown':
        next(r for r in context['lifecycle_contract']['resources'] if r['function_id']==creator)['reuse']='unknown'
    else:
        prepared[4].evidence={eid:r for eid,r in prepared[4].evidence.items()
            if fid not in {r.get('function_id'),r.get('caller_id')} and r.get('tool')!='read_source_range'}
        assert fid not in complete_bodies(prepared[1],prepared[4].evidence)
    assert evaluator._borrowed_source_proof(row,fid,context,graph) is None,case


def test_during_call_source_retention_is_not_a_positive_witness(tmp_path):
    prepared,req,previous,good,evaluator,context,graph=prepare(tmp_path)
    row=deepcopy(good['facts'][0]['value']['entries'][0]);row['lifetime']='during_call'
    assert evaluator._borrowed_source_proof(row,req['subject_function_id'],context,graph) is None
