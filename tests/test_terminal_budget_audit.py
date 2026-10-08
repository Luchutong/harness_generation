"""Independently audit registered extra operations without changing old cohorts."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('terminal_budget_audit',ROOT/'scripts/audit_fresh_stability.py')
auditor=importlib.util.module_from_spec(spec);spec.loader.exec_module(auditor)
collect_spec=importlib.util.spec_from_file_location('terminal_budget_collect',ROOT/'scripts/collect_fresh_stability.py')
collector=importlib.util.module_from_spec(collect_spec);collect_spec.loader.exec_module(collector)


def write(path, document):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(document))


def registration():
    categories={'candidate':['terminal_schema_error','terminal_json_parse_error','candidate_unknown_evidence_reference'],
                'slice':['terminal_schema_error','terminal_json_parse_error','slice_role_choice_not_issued'],
                'context':['terminal_schema_error']}
    for categories_for_stage in categories.values():
        categories_for_stage.append('terminal_native_submission_missing')
    return {'provider':{'timeout':120.0},'validation_slice_budget':{'max_rounds':6,'max_tool_calls':24,'max_source_chars':48000},
            'context_budget':{'max_rounds_per_requirement':4,'max_total_model_calls':24,
                              'max_terminal_repairs':1,'max_tool_calls':64,'max_source_chars':96000},
            'agent_recovery_limits':{'candidate':{'max_terminal_repairs':1},'slice':{'max_terminal_repairs':1}},
            'agent_terminal_policies':{stage:{'terminal_repair_policy_version':'terminal-only-resubmission-v3',
               'terminal_repair_allowed_categories':allowed,'extra_terminal_repair_last_round_only':stage=='slice'}
               for stage,allowed in categories.items()}}


def response(number,round=None,phase='exploration'):
    return {'kind':'model_response','model_call':number,'round':round or number,'phase':phase,
            'metadata':{'response_id':f'response-{number}',
                        'request_diagnostics':{'tool_count':1 if phase=='terminal_repair' else 8,
                                               'request_timeout_seconds':120.0,'sdk_max_retries':0}}}


def request_error(number,round,category):
    return {'kind':'model_error','phase':'terminal_repair','round':round,'error_category':category,
            'diagnostics':{'attempt_number':number,'tool_count':1,
                           **({} if category=='budget_exhausted' else
                              {'request_timeout_seconds':120.0,'sdk_max_retries':0})}}


def put_trace(root,stage='slice',*,ordinary=6,extra=True,category=None,repair='success',
              requirement='req_a',group=None,owner=True,original=None):
    reg=registration();policy=reg['agent_terminal_policies'][stage]
    budget=reg['context_budget' if stage=='context' else 'validation_slice_budget']
    path=(root/'harness_contexts/ft/agent_runs'/requirement/'attempt_0001' if stage=='context' else
          root/('semantic_slices/candidate' if stage=='slice' else 'candidate_discovery/agent_runs/candidate'))
    if original:
        trace,metadata,result=deepcopy(original)
        metadata.update(requirement_id=requirement,group_cost_owner=owner,
                        model_calls=metadata['model_calls'] if owner else 0)
    else:
        events=[response(i) for i in range(1,ordinary+1)]
        category=category or ('terminal_schema_error' if stage=='context' else 'terminal_json_parse_error')
        operation={'operation':1,'category':category,'extra':True,'next_model_call':ordinary+1,
                   'ordinary_round':ordinary,'terminal_only':True}
        operations=[operation] if extra else []
        messages=[]
        if extra:
            error_category = ('terminal_validation_error' if category in
                {'candidate_unknown_evidence_reference','slice_role_choice_not_issued'} else category)
            events.append({'kind':'execution_error','error_category':error_category,
                           **({'terminal_repair_category':category} if error_category=='terminal_validation_error' else {}),
                           **({'terminal_extra_repair_allowed':True} if category=='terminal_schema_error' else {})})
            events.append({'kind':'extra_terminal_repair','round':ordinary,'phase':'terminal_repair','reason':category,
                           'shared_extra_attempt':1,'policy_version':policy['terminal_repair_policy_version'],
                           'max_extra_terminal_repairs':1,'extra_terminal_repair_last_round_only':stage=='slice',
                           'ordinary_round_limit':ordinary if stage=='context' else 6,'operation':operation})
            if repair in {'timeout','budget_exhausted','http_401'}:
                events.append(request_error(ordinary+1,ordinary,repair))
            else:
                events.append(response(ordinary+1,ordinary,'terminal_repair'))
                if repair=='rejected':
                    events.append({'kind':'repair_rejected','round':ordinary,'error_category':'terminal_repair_error'})
                else:
                    events.append({'kind':'decision_submission','round':ordinary,'phase':'terminal_repair','tool_call_id':'repair-id'})
                    name={'candidate':'submit_candidate_decision','slice':'submit_semantic_slice',
                          'context':'submit_requirement_resolutions'}[stage]
                    messages=[{'role':'assistant','tool_calls':[{'id':'repair-id','type':'function',
                              'function':{'name':name,'arguments':'{}'}}]}]
        calls=ordinary+int(extra and repair!='budget_exhausted')
        repair_audit={**policy,'extra_terminal_repair_attempts':int(extra),
                      'terminal_correction_attempts':len(operations),'terminal_correction_operations':operations}
        trace={'events':events,'messages':messages,**repair_audit}
        metadata={'configuration':{'budget':budget,**policy},**repair_audit}
        result={'budget':{'model_calls':calls,'rounds':ordinary,'tool_calls':0,'source_chars':0,'terminal_repairs':int(extra)}}
        if stage=='context':
            metadata.update(model_calls=calls if owner else 0,rounds=ordinary,
                            requirement_id=requirement,group_requirement_ids=group or [requirement],
                            group_cost_owner=owner,group_model_calls=calls)
    write(path/'trace.json',trace);write(path/'metadata.json',metadata)
    write(path/('slice.json' if stage=='slice' else 'result.json'),result)
    if stage=='context' and owner:
        parent=path.parents[2]
        old=json.loads((parent/'metadata.json').read_text()) if (parent/'metadata.json').is_file() else {'metrics':{'model_calls':0,'tool_calls':0,'source_chars':0}}
        old['metrics']['model_calls']+=metadata['model_calls'];write(parent/'metadata.json',old)
    return path,trace,metadata,result


def inspect(root,reg=None):
    return auditor.agent_terminal_budget_checks(root,reg or registration())


def rewrite(path, trace, metadata, result,stage='slice'):
    write(path/'trace.json',trace);write(path/'metadata.json',metadata)
    write(path/('slice.json' if stage=='slice' else 'result.json'),result)


@pytest.mark.parametrize('stage,ordinary', [('candidate',6),('slice',6),('context',4)])
@pytest.mark.parametrize('repair',['success','timeout','http_401','rejected'])
def test_one_recorded_extra_operation_and_request_remain_inside_caps(tmp_path,stage,ordinary,repair):
    put_trace(tmp_path,stage,ordinary=ordinary,repair=repair)
    checks=inspect(tmp_path)
    assert checks and all(checks.values()),[k for k,v in checks.items() if not v]


@pytest.mark.parametrize('stage,ordinary',[('candidate',2),('slice',6),('context',1)])
def test_no_extra_request_has_no_inferred_extra_cost(tmp_path,stage,ordinary):
    put_trace(tmp_path,stage,ordinary=ordinary,extra=False)
    assert all(inspect(tmp_path).values())


def test_context_global_budget_block_counts_operation_but_no_provider_request(tmp_path):
    put_trace(tmp_path,'context',ordinary=4,repair='budget_exhausted')
    checks=inspect(tmp_path)
    assert all(checks.values()),[k for k,v in checks.items() if not v]
    costs=auditor.cost_observations(tmp_path)
    assert costs['observed_agent_model_calls']['context']==4
    assert costs['local_budget_stop_counts']=={'context':1}
    assert costs['failed_request_usage_unknown']==0


@pytest.mark.parametrize('mutation,failed',[('counter','extra_counter'),('extra_cap','shared_extra_limit'),
    ('wrong_category','registered_category'),('early_slice','last_round'),('wrong_version','policy_version'),
    ('wrong_phase','one_terminal_only_request'),('advertises_repository','only_terminal_schema_advertised'),
    ('execute_repository','no_repository_execution'),('two_native_calls','sole_native_terminal_submission'),
    ('wrong_native_name','sole_native_terminal_submission'),('operation_next_call','operation_matches_request'),
    ('sdk_retry','no_sdk_retries'),('timeout_drift','timeout'),('hidden_request','registered_model_call_bound'),
    ('round_counter','round_counter_matches_trace'),('no_eligible_trigger','eligible_recorded_error')])
def test_extra_trace_tampering_is_detected_independently(tmp_path,mutation,failed):
    path,trace,meta,result=put_trace(tmp_path)
    extra=next(e for e in trace['events'] if e['kind']=='extra_terminal_repair')
    req=next(e for e in trace['events'] if e.get('phase')=='terminal_repair' and e['kind']=='model_response')
    if mutation=='counter':meta['extra_terminal_repair_attempts']=2
    elif mutation=='extra_cap':extra['max_extra_terminal_repairs']=2
    elif mutation=='wrong_category':extra['reason']='unproved_ownership'
    elif mutation=='early_slice':extra['round']=5
    elif mutation=='wrong_version':extra['policy_version']='unregistered'
    elif mutation=='wrong_phase':req['phase']='exploration'
    elif mutation=='advertises_repository':req['metadata']['request_diagnostics']['tool_count']=2
    elif mutation=='execute_repository':trace['events'].append({'kind':'tool_call','name':'get_function'})
    elif mutation=='two_native_calls':trace['messages'][0]['tool_calls'].append({'id':'bad','function':{'name':'get_function'}})
    elif mutation=='wrong_native_name':trace['messages'][0]['tool_calls'][0]['function']['name']='get_function'
    elif mutation=='operation_next_call':extra['operation']['next_model_call']=9
    elif mutation=='sdk_retry':req['metadata']['request_diagnostics']['sdk_max_retries']=1
    elif mutation=='timeout_drift':req['metadata']['request_diagnostics']['request_timeout_seconds']=60
    elif mutation=='hidden_request':
        trace['events'].append(response(8,6,'terminal_repair'));result['budget']['model_calls']=8
    elif mutation=='round_counter':result['budget']['rounds']=5
    elif mutation=='no_eligible_trigger':
        trace['events']=[e for e in trace['events'] if e['kind']!='execution_error']
    rewrite(path,trace,meta,result)
    assert any(not v and failed in k for k,v in inspect(tmp_path).items())


@pytest.mark.parametrize('stage', ['candidate','slice'])
def test_eight_calls_are_rejected_even_when_declared_counter_and_registration_match(tmp_path,stage):
    path,trace,meta,result=put_trace(tmp_path,stage)
    trace['events'].append(response(8,6,'terminal_repair'));result['budget']['model_calls']=8
    rewrite(path,trace,meta,result,stage)
    assert any(not v and 'registered_model_call_bound' in k for k,v in inspect(tmp_path).items())


@pytest.mark.parametrize('category',['terminal_schema_error','terminal_json_parse_error','slice_role_choice_not_issued'])
def test_registered_slice_error_categories_share_one_extra_allowance(tmp_path,category):
    put_trace(tmp_path,category=category)
    assert all(inspect(tmp_path).values())


def test_missing_semantic_proof_cannot_be_reclassified_as_shape_error(tmp_path):
    path,trace,meta,result=put_trace(tmp_path,category='terminal_schema_error')
    error=next(e for e in trace['events'] if e['kind']=='execution_error')
    error['terminal_extra_repair_allowed']=False
    rewrite(path,trace,meta,result)
    assert any(not v and 'eligible_recorded_error' in k for k,v in inspect(tmp_path).items())


def test_stale_earlier_error_cannot_authorize_extra_after_a_later_response(tmp_path):
    path,trace,meta,result=put_trace(tmp_path)
    error=next(e for e in trace['events'] if e['kind']=='execution_error')
    trace['events'].remove(error);trace['events'].insert(4,error)
    rewrite(path,trace,meta,result)
    assert any(not v and 'eligible_recorded_error' in k for k,v in inspect(tmp_path).items())


def test_context_unique_owner_avoids_group_replica_double_count(tmp_path):
    original=put_trace(tmp_path,'context',ordinary=3,group=['req_a','req_b'])
    put_trace(tmp_path,'context',ordinary=3,requirement='req_b',owner=False,original=original[1:])
    checks=inspect(tmp_path)
    assert all(checks.values()),[k for k,v in checks.items() if not v]
    costs=auditor.cost_observations(tmp_path)
    assert costs['observed_agent_model_calls']['context']==4


@pytest.mark.parametrize('change',['replica_charged','duplicate_owner','missing_owner','replica_trace_changed'])
def test_context_group_owner_cannot_hide_or_duplicate_provider_calls(tmp_path,change):
    first=put_trace(tmp_path,'context',ordinary=3,group=['req_a','req_b'])
    path,trace,meta,result=put_trace(tmp_path,'context',ordinary=3,requirement='req_b',owner=False,original=first[1:])
    if change=='replica_charged':meta['model_calls']=4
    elif change=='duplicate_owner':meta['group_cost_owner']=True;meta['model_calls']=4
    elif change=='missing_owner':
        primary=json.loads((first[0]/'metadata.json').read_text());primary['group_cost_owner']=False;primary['model_calls']=0
        write(first[0]/'metadata.json',primary)
    else:trace['events'][0]['metadata']['response_id']='other-provider-request'
    rewrite(path,trace,meta,result,'context')
    assert not all(inspect(tmp_path).values())


def test_context_global_calls_never_gain_an_extra_global_allowance(tmp_path):
    for i in range(5):put_trace(tmp_path,'context',ordinary=4,requirement=f'req_{i}')
    assert any(not v and 'model_calls_bound' in k for k,v in inspect(tmp_path).items())


def test_history_without_registered_terminal_policy_is_not_reinterpreted(tmp_path):
    path,trace,meta,result=put_trace(tmp_path)
    trace['events'].append(response(8,6,'terminal_repair'));rewrite(path,trace,meta,result)
    reg=registration();reg.pop('agent_terminal_policies')
    before={p: p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}
    assert auditor.agent_terminal_budget_checks(tmp_path,reg)=={}
    assert before=={p:p.read_bytes() for p in tmp_path.rglob('*') if p.is_file()}


@pytest.mark.parametrize('finish', ['stop', 'tool_calls'])
def test_native_missing_extra_requires_a_recorded_completed_zero_call_message(tmp_path, finish):
    path, trace, meta, result = put_trace(tmp_path, category='terminal_native_submission_missing')
    trigger = next(e for e in reversed(trace['events']) if e.get('kind') == 'model_response' and e.get('phase') != 'terminal_repair')
    trigger['metadata']['finish_reason'] = finish
    trace['messages'].insert(0, {'role': 'assistant', 'content': 'Unaccepted analysis', 'tool_calls': []})
    rewrite(path, trace, meta, result)
    assert all(inspect(tmp_path).values())
    trace['messages'][0]['tool_calls'] = [{'id': 'not-zero', 'function': {'name': 'foreign', 'arguments': '{}'}}]
    rewrite(path, trace, meta, result)
    checks = inspect(tmp_path)
    assert any(not v and 'completed_zero_call_response' in k for k, v in checks.items())


def test_length_response_cannot_claim_missing_native_extra(tmp_path):
    path, trace, meta, result = put_trace(tmp_path, category='terminal_native_submission_missing')
    trigger = next(e for e in reversed(trace['events']) if e.get('kind') == 'model_response' and e.get('phase') != 'terminal_repair')
    trigger['metadata']['finish_reason'] = 'length'
    trace['messages'].insert(0, {'role': 'assistant', 'content': 'Truncated unaccepted analysis'})
    rewrite(path, trace, meta, result)
    assert any(not v and 'completed_zero_call_response' in k for k,v in inspect(tmp_path).items())


def upgrade_v4(trace, metadata):
    reg = registration()
    for policy in reg['agent_terminal_policies'].values():
        policy['terminal_repair_policy_version'] = 'terminal-only-resubmission-v4'
    for document in (trace, metadata, metadata['configuration']):
        document['terminal_repair_policy_version'] = 'terminal-only-resubmission-v4'
    for event in trace['events']:
        if event.get('kind') == 'extra_terminal_repair':
            event['policy_version'] = 'terminal-only-resubmission-v4'
    return reg


@pytest.mark.parametrize('kind', ['budget_stop', 'execution_error'])
def test_v4_extra_local_guard_has_one_operation_and_zero_provider_requests(tmp_path, kind):
    path, trace, meta, result = put_trace(tmp_path, 'context', ordinary=4, repair='budget_exhausted')
    reg = upgrade_v4(trace, meta)
    guard = {'kind': kind, 'round': 4, 'phase': 'terminal_repair',
             'provider_request': False, 'model_call': False,
             **({'reason': 'optional_model_reserve'} if kind == 'budget_stop' else
                {'error': 'pretransport_model_failure', 'error_category': 'invalid_output'})}
    trace['events'] = [guard if e.get('kind') == 'model_error' else e for e in trace['events']]
    rewrite(path, trace, meta, result, 'context')
    checks = inspect(tmp_path, reg)
    assert checks and all(checks.values()), [k for k, v in checks.items() if not v]
    costs = auditor.cost_observations(tmp_path)
    assert costs['observed_agent_model_calls']['context'] == 4
    assert costs['observed_provider_request_attempts'] == 4
    assert costs['failed_request_usage_unknown'] == 0
    assert costs['local_budget_stop_counts'] == ({'context': 1} if kind == 'budget_stop' else {})


@pytest.mark.parametrize('mutation', ['request_flag', 'call_flag', 'later_response', 'later_tool', 'next_call'])
def test_v4_local_guard_cannot_hide_requests_or_execution(tmp_path, mutation):
    path, trace, meta, result = put_trace(tmp_path, 'context', ordinary=4, repair='budget_exhausted')
    reg = upgrade_v4(trace, meta)
    guard = {'kind': 'budget_stop', 'round': 4, 'phase': 'terminal_repair',
             'provider_request': False, 'model_call': False, 'reason': 'max_total_model_calls'}
    trace['events'] = [guard if e.get('kind') == 'model_error' else e for e in trace['events']]
    if mutation == 'request_flag': guard['provider_request'] = True
    elif mutation == 'call_flag': guard['model_call'] = True
    elif mutation == 'later_response': trace['events'].append(response(5, 4, 'terminal_repair'))
    elif mutation == 'later_tool': trace['events'].append({'kind': 'tool_call', 'tool_executed': False})
    else:
        next(e for e in trace['events'] if e['kind'] == 'extra_terminal_repair')['operation']['next_model_call'] = 99
    rewrite(path, trace, meta, result, 'context')
    assert not all(inspect(tmp_path, reg).values())


def test_v4_ordinary_guard_records_round_without_fabricating_model_attempt(tmp_path):
    path, trace, meta, result = put_trace(tmp_path, 'context', ordinary=1, extra=False)
    reg = upgrade_v4(trace, meta)
    trace['events'] = [{'kind': 'budget_stop', 'round': 1, 'phase': 'exploration',
                        'provider_request': False, 'model_call': False, 'reason': 'max_total_model_calls'}]
    meta.update(model_calls=0, group_model_calls=0)
    result['budget']['model_calls'] = 0
    rewrite(path, trace, meta, result, 'context')
    write(path.parents[2] / 'metadata.json', {'metrics': {'model_calls': 0, 'tool_calls': 0, 'source_chars': 0}})
    checks = inspect(tmp_path, reg)
    assert checks and all(checks.values()), [k for k, v in checks.items() if not v]
    assert auditor.cost_observations(tmp_path)['observed_provider_request_attempts'] == 0


def test_context_last_only_policy_uses_actual_remaining_round_limit(tmp_path):
    path, trace, meta, result = put_trace(tmp_path, 'context', ordinary=2, category='terminal_native_submission_missing')
    reg = upgrade_v4(trace, meta)
    trace['messages'].insert(0, {'role': 'assistant', 'content': 'Unaccepted analysis', 'tool_calls': []})
    next(e for e in reversed(trace['events']) if e.get('kind') == 'model_response'
         and e.get('phase') != 'terminal_repair')['metadata']['finish_reason'] = 'stop'
    rewrite(path, trace, meta, result, 'context')
    checks = inspect(tmp_path, reg)
    assert checks and all(checks.values()), [k for k, v in checks.items() if not v]


def test_v4_group_local_stop_and_rejected_tool_are_collected_once_without_provider_cost(tmp_path):
    events = [response(1), {'kind': 'tool_call', 'tool_call_id': 'rejected-query', 'tool_executed': False},
              {'kind': 'budget_stop', 'phase': 'terminal_repair', 'round': 1,
               'provider_request': False, 'model_call': False, 'reason': 'optional_model_reserve'}]
    for requirement, owner in [('req_a', True), ('req_b', False)]:
        directory = tmp_path / 'harness_contexts/ft/agent_runs' / requirement
        for path in (directory, directory / 'attempt_0001'):
            write(path / 'trace.json', {'events': events})
            write(path / 'metadata.json', {'group_cost_owner': owner, 'model_calls': int(owner)})
    row = collector.collect_trial(tmp_path)
    costs = auditor.cost_observations(tmp_path)
    assert row['totals']['local_budget_stops'] == len(costs['local_budget_stops']) == 1
    assert row['totals']['provider_request_attempts'] == costs['observed_provider_request_attempts'] == 1
    assert row['totals']['failed_requests'] == costs['failed_request_usage_unknown'] == 0
    stage = row['stages']['harness-context']
    assert stage['trace_tool_events'] == 1 and stage['trace_tool_executions'] == 0


def test_rejected_upstream_tool_is_an_observation_without_execution_or_budget_cost(tmp_path):
    directory = tmp_path / 'semantic_slices/candidate'
    write(directory / 'trace.json', {'events': [
        {'kind': 'tool_call', 'tool_call_id': 'reject', 'tool_executed': False},
        {'kind': 'tool_call', 'tool_call_id': 'read', 'tool_executed': True},
        {'kind': 'tool_call', 'tool_call_id': 'reuse', 'tool_executed': False, 'evidence_reuse': True}]})
    row = collector.collect_trial(tmp_path)
    costs = auditor.cost_observations(tmp_path)
    assert row['stages']['semantic-slice']['trace_tool_events'] == 3
    assert row['stages']['semantic-slice']['trace_tool_executions'] == 1
    assert row['stages']['semantic-slice']['tool_calls'] == costs['upstream_trace_tool_calls']['slice'] == 1
