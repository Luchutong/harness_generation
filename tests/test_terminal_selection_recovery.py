"""Native terminal-only corrections preserve facts, raw failures, and registered caps."""
import json

import pytest

from harness_generation.semantic_discovery.loop import BoundedAgentLoop, TERMINAL_REPAIR_POLICY_VERSION
from harness_generation.semantic_discovery.models import (
    AgentModelError, AgentModelResponse, AgentToolCall, DecisionSchemaError, FakeAgentModel, ValidationBudget, TerminalSelectionError)
from harness_generation.semantic_discovery.tools import _schema
from harness_generation.semantic_slicing.proposals import SliceChoiceSelectionError

TERMINAL=_schema('submit_semantic_slice','terminal',{},[])
GOOD='{"choice_id":"issued","open_questions":[]}'
ALL=['terminal_schema_error','terminal_json_parse_error','slice_role_choice_not_issued','candidate_unknown_evidence_reference']

class NoSource:
    schemas=[_schema('read_source','source',{},[])]
    def execute(self,*args):raise AssertionError('No repository tools during resubmission')

class Responses(FakeAgentModel):
    def complete(self,messages,tools):
        self.calls.append({'messages':list(messages),'tools':tools})
        if not self.responses:raise AssertionError('Unregistered extra model operation')
        response=self.responses.pop(0)
        if isinstance(response,Exception):raise response
        return response(messages,tools) if callable(response) else response

class CandidateSelectionError(TerminalSelectionError):
    terminal_repair_category='candidate_unknown_evidence_reference'


def response(payload,number=1,*,finish='tool_calls',name='submit_semantic_slice',call_id=None):
    return AgentModelResponse(tool_calls=(AgentToolCall(call_id or f'native-{number}',name,payload),),
        metadata={'finish_reason':finish,'response_id':f'offline-{number}',
                  'usage':{'prompt_tokens':17,'completion_tokens':23,'total_tokens':40}})


def strict(text):
    value=json.loads(text)
    if value=={}:raise DecisionSchemaError('$',{},['choice_id','open_questions'])
    if value.get('choice_id')=='foreign':raise SliceChoiceSelectionError(0,'foreign')
    if value.get('choice_id')=='foreign-eid':raise CandidateSelectionError('unknown evidence reference')
    if value!=json.loads(GOOD):raise ValueError('source_contradiction')
    return value


def run(steps,*,rounds=1,extra=1,categories=ALL,protocol=0,semantic=0,events=(),validator=strict,last_only=False):
    model=Responses(steps)
    outcome=BoundedAgentLoop(model,ValidationBudget(max_rounds=rounds),TERMINAL,validator,
        max_terminal_repairs=extra,terminal_repair_categories=categories,
        max_protocol_recoveries=protocol,max_semantic_recoveries=semantic,
        extra_terminal_repair_last_round_only=last_only,
        terminal_guidance_factory=lambda:{'existing_choices':['issued'],'unproved_roles_remain_unresolved':True}).run([],NoSource(),initial_events=events)
    return outcome,model


@pytest.mark.parametrize('bad,category',[
    ('{}','terminal_schema_error'),('{','terminal_json_parse_error'),
    ('{"choice_id":"foreign","open_questions":[]}','slice_role_choice_not_issued'),
    ('{"choice_id":"foreign-eid","open_questions":[]}','candidate_unknown_evidence_reference'),
])
def test_last_round_explicit_resubmit_preserves_failure_and_all_costs(bad,category):
    outcome,model=run([response(bad),response(GOOD,2)])
    assert outcome.decision==json.loads(GOOD) and outcome.rounds==1
    assert len(model.calls)==outcome.model_calls==2 and outcome.tool_calls==0
    assert outcome.extra_terminal_repair_attempts==outcome.terminal_correction_attempts==1
    assert outcome.extra_terminal_repair_success
    assert model.calls[1]['tools']==[TERMINAL]
    assert outcome.messages[0]['tool_calls'][0]['function']['arguments']==bad
    assert sum(e['metadata']['usage']['total_tokens'] for e in outcome.events if e['kind']=='model_response')==80
    extra=next(e for e in outcome.events if e['kind']=='extra_terminal_repair')
    assert extra['reason']==category and extra['shared_extra_attempt']==1
    assert extra['policy_version']==TERMINAL_REPAIR_POLICY_VERSION
    assert outcome.schema_repair_attempted==(category=='terminal_schema_error')


@pytest.mark.parametrize('bad',['{','{"choice_id":"foreign","open_questions":[]}'])
def test_new_category_never_uses_extra_before_last_ordinary_round(bad):
    outcome,model=run([response(bad),response(GOOD,2)],rounds=3)
    assert outcome.decision is None and len(model.calls)==1 and not outcome.extra_terminal_repair_attempts


@pytest.mark.parametrize('bad',['{','{"choice_id":"foreign","open_questions":[]}'])
@pytest.mark.parametrize('extra,categories',[(0,ALL),(1,['terminal_schema_error'])])
def test_disabled_cap_or_unregistered_category_is_fail_closed(bad,extra,categories):
    outcome,model=run([response(bad),response(GOOD,2)],extra=extra,categories=categories)
    assert outcome.decision is None and len(model.calls)==1 and not outcome.extra_terminal_repair_attempts


@pytest.mark.parametrize('first,second',[
    ('{}','{}'),('{}','{'),('{}','{"choice_id":"foreign","open_questions":[]}'),
    ('{','{}'),('{','{'),('{','{"choice_id":"foreign-eid","open_questions":[]}'),
    ('{"choice_id":"foreign","open_questions":[]}','{}'),
    ('{"choice_id":"foreign","open_questions":[]}','{'),
])
def test_all_categories_share_one_extra_and_second_error_stops(first,second):
    outcome,model=run([response(first),response(second,2),response(GOOD,3)],protocol=1,semantic=1)
    assert outcome.decision is None and len(model.calls)==2
    assert outcome.extra_terminal_repair_attempts==outcome.terminal_correction_attempts==1
    assert not outcome.protocol_recoveries and not outcome.semantic_recoveries


def test_schema_extra_then_second_schema_error_cannot_fallback_to_unused_ordinary_round():
    outcome,model=run([response('{}'),response('{}',2),response(GOOD,3)],rounds=6,protocol=1,semantic=1)
    assert outcome.decision is None and len(model.calls)==2 and outcome.rounds==1
    assert outcome.extra_terminal_repair_attempts==1 and not outcome.protocol_recoveries


def test_ordinary_parse_correction_and_last_extra_are_both_publicly_counted():
    outcome,model=run([response('{'),response('{',2),response(GOOD,3)],rounds=2,protocol=1)
    assert outcome.decision==json.loads(GOOD) and outcome.rounds==2 and len(model.calls)==3
    assert outcome.protocol_recoveries==1 and outcome.extra_terminal_repair_attempts==1
    assert outcome.terminal_correction_attempts==2
    assert [op['extra'] for op in outcome.terminal_correction_operations]==[False,True]
    assert [op['next_model_call'] for op in outcome.terminal_correction_operations]==[2,3]


def test_ordinary_selection_correction_and_extra_do_not_create_per_type_allowances():
    bad='{"choice_id":"foreign-eid","open_questions":[]}'
    outcome,model=run([response(bad),response(bad,2),response(GOOD,3)],rounds=2,semantic=1)
    assert outcome.decision==json.loads(GOOD) and outcome.semantic_recoveries==1
    assert len(model.calls)==3 and outcome.extra_terminal_repair_attempts==1
    assert outcome.terminal_correction_attempts==2


@pytest.mark.parametrize('mode',['mixed','seen-id','oversize-id','oversize-payload','length','text'])
@pytest.mark.parametrize('protocol',[0,1])
def test_invalid_or_non_native_initial_envelope_cannot_obtain_extra(mode,protocol):
    bad=response('{')
    events=()
    if mode=='mixed':bad=AgentModelResponse(tool_calls=(AgentToolCall('one','submit_semantic_slice','{'),AgentToolCall('two','read_source','{}')))
    elif mode=='seen-id':events=({'tool_call_id':'native-1','kind':'bootstrap'},)
    elif mode=='oversize-id':bad=response('{',call_id='x'*513)
    elif mode=='oversize-payload':bad=response('{'+'x'*64000)
    elif mode=='length':bad=response('{',finish='length')
    elif mode=='text':bad=AgentModelResponse(content=GOOD)
    outcome,model=run([bad,response(GOOD,2)],events=events,protocol=protocol)
    assert outcome.decision is None and len(model.calls)==1 and not outcome.extra_terminal_repair_attempts


@pytest.mark.parametrize('mode',['mixed','seen-id','wrong-name','length','no-tool'])
def test_extra_response_must_be_one_fresh_complete_native_terminal(mode):
    repaired=response(GOOD,2)
    if mode=='mixed':repaired=AgentModelResponse(tool_calls=(AgentToolCall('two','submit_semantic_slice',GOOD),AgentToolCall('three','read_source','{}')))
    elif mode=='seen-id':repaired=response(GOOD,2,call_id='native-1')
    elif mode=='wrong-name':repaired=response('{}',2,name='read_source')
    elif mode=='length':repaired=response(GOOD,2,finish='length')
    else:repaired=AgentModelResponse(content=GOOD)
    outcome,model=run([response('{'),repaired,response(GOOD,3)],protocol=1,semantic=1)
    assert outcome.decision is None and len(model.calls)==2 and outcome.extra_terminal_repair_attempts==1
    assert outcome.tool_calls==0 and not outcome.provider_recoveries


@pytest.mark.parametrize('category',['http_401','http_403','timeout','http_429','budget_exhausted','transport_error'])
@pytest.mark.parametrize('during_extra',[False,True])
def test_provider_auth_and_budget_failures_cannot_gain_any_extra(category,during_extra):
    error=AgentModelError('offline recorded failure');error.error_category=category
    steps=[response('{'),error,response(GOOD,3)] if during_extra else [error,response(GOOD,2)]
    outcome,model=run(steps)
    assert outcome.decision is None and len(model.calls)==(2 if during_extra else 1)
    assert outcome.extra_terminal_repair_attempts==int(during_extra) and not outcome.provider_recoveries
    assert any(e['kind']=='model_error' and e['error_category']==category for e in outcome.events)


@pytest.mark.parametrize('message',['source_contradiction','slice_role_choice_not_issued','unknown evidence reference'])
def test_untyped_semantic_error_strings_do_not_gain_selection_extra(message):
    def validator(text):raise ValueError(message)
    outcome,model=run([response(GOOD),response(GOOD,2)],validator=validator)
    assert outcome.decision is None and len(model.calls)==1 and not outcome.extra_terminal_repair_attempts


def test_json_error_inside_semantic_validator_does_not_gain_transport_extra():
    def validator(text):json.loads('{nested invalid proof')
    outcome,model=run([response(GOOD),response(GOOD,2)],validator=validator)
    assert outcome.decision is None and len(model.calls)==1 and not outcome.extra_terminal_repair_attempts


def test_untrusted_category_attribute_on_an_untyped_exception_does_not_authorize_extra():
    def validator(text):
        error=ValueError('unknown evidence reference')
        error.terminal_repair_category='candidate_unknown_evidence_reference'
        raise error
    outcome,model=run([response(GOOD),response(GOOD,2)],validator=validator)
    assert outcome.decision is None and len(model.calls)==1 and not outcome.extra_terminal_repair_attempts


@pytest.mark.parametrize('categories',[['unknown'],['terminal_schema_error','terminal_schema_error'],'terminal_schema_error',[None],[{}]])
def test_policy_allowlist_must_be_explicit_unique_known_categories(categories):
    with pytest.raises(ValueError):run([],categories=categories)


def test_slice_last_only_schema_uses_an_ordinary_round_before_any_extra():
    outcome,model=run([response('{}'),response(GOOD,2)],rounds=2,protocol=1,last_only=True)
    assert outcome.decision==json.loads(GOOD) and len(model.calls)==2
    assert outcome.protocol_recoveries==1 and not outcome.extra_terminal_repair_attempts
    assert outcome.extra_terminal_repair_last_round_only is True


def test_slice_last_only_schema_and_parse_share_the_registered_extra():
    outcome,model=run([response('{}'),response('{',2),response(GOOD,3)],rounds=2,protocol=1,last_only=True)
    assert outcome.decision==json.loads(GOOD) and len(model.calls)==3
    assert outcome.protocol_recoveries==1 and outcome.extra_terminal_repair_attempts==1
    assert [op['extra'] for op in outcome.terminal_correction_operations]==[False,True]
    assert [op['category'] for op in outcome.terminal_correction_operations]==['terminal_schema_error','terminal_json_parse_error']


@pytest.mark.parametrize('value',[0,1,'true',None])
def test_last_round_only_policy_requires_an_explicit_boolean(value):
    with pytest.raises(ValueError,match='last_round_only'):
        run([],last_only=value)


@pytest.mark.parametrize('damage,category',[
    ('malformed','terminal_json_parse_error'),
    ('missing_field','terminal_schema_error'),
    ('foreign_choice','slice_role_choice_not_issued'),
])
def test_real_slice_last_native_failure_requests_one_new_explicit_submission(tmp_path,damage,category):
    from copy import deepcopy
    from harness_generation.semantic_discovery.models import canonical
    from test_semantic_slicing import DIRECT,fixture,run as run_slice,queries,tool
    sample=fixture(tmp_path,DIRECT)
    def registry(messages):
        return next(json.loads(m['content'])['slice_role_choices'] for m in reversed(messages)
            if m['role']=='tool' and 'slice_role_choices' in json.loads(m['content']))
    def good(messages,schemas):
        assert [s['function']['name'] for s in schemas]==['submit_semantic_slice']
        choice=next(c for c in registry(messages) if c['function_id']==sample[3].function_id and c['role']=='core')
        return response(canonical({'classification':[{'choice_id':choice['choice_id'],'open_questions':[]}]}),3)
    def bad(messages,schemas):
        fixed=json.loads(good(messages,schemas).tool_calls[0].arguments)
        if damage=='missing_field':del fixed['classification'][0]['open_questions']
        if damage=='foreign_choice':fixed['classification'][0]['choice_id']='slice_choice_foreign'
        return response('{' if damage=='malformed' else canonical(fixed),2)
    result,model,tools=run_slice(sample,[queries(tool('find_callers','read',function=sample[3].function_id)),bad,good],
        ValidationBudget(max_rounds=2))
    assert result.result['run_status']=='completed_with_unresolved'
    assert len(model.calls)==3 and result.result['budget']['rounds']==2
    assert result.result['budget']['tool_calls']==2
    assert result.metadata['extra_terminal_repair_attempts']==1 and result.metadata['extra_terminal_repair_success']
    assert result.metadata['extra_terminal_repair_last_round_only'] is True
    assert next(e for e in result.trace['events'] if e['kind']=='extra_terminal_repair')['reason']==category
    evidence=deepcopy(tools.evidence)
    assert set(evidence)=={r['evidence_id'] for r in result.evidence['records']}
    assert all(e['round']<2 for e in result.trace['events'] if e['kind']=='tool_call')
    assert [s['function']['name'] for s in model.calls[-1]['tools']]==['submit_semantic_slice']
    # The original native payload remains in the trace alongside the newly
    # submitted complete payload; the framework never fills the omitted field.
    initial=next(c for m in result.trace['messages'] for c in m.get('tool_calls',[]) if c['id']=='native-2')
    if damage=='missing_field':assert 'open_questions' not in json.loads(initial['function']['arguments'])['classification'][0]
    if damage=='foreign_choice':assert json.loads(initial['function']['arguments'])['classification'][0]['choice_id']=='slice_choice_foreign'
    if damage=='malformed':assert initial['function']['arguments']=='{'


def test_actual_source_withdrawn_exclude_cannot_request_last_round_extra(tmp_path):
    from harness_generation.semantic_discovery.models import canonical
    from harness_generation.semantic_slicing.models import validate_submission
    from harness_generation.semantic_slicing.proposals import choices
    from test_slice_source_exclusions import SOURCE,live_slice_tools,selected
    from test_semantic_slicing import fixture
    sample=fixture(tmp_path,SOURCE)
    tools,ids=live_slice_tools(sample),sample[-1]
    tools.execute('find_callees',{'function':ids['usage']})
    tools.execute('get_function',{'function':ids['dispose']})
    withdrawn=selected(tools,ids['dispose'],'exclude')
    tools.execute('read_source_range',{'file':'api.c','line_start':1,'line_end':9})
    payload=canonical({'classification':[selected(tools,ids['parse'],'core'),withdrawn]})
    repaired=canonical({'classification':[selected(tools,ids['parse'],'core'),selected(tools,ids['dispose'],'unresolved')]})
    outcome,model=run([response(payload),response(repaired,2)],validator=lambda s:validate_submission(s,tools),last_only=True)
    assert outcome.decision is None and len(model.calls)==1
    assert outcome.extra_terminal_repair_attempts==0 and outcome.terminal_correction_attempts==0
    error=next(e for e in outcome.events if e['kind']=='execution_error')
    assert error['terminal_extra_repair_allowed'] is False
    assert error['schema_errors'][0]['error']=='source_related_function_excluded'
