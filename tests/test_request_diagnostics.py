"""Request failures are execution observations, never semantic propositions."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from harness_generation.semantic_discovery.models import (
    AgentModelError, AgentModelResponse, AgentToolCall, DecisionSchemaError, ValidationBudget)
from harness_generation.semantic_discovery.provider_config import CompatibleAgentConfig, CompatibleAgentModel
from harness_generation.semantic_discovery.loop import BoundedAgentLoop
from harness_generation.semantic_discovery.request_diagnostics import (
    classify_error, redact, normalize_tool_history)
from harness_generation.harness_context import HarnessContextMiningLoop
from harness_generation.harness_context.agent import HarnessContextAgent
from test_harness_context import setup


class FailedProvider:
    provider,model='fake','recorded-diagnostic'
    def __init__(self,error):
        self.error=error; self.calls=[]
    def complete(self,messages,tools):
        self.calls.append(deepcopy([messages,tools]))
        raise self.error


@pytest.mark.parametrize('status,category',[(400,'http_400'),(401,'http_401'),(403,'http_403'),(429,'http_429'),
                                         (500,'http_5xx'),(503,'http_5xx')])
def test_status_errors_have_sanitized_payload_diagnostics(status,category):
    secret='unit-test-private-api-key'
    err=RuntimeError('Never save exception credentials='+secret)
    err.status_code=status;err.request_id='provider-request-23'
    err.body={'error':{'code':'InvalidParameter','message':'tools rejected Bearer '+secret,
                      'api_key':secret,'env':{'IMPORTANT_SECRET':secret}},'Authorization':'Bearer '+secret}
    count=[]
    def create(**kwargs):
        count.append(kwargs)
        raise err
    model=CompatibleAgentModel(CompatibleAgentConfig(model='alias'),environ={'LLM_API_KEY':secret},
        client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
    with pytest.raises(AgentModelError) as captured:
        model.complete([{'role':'user','content':'source'}],[{'type':'function','function':{'name':'terminal'}}])
    failure=captured.value;d=failure.diagnostics
    assert failure.error_category==category and failure.http_status==status
    assert d['request_id']=='provider-request-23' and d['provider_error_code']=='InvalidParameter'
    assert d['message_count']==1 and d['tool_count']==1 and d['prompt_chars']>0 and d['schema_size']>0
    assert len(d['request_payload_digest'])==64
    assert secret not in json.dumps(d) and secret not in str(failure)
    assert d['error_body']['Authorization']=='[redacted]'
    assert len(count)==1  # No blind identical HTTP retry.


@pytest.mark.parametrize('error,category',[(TimeoutError(),'timeout'),(ConnectionError(),'transport_error'),
                                         (RuntimeError(),'unknown_provider_error')])
def test_transport_taxonomy(error,category):
    assert classify_error(error)==category


def test_invalid_provider_response_is_distinct_from_transport():
    model=CompatibleAgentModel(CompatibleAgentConfig(model='alias'),client=SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **_:SimpleNamespace(choices=[])))))
    with pytest.raises(AgentModelError) as error:
        model.complete([],[])
    assert error.value.error_category=='invalid_response'
    assert error.value.diagnostics['response_status']==200


def test_redaction_precedes_truncation_and_never_saves_environment():
    secret='long-credential-at-limit'
    payload={'error':{'message':'x'*4090+secret,'details':{'env':{'UNRELATED':'value'},'headers':{'Authorization':secret}}}}
    result=redact(payload,[secret])
    assert secret not in json.dumps(result) and 'long-credential' not in result['error']['message']
    assert result['error']['details']['env']=='[redacted]' and result['error']['details']['headers']=='[redacted]'


@pytest.mark.parametrize('category',['http_400','http_429','timeout'])
def test_context_provider_failure_persists_execution_state_without_facts(tmp_path,category):
    prepared=setup(tmp_path)
    error=AgentModelError('recorded failure'); error.error_category=category
    if category.startswith('http_'):
        error.http_status=int(category.split('_')[1])
    model=FailedProvider(error)
    run=HarnessContextMiningLoop(model,prepared[4],group_requirements=True).run(prepared[1],prepared[3],prepared[5],store=prepared[0][0])
    assert run.context['facts']==[]
    assert run.completeness['status']=='incomplete' and not run.completeness['generation_allowed']
    assert run.metadata['execution_failures']
    transient = category in {'http_429', 'timeout'}
    assert len(model.calls)==(2 if transient else 1)
    assert all(row['resolution_attempt_failed']=='provider_error' for row in run.requirements['requirements'])
    assert run.completeness['execution_failed_requirements']
    event=next(e for e in run.metadata['execution_failures'][0]['errors'] if e['kind']=='model_error')
    assert event['diagnostics']['stage']=='harness_context' and event['diagnostics']['attempt_number']==1
    assert event['error_category']==category
    root=prepared[0][0].root/'harness_contexts'/run.context['ft_id']
    for path in root.glob('agent_runs/*/metadata.json'):
        assert json.loads(path.read_text())['execution_status']=='provider_error'
    traces = [json.loads(path.read_text()) for path in root.glob('agent_runs/*/attempt_*/trace.json')]
    recoveries = [event for trace in traces for event in trace['events']
                  if event['kind']=='provider_recovery']
    # Grouped requirement traces repeat the same bounded investigation. Recovery
    # consumes an existing round; completeness never opens a new retry attempt.
    assert bool(recoveries) is transient
    assert all(event['within_existing_budget'] and event['error_category']==category for event in recoveries)
    assert all(int(path.parent.name.split('_')[-1])==1 for path in root.glob('agent_runs/*/attempt_*/trace.json'))


class Tools:
    schemas=[]
    def execute(self,*args):
        return {'error':'invalid_tool_arguments','evidence_ids':[]}


TERMINAL={'type':'function','function':{'name':'terminal','parameters':{'type':'object','properties':{}}}}


def test_malformed_terminal_and_repair_failure_remain_execution_errors():
    # A syntactically valid payload reaches the schema validator. Malformed
    # transport JSON has its own explicit parse-repair category below.
    first=AgentModelResponse(tool_calls=(AgentToolCall('bad','terminal','{}'),))
    error=AgentModelError('HTTP rejected');error.http_status=400
    class Model:
        model='recorded'
        calls=0
        def complete(self,*args):
            self.calls+=1
            if self.calls==1:return first
            raise error
    def validate(text):
        raise DecisionSchemaError('$','malformed',['object'])
    model=Model();result=BoundedAgentLoop(model,ValidationBudget(max_rounds=2),TERMINAL,validate,
        max_terminal_repairs=1,stage='harness_context').run([],Tools())
    assert result.decision is None and result.termination=='provider_error'
    assert model.calls==2 and result.schema_repair_attempted
    assert any(e.get('error_category')=='terminal_schema_error' for e in result.events)
    event=next(e for e in result.events if e['kind']=='model_error')
    assert event['phase']=='terminal_repair' and event['error_category']=='http_400'
    assert event['repair_error_category']=='terminal_repair_error'


def test_invalid_tool_call_is_observed_before_any_fact():
    class Model:
        model='recorded'
        def complete(self,*args):
            return AgentModelResponse(tool_calls=(AgentToolCall('', 'get_function','[]'),))
    result=BoundedAgentLoop(Model(),ValidationBudget(max_rounds=1),TERMINAL,lambda _: {},stage='harness_context').run([],Tools())
    assert result.decision is None
    assert any(e.get('error_category')=='tool_call_parse_error' for e in result.events)


def test_model_unresolved_answer_has_no_provider_failure_marker(tmp_path):
    prepared=setup(tmp_path)
    from test_harness_context import mine
    run,model=mine(prepared,{})
    assert model.calls and run.context['facts']==[]
    assert not run.metadata['execution_failures']
    assert not run.completeness['execution_failed_requirements']
    assert all('resolution_attempt_failed' not in row for row in run.requirements['requirements'])


@pytest.mark.parametrize('bad_arguments', ['{', '{"r": [}', '{"x": NaN}'])
def test_malformed_history_normalizes_only_outbound_copy(bad_arguments):
    messages=[{'role':'assistant','tool_calls':[{'id':'bad','type':'function',
        'function':{'name':'terminal','arguments':bad_arguments}}]},
        {'role':'tool','tool_call_id':'bad','content':'{"error":"malformed"}'}]
    before=deepcopy(messages)
    outbound,changes=normalize_tool_history(messages)
    assert messages==before and outbound[0]['tool_calls'][0]['function']['arguments']=='{}'
    assert outbound[1]==messages[1]
    assert len(changes)==1 and changes[0]['original_arguments_chars']==len(bad_arguments)
    assert len(changes[0]['original_arguments_digest'])==64
    assert 'original_arguments' not in changes[0]


def test_valid_history_is_preserved_exactly():
    messages=[{'role':'assistant','tool_calls':[{'id':'good','type':'function',
        'function':{'name':'terminal','arguments':' {"x": 1}  '}}]}]
    outbound,changes=normalize_tool_history(messages)
    assert outbound==messages and outbound is not messages and changes==[]


@pytest.mark.parametrize('repair_arguments', ['{"resolved": true}', '{'])
def test_recorded_malformed_history_repair_is_bounded_and_trace_remains_original(repair_arguments):
    requests=[]
    def create(**kwargs):
        requests.append(deepcopy(kwargs))
        # Emulate a provider that rejects malformed JSON in request history.
        for message in kwargs['messages']:
            for call in message.get('tool_calls',[]):
                json.loads(call['function']['arguments'])
        arguments='{' if len(requests)==1 else repair_arguments
        message=SimpleNamespace(content=None, tool_calls=[SimpleNamespace(id='bad' if len(requests)==1 else 'repaired',
            function=SimpleNamespace(name='terminal',arguments=arguments))])
        return SimpleNamespace(id='recorded-response',model='recorded-served',usage=None,
            choices=[SimpleNamespace(message=message,finish_reason='tool_calls')])
    model=CompatibleAgentModel(CompatibleAgentConfig(model='alias'),client=SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
    def validate(text):
        try:return json.loads(text)
        except ValueError:raise DecisionSchemaError('$','malformed',['object'])
    result=BoundedAgentLoop(model,ValidationBudget(max_rounds=1),TERMINAL,validate,
        max_terminal_repairs=1,stage='harness_context',
        terminal_repair_categories=('terminal_schema_error','terminal_json_parse_error')).run([],Tools())
    assert len(requests)==2 and result.extra_terminal_repair_attempts==1
    assert not result.schema_repair_attempted and result.rounds==1
    assert result.messages[0]['tool_calls'][0]['function']['arguments']=='{'
    assert requests[1]['messages'][0]['tool_calls'][0]['function']['arguments']=='{}'
    event=[e for e in result.events if e['kind']=='model_response'][-1]
    assert event['metadata']['request_diagnostics']['normalized_tool_history_count']==1
    assert not any(e['kind']=='tool_call' for e in result.events)
    if repair_arguments.startswith('{"'):
        assert result.decision=={'resolved':True} and result.extra_terminal_repair_success
    else:
        assert result.decision is None and not result.extra_terminal_repair_success
        assert result.termination=='invalid_output'


def test_history_diagnostics_redact_identifiers_and_digest_actual_wire_payload():
    from harness_generation.semantic_discovery.models import digest
    secret='history-private-key'
    error=RuntimeError();error.status_code=400
    requests=[]
    def create(**kwargs):
        requests.append(kwargs);raise error
    model=CompatibleAgentModel(CompatibleAgentConfig(model='alias'),environ={'LLM_API_KEY':secret},
        client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create))))
    messages=[{'role':'assistant','tool_calls':[{'id':secret,'type':'function',
        'function':{'name':'terminal','arguments':'{'+secret}}]}]
    with pytest.raises(AgentModelError) as captured:model.complete(messages,[])
    d=captured.value.diagnostics
    assert d['normalized_tool_history_count']==1 and secret not in json.dumps(d)
    assert d['request_payload_digest']==digest(requests[0])
    assert messages[0]['tool_calls'][0]['function']['arguments']=='{'+secret
