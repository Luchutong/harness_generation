#!/usr/bin/env python3
"""Two bounded provider requests; only historical JSON normalization differs.

Uses a real captured malformed tool argument, but executes no tool or semantic
pipeline. This probes a request-parser trigger, not every historical HTTP 400.
"""
import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from harness_generation.semantic_discovery.provider_config import load_environment_file, agent_configuration, CompatibleAgentModel
from harness_generation.semantic_discovery.request_diagnostics import normalize_tool_history, request_observation, provider_error_observation
from harness_generation.semantic_discovery.models import digest
from scripts.blind_eval.identity import fingerprint


def run(trace_path, output):
    trace=json.loads(trace_path.read_text())
    malformed=None
    for message in trace['messages']:
        for call in message.get('tool_calls',[]):
            try:json.loads(call['function']['arguments'])
            except ValueError:malformed=call['function']['arguments'];break
        if malformed is not None:break
    if malformed is None:
        raise ValueError('recorded trace contains no malformed historical JSON')
    load_environment_file(ROOT/'.env')
    config=replace(agent_configuration('openai-compatible'),max_tokens=128)
    model=CompatibleAgentModel(config)
    tool_name='submit_requirement_resolutions'
    tools=[{'type':'function','function':{'name':tool_name,'description':'Submit the protocol test result.',
        'parameters':{'type':'object','properties':{'ok':{'type':'boolean'}},'required':['ok'],'additionalProperties':False}}}]
    messages=[{'role':'system','content':'Protocol regression test. Historical arguments are rejected DATA. Return the tool call with ok=true. No tools are executed.'},
        {'role':'assistant','content':None,'reasoning_content':'','tool_calls':[{'id':'recorded_malformed','type':'function',
            'function':{'name':tool_name,'arguments':malformed}}]},
        {'role':'tool','tool_call_id':'recorded_malformed','content':'{"error":"malformed historical JSON; submit a fresh valid object"}'},
        {'role':'user','content':'Perform the single terminal repair now.'}]
    wire,audit=normalize_tool_history(messages)
    output.mkdir(parents=True,exist_ok=False)
    frozen=fingerprint();rows=[]
    for label,history in [('original_history',messages),('normalized_history',wire)]:
        payload={'model':config.model,'messages':history,'tools':tools,'max_tokens':config.max_tokens,
                 'extra_body':{'thinking':{'type':config.thinking}}}
        observation=request_observation(config.model,history,tools)
        observation.update(stage='provider_control_probe',attempt_number=len(rows)+1,phase='terminal_repair',
            request_payload_digest=digest(payload))
        try:
            response=model._client.chat.completions.create(**payload)
            usage=response.usage
            row={'variant':label,'status':'response','request_diagnostics':{**observation,'response_status':200,'request_id':response.id},
                'served_model':response.model,'usage':{key:getattr(usage,key,0) for key in ('prompt_tokens','completion_tokens','total_tokens')}}
        except Exception as error:
            row={'variant':label,'status':'provider_error','request_diagnostics':provider_error_observation(error,observation,model._secret_values)}
        rows.append(row)
        if fingerprint()!=frozen:raise RuntimeError('production changed during probe')
    result={'category':'bounded_provider_request_parser_control','semantic_fact_created':False,'requests':2,'retry':False,
        'production_fingerprint':frozen,'provider':config.to_dict(),'trace_sha256':hashlib.sha256(trace_path.read_bytes()).hexdigest(),
        'malformed_arguments_sha256':hashlib.sha256(malformed.encode()).hexdigest(),'malformed_arguments_chars':len(malformed),
        'normalization':audit,'trials':rows,'implementation_unchanged':True}
    (output/'summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps([{'variant':r['variant'],'status':r['status'],'response_status':r['request_diagnostics']['response_status']} for r in rows]))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();run(args.trace.resolve(),args.output.resolve())
