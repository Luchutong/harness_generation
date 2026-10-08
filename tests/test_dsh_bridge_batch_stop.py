"""Authored while testing is paused; future JS tests use a fake SDK host only."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


def test_dsh_plugin_drains_remaining_batch_locally_after_python_budget_stop(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node parser/runtime is required for this offline plugin contract test")
    plugin = Path(__file__).resolve().parents[1] / "harness_generation/harness_context/dsh_bridge.mjs"
    source = plugin.read_text().replace(
        "import { LlmAdapter, LlmError } from '@deepseek-ai/dsh-llm'",
        "class LlmAdapter {}\nclass LlmError extends Error {constructor(message, code) {super(message); this.code=code}}")
    target = tmp_path / "isolated-bridge.mjs"
    target.write_text(source)
    driver = tmp_path / "driver.mjs"
    driver.write_text(r'''
import assert from 'node:assert/strict'
import {apply} from './isolated-bridge.mjs'
const requests = []
const schemas = [{type: 'function', function: {name:'read_source', description:'Read issued source', parameters:{type:'object'}}}]
globalThis.fetch = async (_url, init) => {
  const request = JSON.parse(init.body)
  requests.push(request)
  let packet
  if (request.op === 'initialize') packet = {system:'Exact system', schemas}
  else if (request.op === 'model') packet = {action:'tools', done:false, schemas,
    response:{content:null, reasoning_content:null, usage:null,
      tool_calls:[1,2,3].map(i=>({id:`read-${i}`,name:'read_source',arguments:'{}'}))}}
  else if (request.op === 'tool' && request.tool_call_id === 'read-1')
    packet = {done:false, result:{evidence_ids:['issued-read'], tool_executed:true}}
  else if (request.op === 'tool' && request.tool_call_id === 'read-2')
    packet = {done:true, result:{error:'budget_exhausted', evidence_ids:[], tool_executed:false}}
  else throw new Error('Stopped sibling must not reach Python')
  return {ok:true, status:200, body:[new TextEncoder().encode(JSON.stringify(packet))]}
}
const tools = new Map()
let adapter
const ctx = {
  effect:()=>()=>{}, on:()=>()=>{},
  tools:{register:definition=>{tools.set(definition.name,definition);return()=>tools.delete(definition.name)}},
  systemPrompt:{variable:()=>{},section:()=>{}},
  llm:{registerAdapter:(_providers,value)=>{adapter=value}},
}
await apply(ctx,{endpoint:'http://127.0.0.1:1/context',token:'fixture-token'})
const calls = []
for await (const chunk of adapter.stream({messages:[],sessionId:'session'}))
  if (chunk.type==='block-end' && chunk.block.type==='tool-call') calls.push(chunk.block)
let concluded = 0
const results = []
for (const call of calls) results.push(await tools.get(call.name).execute(JSON.parse(call.arguments),
  {callId:call.id,concludeTurn:()=>concluded++}))
assert.equal(concluded,1)
assert.deepEqual(results[2],{error:'investigation_stopped',evidence_ids:[],tool_executed:false})
assert.equal(requests.filter(r=>r.op==='tool').length,2)
assert.equal(requests.filter(r=>r.op==='model').length,1)
assert.ok(requests.filter(r=>r.op==='tool').every(r=>r.arguments_raw==='{}'))
let rejected = false
try {for await (const _chunk of adapter.stream({messages:[],sessionId:'session'})) {}}
catch(error) {rejected=error.code==='HARNESS_BRIDGE_CLOSED'}
assert.equal(rejected,true)
assert.equal(requests.filter(r=>r.op==='model').length,1)
process.stdout.write(JSON.stringify({tool_requests:2,model_requests:1,concluded}))
''')
    result = subprocess.run([node, str(driver)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"tool_requests": 2, "model_requests": 1, "concluded": 1}
