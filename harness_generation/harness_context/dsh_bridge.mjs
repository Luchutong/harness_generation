/** DeepSeek Harness 0.1.5-rc.1 plugin. Provider and policy stay in Python. */
import { LlmAdapter, LlmError } from '@deepseek-ai/dsh-llm'

export const name = 'harness-generation-context-bridge'
export const inject = ['llm', 'tools', 'systemPrompt', 'agents']

const FEEDBACK_TOOL = '__harness_context_feedback'
const PROVIDER = 'harness-generation'
const DEFAULT_RESPONSE_BYTES = 16 * 1024 * 1024

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0)
    throw new LlmError(`Invalid Python bridge ${label}`, 'HARNESS_BRIDGE_PROTOCOL')
  return value
}

function lossless(value, active = new Set()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return
  if (typeof value === 'number' && Number.isFinite(value)) return
  if (!record(value) && !Array.isArray(value))
    throw new LlmError('Python bridge result is not JSON', 'HARNESS_BRIDGE_PROTOCOL')
  if (active.has(value))
    throw new LlmError('Python bridge result is circular', 'HARNESS_BRIDGE_PROTOCOL')
  active.add(value)
  for (const child of Object.values(value)) lossless(child, active)
  active.delete(value)
}

function schemasFrom(value) {
  if (!Array.isArray(value))
    throw new LlmError('Invalid Python bridge schemas', 'HARNESS_BRIDGE_PROTOCOL')
  const names = new Set()
  return value.map(item => {
    const schema = record(item) && record(item.function) ? item.function : item
    if (!record(schema))
      throw new LlmError('Invalid Python bridge tool schema', 'HARNESS_BRIDGE_PROTOCOL')
    const toolName = requireString(schema.name, 'tool name')
    if (toolName === FEEDBACK_TOOL || toolName === 'run_code' || names.has(toolName))
      throw new LlmError('Invalid Python bridge tool roster', 'HARNESS_BRIDGE_PROTOCOL')
    names.add(toolName)
    if (typeof schema.description !== 'string' || !record(schema.parameters))
      throw new LlmError('Invalid Python bridge tool schema', 'HARNESS_BRIDGE_PROTOCOL')
    lossless(schema.parameters)
    return {name: toolName, description: schema.description, parameters: schema.parameters}
  })
}

function usageFrom(value) {
  if (value === undefined || value === null) return undefined
  if (!record(value))
    throw new LlmError('Invalid Python bridge usage', 'HARNESS_BRIDGE_PROTOCOL')
  // Only the explicitly normalized, disjoint DSH vocabulary is accepted.
  const keys = ['inputTokens', 'outputTokens', 'totalTokens', 'cacheReadTokens',
    'cacheWriteTokens', 'reasoningTokens']
  const usage = {}
  for (const key of keys) {
    if (value[key] === undefined) continue
    if (!Number.isSafeInteger(value[key]) || value[key] < 0)
      throw new LlmError('Invalid Python bridge token count', 'HARNESS_BRIDGE_PROTOCOL')
    usage[key] = value[key]
  }
  if (usage.inputTokens === undefined || usage.outputTokens === undefined)
    throw new LlmError('Python bridge usage lacks authoritative counts', 'HARNESS_BRIDGE_PROTOCOL')
  return usage
}

function responseBlocks(value, allowedNames) {
  if (!record(value))
    throw new LlmError('Invalid Python bridge model response', 'HARNESS_BRIDGE_PROTOCOL')
  const blocks = []
  for (const [field, type] of [['reasoning_content', 'reasoning'], ['content', 'text']]) {
    if (value[field] === null || value[field] === undefined || value[field] === '') continue
    if (typeof value[field] !== 'string')
      throw new LlmError('Invalid Python bridge model text', 'HARNESS_BRIDGE_PROTOCOL')
    blocks.push({type, text: value[field]})
  }
  const calls = value.tool_calls ?? []
  if (!Array.isArray(calls))
    throw new LlmError('Invalid Python bridge tool calls', 'HARNESS_BRIDGE_PROTOCOL')
  const ids = new Set()
  for (const call of calls) {
    if (!record(call))
      throw new LlmError('Invalid Python bridge tool call', 'HARNESS_BRIDGE_PROTOCOL')
    const id = requireString(call.id, 'tool call id')
    const toolName = requireString(call.name, 'tool call name')
    if (ids.has(id) || !allowedNames.has(toolName) || typeof call.arguments !== 'string')
      throw new LlmError('Invalid Python bridge tool call identity', 'HARNESS_BRIDGE_PROTOCOL')
    ids.add(id)
    blocks.push({type: 'tool-call', id, name: toolName, arguments: call.arguments})
  }
  return blocks
}

/** Apply is async so the SDK readiness handshake joins initial bridge setup. */
export async function apply(ctx, config) {
  if (!record(config)) throw new Error('harness-generation bridge requires config')
  const endpoint = new URL(requireString(config.endpoint, 'endpoint'))
  if (endpoint.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(endpoint.hostname)
      || endpoint.username || endpoint.password || endpoint.search || endpoint.hash)
    throw new Error('harness-generation bridge requires a private loopback HTTP endpoint')
  const token = requireString(config.token, 'authorization token')
  const maxResponseBytes = config.maxResponseBytes ?? DEFAULT_RESPONSE_BYTES
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 1)
    throw new Error('harness-generation bridge maxResponseBytes must be positive')
  let disposed = false
  let sequence = 0
  let feedbackSequence = 0
  const controllers = new Set()
  const allowedNames = new Set()
  const registrations = new Map()
  const nativeCalls = new Map()
  let visibleSchemas = []
  let investigationStopped = false

  ctx.effect(() => () => {
    disposed = true
    for (const controller of controllers) controller.abort()
  }, 'harness-generation.bridge-requests')

  async function request(op, payload, signal) {
    if (disposed) throw new LlmError('Python bridge was disposed', 'HARNESS_BRIDGE_CLOSED')
    signal?.throwIfAborted()
    const controller = new AbortController()
    const abort = () => controller.abort(signal?.reason)
    signal?.addEventListener('abort', abort, {once: true})
    controllers.add(controller)
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {'content-type': 'application/json', authorization: `Bearer ${token}`},
        body: JSON.stringify({op, seq: ++sequence, ...payload}),
        signal: controller.signal,
      })
      if (!response.ok)
        throw new LlmError('Python bridge request failed', 'HARNESS_BRIDGE_HTTP', {status: response.status})
      const chunks = []
      let size = 0
      for await (const chunk of response.body ?? []) {
        size += chunk.byteLength
        if (size > maxResponseBytes) {
          controller.abort()
          throw new LlmError('Python bridge response exceeded limit', 'HARNESS_BRIDGE_RESPONSE_LIMIT')
        }
        chunks.push(Buffer.from(chunk))
      }
      let packet
      try { packet = JSON.parse(Buffer.concat(chunks).toString('utf8')) }
      catch { throw new LlmError('Python bridge returned invalid JSON', 'HARNESS_BRIDGE_PROTOCOL') }
      if (!record(packet))
        throw new LlmError('Python bridge returned invalid packet', 'HARNESS_BRIDGE_PROTOCOL')
      if (packet.error !== undefined) {
        const code = record(packet.error) && typeof packet.error.code === 'string'
          && /^[A-Z][A-Z0-9_]{0,63}$/.test(packet.error.code) ? packet.error.code : 'HARNESS_BRIDGE_ERROR'
        throw new LlmError('Python bridge operation failed', code)
      }
      return packet
    } finally {
      signal?.removeEventListener('abort', abort)
      controllers.delete(controller)
    }
  }

  async function executeBridgeTool(toolName, args, exec) {
    const identity = String(exec.callId)
    const native = nativeCalls.get(identity)
    if (native === undefined || native.name !== toolName)
      throw new Error('SDK call has no matching native submission')
    let projected
    try { projected = native.arguments ? JSON.parse(native.arguments) : {} }
    catch { projected = native.arguments }
    if (JSON.stringify(projected) !== JSON.stringify(args))
      throw new Error('SDK arguments differ from the native submission')
    nativeCalls.delete(identity)
    if (investigationStopped) {
      // DSH concludes the turn after draining this response's entire batch.
      // Verify the issued sibling, but do not call Python or charge any tool.
      return {error: 'investigation_stopped', evidence_ids: [], tool_executed: false}
    }
    const packet = await request('tool', {
      name: toolName, arguments: args, arguments_raw: native.arguments, tool_call_id: identity,
    }, exec.signal)
    if (typeof packet.done !== 'boolean' || !Object.hasOwn(packet, 'result'))
      throw new Error('Invalid Python bridge tool result')
    lossless(packet.result)
    if (packet.done) {
      investigationStopped = true
      exec.concludeTurn()
    }
    return packet.result
  }

  function updateSchemas(value, initial = false) {
    const schemas = schemasFrom(value)
    if (!initial && schemas.some(schema => !allowedNames.has(schema.name)))
      throw new LlmError('Python bridge changed allowed tool roster', 'HARNESS_BRIDGE_PROTOCOL')
    for (const schema of schemas) {
      const previous = registrations.get(schema.name)
      const key = JSON.stringify(schema)
      if (previous?.key === key) continue
      previous?.dispose()
      const dispose = ctx.tools.register({
        ...schema,
        output: {schema: {}, render: (_args, value) => [{type: 'text', text: JSON.stringify(value)}]},
        execute: (args, exec) => executeBridgeTool(schema.name, args, exec),
      })
      registrations.set(schema.name, {key, dispose})
      if (initial) allowedNames.add(schema.name)
    }
    // Keep executors for the complete initial roster; only expose current schemas.
    visibleSchemas = schemas
  }

  const initial = await request('initialize', {})
  if (typeof initial.system !== 'string')
    throw new Error('Invalid Python bridge initial system prompt')
  updateSchemas(initial.schemas, true)
  ctx.systemPrompt.variable('harness_generation_system', () => initial.system)
  ctx.systemPrompt.section({name: 'harness-generation:system', order: 0,
    text: '{{harness_generation_system}}', complete: true})

  ctx.tools.register({
    name: FEEDBACK_TOOL,
    description: 'Carry framework feedback through the runtime loop.',
    parameters: {type: 'object', properties: {}, additionalProperties: false},
    output: {schema: {}, render: (_args, value) => [{type: 'text', text: JSON.stringify(value)}]},
    async execute(_args, exec) {
      const packet = await request('feedback', {tool_call_id: String(exec.callId)}, exec.signal)
      if (typeof packet.done !== 'boolean' || !Object.hasOwn(packet, 'result'))
        throw new Error('Invalid Python bridge feedback result')
      lossless(packet.result)
      if (packet.done) {
        investigationStopped = true
        exec.concludeTurn()
      }
      return packet.result
    },
  })
  ctx.on('system-prompt/assemble', async (assembly, _context, next) => {
    const surface = await request('surface', {}, _context.signal)
    updateSchemas(surface.schemas)
    const resolved = await next()
    return {...resolved, tools: [...visibleSchemas]}
  })
  ctx.on('tools/pre-execute', async (exec, next) => {
    if (exec.name !== FEEDBACK_TOOL && !allowedNames.has(exec.name))
      return {kind: 'deny', reason: 'Tool is outside the registered Context bridge roster'}
    return next()
  })

  class PythonBridgeAdapter extends LlmAdapter {
    async *stream(options) {
      if (investigationStopped)
        throw new LlmError('Context investigation has stopped', 'HARNESS_BRIDGE_CLOSED')
      if (options.purpose !== undefined)
        throw new LlmError('Auxiliary model calls are disabled', 'HARNESS_BRIDGE_AUXILIARY_DENIED')
      const packet = await request('model', {
        purpose: options.purpose ?? null,
        session_id: options.sessionId ?? null,
        runtime_message_count: options.messages.length,
      }, options.signal)
      if (!['continue', 'stop', 'tools'].includes(packet.action) || typeof packet.done !== 'boolean')
        throw new LlmError('Invalid Python bridge model action', 'HARNESS_BRIDGE_PROTOCOL')
      if (packet.schemas !== undefined) updateSchemas(packet.schemas)
      let blocks
      let usage
      if (packet.response === null) {
        // No provider response: emit only a runtime continuation, never a model-visible tool schema.
        blocks = [{type: 'tool-call', id: `harness-feedback-${++feedbackSequence}`,
          name: FEEDBACK_TOOL, arguments: '{}'}]
        usage = usageFrom(packet.usage)
      } else {
        blocks = responseBlocks(packet.response, allowedNames)
        for (const call of packet.response.tool_calls ?? []) {
          if (nativeCalls.has(call.id))
            throw new LlmError('Python bridge reused a pending tool identity', 'HARNESS_BRIDGE_PROTOCOL')
          nativeCalls.set(call.id, {name: call.name, arguments: call.arguments})
        }
        usage = usageFrom(packet.response.usage)
        if (!blocks.some(block => block.type === 'tool-call') && !packet.done) {
          // Text-only rejected outcomes still deliver framework feedback without an implicit model retry.
          blocks.push({type: 'tool-call', id: `harness-feedback-${++feedbackSequence}`,
            name: FEEDBACK_TOOL, arguments: '{}'})
        }
      }
      for (const [index, block] of blocks.entries()) {
        yield {type: 'block-start', index, blockType: block.type}
        yield {type: 'block-end', index, block}
      }
      if (usage !== undefined) yield {type: 'usage', usage}
      yield {type: 'finish', reason: {kind: blocks.some(block => block.type === 'tool-call') ? 'tool-calls' : 'stop'}}
    }
  }
  ctx.llm.registerAdapter([PROVIDER], new PythonBridgeAdapter())
}
