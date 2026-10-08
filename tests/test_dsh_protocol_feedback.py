"""Offline regression definitions for native unknown-tool feedback.

These definitions exercise the Python policy and bridge without starting the
optional SDK, invoking a provider, or changing the registered source tools.
"""
from copy import deepcopy
import json

import pytest

from harness_generation.harness_context.agent import BudgetedModel
from harness_generation.harness_context.dsh_backend import _Bridge
from harness_generation.harness_context.dsh_config import normalize_dsh_profile
from harness_generation.harness_context.dsh_policy import DSHContextPolicy
from harness_generation.harness_context.models import ContextBudget, MiningState
from harness_generation.semantic_discovery.models import (
    AgentModelResponse, AgentToolCall, ValidationBudget,
)


READ = {"type": "function", "function": {"name": "read_source",
    "description": "Read authorized source", "parameters": {"type": "object"}}}
TERMINAL = {"type": "function", "function": {"name": "submit_context",
    "description": "Submit the native decision", "parameters": {"type": "object"}}}


class Model:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def complete(self, messages, tools):
        self.calls.append((deepcopy(messages), deepcopy(tools)))
        return self.responses.pop(0)


class Tools:
    schemas = [READ]

    def __init__(self, state=None):
        self.state, self.calls = state, []

    def execute(self, name, arguments):
        self.calls.append((name, arguments))
        if self.state is not None:
            self.state.tool_calls += 1
        return {"evidence_ids": ["native-read"], "value": arguments}


def call(identity, name="read_source", arguments='{}'):
    return AgentToolCall(identity, name, arguments)


def response(*calls, **metadata):
    return AgentModelResponse(tool_calls=tuple(calls), metadata=metadata)


def policy(model, *, tools=None, rounds=3, protocol_recoveries=1, reserve_terminal_round=True):
    return DSHContextPolicy(model=model, tools=tools or Tools(),
        budget=ValidationBudget(max_rounds=rounds, max_tool_calls=4),
        terminal=TERMINAL, validator=json.loads,
        messages=[{"role": "system", "content": "Use issued repository evidence"},
                  {"role": "user", "content": "Investigate the obligation"}],
        reserve_terminal_round=reserve_terminal_round,
        max_protocol_recoveries=protocol_recoveries)


def tool_feedback(current):
    return [(message["tool_call_id"], json.loads(message["content"]))
        for message in current.outcome.messages if message.get("role") == "tool"]


def test_unknown_tool_feedback_continues_real_investigation_then_reserved_terminal():
    state = MiningState(ContextBudget())
    usage = {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3}
    model = Model(response(call("bad", "invented_reader", '{"line":4}'), usage=usage),
        response(call("read", arguments='{"line":4}'), usage=usage),
        response(call("submit", "submit_context", '{"accepted":true}'), usage=usage))
    tools = Tools(state)
    current = policy(BudgetedModel(model, state), tools=tools)

    assert current.complete() is None
    assert current.action == "continue" and not current.done
    assert current.pending_calls == [] and tools.calls == []
    assert current.outcome.tool_calls == state.tool_calls == 0
    assert current.outcome.model_calls == state.model_calls == 1
    identity, feedback = tool_feedback(current)[0]
    assert identity == "bad"
    assert feedback["data_class"] == "framework_protocol_feedback"
    assert feedback["error"] == feedback["error_category"] == "unknown_repository_tool"
    assert feedback["evidence_ids"] == [] and feedback["tool_executed"] is False
    event = next(event for event in current.outcome.events if event.get("kind") == "protocol_recovery")
    assert event["reason"] == "unknown_repository_tool" and event["within_existing_budget"]
    assert event["operation"]["terminal_only"] is False
    assert current.outcome.terminal_correction_operations == [event["operation"]]

    assert current.complete().tool_calls[0].id == "read"
    assert model.calls[1][1] == [READ, TERMINAL]
    assert current.execute_named("read_source", {"line": 4}, "read")[0]["evidence_ids"] == ["native-read"]
    assert current.complete().tool_calls[0].id == "submit"
    assert model.calls[2][1] == [TERMINAL]
    assert current.execute_named("submit_context", {"accepted": True}, "submit")[1]
    assert current.outcome.decision == {"accepted": True}
    assert current.outcome.rounds == 3
    assert current.outcome.protocol_recoveries == 1
    assert current.outcome.model_calls == state.model_calls == 3
    assert current.outcome.tool_calls == state.tool_calls == 1
    assert state.tokens == {"prompt_tokens": 6, "completion_tokens": 3, "total_tokens": 9}
    assert tools.calls == [("read_source", {"line": 4})]


def test_unknown_and_registered_batch_is_rejected_before_any_source_execution():
    model = Model(response(call("known", arguments='{"line":4}'),
                           call("unknown", "invented_reader", '{"line":5}')))
    tools = Tools()
    current = policy(model, tools=tools)

    assert current.complete() is None
    assert tools.calls == [] and current.outcome.tool_calls == 0
    assert [(identity, output["error"]) for identity, output in tool_feedback(current)] == [
        ("known", "repository_batch_not_executed"), ("unknown", "unknown_repository_tool")]
    assert all(not output["evidence_ids"] and output["tool_executed"] is False
               for _identity, output in tool_feedback(current))
    assert current.seen_calls == {"known", "unknown"}
    original = next(message for message in current.outcome.messages if message["role"] == "assistant")
    assert original["tool_calls"][0]["function"]["arguments"] == '{"line":4}'
    assert original["tool_calls"][1]["function"]["arguments"] == '{"line":5}'


def test_unknown_tool_in_terminal_only_round_keeps_original_rejection_policy():
    tools = Tools()
    current = policy(Model(response(call("last", "invented_reader"))), tools=tools, rounds=1)

    assert current.complete() is None and current.done
    assert current.outcome.termination == "terminal_round_without_submission"
    assert current.outcome.protocol_recoveries == 0
    assert current.outcome.terminal_correction_operations == []
    assert tool_feedback(current)[0][1]["error"] == "terminal_only_round"
    assert tools.calls == [] and current.outcome.tool_calls == 0


def test_unknown_tool_mixed_with_terminal_does_not_enable_source_recovery():
    tools = Tools()
    current = policy(Model(response(call("bad", "invented_reader"),
        call("submit", "submit_context", '{"accepted":true}'))), tools=tools)

    assert current.complete() is None and current.done
    assert current.outcome.decision is None
    assert current.outcome.protocol_recoveries == 0
    assert current.outcome.terminal_correction_operations == []
    assert tools.calls == [] and current.outcome.tool_calls == 0
    assert all(output["error"] == "mixed_or_invalid_terminal_not_executed"
               for _identity, output in tool_feedback(current))


def test_truncated_unknown_batch_keeps_terminal_only_protocol_recovery():
    model = Model(response(call("partial", "invented_reader"), finish_reason="length"),
        response(call("submit", "submit_context", '{"accepted":true}')))
    current = policy(model)

    assert current.complete() is None and not current.done
    event = next(event for event in current.outcome.events if event.get("kind") == "protocol_recovery")
    assert event["reason"] == "output_truncated"
    assert current.outcome.terminal_correction_operations[0]["terminal_only"] is True
    current.complete()
    assert model.calls[1][1] == [TERMINAL]
    assert current.execute_named("submit_context", {"accepted": True}, "submit")[1]
    assert current.tools.calls == [] and current.outcome.tool_calls == 0


def test_repeated_unknown_tools_share_existing_protocol_recovery_limit():
    model = Model(response(call("first", "invented_reader")),
                  response(call("second", "another_invented_reader")))
    current = policy(model, rounds=4)

    assert current.complete() is None and not current.done
    assert current.complete() is None and current.done
    assert current.outcome.termination == "invalid_output"
    assert current.outcome.model_calls == len(model.calls) == 2
    assert current.outcome.protocol_recoveries == 1
    assert current.outcome.terminal_correction_attempts == 1
    assert [identity for identity, _output in tool_feedback(current)] == ["first", "second"]
    assert current.outcome.tool_calls == 0 and current.tools.calls == []


@pytest.mark.parametrize("rounds,recoveries", [(3, 0), (1, 1)])
def test_unknown_tool_feedback_does_not_grant_unregistered_recovery(rounds, recoveries):
    current = policy(Model(response(call("bad", "invented_reader"))), rounds=rounds,
        protocol_recoveries=recoveries, reserve_terminal_round=False)

    assert current.complete() is None and current.done
    assert current.outcome.termination == "invalid_output"
    assert current.outcome.protocol_recoveries == 0
    assert current.outcome.terminal_correction_operations == []
    assert tool_feedback(current)[0][1]["error"] == "unknown_repository_tool"
    assert current.outcome.model_calls == 1 and current.outcome.tool_calls == 0


@pytest.mark.parametrize("invalid", [
    call("", "invented_reader"),
    call(None, "invented_reader"),
    call("x" * 513, "invented_reader"),
    call("known", "invented_reader"),
    call("bad", "invented_reader", '"' + "x" * 8192 + '"'),
    call("bad", "invented_reader", '{"line":'),
    call("bad", "invented_reader", '{"line":NaN}'),
    call("bad", "invented_reader", '{"line":1,"line":2}'),
    call("bad", "invented_reader", '{"line":1e1000}'),
    call("bad", "x" * 513),
])
def test_invalid_unknown_batch_envelopes_stop_without_execution_or_recovery(invalid):
    tools = Tools()
    current = policy(Model(response(call("known"), invalid)), tools=tools)

    assert current.complete() is None and current.done
    assert tools.calls == [] and current.outcome.tool_calls == 0
    assert current.outcome.protocol_recoveries == 0
    assert current.outcome.terminal_correction_operations == []
    assert any(event.get("error_category") == "tool_call_parse_error"
               for event in current.outcome.events)


def test_unknown_batch_preserves_bootstrap_calls_and_does_not_replay_old_ids():
    current = policy(Model(response(call("bootstrap", "invented_reader"))))
    current.seen_calls.add("bootstrap")

    assert current.complete() is None and current.done
    assert current.outcome.protocol_recoveries == 0
    assert tool_feedback(current) == []
    assert current.outcome.tool_calls == 0 and current.tools.calls == []


def test_bridge_carries_native_unknown_tool_feedback_without_emitting_unknown_sdk_call():
    model = Model(response(call("bad", "invented_reader")), response(call("read")))
    current = policy(model)
    bridge = _Bridge(current, normalize_dsh_profile({}), session_id="offline-session")
    bridge.dispatch({"op": "initialize", "seq": 1})

    packet = bridge.dispatch({"op": "model", "seq": 2,
        "session_id": "offline-session", "purpose": None})
    assert packet["response"] is None and packet["action"] == "continue"
    assert packet["done"] is False
    assert packet["schemas"] == [READ, TERMINAL]
    feedback = bridge.dispatch({"op": "feedback", "seq": 3})
    assert feedback == {"result": {"action": "continue"}, "done": False}
    next_packet = bridge.dispatch({"op": "model", "seq": 4,
        "session_id": "offline-session", "purpose": None})
    assert next_packet["response"]["tool_calls"][0]["name"] == "read_source"
    assert current.outcome.model_calls == len(model.calls) == 2
    assert current.outcome.tool_calls == 0


def test_unknown_tool_recovery_keeps_global_provider_guard_and_token_accounting():
    model = Model(response(call("bad", "invented_reader"),
        usage={"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3}))
    state = MiningState(ContextBudget(max_total_model_calls=1))
    current = policy(BudgetedModel(model, state))

    assert current.complete() is None and not current.done
    assert current.complete() is None and current.done
    assert current.outcome.model_calls == state.model_calls == len(model.calls) == 1
    assert state.tokens == {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3}
    assert state.tool_calls == current.outcome.tool_calls == 0
    assert any(event.get("kind") == "budget_stop" and event["provider_request"] is False
               for event in current.outcome.events)
