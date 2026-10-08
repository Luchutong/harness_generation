"""Regression definitions for the bridge; these do not require the optional SDK."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from harness_generation.harness_context.agent import BudgetedModel
from harness_generation.harness_context.dsh_backend import (
    ASSETS, DeepSeekHarnessContextBackend, _Bridge, _check_dependency_versions,
    _isolate_sdk_environment, _runtime_environment, _start_server, _usage, _write_runtime_profile,
)
from harness_generation.harness_context.dsh_config import normalize_dsh_profile
from harness_generation.harness_context.dsh_policy import DSHContextPolicy
from harness_generation.harness_context.models import ContextBudget, MiningState
from harness_generation.semantic_discovery.models import (
    AgentModelError, AgentModelResponse, AgentToolCall, DecisionSchemaError, ValidationBudget,
)


TERMINAL = {"type": "function", "function": {"name": "submit_context",
    "description": "Submit an explicit decision", "parameters": {"type": "object"}}}
READ = {"type": "function", "function": {"name": "read_source",
    "description": "Read authorized source", "parameters": {"type": "object"}}}


class Model:
    provider = model = "offline"

    def __init__(self, *steps):
        self.steps, self.calls = list(steps), []

    def complete(self, messages, tools):
        self.calls.append((deepcopy(messages), deepcopy(tools)))
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        return step


class Tools:
    schemas = [READ]

    def __init__(self):
        self.calls = []

    def execute(self, name, arguments):
        self.calls.append((name, arguments))
        return {"evidence_ids": ["issued-read"], "value": arguments}


def response(*calls, **metadata):
    return AgentModelResponse(tool_calls=tuple(calls), metadata=metadata)


def call(identity, name="submit_context", arguments='{"accepted":true}'):
    return AgentToolCall(identity, name, arguments)


def policy(model, *, tools=None, rounds=3, validator=json.loads, **options):
    return DSHContextPolicy(model=model, budget=ValidationBudget(max_rounds=rounds, max_tool_calls=4),
        terminal=TERMINAL, validator=validator, messages=[{"role": "system", "content": "Exact {{text}}"},
            {"role": "user", "content": "Investigate"}], tools=tools or Tools(),
        reserve_terminal_round=True, max_protocol_recoveries=1, max_semantic_recoveries=1,
        max_provider_recoveries=1, **options)


def test_policy_executes_exact_calls_and_reuses_bootstrap_history_without_nested_loop(monkeypatch):
    from harness_generation.semantic_discovery.loop import BoundedAgentLoop
    monkeypatch.setattr(BoundedAgentLoop, "run", lambda *_a, **_k: pytest.fail("nested native loop"))
    model = Model(response(call("read-1", "read_source", '{"line":4}')), response(call("submit-1")))
    tools = Tools()
    current = policy(model, tools=tools, rounds=2, initial_tool_calls=2,
        initial_events=[{"kind": "tool_call", "tool_call_id": "bootstrap"}])
    current.outcome.messages.extend([{"role": "assistant", "content": None,
        "tool_calls": [call("bootstrap", "read_source", '{}').to_dict()]},
        {"role": "tool", "tool_call_id": "bootstrap", "content": '{"evidence_ids":["seed"]}'}])
    assert current.prepare() == current.prepare()
    assert current.outcome.rounds == 0
    assert current.complete().tool_calls[0].id == "read-1"
    output, done = current.execute_named("read_source", {"line": 4}, "read-1")
    assert output["evidence_ids"] == ["issued-read"] and not done
    assert current.complete().tool_calls[0].id == "submit-1"
    assert model.calls[1][1] == [TERMINAL]
    assert current.execute_named("submit_context", {"accepted": True}, "submit-1")[1]
    assert current.outcome.decision == {"accepted": True}
    assert current.outcome.model_calls == 2 and current.outcome.tool_calls == 3
    assert tools.calls == [("read_source", {"line": 4})]


def test_mixed_terminal_batch_is_rejected_before_any_tool_or_validator_executes():
    tools = Tools()
    model = Model(response(call("submit-1"), call("read-1", "read_source", '{}')))
    current = policy(model, tools=tools, validator=lambda _v: pytest.fail("mixed terminal accepted"))
    assert current.complete() is None
    assert current.done and current.outcome.decision is None
    assert tools.calls == [] and current.outcome.tool_calls == 0


def test_malformed_terminal_receives_original_json_feedback_and_new_budgeted_submission():
    model = Model(response(call("broken", arguments='{"accepted":')), response(call("corrected")))
    current = policy(model, rounds=2)
    assert current.complete() is None and current.action == "continue"
    assert current.outcome.protocol_recoveries == 1
    assert any(event.get("error_category") == "terminal_json_parse_error" for event in current.outcome.events)
    current.complete()
    assert model.calls[1][1] == [TERMINAL]
    current.execute_named("submit_context", {"accepted": True}, "corrected")
    assert current.outcome.decision == {"accepted": True}
    assert current.outcome.model_calls == 2 and current.outcome.terminal_submission_attempts == 2


def test_semantic_rejection_never_carries_invalid_decision_into_next_submission():
    def validate(raw):
        value = json.loads(raw)
        if not value.get("accepted"):
            raise ValueError("missing proof")
        return value
    model = Model(response(call("invalid", arguments='{"accepted":false}')), response(call("corrected")))
    current = policy(model, validator=validate)
    current.complete()
    assert not current.execute_named("submit_context", {"accepted": False}, "invalid")[1]
    assert current.outcome.decision is None and current.outcome.semantic_recoveries == 1
    current.complete()
    current.execute_named("submit_context", {"accepted": True}, "corrected")
    assert current.outcome.decision == {"accepted": True}


def test_schema_extra_request_remains_inside_global_model_guard():
    raw = Model(response(call("shape-error", arguments='{}')))
    state = MiningState(ContextBudget(max_total_model_calls=1))
    guarded = BudgetedModel(raw, state, max_model_calls=2)
    def reject(_raw):
        raise DecisionSchemaError("accepted", None, [True, False])
    current = policy(guarded, validator=reject, max_terminal_repairs=1)
    current.complete()
    assert not current.execute_named("submit_context", {}, "shape-error")[1]
    assert current.outcome.extra_terminal_repair_attempts == 1
    assert current.complete() is None and current.done
    assert len(raw.calls) == state.model_calls == current.outcome.model_calls == 1
    assert any(event.get("kind") == "budget_stop" and event["provider_request"] is False
        for event in current.outcome.events)


def test_truncated_tool_batch_never_issues_evidence_and_uses_terminal_only_recovery():
    tools = Tools()
    model = Model(response(call("partial", "read_source", '{}'), finish_reason="length"),
        response(call("corrected")))
    current = policy(model, tools=tools)
    assert current.complete() is None and current.action == "continue"
    assert tools.calls == [] and current.outcome.tool_calls == 0
    current.complete()
    assert model.calls[1][1] == [TERMINAL]


def test_provider_recovery_uses_one_existing_round_without_silent_sdk_retry():
    error = AgentModelError("provider timeout")
    error.error_category = "timeout"
    model = Model(error, response(call("submit")))
    current = policy(model)
    assert current.complete() is None and current.action == "continue"
    assert current.outcome.provider_recoveries == 1 and current.outcome.model_calls == 1
    current.complete()
    current.execute_named("submit_context", {"accepted": True}, "submit")
    assert current.outcome.model_calls == 2 and len(model.calls) == 2


def test_call_identity_mismatch_and_replay_cannot_repeat_source_execution():
    tools = Tools()
    current = policy(Model(response(call("read-1", "read_source", '{}'))), tools=tools)
    current.complete()
    assert current.execute_named("read_source", {}, "foreign")[1]
    assert tools.calls == []
    second = policy(Model(response(call("read-2", "read_source", '{}'))), tools=tools)
    second.complete()
    assert not second.execute_named("read_source", {}, "read-2")[1]
    assert second.execute_named("read_source", {}, "read-2")[1]
    assert tools.calls == [("read_source", {})]


def test_bridge_rejected_paid_response_preserves_usage_and_internal_feedback_is_free():
    model = Model(AgentModelResponse(content="unsubmitted prose", metadata={"finish_reason": "stop",
        "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}}))
    current = policy(model)
    bridge = _Bridge(current, normalize_dsh_profile({}), session_id="session")
    bridge.dispatch({"op": "initialize", "seq": 1})
    packet = bridge.dispatch({"op": "model", "seq": 2, "session_id": "session", "purpose": None})
    assert packet["response"] is None and packet["action"] == "continue"
    assert packet["usage"] == {"inputTokens": 10, "outputTokens": 2, "totalTokens": 12}
    feedback = bridge.dispatch({"op": "feedback", "seq": 3})
    assert feedback["done"] is False
    assert current.outcome.model_calls == 1 and current.outcome.tool_calls == 0
    with pytest.raises(ValueError, match="sequence"):
        bridge.dispatch({"op": "model", "seq": 3, "session_id": "session"})
    assert len(model.calls) == 1


def test_bridge_prompt_and_auxiliary_limits_precede_actual_provider_request():
    model = Model()
    current = policy(model)
    bridge = _Bridge(current, normalize_dsh_profile({"max_prompt_chars": 1}), session_id="session")
    bridge.dispatch({"op": "initialize", "seq": 1})
    packet = bridge.dispatch({"op": "model", "seq": 2, "session_id": "session"})
    assert packet["done"] and model.calls == [] and packet["usage"] is None
    other = policy(Model())
    bridge = _Bridge(other, normalize_dsh_profile({}), session_id="session")
    bridge.dispatch({"op": "initialize", "seq": 1})
    assert bridge.dispatch({"op": "model", "seq": 2, "session_id": "session", "purpose": "session-title"})["done"]
    assert other.outcome.model_calls == 0


def test_response_cap_records_the_paid_request_without_executing_its_tools():
    current = policy(Model(response(call("read", "read_source", '{}'))))
    bridge = _Bridge(current, normalize_dsh_profile({"max_response_chars": 1}), session_id="session")
    bridge.dispatch({"op": "initialize", "seq": 1})
    packet = bridge.dispatch({"op": "model", "seq": 2, "session_id": "session"})
    assert packet["done"] and packet["response"] is None
    assert current.outcome.model_calls == 1 and current.outcome.tool_calls == 0


def test_runtime_abort_discards_a_decision_but_keeps_the_paid_ledger():
    current = policy(Model(response(call("submit"))))
    current.complete()
    current.execute_named("submit_context", {"accepted": True}, "submit")
    current.abort("dsh_runtime_error")
    assert current.outcome.decision is None and current.outcome.model_calls == 1
    assert current.outcome.events[-1]["provider_request"] is False


def test_private_profile_is_complete_restricted_and_copies_plugin_into_module_fallback_tree(tmp_path):
    _write_runtime_profile(tmp_path, endpoint="http://127.0.0.1:1/context", token="fixture-token",
        profile=normalize_dsh_profile({}))
    directory = tmp_path / "profiles" / "harness-context"
    manifest = json.loads((directory / "package.json").read_text())
    assert manifest["dsh"]["profile"] == {"bundles": [], "patchReload": "startup"}
    entries = json.loads((directory / "cordis.patch.yml").read_text())[0]["insert"]
    names = {entry["name"] for entry in entries}
    assert "@deepseek-ai/dsh-agent-loop" in names
    assert "@deepseek-ai/dsh-sdk-jsonrpc-server" in names
    assert not any(marker in name for name in names for marker in ("bash", "retry", "subagent", "title", "compaction"))
    assert entries[-1]["name"] == str(directory / "bridge.mjs")
    assert (directory / "cordis.patch.yml").stat().st_mode & 0o777 == 0o600


def test_descriptor_copies_budget_profile_and_all_runtime_assets_without_loading_sdk():
    backend = DeepSeekHarnessContextBackend(SimpleNamespace(model="offline"), budget=ContextBudget())
    value = backend.descriptor()
    assert set(value["assets_sha256"]) == set(ASSETS)
    assert value["sdk_version"] == value["runtime_version"] == "0.1.5rc1"
    value["budget"]["max_tool_calls"] = 1
    assert backend.descriptor()["budget"]["max_tool_calls"] == 64


def test_dependency_metadata_mismatch_and_missing_package_are_clear_without_runtime_import(monkeypatch):
    from harness_generation.harness_context import dsh_backend
    monkeypatch.setattr(dsh_backend.metadata, "version", lambda _p: "0.2.1a1")
    with pytest.raises(ValueError, match="pinned"):
        _check_dependency_versions()
    def missing(_name):
        raise dsh_backend.metadata.PackageNotFoundError()
    monkeypatch.setattr(dsh_backend.metadata, "version", missing)
    with pytest.raises(ValueError, match="missing"):
        _check_dependency_versions()


def test_usage_is_not_invented_and_cached_prompt_tokens_are_disjoint():
    assert _usage({}) is None
    assert _usage({"usage": {"prompt_tokens": 10}}) is None
    assert _usage({"usage": {"prompt_tokens": True, "completion_tokens": 2}}) is None
    assert _usage({"usage": {"prompt_tokens": 10, "completion_tokens": 2,
        "prompt_tokens_details": {"cached_tokens": 4}}}) == {
            "inputTokens": 6, "cacheReadTokens": 4, "outputTokens": 2}


def test_sdk_environment_never_forwards_inherited_provider_credentials(monkeypatch):
    monkeypatch.setenv("DEEPSEEK_API_KEY", "never-forward")
    monkeypatch.setenv("LLM_API_KEY", "never-forward")
    monkeypatch.setenv("NODE_OPTIONS", "--import=outside-profile")
    monkeypatch.setenv("DSH_SYSTEM_PROMPT", "outside-prompt")
    value = _runtime_environment()
    assert not {"DEEPSEEK_API_KEY", "LLM_API_KEY", "NODE_OPTIONS", "DSH_SYSTEM_PROMPT"} & set(value)


def test_sdk_launch_removes_existence_selectors_and_unknown_credentials_without_changing_parent(monkeypatch):
    monkeypatch.setenv("DSH_SUBPROCESS_RUNNER", "")
    monkeypatch.setenv("VOLC_ACCESSKEY", "never-forward")
    monkeypatch.setenv("DEEPSEEK_KEY", "never-forward")
    import os
    parent = dict(os.environ)
    observed = {}
    def original(environment):
        observed.update(environment)
        environment["DSH_HOME"] = "/private/explicit-home"
        return ("bundled-runtime", "--profile", "harness-context")
    runtime = SimpleNamespace(client=SimpleNamespace(_launch_args=None, _default_launch_args=original))
    _isolate_sdk_environment(runtime)
    fresh_child = dict(parent)
    result = runtime.client._default_launch_args(fresh_child)
    assert "DSH_SUBPROCESS_RUNNER" not in observed
    assert "VOLC_ACCESSKEY" not in observed and "DEEPSEEK_KEY" not in observed
    assert fresh_child["DSH_HOME"] == "/private/explicit-home" and result[0] == "bundled-runtime"
    assert dict(os.environ) == parent


def test_sdk_launch_rejects_an_unreviewed_launch_override():
    runtime = SimpleNamespace(client=SimpleNamespace(_launch_args=("outside-runtime",),
        _default_launch_args=lambda _env: ("ignored",)))
    with pytest.raises(ValueError, match="isolation contract"):
        _isolate_sdk_environment(runtime)


def _offline_sdk_run(monkeypatch, *, finish="completed", fail=False, deadline=False,
                     shutdown_fail=False, expire_before_start=False, expire_on_cancel=False):
    """Run a fake SDK driver without starting Node, a server or a provider."""
    from harness_generation.harness_context import dsh_backend
    captured = {}
    class Server:
        server_address = ("127.0.0.1", 1)
        def stop_io(self):
            captured["bridge_io_stopped"] = True
        def shutdown(self):
            captured["server_drained"] = True
        def server_close(self):
            captured["server_closed"] = True
    class Thread:
        def join(self):
            captured["bridge_joined"] = True
    class Timer:
        def __init__(self, _seconds, callback):
            self.callback = callback
            captured["timer"] = self
        def start(self):
            if expire_before_start:
                self.callback()
        def cancel(self):
            captured["timer_cancelled"] = True
            if expire_on_cancel:
                self.callback()
        def is_alive(self):
            return False
    def server(bridge, _token):
        captured["bridge"] = bridge
        return Server(), Thread()
    class SDK:
        def __init__(self, **config):
            captured["config"] = config
            self.config = config
            self.client = SimpleNamespace(_launch_args=None, _proc=None, _default_launch_args=lambda _env: ("fixture",))
        def start_session(self, session_id):
            captured["session_started"] = True
            return SimpleNamespace(run=lambda seed, on_notification:
                self.run(seed, session_id=session_id, on_notification=on_notification))
        def run(self, seed, *, session_id, on_notification):
            captured["seed"] = json.loads(seed)
            if fail:
                raise RuntimeError("sensitive-runtime-text")
            bridge = captured["bridge"]
            bridge.dispatch({"seq": 1, "op": "initialize"})
            bridge.dispatch({"seq": 2, "op": "surface"})
            packet = bridge.dispatch({"seq": 3, "op": "model", "session_id": session_id})
            assert packet["response"]["tool_calls"][0]["id"] == "submit"
            if deadline:
                captured["timer"].callback()
            else:
                bridge.dispatch({"seq": 4, "op": "tool", "name": "submit_context",
                    "tool_call_id": "submit", "arguments": {"accepted": True},
                    "arguments_raw": '{"accepted":true}'})
            from pathlib import Path
            entries = json.loads((Path(self.config["dsh_home"]) / "profiles" / "harness-context"
                / "cordis.patch.yml").read_text())[0]["insert"]
            token = entries[-1]["config"]["token"]
            captured["private_token"] = token
            on_notification(SimpleNamespace(method="session.event", payload={"sessionId": session_id,
                "event": {"type": "fixture", "data": {"token": token}}}))
            return SimpleNamespace(session_id=session_id, finish_reason=finish)
        def close(self):
            captured["sdk_closed"] = True
            if shutdown_fail:
                raise RuntimeError("sensitive-runtime-text")
    monkeypatch.setattr(dsh_backend, "_load_sdk", lambda: SDK)
    monkeypatch.setattr(dsh_backend, "_bundled_runtime_executable", lambda: "/fixture/bundled-exe")
    monkeypatch.setattr(dsh_backend, "_start_server", server)
    monkeypatch.setattr(dsh_backend.threading, "Timer", Timer)
    backend = DeepSeekHarnessContextBackend(SimpleNamespace(model="offline"), budget=ContextBudget())
    model = Model(response(call("submit"), usage={"prompt_tokens": 10, "completion_tokens": 2}))
    outcome = backend.run(model=model, budget=ValidationBudget(max_rounds=2), terminal=TERMINAL,
        validator=json.loads, messages=[{"role": "system", "content": "Exact {{text}}"}], tools=Tools(),
        initial_tool_calls=2, initial_events=[{"kind": "tool_call", "tool_call_id": "bootstrap"}])
    return outcome, captured, model


def test_backend_fake_sdk_uses_canonical_projection_redacts_events_and_closes_resources(monkeypatch):
    outcome, captured, model = _offline_sdk_run(monkeypatch)
    assert outcome.decision == {"accepted": True} and outcome.model_calls == len(model.calls) == 1
    assert outcome.tool_calls == 2
    assert captured["seed"]["messages"] == [{"role": "system", "content": "Exact {{text}}"}]
    assert "api_key" not in captured["config"] and "base_url" not in captured["config"]
    assert captured["config"]["dsh_bin"] == "/fixture/bundled-exe"
    assert captured["private_token"] not in json.dumps(outcome.events)
    assert captured["sdk_closed"] and captured["server_drained"] and captured["server_closed"]
    assert captured["timer_cancelled"] and captured["bridge_joined"]


@pytest.mark.parametrize("options,category", [({"fail": True}, "dsh_runtime_error"),
    ({"finish": "error"}, "dsh_turn_failed"), ({"deadline": True}, "dsh_deadline_exceeded"),
    ({"shutdown_fail": True}, "dsh_shutdown_error"),
    ({"expire_before_start": True}, "dsh_deadline_exceeded")])
def test_backend_fake_sdk_failures_discard_decision_preserve_cost_and_reap_resources(monkeypatch, options, category):
    outcome, captured, model = _offline_sdk_run(monkeypatch, **options)
    assert outcome.decision is None
    assert outcome.model_calls == len(model.calls) == (0 if options.get("fail") or options.get("expire_before_start") else 1)
    assert outcome.tool_calls == 2
    assert any(event.get("error_category") == category and event["provider_request"] is False
        for event in outcome.events)
    assert "sensitive-runtime-text" not in json.dumps(outcome.events)
    assert captured["sdk_closed"] and captured["server_drained"] and captured["bridge_joined"]
    if options.get("expire_before_start"):
        assert "session_started" not in captured


def test_watchdog_callback_after_run_completion_cannot_reclassify_valid_submission(monkeypatch):
    outcome, captured, model = _offline_sdk_run(monkeypatch, expire_on_cancel=True)
    assert outcome.decision == {"accepted": True}
    assert outcome.model_calls == len(model.calls) == 1
    assert not any(event.get("error_category") == "dsh_deadline_exceeded" for event in outcome.events)
    assert captured["sdk_closed"] and captured["server_drained"] and captured["bridge_joined"]


def test_paid_response_stopped_by_runtime_failure_is_not_reported_as_deadline():
    model = Model(response(call("submit")))
    current = policy(model)
    bridge = _Bridge(current, normalize_dsh_profile({}), session_id="session")
    complete = model.complete
    def stop_while_request_is_in_flight(messages, tools):
        bridge.stop("dsh_runtime_error")
        return complete(messages, tools)
    model.complete = stop_while_request_is_in_flight
    bridge.dispatch({"op": "initialize", "seq": 1})
    packet = bridge.dispatch({"op": "model", "seq": 2, "session_id": "session"})
    assert packet["done"] and packet["response"] is None
    assert current.outcome.model_calls == len(model.calls) == 1
    assert current.outcome.tool_calls == 0 and current.outcome.decision is None
    assert current.outcome.events[-1]["error_category"] == "dsh_runtime_error"
    bridge.stop("dsh_deadline_exceeded")
    assert bridge.stop_reason == "dsh_runtime_error"


def test_bridge_server_bounds_incomplete_request_headers_before_shutdown():
    import socket
    current = policy(Model())
    bridge = _Bridge(current, normalize_dsh_profile({"request_timeout_seconds": 0.05}),
        session_id="session")
    server, thread = _start_server(bridge, "fixture-token")
    connection = socket.create_connection(server.server_address, timeout=1)
    try:
        connection.sendall(b"POST /context HTTP/1.0\r\nX-Incomplete: ")
        # The handler must close the incomplete request at its socket deadline.
        # This would time out here if only do_POST applied a socket deadline.
        assert connection.recv(1) == b""
        assert current.outcome.model_calls == current.outcome.tool_calls == 0
    finally:
        connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
    assert not thread.is_alive()


def test_bridge_preserves_original_large_integer_and_float_types_in_terminal_payload():
    raw = '{"integer":9007199254740993,"floating":1.0}'
    current = policy(Model(response(call("submit", arguments=raw))))
    bridge = _Bridge(current, normalize_dsh_profile({}), session_id="session")
    bridge.dispatch({"op": "initialize", "seq": 1})
    bridge.dispatch({"op": "model", "seq": 2, "session_id": "session"})
    result = bridge.dispatch({"op": "tool", "seq": 3, "name": "submit_context",
        "tool_call_id": "submit", "arguments_raw": raw,
        "arguments": {"integer": 9007199254740992, "floating": 1}})
    assert result["done"] and current.outcome.decision["integer"] == 9007199254740993
    assert type(current.outcome.decision["floating"]) is float
