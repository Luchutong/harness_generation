"""Offline cleanup regression definitions; never launch DSH or a provider."""
from http.client import HTTPConnection, HTTPException
import json
from pathlib import Path
import socket
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest

from harness_generation.harness_context import dsh_backend
from harness_generation.harness_context.dsh_config import normalize_dsh_profile
from harness_generation.harness_context.dsh_policy import DSHContextPolicy
from harness_generation.harness_context.models import ContextBudget
from harness_generation.semantic_discovery.models import (
    AgentModelResponse, AgentToolCall, ValidationBudget,
)


TERMINAL = {"type": "function", "function": {"name": "submit_context",
    "description": "Submit", "parameters": {"type": "object"}}}


class Tools:
    schemas = []


class Model:
    def __init__(self):
        self.calls = 0
        self.started = None
        self.release = None

    def complete(self, _messages, _tools):
        self.calls += 1
        if self.started is not None:
            self.started.set()
            assert self.release.wait(timeout=3)
        return AgentModelResponse(tool_calls=(AgentToolCall("submit", "submit_context", '{"accepted":true}'),))


def policy(model):
    return DSHContextPolicy(model=model, budget=ValidationBudget(max_rounds=2),
        terminal=TERMINAL, validator=json.loads,
        messages=[{"role": "system", "content": "Investigate"}], tools=Tools())


@pytest.mark.parametrize("error_type", [ValueError, OSError])
def test_dependency_loader_failure_revokes_unpaid_submission_without_leaking_exception_text(monkeypatch, error_type):
    private_diagnostic = "/private/runtime/path Bearer fixture-private-credential"

    def fail():
        raise error_type(private_diagnostic)

    monkeypatch.setattr(dsh_backend, "_load_sdk", fail)
    backend = dsh_backend.DeepSeekHarnessContextBackend(SimpleNamespace(model="offline"), budget=ContextBudget())
    model = Model()
    outcome = backend.run(model=model, budget=ValidationBudget(max_rounds=2), terminal=TERMINAL,
        validator=json.loads, messages=[{"role": "system", "content": "Investigate"}], tools=Tools())
    assert outcome.decision is None and outcome.submission_revoked
    assert outcome.model_calls == model.calls == outcome.tool_calls == 0
    assert outcome.events[-1]["error_category"] == "dsh_dependency_error"
    assert outcome.events[-1]["exception_type"] == error_type.__name__
    assert outcome.events[-1]["detail"] == "pinned DSH dependencies are unavailable"
    archived = json.dumps(outcome.events)
    assert private_diagnostic not in archived and "fixture-private-credential" not in archived


def _wait_for_accepted_connection(server):
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        with server._io_lock:
            if server._connections:
                return
        time.sleep(0.005)
    raise AssertionError("bridge did not accept the fixture connection")


def test_stop_io_unblocks_trickled_headers_without_waiting_for_inactivity_timeout():
    current = policy(Model())
    bridge = dsh_backend._Bridge(current, normalize_dsh_profile({"request_timeout_seconds": 5}),
        session_id="fixture")
    server, thread = dsh_backend._start_server(bridge, "fixture-token")
    connection = socket.create_connection(server.server_address, timeout=1)
    stop_sender = threading.Event()
    shutdown_done = threading.Event()

    def trickle():
        while not stop_sender.wait(0.01):
            try:
                connection.sendall(b"a")
            except OSError:
                return

    sender = threading.Thread(target=trickle, daemon=True)
    closer = None
    try:
        connection.sendall(b"POST /context HTTP/1.0\r\nX-Incomplete: ")
        _wait_for_accepted_connection(server)
        sender.start()
        bridge.stop("dsh_deadline_exceeded")
        server.stop_io()
        closer = threading.Thread(target=lambda: (server.shutdown(), shutdown_done.set()), daemon=True)
        closer.start()
        assert shutdown_done.wait(timeout=1)
        assert current.outcome.model_calls == current.outcome.tool_calls == 0
    finally:
        stop_sender.set()
        connection.close()
        server.stop_io()
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
        if sender.ident is not None:
            sender.join(timeout=1)
        if closer is not None:
            closer.join(timeout=1)
    assert not thread.is_alive()


def test_closing_authorized_partial_body_does_not_replace_the_original_stop_reason():
    current = policy(Model())
    bridge = dsh_backend._Bridge(current, normalize_dsh_profile({"request_timeout_seconds": 5}),
        session_id="fixture")
    server, thread = dsh_backend._start_server(bridge, "fixture-token")
    connection = socket.create_connection(server.server_address, timeout=1)
    try:
        connection.sendall(b"POST /context HTTP/1.0\r\nAuthorization: Bearer fixture-token\r\n"
            b"Content-Length: 100\r\n\r\n{")
        _wait_for_accepted_connection(server)
        bridge.stop("dsh_runtime_error")
        server.stop_io()
        server.shutdown()
        assert bridge.stop_reason == "dsh_runtime_error"
        assert not any(event.get("error_category") == "dsh_bridge_protocol_error"
            for event in current.outcome.events)
    finally:
        connection.close()
        server.stop_io()
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_transport_stop_still_drains_the_paid_provider_before_returning_ledger():
    model = Model()
    model.started, model.release = threading.Event(), threading.Event()
    current = policy(model)
    bridge = dsh_backend._Bridge(current, normalize_dsh_profile({}), session_id="fixture")
    server, thread = dsh_backend._start_server(bridge, "fixture-token")
    bridge.dispatch({"op": "initialize", "seq": 1})
    request_finished = threading.Event()
    shutdown_done = threading.Event()

    def model_request():
        connection = HTTPConnection(*server.server_address, timeout=2)
        try:
            connection.request("POST", "/context", json.dumps({"op": "model", "seq": 2,
                "session_id": "fixture"}), {"Authorization": "Bearer fixture-token"})
            connection.getresponse().read()
        except (OSError, HTTPException):
            pass  # Active transport cancellation is expected.
        finally:
            connection.close()
            request_finished.set()

    requester = threading.Thread(target=model_request, daemon=True)
    closer = None
    try:
        requester.start()
        assert model.started.wait(timeout=1)
        bridge.stop("dsh_runtime_error")
        server.stop_io()
        closer = threading.Thread(target=lambda: (server.shutdown(), shutdown_done.set()), daemon=True)
        closer.start()
        assert request_finished.wait(timeout=1)
        assert not shutdown_done.is_set()
        model.release.set()
        assert shutdown_done.wait(timeout=1)
        assert current.outcome.model_calls == model.calls == 1
        assert current.outcome.tool_calls == 0 and current.outcome.decision is None
        assert current.outcome.events[-1]["error_category"] == "dsh_runtime_error"
    finally:
        model.release.set()
        server.stop_io()
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
        requester.join(timeout=1)
        if closer is not None:
            closer.join(timeout=1)


def test_server_thread_failure_is_archived_without_private_exception_text(monkeypatch):
    def fail(_server):
        raise RuntimeError("private server diagnostic")
    monkeypatch.setattr(dsh_backend.HTTPServer, "service_actions", fail)
    current = policy(Model())
    bridge = dsh_backend._Bridge(current, normalize_dsh_profile({}), session_id="fixture")
    server, thread = dsh_backend._start_server(bridge, "fixture-token")
    try:
        thread.join(timeout=1)
        assert not thread.is_alive()
        assert bridge.stop_reason == "dsh_bridge_server_error"
        assert current.outcome.events[-1]["exception_type"] == "RuntimeError"
        assert "private server diagnostic" not in json.dumps(current.outcome.events)
    finally:
        server.stop_io()
        server.shutdown()
        server.server_close()


def _cleanup_run(monkeypatch, tmp_path, *, failures=(), messages=None, runtime_process=None,
                 late_startup=False):
    seen = []
    selected = set(failures)
    startup_entered = threading.Event()

    def action(name):
        seen.append(name)
        if name in selected:
            raise OSError("private cleanup diagnostic")

    class Directory:
        def __init__(self, **_kwargs):
            action("workspace_create")
            self.name = str(tmp_path / "home")
            Path(self.name).mkdir()
        def cleanup(self):
            action("workspace_cleanup")

    class Server:
        server_address = ("127.0.0.1", 1)
        def stop_io(self):
            action("stop_io")
        def shutdown(self):
            action("server_shutdown")
        def server_close(self):
            action("server_close")

    class Thread:
        def join(self):
            action("bridge_join")

    class Timer:
        def __init__(self, _timeout, callback):
            self.callback = callback
            self.thread = None
        def start(self):
            if late_startup:
                def expire_after_startup():
                    assert startup_entered.wait(timeout=1)
                    self.callback()
                self.thread = threading.Thread(target=expire_after_startup, daemon=True)
                self.thread.start()
        def cancel(self):
            action("timer_cancel")
        def is_alive(self):
            return self.thread.is_alive() if self.thread is not None else True
        def join(self):
            action("timer_join")
            if self.thread is not None:
                self.thread.join()

    bridge_holder = {}
    def start_server(bridge, _token):
        bridge_holder["value"] = bridge
        return Server(), Thread()

    class SDK:
        def __init__(self, **_config):
            self.client = SimpleNamespace(_launch_args=None, _proc=None if late_startup else runtime_process,
                _default_launch_args=lambda _env: ("fixture",))
        def start_session(self, identity):
            if late_startup:
                startup_entered.set()
                assert bridge_holder["value"].stopped.wait(timeout=1)
                self.client._proc = runtime_process
                assert runtime_process.released.wait(timeout=2)
                raise RuntimeError("private stopped startup diagnostic")
            def run(_seed, *, on_notification):
                bridge = bridge_holder["value"]
                bridge.dispatch({"op": "initialize", "seq": 1})
                bridge.dispatch({"op": "model", "seq": 2, "session_id": identity})
                bridge.dispatch({"op": "tool", "seq": 3, "name": "submit_context",
                    "tool_call_id": "submit", "arguments_raw": '{"accepted":true}'})
                return SimpleNamespace(session_id=identity, finish_reason="completed")
            return SimpleNamespace(run=run)
        def close(self):
            action("sdk_close")
            if runtime_process is not None:
                assert runtime_process.released.wait(timeout=2)
                self.client._proc = None

    monkeypatch.setattr(dsh_backend, "_load_sdk", lambda: SDK)
    monkeypatch.setattr(dsh_backend, "_bundled_runtime_executable", lambda: "/fixture/runtime")
    monkeypatch.setattr(dsh_backend, "_start_server", start_server)
    monkeypatch.setattr(dsh_backend.threading, "Timer", Timer)
    monkeypatch.setattr(dsh_backend.tempfile, "TemporaryDirectory", Directory)
    backend = dsh_backend.DeepSeekHarnessContextBackend(SimpleNamespace(model="offline"), budget=ContextBudget())
    model = Model()
    outcome = backend.run(model=model, budget=ValidationBudget(max_rounds=2), terminal=TERMINAL,
        validator=json.loads, messages=messages or [{"role": "system", "content": "Investigate"}], tools=Tools())
    return outcome, seen, model


@pytest.mark.parametrize("failure,category", [("stop_io", "dsh_bridge_transport_close_error"),
    ("sdk_close", "dsh_shutdown_error"), ("server_shutdown", "dsh_bridge_shutdown_error"),
    ("server_close", "dsh_bridge_server_close_error"), ("bridge_join", "dsh_bridge_thread_join_error"),
    ("timer_cancel", "dsh_timer_cancel_error"), ("timer_join", "dsh_timer_join_error"),
    ("workspace_cleanup", "dsh_workspace_cleanup_error")])
def test_each_cleanup_failure_is_returned_and_all_remaining_cleanup_is_attempted(monkeypatch, tmp_path, failure, category):
    outcome, seen, model = _cleanup_run(monkeypatch, tmp_path, failures=[failure])
    assert outcome.decision is None
    assert outcome.model_calls == model.calls == 1
    assert {"stop_io", "sdk_close", "server_shutdown", "server_close", "bridge_join",
        "timer_join", "workspace_cleanup"}.issubset(seen)
    assert any(event.get("error_category") == category and event["exception_type"] == "OSError"
        for event in outcome.events)
    assert "private cleanup diagnostic" not in json.dumps(outcome.events)


def test_multiple_cleanup_failures_are_all_archived_after_the_last_cleanup(monkeypatch, tmp_path):
    outcome, seen, model = _cleanup_run(monkeypatch, tmp_path,
        failures=["sdk_close", "server_shutdown", "workspace_cleanup"])
    categories = {event.get("error_category") for event in outcome.events}
    assert {"dsh_shutdown_error", "dsh_bridge_shutdown_error", "dsh_workspace_cleanup_error"} <= categories
    assert seen[-1] == "workspace_cleanup"
    assert outcome.decision is None and outcome.model_calls == model.calls == 1


def test_supervisor_start_failure_does_not_skip_sdk_close_or_other_cleanup(monkeypatch, tmp_path):
    class FailedSupervisor:
        def __init__(self, _runtime, _report, **_kwargs):
            pass
        def begin_close(self, **_kwargs):
            raise RuntimeError("private monitor diagnostic")
        def finish_close(self):
            pass
        def join(self):
            pass
    monkeypatch.setattr(dsh_backend, "_RuntimeProcessSupervisor", FailedSupervisor)
    outcome, seen, model = _cleanup_run(monkeypatch, tmp_path)
    assert {"sdk_close", "server_shutdown", "server_close", "bridge_join", "workspace_cleanup"}.issubset(seen)
    assert outcome.decision is None and outcome.model_calls == model.calls == 1
    assert any(event.get("error_category") == "dsh_runtime_supervision_error" for event in outcome.events)
    assert "private monitor diagnostic" not in json.dumps(outcome.events)


def test_workspace_creation_failure_returns_an_unpaid_outcome(monkeypatch, tmp_path):
    outcome, seen, model = _cleanup_run(monkeypatch, tmp_path, failures=["workspace_create"])
    assert outcome.decision is None and outcome.model_calls == model.calls == 0
    assert seen == ["workspace_create"]
    assert outcome.events[-1]["error_category"] == "dsh_workspace_error"
    assert "private cleanup diagnostic" not in json.dumps(outcome.events)


def test_seed_serialization_failure_returns_an_unpaid_outcome_without_creating_workspace(monkeypatch, tmp_path):
    outcome, seen, model = _cleanup_run(monkeypatch, tmp_path,
        messages=[{"role": "system", "content": object()}])
    assert outcome.decision is None and outcome.model_calls == model.calls == 0
    assert seen == []
    assert outcome.events[-1]["error_category"] == "dsh_seed_error"


class Process:
    """Popen-shaped fixture with no operating-system process."""
    def __init__(self, *, ignore_terminate=False, unreapable=False):
        self.released = threading.Event()
        self.ignore_terminate = ignore_terminate
        self.unreapable = unreapable
        self.operations = []

    def poll(self):
        return 0 if self.released.is_set() else None

    def terminate(self):
        self.operations.append("terminate")
        if not self.ignore_terminate and not self.unreapable:
            self.released.set()

    def kill(self):
        self.operations.append("kill")
        if not self.unreapable:
            self.released.set()

    def wait(self, *, timeout):
        self.operations.append(("wait", timeout))
        if self.unreapable or not self.released.wait(timeout):
            raise subprocess.TimeoutExpired("private process description", timeout)
        return 0


def test_forced_supervision_observes_a_process_assigned_after_the_deadline(monkeypatch):
    monkeypatch.setattr(dsh_backend, "SDK_PROCESS_POLL_SECONDS", 0.005)
    missing_observed = threading.Event()

    class Client:
        value = None
        @property
        def _proc(self):
            if self.value is None:
                missing_observed.set()
            return self.value

    client = Client()
    failures = []
    events = []
    supervisor = dsh_backend._RuntimeProcessSupervisor(SimpleNamespace(client=client),
        lambda reason, error: failures.append((reason, type(error).__name__)), report_event=events.append)
    missing_observed.clear()
    process = Process()
    try:
        supervisor.begin_close(force=True)
        assert missing_observed.wait(timeout=1)
        client.value = process
        assert process.released.wait(timeout=1)
    finally:
        supervisor.finish_close()
        supervisor.join()
    assert "terminate" in process.operations and failures == []
    assert any(event["trigger"] == "deadline" and event["operation"] == "terminate"
        for event in events)


def test_normal_close_supervision_releases_an_sdk_write_lock_after_short_grace(monkeypatch):
    monkeypatch.setattr(dsh_backend, "SDK_CLOSE_GRACE_SECONDS", 0.01)
    monkeypatch.setattr(dsh_backend, "SDK_PROCESS_POLL_SECONDS", 0.005)
    process = Process()
    runtime = SimpleNamespace(client=SimpleNamespace(_proc=process))
    failures = []
    events = []
    supervisor = dsh_backend._RuntimeProcessSupervisor(runtime,
        lambda reason, error: failures.append((reason, type(error).__name__)), report_event=events.append)
    write_lock = threading.Lock()
    writer_started, closed = threading.Event(), threading.Event()

    def stalled_writer():
        with write_lock:
            writer_started.set()
            assert process.released.wait(timeout=2)

    def blocked_close():
        supervisor.begin_close()
        try:
            with write_lock:
                closed.set()
        finally:
            supervisor.finish_close()

    writer = threading.Thread(target=stalled_writer, daemon=True)
    closer = threading.Thread(target=blocked_close, daemon=True)
    try:
        writer.start()
        assert writer_started.wait(timeout=1)
        closer.start()
        assert closed.wait(timeout=1)
        assert "terminate" in process.operations
    finally:
        process.released.set()
        supervisor.finish_close()
        supervisor.join()
        writer.join(timeout=1)
        if closer.ident is not None:
            closer.join(timeout=1)
    assert failures == [] and not writer.is_alive() and not closer.is_alive()
    assert any(event["trigger"] == "close_grace" and event["operation"] == "terminate"
        for event in events)


def test_supervision_escalates_terminate_to_kill_with_finite_reap_waits(monkeypatch):
    monkeypatch.setattr(dsh_backend, "SDK_TERMINATE_GRACE_SECONDS", 0.01)
    process = Process(ignore_terminate=True)
    failures = []
    events = []
    supervisor = dsh_backend._RuntimeProcessSupervisor(SimpleNamespace(client=SimpleNamespace(_proc=process)),
        lambda reason, error: failures.append((reason, type(error).__name__)), report_event=events.append)
    supervisor.finish_close()
    supervisor.begin_close(force=True)
    supervisor.join()
    assert "terminate" in process.operations and "kill" in process.operations
    assert all(0 < operation[1] <= dsh_backend.SDK_REAP_TIMEOUT_SECONDS
        for operation in process.operations if isinstance(operation, tuple))
    assert failures == []
    assert [(event["operation"], event["status"]) for event in events] == [
        ("terminate", "requested"), ("terminate", "sent"),
        ("kill", "requested"), ("kill", "sent"), ("reap", "succeeded")]


def test_unreapable_process_is_retained_until_os_exit_even_if_sdk_clears_its_reference(monkeypatch):
    monkeypatch.setattr(dsh_backend, "SDK_PROCESS_POLL_SECONDS", 0.005)
    process = Process(unreapable=True)
    failures = []
    events = []
    reap_failed, joined = threading.Event(), threading.Event()
    client = SimpleNamespace(_proc=process)

    def report_failure(reason, error):
        failures.append((reason, type(error).__name__))
        reap_failed.set()

    supervisor = dsh_backend._RuntimeProcessSupervisor(SimpleNamespace(client=client),
        report_failure, report_event=events.append)
    joiner = threading.Thread(target=lambda: (supervisor.join(), joined.set()), daemon=True)
    try:
        supervisor.finish_close()
        supervisor.begin_close(force=True)
        joiner.start()
        assert reap_failed.wait(timeout=1)
        client._proc = None
        assert not joined.wait(timeout=0.05)
        process.unreapable = False
        process.released.set()
        assert joined.wait(timeout=1)
    finally:
        process.unreapable = False
        process.released.set()
        supervisor.finish_close()
        supervisor.join()
        if joiner.ident is not None:
            joiner.join(timeout=1)
    assert failures == [("dsh_runtime_reap_error", "TimeoutExpired")]
    assert "private process description" not in json.dumps(failures + events)
    assert process.operations.count("terminate") == process.operations.count("kill") == 1
    assert events[-1]["operation"] == "reap" and events[-1]["status"] == "succeeded"


def test_completed_but_incomplete_sdk_close_is_diagnosed_and_live_process_is_reaped():
    process = Process()
    events, failures = [], []
    supervisor = dsh_backend._RuntimeProcessSupervisor(SimpleNamespace(client=SimpleNamespace(_proc=process)),
        lambda reason, error: failures.append((reason, type(error).__name__)), report_event=events.append)
    supervisor.finish_close()
    supervisor.begin_close()
    supervisor.join()
    assert failures == [] and process.released.is_set()
    assert events[0]["trigger"] == "incomplete_close"
    assert events[-1]["operation"] == "reap" and events[-1]["status"] == "succeeded"


def test_successful_normal_close_preemption_is_archived_without_revoking_submission(monkeypatch, tmp_path):
    monkeypatch.setattr(dsh_backend, "SDK_CLOSE_GRACE_SECONDS", 0.01)
    monkeypatch.setattr(dsh_backend, "SDK_PROCESS_POLL_SECONDS", 0.005)
    outcome, seen, model = _cleanup_run(monkeypatch, tmp_path, runtime_process=Process())
    events = [event for event in outcome.events if event.get("kind") == "dsh_runtime_supervision"]
    assert outcome.decision == {"accepted": True} and not outcome.submission_revoked
    assert outcome.model_calls == model.calls == 1 and outcome.tool_calls == 0
    assert any(event["trigger"] == "close_grace" and event["operation"] == "terminate"
        for event in events)
    assert events[-1]["operation"] == "reap" and events[-1]["status"] == "succeeded"
    assert all(event["provider_request"] is False and event["model_call"] is False
        and event["tool_executed"] is False for event in events)
    assert seen[-1] == "workspace_cleanup"


def test_failed_sdk_close_reaps_a_live_child_and_revokes_the_accepted_submission(monkeypatch, tmp_path):
    process = Process()
    outcome, seen, model = _cleanup_run(monkeypatch, tmp_path,
        failures=["sdk_close"], runtime_process=process)
    assert process.released.is_set() and "terminate" in process.operations
    assert outcome.decision is None and outcome.submission_revoked
    assert outcome.model_calls == model.calls == 1
    assert any(event.get("kind") == "dsh_runtime_supervision"
        and event["trigger"] == "incomplete_close" for event in outcome.events)
    assert any(event.get("error_category") == "dsh_shutdown_error" for event in outcome.events)
    assert seen[-1] == "workspace_cleanup"


def test_startup_deadline_preempts_a_late_process_without_waiting_for_the_close_lock(monkeypatch, tmp_path):
    monkeypatch.setattr(dsh_backend, "SDK_PROCESS_POLL_SECONDS", 0.005)
    process = Process()
    outcome, seen, model = _cleanup_run(monkeypatch, tmp_path,
        runtime_process=process, late_startup=True)
    assert outcome.decision is None and outcome.submission_revoked
    assert outcome.model_calls == model.calls == 0 and process.released.is_set()
    assert any(event.get("error_category") == "dsh_deadline_exceeded" for event in outcome.events)
    assert any(event.get("kind") == "dsh_runtime_supervision"
        and event["trigger"] == "deadline" and event["operation"] == "terminate"
        for event in outcome.events)
    assert "private stopped startup diagnostic" not in json.dumps(outcome.events)
    assert {"sdk_close", "server_shutdown", "bridge_join", "workspace_cleanup"}.issubset(seen)
