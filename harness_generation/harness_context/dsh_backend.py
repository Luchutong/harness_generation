"""Optional official DSH executor for the existing bounded Context policy.

The Node runtime drives the loop; the Python bridge owns the model history,
actual provider requests, signed repository tools and terminal validation.
Importing this module never imports or starts the optional SDK.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import metadata
import json
import math
import os
import errno
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid

from .dsh_config import (BACKEND_NAME, BRIDGE_POLICY_VERSION, PROFILE_VERSION,
    load_dsh_profile, normalize_dsh_profile, profile_sha256)
from .dsh_policy import DSHContextPolicy, VERSION as BOUNDED_POLICY_VERSION


SDK_VERSION = "0.1.5rc1"
UPSTREAM_COMMIT = "183f08e9c6dde7e36cd2318eaee70b0da08fb35e"
PROVIDER_ROUTE = "harness-generation"
RUNTIME_PROFILE = "harness-context"
HISTORY_PROJECTION = "python-authoritative-context-history-v1"
ASSETS = ("dsh_backend.py", "dsh_policy.py", "dsh_config.py", "dsh_dependencies.py", "dsh_bridge.mjs", "dsh_kernel.json")
NATIVE_POLICY_FILES = ("agent.py", "prompt_projection.py", "terminal.py", "tools.py",
    "loop.py", "models.py", "persistence.py", "../semantic_discovery/loop.py")
SDK_CLOSE_GRACE_SECONDS = 2.0
SDK_TERMINATE_GRACE_SECONDS = 0.25
SDK_REAP_TIMEOUT_SECONDS = 1.0
SDK_PROCESS_POLL_SECONDS = 0.02
CHILD_ENVIRONMENT_NAMES = frozenset({"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL",
    "LC_CTYPE", "TZ", "TMPDIR", "TMP", "TEMP", "SystemRoot", "SYSTEMROOT", "WINDIR",
    "COMSPEC", "PATHEXT", "USERPROFILE"})


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _check_dependency_versions():
    """Read package metadata without importing or launching the SDK."""
    for package in ("deepseek-harness-sdk", "deepseek-harness-runtime-bin"):
        try:
            installed = metadata.version(package)
        except metadata.PackageNotFoundError:
            raise ValueError("DSH dependencies are missing; install harness-generation[dsh]") from None
        if installed != SDK_VERSION:
            raise ValueError("DSH SDK and runtime must both match the pinned 0.1.5rc1 release")


def _load_sdk():
    """Import the published SDK only when a real investigation is needed."""
    _check_dependency_versions()
    try:
        from deepseek_harness import DeepSeekHarness
    except ImportError:
        raise ValueError("cannot import the pinned DeepSeek Harness SDK") from None
    return DeepSeekHarness


def _bundled_runtime_executable():
    # Explicit production carrier also avoids the resolver reading a parent's
    # DSH_RUNTIME_MODE before the sanitized child environment is constructed.
    from deepseek_harness_runtime import bundled_runtime_path
    return str(bundled_runtime_path())


def _runtime_environment(inherited=None):
    """Return only OS launch settings; omit credentials and runtime selectors."""
    source = os.environ if inherited is None else inherited
    return {key: value for key, value in source.items() if key in CHILD_ENVIRONMENT_NAMES}


def _isolate_sdk_environment(runtime):
    """Apply the 0.1.5rc1 launch contract to a fresh child environment only.

    SDK env= overrides merge into os.environ, so {} or empty string overrides
    cannot remove existence-based selectors such as DSH_SUBPROCESS_RUNNER.
    The pinned client invokes this hook on its local dict before Popen. Its
    original hook then adds the explicit DSH_HOME and resolves its bundled bin.
    This version-specific adapter never changes os.environ or installed code.
    """
    client = runtime.client
    original = getattr(client, "_default_launch_args", None)
    if not callable(original) or getattr(client, "_launch_args", None) is not None:
        raise ValueError("DSH client does not match the pinned environment isolation contract")
    def isolated_launch_args(environment):
        clean = _runtime_environment(environment)
        environment.clear()
        environment.update(clean)
        return original(environment)
    client._default_launch_args = isolated_launch_args


class _RuntimeProcessSupervisor:
    """Preempt the pinned SDK's blocking writes without taking its locks.

    0.1.5rc1 assigns client._proc before writing initialization and prompt RPCs.
    Its request timeout starts after stdin.write/flush, so an independent owner
    must kill a stalled child to release the SDK's writer/close locks. A proc
    not yet assigned is observed until startup or close reaches quiescence.
    """
    def __init__(self, runtime, report_failure, *, report_event=None):
        self.client = runtime.client
        if not hasattr(self.client, "_proc"):
            raise ValueError("DSH client does not match the pinned process supervision contract")
        self.report_failure = report_failure
        self.report_event = report_event
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._force = threading.Event()
        self._close_finished = threading.Event()
        self._thread = None
        self._deadline = None
        self._reported = set()
        self._diagnostics_reported = set()

    def begin_close(self, *, force=False):
        with self._lock:
            if force:
                self._force.set()
            if self._deadline is None:
                self._deadline = time.monotonic() + SDK_CLOSE_GRACE_SECONDS
            if self._thread is None:
                thread = threading.Thread(target=self._run,
                    name="harness-context-dsh-process-supervisor", daemon=True)
                thread.start()
                self._thread = thread
        self._wake.set()

    def finish_close(self):
        self._close_finished.set()
        self._wake.set()

    def join(self):
        with self._lock:
            thread = self._thread
        if thread is not None:
            thread.join()

    def _failure(self, error):
        key = type(error).__name__
        if key not in self._reported:
            self._reported.add(key)
            self.report_failure("dsh_runtime_reap_error", error)

    def _event(self, trigger, operation, status, error=None):
        if self.report_event is None:
            return
        key = (trigger, operation, status, None if error is None else type(error).__name__)
        if key in self._diagnostics_reported:
            return
        self._diagnostics_reported.add(key)
        event = {"kind": "dsh_runtime_supervision", "trigger": trigger,
            "operation": operation, "status": status, "provider_request": False,
            "model_call": False, "tool_executed": False}
        if error is not None:
            event["exception_type"] = type(error).__name__
        self.report_event(event)

    def _wait_reaped(self, process, trigger, *, emit=True):
        try:
            process.wait(timeout=SDK_REAP_TIMEOUT_SECONDS)
        except Exception as error:
            if emit:
                self._event(trigger, "reap", "failed", error)
            self._failure(error)
            return False
        if emit:
            self._event(trigger, "reap", "succeeded")
        return True

    def _reap(self, process, trigger="incomplete_close"):
        try:
            if process.poll() is not None:
                return self._wait_reaped(process, trigger)
            self._event(trigger, "terminate", "requested")
            try:
                process.terminate()
            except ProcessLookupError:
                self._event(trigger, "terminate", "already_exited")
            except Exception as error:
                self._event(trigger, "terminate", "failed", error)
                self._failure(error)
            else:
                self._event(trigger, "terminate", "sent")
            try:
                process.wait(timeout=SDK_TERMINATE_GRACE_SECONDS)
                self._event(trigger, "reap", "succeeded")
                return True
            except subprocess.TimeoutExpired:
                pass
            except Exception as error:
                self._event(trigger, "reap", "failed", error)
                self._failure(error)
            self._event(trigger, "kill", "requested")
            try:
                process.kill()
            except ProcessLookupError:
                self._event(trigger, "kill", "already_exited")
            except Exception as error:
                self._event(trigger, "kill", "failed", error)
                self._failure(error)
            else:
                self._event(trigger, "kill", "sent")
            return self._wait_reaped(process, trigger)
        except Exception as error:
            self._event(trigger, "reap", "failed", error)
            self._failure(error)
            return False

    def _run(self):
        attempted = set()
        observed = {}
        reaped = set()
        triggers = {}
        while True:
            try:
                process = self.client._proc
                if process is not None:
                    observed[id(process)] = process
                closing_finished = self._close_finished.is_set()
                forced = self._force.is_set()
                expired = time.monotonic() >= self._deadline
                for identity, child in tuple(observed.items()):
                    if identity in reaped:
                        continue
                    if child.poll() is not None:
                        if self._wait_reaped(child, triggers.get(identity, "sdk_close"),
                                emit=identity in attempted):
                            reaped.add(identity)
                    elif identity not in attempted and (forced or expired or closing_finished):
                        trigger = ("deadline" if forced else "close_grace" if expired
                            else "incomplete_close")
                        triggers[identity] = trigger
                        attempted.add(identity)
                        if self._reap(child, trigger):
                            reaped.add(identity)
                        # A failed reap is not SDK quiescence. Retain this
                        # process even if client._proc is later cleared, and
                        # observe its OS exit without repeating terminate/kill.
                if closing_finished and len(reaped) == len(observed):
                    return
            except Exception as error:
                self._failure(error)
            self._wake.wait(SDK_PROCESS_POLL_SECONDS)
            self._wake.clear()


def _write_runtime_profile(home, *, endpoint, token, profile):
    """Create a private, complete Cordis tree, without npm/plugin installation."""
    directory = home / "profiles" / RUNTIME_PROFILE
    directory.mkdir(parents=True, mode=0o700)
    plugin = directory / "bridge.mjs"
    shutil.copyfile(Path(__file__).with_name("dsh_bridge.mjs"), plugin)
    manifest = {"name": "harness-generation-context-runtime", "private": True,
        "type": "module", "dependencies": {},
        "dsh": {"profile": {"bundles": [], "patchReload": "startup"}}}
    entries = json.loads(Path(__file__).with_name("dsh_kernel.json").read_text(encoding="utf-8"))
    for entry in entries:
        if entry["id"] == "sessions":
            entry["config"]["root"] = str(home / "sessions")
    entries.append({"id": "harness-generation-context-bridge", "name": str(plugin),
        "config": {"endpoint": endpoint, "token": token,
            "maxResponseBytes": 4 * (profile["max_prompt_chars"] + profile["max_response_chars"]
                + profile["max_event_chars"])}})
    for name, value in (("package.json", manifest), ("cordis.patch.yml", [{"insert": entries}])):
        path = directory / name
        path.write_text(_json(value) + "\n", encoding="utf-8")
        path.chmod(0o600)
    plugin.chmod(0o600)


def _usage(metadata_value):
    """Emit DSH counts only when both authoritative aggregate counts exist."""
    raw = metadata_value.get("usage")
    if not isinstance(raw, dict):
        return None
    def count(name):
        value = raw.get(name)
        return (int(value) if not isinstance(value, bool) and isinstance(value, (int, float))
            and 0 <= value <= 2**53 - 1 and math.isfinite(value) and value == int(value) else None)
    prompt, completion = count("prompt_tokens"), count("completion_tokens")
    if prompt is None or completion is None:
        return None
    # Split cached input only when the provider reported an exact count.
    result = {"inputTokens": prompt, "outputTokens": completion}
    details = raw.get("prompt_tokens_details")
    cached = details.get("cached_tokens") if isinstance(details, dict) else raw.get("prompt_cache_hit_tokens")
    if type(cached) is int and 0 <= cached <= prompt:
        result["inputTokens"] = prompt - cached
        result["cacheReadTokens"] = cached
    total = count("total_tokens")
    if total is not None:
        result["totalTokens"] = total
    return result


class _Bridge:
    """Serialized, authenticated control plane; never trusts runtime messages."""
    def __init__(self, policy, profile, *, session_id):
        self.policy, self.profile, self.session_id = policy, profile, session_id
        self.lock = threading.RLock()
        self.stopped = threading.Event()
        self._stop_lock = threading.Lock()
        self.stop_reason = None
        self.sequence = 0
        self.initialized = False
        self._last_usage = None

    def stop(self, reason):
        # Do not wait for the policy lock: a bounded provider request may own
        # it while the watchdog or SDK failure stops new bridge operations.
        with self._stop_lock:
            if not self.stopped.is_set():
                self.stop_reason = reason
                self.stopped.set()

    def dispatch(self, packet):
        with self.lock:
            if not isinstance(packet, dict) or type(packet.get("seq")) is not int:
                raise ValueError("invalid bridge packet")
            if packet["seq"] != self.sequence + 1:
                raise ValueError("bridge sequence mismatch")
            self.sequence = packet["seq"]
            if self.stopped.is_set():
                return {"error": {"code": "HARNESS_BRIDGE_CLOSED"}}
            op = packet.get("op")
            if op == "initialize":
                if self.initialized:
                    raise ValueError("bridge already initialized")
                self.initialized = True
                # Always register the full roster. Last-round visibility is
                # narrowed separately without removing executable definitions.
                schemas = self.policy.tools.schemas + [self.policy.helper.terminal_schema]
                system = "\n".join(str(message.get("content", "")) for message in
                    self.policy.outcome.messages if message.get("role") == "system")
                return {"system": system, "schemas": schemas}
            if not self.initialized:
                raise ValueError("bridge is not initialized")
            if op == "surface":
                return {"schemas": self.policy.prepare()}
            if op == "model":
                self._last_usage = None
                if packet.get("purpose") is not None or packet.get("session_id") != self.session_id:
                    self.policy.abort("dsh_auxiliary_or_foreign_model_request")
                    return self._model_packet(None)
                self.policy.prepare()
                request = {"messages": self.policy.outcome.messages, "tools": self.policy.surface()}
                if len(_json(request)) > self.profile["max_prompt_chars"]:
                    self.policy.abort("dsh_prompt_limit")
                    return self._model_packet(None)
                event_offset = len(self.policy.outcome.events)
                response = self.policy.complete()
                for event in self.policy.outcome.events[event_offset:]:
                    if event.get("kind") == "model_response":
                        self._last_usage = _usage(event.get("metadata", {}))
                # A timer may have closed the runtime during a paid provider
                # request. Keep its ledger, but execute none of its calls.
                if self.stopped.is_set():
                    self.policy.abort(self.stop_reason or "dsh_bridge_closed")
                    return self._model_packet(None)
                result = self._model_packet(response)
                if len(_json(result.get("response"))) > self.profile["max_response_chars"]:
                    self.policy.abort("dsh_response_limit")
                    result = self._model_packet(None)
                self.policy.outcome.events.append({"kind": "dsh_bridge_model",
                    "round": self.policy.outcome.rounds, "runtime_message_count": packet.get("runtime_message_count"),
                    "native_model_calls": self.policy.outcome.model_calls,
                    "action": result["action"], "history_projection": HISTORY_PROJECTION})
                return result
            if op == "tool":
                call_id = packet.get("tool_call_id")
                if not isinstance(call_id, str) or not call_id:
                    raise ValueError("bridge tool call lacks identity")
                raw = packet.get("arguments_raw")
                if (not isinstance(raw, str) or not self.policy.pending_calls
                        or raw != self.policy.pending_calls[0].arguments):
                    raise ValueError("bridge raw arguments differ from the native submission")
                # Keep integers and floats in Python's original JSON types.
                # The official runtime parses through JavaScript numbers;
                # the bridge plugin verifies that SDK projection separately.
                try:
                    arguments = json.loads(raw)
                except (TypeError, ValueError):
                    arguments = raw if raw else {}
                result, done = self.policy.execute_named(packet.get("name"), arguments, call_id)
                return {"result": result, "done": done}
            if op == "feedback":
                if self.policy.pending_calls:
                    raise ValueError("feedback cannot skip native pending calls")
                self.policy.outcome.events.append({"kind": "dsh_bridge_feedback",
                    "round": self.policy.outcome.rounds, "action": self.policy.action,
                    "model_call": False, "tool_executed": False})
                return {"result": {"action": self.policy.action}, "done": self.policy.done}
            raise ValueError("unsupported bridge operation")

    def _model_packet(self, response):
        usage = self._last_usage
        value = None if response is None else {"content": response.content,
            "reasoning_content": response.reasoning_content,
            "tool_calls": [{"id": call.id, "name": call.name, "arguments": call.arguments}
                for call in response.tool_calls], "usage": usage}
        return {"response": value, "usage": usage, "done": self.policy.done,
            "action": "tools" if response is not None else self.policy.action,
            "schemas": self.policy.surface()}


def _start_server(bridge, token):
    class Server(HTTPServer):
        def __init__(self, *args, **kwargs):
            self._io_lock = threading.Lock()
            self._io_closed = False
            self._connections = set()
            super().__init__(*args, **kwargs)

        def get_request(self):
            connection, address = super().get_request()
            with self._io_lock:
                if self._io_closed:
                    connection.close()
                    raise OSError("Context bridge transport is closed")
                self._connections.add(connection)
            return connection, address

        def close_request(self, request):
            try:
                super().close_request(request)
            finally:
                with self._io_lock:
                    self._connections.discard(request)

        def stop_io(self):
            # Socket timeouts bound inactivity, not trickled request bytes.
            # Close accepted peers at stop even when parsing has not reached
            # authentication; provider execution still drains on this thread.
            with self._io_lock:
                self._io_closed = True
                connections = tuple(self._connections)
            failure = None
            for connection in connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError as error:
                    if error.errno not in {errno.EBADF, errno.ENOTCONN, errno.EINVAL}:
                        failure = failure or error
                except Exception as error:
                    failure = failure or error
                try:
                    connection.close()
                except Exception as error:
                    failure = failure or error
            if failure is not None:
                raise failure

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def setup(self):
            # BaseHTTPRequestHandler reads request line and headers before
            # do_POST; those reads must also be bounded for shutdown to drain.
            self.request.settimeout(min(30.0, bridge.profile["request_timeout_seconds"]))
            super().setup()

        def log_message(self, _format, *args):
            pass  # Never print request paths, authentication or payloads.

        def do_POST(self):
            status = 200
            packet = {"error": {"code": "HARNESS_BRIDGE_PROTOCOL"}}
            authorized = secrets.compare_digest(self.headers.get("Authorization", ""), f"Bearer {token}")
            try:
                self.connection.settimeout(min(30.0, bridge.profile["request_timeout_seconds"]))
                if not authorized or self.path != "/context":
                    status = 403
                elif self.headers.get("Transfer-Encoding"):
                    status = 400
                else:
                    length = int(self.headers.get("Content-Length", "-1"))
                    # Only call identity/arguments enter here; model history
                    # stays in Python. Limit before allocating or decoding.
                    if not 0 < length <= 8 * bridge.profile["max_response_chars"] + 8192:
                        status = 413
                    else:
                        raw = self.rfile.read(length)
                        if len(raw) != length:
                            raise ValueError("incomplete bridge request")
                        packet = bridge.dispatch(json.loads(raw.decode("utf-8")))
                encoded = _json(packet).encode("utf-8")
            except Exception:
                status = 400
                encoded = _json({"error": {"code": "HARNESS_BRIDGE_PROTOCOL"}}).encode("utf-8")
                if authorized and not bridge.stopped.is_set():
                    with bridge.lock:
                        if not bridge.stopped.is_set():
                            bridge.policy.abort("dsh_bridge_protocol_error")
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)
            except OSError:
                pass

    # Source tools mutate one evidence registry. A single handler preserves
    # model response/call ordering and makes duplicate requests fail closed.
    server = Server(("127.0.0.1", 0), Handler)

    def serve():
        try:
            server.serve_forever(poll_interval=0.05)
        except Exception as error:
            bridge.stop("dsh_bridge_server_error")
            with bridge.lock:
                bridge.policy.abort("dsh_bridge_server_error")
                bridge.policy.outcome.events[-1]["exception_type"] = type(error).__name__

    thread = threading.Thread(target=serve,
        name="harness-context-dsh-bridge", daemon=True)
    try:
        thread.start()
    except Exception:
        try:
            server.server_close()
        except Exception as error:
            with bridge.lock:
                bridge.policy.abort("dsh_bridge_server_close_error")
                bridge.policy.outcome.events[-1]["exception_type"] = type(error).__name__
        raise
    return server, thread


class DeepSeekHarnessContextBackend:
    def __init__(self, model_config, *, budget, profile=None):
        self.model_config = model_config
        self.budget = deepcopy(budget.to_dict())
        self.profile = normalize_dsh_profile({} if profile is None else profile)
        self._descriptor = {"name": BACKEND_NAME, "sdk_version": SDK_VERSION,
            "runtime_version": SDK_VERSION, "runtime_carrier": "bundled-exe", "upstream_commit": UPSTREAM_COMMIT,
            "runtime_close_policy": "sdk-private-process-preemption-v1",
            "bridge_policy_version": BRIDGE_POLICY_VERSION, "bounded_policy_version": BOUNDED_POLICY_VERSION,
            "profile_version": PROFILE_VERSION, "history_projection": HISTORY_PROJECTION,
            "profile": deepcopy(self.profile), "profile_sha256": profile_sha256(self.profile),
            "budget": deepcopy(self.budget), "assets_sha256": {
                name: sha256(Path(__file__).with_name(name).read_bytes()).hexdigest() for name in ASSETS},
            "native_policy_sha256": {name: sha256((Path(__file__).parent / name).read_bytes()).hexdigest()
                for name in NATIVE_POLICY_FILES}}

    def descriptor(self):
        return deepcopy(self._descriptor)

    def run(self, **kwargs):
        policy = DSHContextPolicy(**kwargs)
        outcome = policy.outcome
        outcome.events.append({"kind": "dsh_backend_start", "agent_backend": self.descriptor()})
        try:
            sdk_type = _load_sdk()
        except Exception as error:
            policy.abort("dsh_dependency_error")
            outcome.events[-1]["detail"] = "pinned DSH dependencies are unavailable"
            outcome.events[-1]["exception_type"] = type(error).__name__
            return outcome
        bridge = _Bridge(policy, self.profile, session_id=f"context-{uuid.uuid4().hex}")
        token = secrets.token_urlsafe(32)
        runtime = server = server_thread = timer = temporary = supervisor = None
        expired = threading.Event()
        completed = threading.Event()
        deadline_lock = threading.Lock()
        close_lock = threading.Lock()
        cleanup_lock = threading.Lock()
        cleanup_failures = []
        supervision_events = []
        session_events = 0
        started = time.monotonic()
        endpoint = ""

        def report_cleanup_failure(reason, error):
            # Never retain exception messages or traceback payloads. A
            # watchdog may report concurrently while a provider drains.
            with cleanup_lock:
                cleanup_failures.append((reason, type(error).__name__))

        def report_supervision_event(event):
            # The supervisor never enters the policy/provider locks. Publish
            # its safe diagnostics only after all owner threads have drained.
            with cleanup_lock:
                supervision_events.append(event)

        def attempt_cleanup(reason, operation):
            try:
                operation()
            except Exception as error:
                report_cleanup_failure(reason, error)

        def stop_io():
            if server is not None:
                server.stop_io()

        def close_runtime():
            if runtime is not None:
                if supervisor is not None:
                    try:
                        supervisor.begin_close(force=expired.is_set())
                    except Exception as error:
                        report_cleanup_failure("dsh_runtime_supervision_error", error)
                        # A failure to start the monitor must not skip the SDK
                        # close attempt. Preempt an already assigned child
                        # without the close/write locks before falling back.
                        process = getattr(runtime.client, "_proc", None)
                        if process is not None:
                            supervisor._reap(process)
                try:
                    with close_lock:
                        runtime.close()
                finally:
                    if supervisor is not None:
                        supervisor.finish_close()

        def expire():
            with deadline_lock:
                if completed.is_set():
                    return
                expired.set()
                bridge.stop("dsh_deadline_exceeded")
            attempt_cleanup("dsh_bridge_transport_close_error", stop_io)
            attempt_cleanup("dsh_shutdown_error", close_runtime)

        def finish_deadline():
            # Timer.cancel cannot stop a callback which has already begun.
            # Arbitrate completion without holding SDK or provider locks.
            with deadline_lock:
                completed.set()
                deadline_expired = expired.is_set()
            if timer is not None:
                attempt_cleanup("dsh_timer_cancel_error", timer.cancel)
            return deadline_expired

        def collect(notification):
            nonlocal session_events
            if notification.method != "session.event":
                return
            payload = notification.payload
            if payload.get("sessionId") != bridge.session_id:
                raise ValueError("foreign DSH session event")
            event = payload.get("event")
            if not isinstance(event, dict):
                raise ValueError("invalid DSH session event")
            session_events += 1
            if session_events > self.profile["max_session_events"]:
                raise ValueError("DSH session event count exceeded")
            serialized = _json(event)
            if len(serialized) > self.profile["max_event_chars"]:
                raise ValueError("DSH session event size exceeded")
            # External runtime events are diagnostic data, not native proof.
            # Redact private launch details even if an upstream event includes
            # a plugin config or error chain in a future maintenance release.
            serialized = serialized.replace(token, "<bridge-token-redacted>")
            if endpoint:
                serialized = serialized.replace(endpoint, "<bridge-endpoint-redacted>")
            with bridge.lock:
                outcome.events.append({"kind": "dsh_session_event", "event": json.loads(serialized)})

        phase = "seed"
        try:
            seed = _json({"history_projection": HISTORY_PROJECTION,
                "instruction": "The Python Context bridge owns exact model history and validates every call. This durable seed records framework-prepared messages; do not reexecute their bootstrap tools.",
                "messages": outcome.messages})
            if len(seed) > self.profile["max_prompt_chars"]:
                policy.abort("dsh_prompt_limit")
                return outcome
            phase = "workspace"
            temporary = tempfile.TemporaryDirectory(prefix="harness-context-dsh-")
            home = Path(temporary.name).resolve()
            phase = "runtime"
            server, server_thread = _start_server(bridge, token)
            endpoint = f"http://127.0.0.1:{server.server_address[1]}/context"
            _write_runtime_profile(home, endpoint=endpoint, token=token, profile=self.profile)
            runtime = sdk_type(dsh_home=str(home), cwd=str(home), runtime_cwd=str(home),
                dsh_bin=_bundled_runtime_executable(),
                provider=PROVIDER_ROUTE, model=self.model_config.model, profile=RUNTIME_PROFILE,
                env=_runtime_environment(),
                initialize_timeout_seconds=min(30.0, self.profile["request_timeout_seconds"]),
                request_timeout_seconds=self.profile["request_timeout_seconds"], shutdown_timeout_seconds=1.0)
            _isolate_sdk_environment(runtime)
            supervisor = _RuntimeProcessSupervisor(runtime, report_cleanup_failure,
                report_event=report_supervision_event)
            timer = threading.Timer(self.profile["request_timeout_seconds"], expire)
            timer.daemon = True
            timer.start()
            # Serialize startup against watchdog close. Session.run does
            # not autostart the SDK, whereas Harness.run would relaunch it
            # if a deadline closed it immediately before the call.
            with close_lock:
                if expired.is_set():
                    raise TimeoutError("DSH deadline expired before startup")
                session = runtime.start_session(bridge.session_id)
            result = session.run(seed, on_notification=collect)
            deadline_expired = finish_deadline()
            if deadline_expired:
                policy.abort("dsh_deadline_exceeded")
            elif result.session_id != bridge.session_id or result.finish_reason != "completed":
                policy.abort("dsh_turn_failed")
            elif not policy.done:
                policy.abort("dsh_turn_ended_before_native_completion")
            outcome.events.append({"kind": "dsh_backend_finish", "session_id": bridge.session_id,
                "finish_reason": result.finish_reason, "session_events": session_events,
                "elapsed_seconds": round(time.monotonic() - started, 6)})
        except Exception as error:
            # Never expose SDK stderr/payload/config: runtime exception text
            # can contain the private bridge endpoint or authentication.
            deadline_expired = finish_deadline()
            reason = bridge.stop_reason or ("dsh_deadline_exceeded" if deadline_expired else
                "dsh_seed_error" if phase == "seed" else "dsh_workspace_error" if phase == "workspace"
                else "dsh_runtime_error")
            bridge.stop(reason)
            with bridge.lock:
                policy.abort(reason)
                outcome.events[-1]["exception_type"] = type(error).__name__
        finally:
            finish_deadline()
            bridge.stop("dsh_bridge_closed")
            attempt_cleanup("dsh_bridge_transport_close_error", stop_io)
            attempt_cleanup("dsh_shutdown_error", close_runtime)
            if server is not None:
                # Close trickled peers, then drain any in-flight provider
                # before returning: the ledger cannot change after this run.
                attempt_cleanup("dsh_bridge_shutdown_error", server.shutdown)
                attempt_cleanup("dsh_bridge_server_close_error", server.server_close)
            if server_thread is not None:
                attempt_cleanup("dsh_bridge_thread_join_error", server_thread.join)
            if timer is not None:
                attempt_cleanup("dsh_timer_join_error", lambda: timer.join() if timer.is_alive() else None)
            if supervisor is not None:
                attempt_cleanup("dsh_runtime_supervisor_join_error", supervisor.join)
            if temporary is not None:
                attempt_cleanup("dsh_workspace_cleanup_error", temporary.cleanup)
            with cleanup_lock:
                failures = list(cleanup_failures)
                diagnostics = list(supervision_events)
            with bridge.lock:
                outcome.events.extend(diagnostics)
                for reason, exception_type in failures:
                    policy.abort(reason)
                    outcome.events[-1]["exception_type"] = exception_type
        return outcome


def create_context_backend(model_config, *, budget, profile_path=None):
    profile = load_dsh_profile(profile_path)
    _check_dependency_versions()
    return DeepSeekHarnessContextBackend(model_config, budget=budget, profile=profile)
