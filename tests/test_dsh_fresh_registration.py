"""Offline definitions for fresh-run backend registration and observation identity.

These tests never need the SDK, a provider, target parsing or runtime execution.
"""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    spec = importlib.util.spec_from_file_location("dsh_registration_" + name,
        ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load_script("repeat_fresh_stability")
collector = load_script("collect_fresh_stability")
auditor = load_script("audit_fresh_stability")


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")


def dsh_descriptor():
    profile = {"max_prompt_chars": 400000, "max_response_chars": 64000,
        "max_session_events": 4096, "max_event_chars": 1000000,
        "request_timeout_seconds": 180.0}
    return {"name": "deepseek-harness", "sdk_version": "0.1.5rc1",
        "runtime_version": "0.1.5rc1", "runtime_carrier": "bundled-exe",
        "runtime_close_policy": "sdk-private-process-preemption-v1",
        "upstream_commit": "frozen-upstream", "bridge_policy_version": "bridge-v2",
        "bounded_policy_version": "bounded-v2", "profile_version": "profile-v1",
        "history_projection": "history-v1", "budget": {"max_total_model_calls": 10},
        "profile": profile, "profile_sha256": auditor.digest(profile),
        "assets_sha256": {"dsh_bridge.mjs": hashlib.sha256(b"bridge\n").hexdigest(),
                          "dsh_aux.mjs": hashlib.sha256(b"auxiliary\n").hexdigest()},
        "native_policy_sha256": {"../semantic_discovery/loop.py": hashlib.sha256(b"loop\n").hexdigest(),
                                 "agent.py": hashlib.sha256(b"agent\n").hexdigest()}}


def registered_dsh(root):
    backend = dsh_descriptor()
    for relative, contents in (("harness_generation/harness_context/dsh_bridge.mjs", "bridge\n"),
                               ("harness_generation/harness_context/dsh_aux.mjs", "auxiliary\n"),
                               ("harness_generation/harness_context/agent.py", "agent\n"),
                               ("harness_generation/semantic_discovery/loop.py", "loop\n"),
                               ("harness_generation/harness_context/dsh_backend.py", '''SDK_VERSION = "0.1.5rc1"
UPSTREAM_COMMIT = "frozen-upstream"
HISTORY_PROJECTION = "history-v1"
ASSETS = ("dsh_bridge.mjs", "dsh_aux.mjs")
NATIVE_POLICY_FILES = ("../semantic_discovery/loop.py", "agent.py")
class DeepSeekHarnessContextBackend:
    def __init__(self):
        self._descriptor = {"name": BACKEND_NAME, "sdk_version": SDK_VERSION,
            "runtime_version": SDK_VERSION, "runtime_carrier": "bundled-exe",
            "runtime_close_policy": "sdk-private-process-preemption-v1",
            "upstream_commit": UPSTREAM_COMMIT, "bridge_policy_version": BRIDGE_POLICY_VERSION,
            "bounded_policy_version": BOUNDED_POLICY_VERSION, "profile_version": PROFILE_VERSION,
            "history_projection": HISTORY_PROJECTION, "profile": profile, "profile_sha256": digest(profile),
            "budget": budget, "assets_sha256": {}, "native_policy_sha256": {}}
'''),
                               ("harness_generation/harness_context/dsh_policy.py", 'VERSION = "bounded-v2"\n'),
                               ("harness_generation/harness_context/dsh_config.py", '''BACKEND_NAME = "deepseek-harness"
PROFILE_VERSION = "profile-v1"
BRIDGE_POLICY_VERSION = "bridge-v2"
DEFAULT_DSH_PROFILE = {"max_prompt_chars": 400000, "max_response_chars": 64000,
    "max_session_events": 4096, "max_event_chars": 1000000, "request_timeout_seconds": 180}
_INTEGER_LIMITS = {"max_prompt_chars": 2000000, "max_response_chars": 1000000,
    "max_session_events": 65536, "max_event_chars": 16000000}
_MAX_REQUEST_TIMEOUT_SECONDS = 3600
'''),
                               ("pyproject.toml", 'dependencies = ["deepseek-harness-sdk==0.1.5rc1", "deepseek-harness-runtime-bin==0.1.5rc1"]\n')):
        path = root / "frozen" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
    write_json(root / "dsh_profile.json", backend["profile"])
    inventory = {p.relative_to(root / "frozen").as_posix(): runner.sha(p)
        for p in (root / "frozen").rglob("*") if p.is_file()}
    return {"context_agent_backend": backend,
        "context_agent_backend_fingerprint": auditor.digest(backend),
        "context_budget": backend["budget"], "freeze_mode": "current",
        "production_file_hashes": inventory,
        "dsh_profile": {"source": "dsh_profile.json",
            "sha256": runner.sha(root / "dsh_profile.json"),
            "profile_sha256": backend["profile_sha256"]}}


def test_fresh_cli_defaults_native_and_accepts_explicit_dsh_profile(tmp_path):
    defaults = runner.argument_parser().parse_args([])
    assert defaults.agent_backend == "native" and defaults.dsh_profile is None
    profile = tmp_path / "limits.json"
    args = runner.argument_parser().parse_args(["--agent-backend", "deepseek-harness",
        "--dsh-profile", str(profile), "--freeze-current"])
    assert args.agent_backend == "deepseek-harness" and args.dsh_profile == profile


@pytest.mark.parametrize("kwargs,reason", [
    ({"agent_backend": "deepseek-harness"}, "newly registered"),
    ({"agent_backend": "native", "dsh_profile": "unused.json"}, "requires"),
    ({"agent_backend": "unknown"}, "must be"),
])
def test_invalid_backend_selection_is_rejected_before_registration(tmp_path, kwargs, reason):
    output = tmp_path / "never-created"
    with pytest.raises(ValueError, match=reason):
        runner.register(output, 1, 1, 1, **kwargs)
    assert not output.exists()


def test_descriptor_registration_has_no_dependency_or_sdk_check(tmp_path, monkeypatch):
    from harness_generation.harness_context import dsh_backend
    from harness_generation.harness_context.models import ContextBudget
    monkeypatch.setattr(dsh_backend, "_check_dependency_versions",
        lambda: pytest.fail("registration must not inspect installed SDK packages"))
    monkeypatch.setattr(dsh_backend, "_load_sdk",
        lambda: pytest.fail("registration must not import the SDK"))
    profile = tmp_path / "profile.json"
    write_json(profile, {"request_timeout_seconds": 500})
    descriptor = runner.backend_registration(SimpleNamespace(model="offline"),
        budget=ContextBudget(), agent_backend="deepseek-harness", profile_path=profile)
    assert descriptor["profile"]["request_timeout_seconds"] == 500.0
    assert set(descriptor["profile"]) == {"max_prompt_chars", "max_response_chars",
        "max_session_events", "max_event_chars", "request_timeout_seconds"}


def test_worker_backend_arguments_use_registered_effective_profile(tmp_path):
    assert runner.context_backend_options(tmp_path, {}) == []
    assert runner.context_backend_options(tmp_path, {"context_agent_backend": {"name": "native"}}) == []
    registration = registered_dsh(tmp_path)
    assert runner.context_backend_options(tmp_path, registration) == ["--agent-backend",
        "deepseek-harness", "--dsh-profile", str(tmp_path / "dsh_profile.json")]
    registration["dsh_profile"]["source"] = "../../unregistered.json"
    with pytest.raises(ValueError, match="unavailable"):
        runner.context_backend_options(tmp_path, registration)


def test_registered_profile_assets_and_pins_are_independently_authenticated(tmp_path):
    registration = registered_dsh(tmp_path)
    assert all(auditor.backend_registration_checks(tmp_path, registration).values())
    write_json(tmp_path / "dsh_profile.json", {**registration["context_agent_backend"]["profile"],
        "request_timeout_seconds": 300.0})
    checks = auditor.backend_registration_checks(tmp_path, registration)
    assert not checks["backend:profile_file"]
    assert not checks["backend:effective_profile"]
    assert not checks["backend:profile_fingerprint"]


@pytest.mark.parametrize("mutation", ["asset", "pin", "budget", "fingerprint"])
def test_registration_detects_backend_identity_mutation(tmp_path, mutation):
    registration = registered_dsh(tmp_path)
    if mutation == "asset":
        (tmp_path / "frozen/harness_generation/harness_context/dsh_bridge.mjs").write_text("changed\n")
    elif mutation == "pin":
        (tmp_path / "frozen/pyproject.toml").write_text('dependencies = ["deepseek-harness-sdk==99"]\n')
    elif mutation == "budget":
        registration["context_budget"] = {"max_total_model_calls": 11}
    else:
        registration["context_agent_backend_fingerprint"] = "0" * 64
    assert not all(auditor.backend_registration_checks(tmp_path, registration).values())


def test_historical_native_metadata_is_compatible_but_cannot_claim_dsh():
    assert all(auditor.context_backend_checks({}, {}).values())
    dsh = {"context_agent_backend": dsh_descriptor()}
    assert not auditor.context_backend_checks({}, dsh)["registered_context_backend"]
    assert not auditor.context_backend_checks({"agent_backend": dsh_descriptor()}, {})["registered_context_backend"]
    assert all(auditor.context_backend_checks({"agent_backend": dsh_descriptor()}, dsh).values())


def test_collector_matches_backend_descriptors_and_keeps_native_compatibility():
    row = {"stages": {"harness-context": {"configurations": [{}]}}}
    assert collector.configuration_audit(row, {})["all_observed_match"] is True
    backend = dsh_descriptor()
    registration = {"context_agent_backend": backend,
        "context_agent_backend_fingerprint": auditor.digest(backend)}
    assert collector.configuration_audit(row, registration)["all_observed_match"] is False
    row["stages"]["harness-context"]["configurations"] = [{"agent_backend": backend}]
    assert collector.configuration_audit(row, registration)["all_observed_match"] is True
    changed = deepcopy(backend)
    changed["profile_sha256"] = "wrong"
    row["stages"]["harness-context"]["configurations"] = [{"agent_backend": changed}]
    assert collector.configuration_audit(row, registration)["all_observed_match"] is False


def test_trace_receipt_requires_the_registered_dsh_loop(tmp_path):
    artifacts = tmp_path / "artifacts"
    trace = artifacts / "harness_contexts/ft_one/agent_runs/req_one/attempt_0001/trace.json"
    backend = dsh_descriptor()
    registration = {"context_agent_backend": backend}
    write_json(trace.with_name("metadata.json"), {"model_calls": 1,
        "configuration": {"agent_backend": backend}})
    write_json(trace, {"events": [{"kind": "model_response", "metadata": {}}]})
    assert not all(auditor.backend_trace_checks(artifacts, registration).values())
    write_json(trace, {"events": [{"kind": "dsh_backend_start", "agent_backend": backend},
        {"kind": "model_response", "metadata": {}}]})
    assert all(auditor.backend_trace_checks(artifacts, registration).values())


def test_runtime_events_do_not_duplicate_provider_costs(tmp_path):
    artifacts = tmp_path / "artifacts"
    trace = artifacts / "harness_contexts/ft_one/agent_runs/req_one/attempt_0001/trace.json"
    backend = dsh_descriptor()
    usage = {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
    write_json(trace.with_name("metadata.json"), {"model_calls": 1, "tool_calls": 0,
        "group_cost_owner": True, "configuration": {"agent_backend": backend}})
    write_json(trace, {"events": [{"kind": "dsh_backend_start", "agent_backend": backend},
        {"kind": "dsh_session_event", "event": {"type": "llm.usage", "usage": usage}},
        {"kind": "model_response", "metadata": {"response_id": "offline-one", "usage": usage}}]})
    collected = collector.collect_trial(artifacts)
    assert collected["totals"]["provider_responses"] == 1
    assert collected["totals"]["tokens"] == usage
    assert collected["agent_backend_event_counts"] == {"dsh_backend_start": 1, "dsh_session_event": 1}
    assert collected["stages"]["harness-context"]["configurations"][0]["agent_backend"] == backend


@pytest.mark.parametrize("field", ["runtime_carrier", "runtime_close_policy", "upstream_commit", "sdk_version",
    "runtime_version", "bridge_policy_version", "bounded_policy_version", "profile_version", "history_projection"])
def test_rehashed_self_declared_metadata_cannot_change_frozen_contract(tmp_path, monkeypatch, field):
    registration = registered_dsh(tmp_path)
    monkeypatch.setattr(runner, "ROOT", tmp_path / "frozen")
    assert runner.backend_integrity(tmp_path, registration)
    backend = registration["context_agent_backend"]
    backend[field] = "self-declared-replacement"
    registration["context_agent_backend_fingerprint"] = auditor.digest(backend)
    assert not runner.backend_integrity(tmp_path, registration)
    assert not auditor.backend_registration_checks(tmp_path, registration)["backend:frozen_descriptor_contract"]


@pytest.mark.parametrize("field,key", [("assets_sha256", "dsh_bridge.mjs"),
    ("native_policy_sha256", "../semantic_discovery/loop.py")])
def test_rehashed_partial_asset_roster_is_rejected(tmp_path, monkeypatch, field, key):
    registration = registered_dsh(tmp_path)
    monkeypatch.setattr(runner, "ROOT", tmp_path / "frozen")
    del registration["context_agent_backend"][field][key]
    assert registration["context_agent_backend"][field]
    registration["context_agent_backend_fingerprint"] = auditor.digest(registration["context_agent_backend"])
    assert not runner.backend_integrity(tmp_path, registration)
    assert not auditor.backend_registration_checks(tmp_path, registration)["backend:frozen_descriptor_contract"]


def test_frozen_descriptor_recovery_never_executes_module_source(tmp_path):
    registration = registered_dsh(tmp_path)
    source = tmp_path / "frozen/harness_generation/harness_context/dsh_backend.py"
    source.write_text(source.read_text() + '\nraise AssertionError("must never execute")\n')
    assert runner.frozen_backend_descriptor(tmp_path / "frozen",
        budget=registration["context_budget"], profile=registration["context_agent_backend"]["profile"]) == registration["context_agent_backend"]
    assert auditor.frozen_backend_contract(tmp_path / "frozen", registration["context_agent_backend"]["profile"],
        registration["context_budget"]) == registration["context_agent_backend"]


@pytest.mark.parametrize("record,finished,expected", [
    ({}, False, "not_started"),
    ({"status": "candidate-validate_failed", "stage_exits": {"candidate-validate": 1}}, True, "skipped_upstream"),
    ({"status": "running"}, False, "in_progress"),
    ({"status": "passed", "stage_exits": {"harness-context": 0}}, True, "missing_observations"),
    ({"status": "harness-context_failed", "stage_exits": {"harness-context": 1}}, True, "missing_observations"),
])
def test_context_missing_observations_are_distinct_from_unentered_stage(tmp_path, record, finished, expected):
    entered = expected == "in_progress"
    checks, observation = auditor.context_observation_checks(tmp_path / "artifacts",
        record, finished=finished, entered=entered)
    assert observation["state"] == expected
    assert (not all(checks.values())) == (expected == "missing_observations")


def test_finished_context_with_paid_calls_requires_a_primary_trace(tmp_path):
    artifacts = tmp_path / "artifacts"
    directory = artifacts / "harness_contexts/ft_one"
    write_json(directory / "metadata.json", {"configuration": {"policy": "offline"},
        "metrics": {"model_calls": 1, "tool_calls": 0}})
    write_json(directory / "harness_context.json", {"frozen": True})
    write_json(directory / "completeness.json", {"generation_allowed": True})
    checks, observation = auditor.context_observation_checks(artifacts,
        {"status": "passed", "stage_exits": {"harness-context": 0}}, finished=True)
    assert observation["state"] == "missing_observations"
    assert not checks["context:primary_trace_observed_for_paid_calls"]


def test_receipt_check_uses_actual_provider_events_even_when_counter_is_zero(tmp_path):
    artifacts = tmp_path / "artifacts"
    trace = artifacts / "harness_contexts/ft_one/agent_runs/req_one/attempt_0001/trace.json"
    backend = dsh_descriptor()
    write_json(trace.with_name("metadata.json"), {"model_calls": 0,
        "configuration": {"agent_backend": backend}})
    write_json(trace, {"events": [{"kind": "model_response", "metadata": {}}]})
    assert not all(auditor.backend_trace_checks(artifacts, {"context_agent_backend": backend}).values())


def test_collector_does_not_report_empty_configuration_observations_as_match(tmp_path):
    root = tmp_path / "cohort"
    artifacts = root / "owned_return_r01/artifacts"
    write_json(root / "registration.json", {"context_agent_backend": dsh_descriptor(),
        "schedule": [{"trial_id": "owned_return_r01", "case": "owned_return", "artifacts": str(artifacts)}]})
    metrics = collector.collect_experiment(root, write_outputs=False)
    assert metrics["configuration_audit"]["all_observed_match"] is None
    assert metrics["trials"][0]["context_backend_execution_state"] == "not_started"
    write_json(artifacts.parent / "trial.json", {"trial_id": "owned_return_r01", "status": "passed",
        "context_agent_backend": dsh_descriptor(), "stage_exits": {"harness-context": 0}})
    metrics = collector.collect_experiment(root, write_outputs=False)
    assert metrics["configuration_audit"]["all_observed_match"] is False
    assert metrics["trials"][0]["context_backend_execution_state"] == "unknown"


def test_collector_compares_root_and_primary_attempt_backends(tmp_path):
    artifacts = tmp_path / "artifacts"
    backend = dsh_descriptor()
    root_config = {"agent_backend": backend}
    write_json(artifacts / "harness_contexts/ft_one/metadata.json", {"configuration": root_config})
    trace = artifacts / "harness_contexts/ft_one/agent_runs/req_one/attempt_0001/trace.json"
    write_json(trace.with_name("metadata.json"), {"configuration": {"native-policy": "offline"}, "model_calls": 1})
    write_json(trace, {"events": [{"kind": "model_response", "metadata": {"response_id": "offline-conflict"}}]})
    row = collector.collect_trial(artifacts)
    assert len(row["stages"]["harness-context"]["configurations"]) == 2
    assert collector.configuration_audit(row, {"context_agent_backend": backend})["all_observed_match"] is False


def test_completed_upstream_failure_keeps_context_unobserved(tmp_path):
    root = tmp_path / "cohort"
    artifacts = root / "owned_return_r01/artifacts"
    backend = dsh_descriptor()
    write_json(root / "registration.json", {"context_agent_backend": backend,
        "schedule": [{"trial_id": "owned_return_r01", "case": "owned_return", "artifacts": str(artifacts)}]})
    write_json(artifacts.parent / "trial.json", {"trial_id": "owned_return_r01",
        "status": "candidate-validate_failed", "context_agent_backend": backend,
        "finished_utc": "offline-finished", "stage_exits": {"candidate-validate": 1}})
    metrics = collector.collect_experiment(root, write_outputs=False)
    row = metrics["trials"][0]
    assert row["context_backend_execution_state"] == "skipped_upstream"
    assert row["configuration_audit"]["observation_checks"] == {}
    assert row["configuration_audit"]["all_observed_match"] is None
    assert row["configuration_audit"]["context_backend_matches_registration"] is None
    assert metrics["configuration_audit"]["all_observed_match"] is None
    assert metrics["configuration_audit"]["context_backend_all_observed_match"] is None


def test_paid_trace_without_metadata_still_requires_a_dsh_receipt(tmp_path):
    artifacts = tmp_path / "artifacts"
    trace = artifacts / "harness_contexts/ft_one/agent_runs/req_one/attempt_0001/trace.json"
    write_json(trace, {"events": [{"kind": "model_response", "metadata": {"response_id": "offline-paid"}}]})
    checks = auditor.backend_trace_checks(artifacts, {"context_agent_backend": dsh_descriptor()})
    assert not all(checks.values())
    assert any(key.endswith("metadata_present") and value is False for key, value in checks.items())
    assert any(key.endswith("one_dsh_loop_receipt") and value is False for key, value in checks.items())


def test_valid_attempt_cannot_hide_missing_root_context_configuration(tmp_path):
    artifacts = tmp_path / "artifacts"
    backend = dsh_descriptor()
    directory = artifacts / "harness_contexts/ft_one"
    write_json(directory / "metadata.json", {"metrics": {"model_calls": 1, "tool_calls": 0}})
    write_json(directory / "harness_context.json", {"frozen": True})
    write_json(directory / "completeness.json", {"generation_allowed": True, "hard_missing": []})
    trace = directory / "agent_runs/req_one/attempt_0001/trace.json"
    write_json(trace.with_name("metadata.json"), {"model_calls": 1,
        "configuration": {"agent_backend": backend}})
    write_json(trace, {"events": [{"kind": "dsh_backend_start", "agent_backend": backend}]})
    write_json(artifacts.parent / "trial.json", {"status": "passed", "context_agent_backend": backend,
        "stage_exits": {"harness-context": 0}})
    row = collector.collect_trial(artifacts)
    result = collector.configuration_audit(row, {"context_agent_backend": backend})
    assert result["observation_checks"]["context_configuration_observed"] is True
    assert result["observation_checks"]["context_root_configuration_observed"] is False
    assert result["all_observed_match"] is False


def execution_registration(root, *, native=False):
    backend = {"name": "native"} if native else dsh_descriptor()
    return {"context_agent_backend": backend,
        "context_agent_backend_fingerprint": auditor.digest(backend),
        "production_fingerprint": "frozen-production", "planned_trials": 1, "workers": 1,
        "schedule": runner.build_schedule(root, ["owned_return"], 1, 1),
        "samples": {"owned_return": {"anchor": "parse", "anchor_file": "api.c"}},
        "context_budget": {"max_total_model_calls": 10}, "validation_slice_budget": {},
        "provider": {}, "code_max_tokens": 8192, "code_temperature": 0.2}


def capability_observation(*, available=True):
    return {"schema_version": 1, "policy_version": "dsh-static-capability-preflight-v1",
        "status": "static_ready" if available else "static_unavailable",
        "static_capability_available": available, "sdk_version": "0.1.5rc1",
        "runtime_version": "0.1.5rc1", "runtime_carrier": "bundled-exe",
        "runtime_started": False, "optional_sdk_imported": False, "provider_requests": 0,
        "error_category": None if available else "dsh_dependency_missing"}


def install_offline_probe(monkeypatch, probe):
    # The replacement is an unexecuted distribution observation, never an SDK.
    monkeypatch.setitem(sys.modules, "harness_generation.harness_context.dsh_dependencies",
        SimpleNamespace(probe_dsh_dependencies=probe))


def test_register_only_publishes_review_without_probe_or_workers(tmp_path, monkeypatch):
    output = tmp_path / "review"
    registration = execution_registration(output)
    def register(destination, *_args, **kwargs):
        assert destination == output and kwargs["agent_backend"] == "deepseek-harness"
        destination.mkdir()
        write_json(destination / "registration.json", registration)
        write_json(destination / "manifest.json", registration)
        return registration
    monkeypatch.setattr(runner, "register", register)
    for function in ("dependency_preflight", "supervise", "worker"):
        monkeypatch.setattr(runner, function, lambda *_a, **_k: pytest.fail("register-only must return before execution"))
    install_offline_probe(monkeypatch, lambda **_kwargs: pytest.fail("optional dependency metadata must not be read"))
    runner.cli(["--output", str(output), "--freeze-current", "--register-only",
        "--agent-backend", "deepseek-harness"])
    assert runner.read(output / "registration.json") == registration
    assert runner.read(output / "manifest.json") == registration
    review = runner.read(output / "registration_review.json")
    assert review["execution_started"] is False and review["runtime_started"] is False
    assert review["dependency_preflight"] == "not_requested" and review["provider_requests"] == 0
    assert not (output / "dependency_preflight.json").exists()
    assert not Path(registration["schedule"][0]["trial_dir"]).exists()


def test_run_registered_preserves_registration_and_binds_frozen_import_source(tmp_path, monkeypatch):
    registration = execution_registration(tmp_path)
    write_json(tmp_path / "registration.json", registration)
    original = (tmp_path / "registration.json").read_bytes()
    calls = []
    monkeypatch.setattr(runner.sys, "path", list(runner.sys.path))
    def integrity(output, observed):
        assert output == tmp_path and observed == registration
        calls.append("integrity")
        return {"current": True, "frozen": True, "target": True, "backend": True}
    def supervise(output, observed):
        assert output == tmp_path and observed == registration
        assert runner.sys.path[0] == str(tmp_path / "frozen")
        calls.append("supervise")
    monkeypatch.setattr(runner, "integrity", integrity)
    monkeypatch.setattr(runner, "supervise", supervise)
    monkeypatch.setattr(runner, "register", lambda *_a, **_k: pytest.fail("must reuse the reviewed registration"))
    runner.cli(["--run-registered", str(tmp_path)])
    assert calls == ["integrity", "supervise"]
    assert (tmp_path / "registration.json").read_bytes() == original
    assert not (tmp_path / "manifest.json").exists()


def test_registered_dsh_execution_reaches_preflight_after_integrity_without_workers(tmp_path, monkeypatch):
    registration = execution_registration(tmp_path)
    write_json(tmp_path / "registration.json", registration)
    original = (tmp_path / "registration.json").read_bytes()
    monkeypatch.setattr(runner.sys, "path", list(runner.sys.path))
    calls = []
    def integrity(*_args):
        calls.append("integrity")
        return {"unchanged": True}
    def probe(**_kwargs):
        assert runner.sys.path[0] == str(tmp_path / "frozen")
        calls.append("probe")
        return capability_observation(available=False)
    monkeypatch.setattr(runner, "integrity", integrity)
    install_offline_probe(monkeypatch, probe)
    monkeypatch.setattr(runner, "register", lambda *_a, **_k: pytest.fail("must not register again"))
    monkeypatch.setattr(runner, "ThreadPoolExecutor", lambda **_kwargs: pytest.fail("no workers with missing SDK"))
    with pytest.raises(SystemExit) as error:
        runner.cli(["--run-registered", str(tmp_path)])
    assert error.value.code == 2 and calls == ["integrity", "probe"]
    assert (tmp_path / "registration.json").read_bytes() == original
    assert runner.read(tmp_path / "dependency_preflight.json")["status"] == "static_unavailable"


@pytest.mark.parametrize("failed_check", ["current", "frozen", "target", "backend"])
def test_run_registered_checks_every_integrity_result_before_execution(tmp_path, monkeypatch, failed_check):
    write_json(tmp_path / "registration.json", execution_registration(tmp_path))
    checks = {name: name != failed_check for name in ("current", "frozen", "target", "backend")}
    monkeypatch.setattr(runner, "integrity", lambda *_args: checks)
    monkeypatch.setattr(runner, "supervise", lambda *_args: pytest.fail("changed registration must not run"))
    with pytest.raises(SystemExit) as error:
        runner.cli(["--run-registered", str(tmp_path)])
    assert error.value.code == 2


@pytest.mark.parametrize("override", [["--register-only"], ["--worker", "unused"], ["--output", "unused"],
    ["--freeze-current"], ["--dsh-profile", "unused.json"], ["--agent-backend", "native"],
    ["--workers", "2"], ["--cases", "owned_return"], ["--index", "0"], ["--agent-timeout", "60"]])
def test_run_registered_rejects_explicit_overrides_even_matching_defaults(tmp_path, monkeypatch, override):
    monkeypatch.setattr(runner, "read", lambda *_args: pytest.fail("overrides must fail before reading registration"))
    with pytest.raises(SystemExit) as error:
        runner.cli(["--run-registered", str(tmp_path), *override])
    assert error.value.code == 2


@pytest.mark.parametrize("started", ["trial", "log", "progress.json", "completion_audit.json"])
def test_run_registered_cannot_repeat_started_trials(tmp_path, monkeypatch, started):
    registration = execution_registration(tmp_path)
    write_json(tmp_path / "registration.json", registration)
    identity = registration["schedule"][0]
    if started == "trial":
        Path(identity["trial_dir"]).mkdir()
    else:
        name = identity["trial_id"] + ".log" if started == "log" else started
        (tmp_path / name).write_text("already started\n")
    monkeypatch.setattr(runner, "integrity", lambda *_args: {"unchanged": True})
    monkeypatch.setattr(runner, "supervise", lambda *_args: pytest.fail("failed trials cannot be silently repeated"))
    with pytest.raises(SystemExit) as error:
        runner.cli(["--run-registered", str(tmp_path)])
    assert error.value.code == 2


def test_register_only_cannot_be_combined_with_worker(tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "worker", lambda *_args: pytest.fail("review mode cannot execute a worker"))
    with pytest.raises(SystemExit):
        runner.cli(["--register-only", "--worker", str(tmp_path), "--index", "0"])


@pytest.mark.parametrize("registration", [{}, {"context_agent_backend": {"name": "native"}}])
def test_native_preflight_never_reads_optional_distribution_metadata(tmp_path, monkeypatch, registration):
    install_offline_probe(monkeypatch, lambda **_kwargs: pytest.fail("native never probes optional SDK dependencies"))
    assert runner.dependency_preflight(tmp_path, registration) is None
    assert list(tmp_path.iterdir()) == []


def test_supervisor_missing_dependency_prevents_all_worker_creation(tmp_path, monkeypatch):
    registration = execution_registration(tmp_path)
    install_offline_probe(monkeypatch, lambda **_kwargs: capability_observation(available=False))
    monkeypatch.setattr(runner, "ThreadPoolExecutor", lambda **_kwargs: pytest.fail("no pool before capability"))
    monkeypatch.setattr(runner.subprocess, "run", lambda *_a, **_k: pytest.fail("no worker process before capability"))
    with pytest.raises(runner.CapabilityPreflightError, match="dsh_dependency_missing"):
        runner.supervise(tmp_path, registration)
    failure = runner.read(tmp_path / "execution_preflight_failed.json")
    assert failure["execution_started"] is False and failure["worker_subprocesses_started"] == 0
    assert failure["provider_requests"] == 0
    assert not Path(registration["schedule"][0]["trial_dir"]).exists()
    assert len(list((tmp_path / "dependency_preflight_history/supervisor").glob("attempt_*.json"))) == 1


def test_supervisor_static_preflight_precedes_threadpool_creation(tmp_path, monkeypatch):
    registration = execution_registration(tmp_path)
    calls = []
    def probe(**kwargs):
        assert kwargs == {"expected_sdk_version": "0.1.5rc1", "expected_runtime_version": "0.1.5rc1"}
        calls.append("probe")
        return capability_observation()
    class StopBeforeWorkers(Exception):
        pass
    def pool(**_kwargs):
        assert runner.read(tmp_path / "dependency_preflight.json")["status"] == "static_ready"
        calls.append("pool")
        raise StopBeforeWorkers
    install_offline_probe(monkeypatch, probe)
    monkeypatch.setattr(runner, "ThreadPoolExecutor", pool)
    with pytest.raises(StopBeforeWorkers):
        runner.supervise(tmp_path, registration)
    assert calls == ["probe", "pool"]


def test_worker_preflight_failure_precedes_project_imports_and_model_stages(tmp_path, monkeypatch):
    registration = execution_registration(tmp_path)
    identity = registration["schedule"][0]
    write_json(tmp_path / "registration.json", registration)
    monkeypatch.setattr(runner.sys, "path", list(runner.sys.path))
    monkeypatch.setattr(runner, "integrity", lambda *_args: {"unchanged": True})
    install_offline_probe(monkeypatch, lambda **_kwargs: capability_observation(available=False))
    for name in ("harness_generation.artifacts", "harness_generation.cli", "sfg_builder.parser"):
        monkeypatch.setitem(sys.modules, name, SimpleNamespace())
    with pytest.raises(runner.CapabilityPreflightError, match="dsh_dependency_missing"):
        runner.worker(tmp_path, 0)
    receipt = runner.read(tmp_path / (identity["trial_id"] + "_dependency_preflight.json"))
    assert receipt["scope"] == "worker" and receipt["trial_id"] == identity["trial_id"]
    assert not Path(identity["trial_dir"]).exists()
    assert not (tmp_path / (identity["trial_id"] + ".log")).exists()


def test_preflight_errors_have_safe_categories_and_preserve_attempt_history(tmp_path, monkeypatch):
    registration = execution_registration(tmp_path)
    def private_error(**_kwargs):
        raise OSError("/private/path Authorization=Bearer private-secret")
    install_offline_probe(monkeypatch, private_error)
    with pytest.raises(runner.CapabilityPreflightError) as error:
        runner.dependency_preflight(tmp_path, registration)
    assert error.value.category == "dsh_preflight_implementation_error"
    failed_path = tmp_path / "dependency_preflight_history/supervisor/attempt_0001.json"
    original = failed_path.read_bytes()
    assert "private" not in original.decode() and "private" not in str(error.value)
    install_offline_probe(monkeypatch, lambda **_kwargs: capability_observation())
    runner.dependency_preflight(tmp_path, registration)
    assert failed_path.read_bytes() == original
    assert runner.read(tmp_path / "dependency_preflight_history/supervisor/attempt_0002.json")["status"] == "static_ready"
    assert runner.read(tmp_path / "dependency_preflight.json")["runtime_started"] is False


@pytest.mark.parametrize("available", [True, False])
def test_auditor_validates_static_preflight_receipts_without_probing(tmp_path, monkeypatch, available):
    registration = execution_registration(tmp_path)
    identity = registration["schedule"][0]
    install_offline_probe(monkeypatch, lambda **_kwargs: capability_observation(available=available))
    if available:
        runner.dependency_preflight(tmp_path, registration, identity=identity)
    else:
        with pytest.raises(runner.CapabilityPreflightError):
            runner.dependency_preflight(tmp_path, registration, identity=identity)
    install_offline_probe(monkeypatch, lambda **_kwargs: pytest.fail("auditor must only read persisted observations"))
    path = tmp_path / (identity["trial_id"] + "_dependency_preflight.json")
    checks, observed = auditor.dependency_preflight_checks(path, registration,
        scope="worker", trial_id=identity["trial_id"], required=True)
    assert all(checks.values()) and observed["static_capability_available"] is available
    assert observed["runtime_started"] is False


@pytest.mark.parametrize("field,value", [("production_fingerprint", "wrong"),
    ("context_agent_backend_fingerprint", "wrong"), ("trial_id", "wrong"), ("scope", "supervisor"),
    ("runtime_carrier", "wrong"), ("sdk_version", "wrong"), ("runtime_version", "wrong"),
    ("provider_requests", False), ("runtime_started", True), ("optional_sdk_imported", True)])
def test_auditor_rejects_rehashed_receipt_identity_and_runtime_claims(tmp_path, monkeypatch, field, value):
    registration = execution_registration(tmp_path)
    identity = registration["schedule"][0]
    install_offline_probe(monkeypatch, lambda **_kwargs: capability_observation())
    receipt = runner.dependency_preflight(tmp_path, registration, identity=identity)
    receipt[field] = value
    receipt["record_fingerprint"] = auditor.digest({key: item for key, item in receipt.items() if key != "record_fingerprint"})
    path = tmp_path / (identity["trial_id"] + "_dependency_preflight.json")
    write_json(path, receipt)
    checks, _observed = auditor.dependency_preflight_checks(path, registration,
        scope="worker", trial_id=identity["trial_id"], required=True)
    assert not all(checks.values())


def test_auditor_missing_required_worker_receipt_is_not_a_success(tmp_path):
    registration = execution_registration(tmp_path)
    checks, observed = auditor.dependency_preflight_checks(tmp_path / "absent.json", registration,
        scope="worker", trial_id="owned_return_r01", required=True)
    assert observed is None and checks == {"preflight:worker:observed": False}
    checks, observed = auditor.dependency_preflight_checks(tmp_path / "absent.json", registration,
        scope="supervisor")
    assert observed is None and checks == {}  # Historical registries do not require this receipt.


@pytest.mark.parametrize("contradiction", ["passed", "stage_exit", "stage_entry", "artifact", "response", "unknown", "model", "tool"])
def test_failed_preflight_cannot_coexist_with_pipeline_success_or_paid_observations(contradiction):
    record = {"status": "dependency_preflight_failed", "stage_exits": {}}
    costs = {"observed_provider_request_attempts": 0, "unknown_request_attempts": 0,
        "observed_agent_model_calls": {}, "upstream_trace_tool_calls": {}}
    if contradiction == "passed":
        record["status"] = "passed"
    elif contradiction == "stage_exit":
        record["stage_exits"] = {"candidates": 0}
    elif contradiction == "response":
        costs["observed_provider_request_attempts"] = 1
    elif contradiction == "unknown":
        costs["unknown_request_attempts"] = 1
    elif contradiction == "model":
        costs["observed_agent_model_calls"] = {"candidate": 1}
    elif contradiction == "tool":
        costs["upstream_trace_tool_calls"] = {"candidate": 1}
    checks = auditor.failed_preflight_execution_checks(capability_observation(available=False), record, costs,
        stage_entered=contradiction == "stage_entry", paid_artifacts=contradiction == "artifact")
    assert not all(checks.values())


def test_legitimate_failed_preflight_is_valid_failure_evidence(tmp_path, monkeypatch):
    registration = execution_registration(tmp_path)
    identity = registration["schedule"][0]
    install_offline_probe(monkeypatch, lambda **_kwargs: capability_observation(available=False))
    with pytest.raises(runner.CapabilityPreflightError):
        runner.dependency_preflight(tmp_path, registration, identity=identity)
    write_json(Path(identity["trial_dir"]) / "supervisor.json", {**identity,
        "status": "dependency_preflight_failed", "production_fingerprint": registration["production_fingerprint"],
        "context_agent_backend": registration["context_agent_backend"], "fresh": True,
        "resume": False, "failed_retry": False, "stage_exits": {}, "integrity": {"unchanged": True}})
    audited = auditor.audit_trial(identity, registration)
    assert audited["status"] == "dependency_preflight_failed"
    assert audited["costs"]["observed_provider_request_attempts"] == 0
    assert all(value for key, value in audited["checks"].items() if key.startswith("preflight:"))
    assert not audited["pipeline_execution_observation"]["stage_entered"]
