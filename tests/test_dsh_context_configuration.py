"""Offline bridge/profile/cache checks; no DSH runtime or provider is started."""
from types import SimpleNamespace

import pytest

from harness_generation.harness_context.cli import main
from harness_generation.harness_context.dsh_config import (
    BACKEND_NAME, DEFAULT_DSH_PROFILE, MAX_PROFILE_BYTES,
    load_dsh_profile, normalize_dsh_profile, profile_sha256,
)
from harness_generation.harness_context.models import ContextBudget
from harness_generation.harness_context.persistence import run_configuration
from harness_generation.semantic_discovery.models import digest


def _configuration(*, backend=None, budget=None):
    return run_configuration({"policy_version": "fixture-ft"}, {},
        SimpleNamespace(source_fingerprint="fixture-source", functions_fingerprint="fixture-functions"),
        budget or ContextBudget(), SimpleNamespace(provider="offline", model="offline"),
        investigation_backend=backend)


class DescriptorBackend:
    def __init__(self, *, budget=None):
        self.value = {"name": BACKEND_NAME, "budget": (budget or ContextBudget()).to_dict(),
            "sdk_version": "fixture-sdk", "runtime_version": "fixture-runtime",
            "plugin_sha256": "1" * 64, "guidance_sha256": "2" * 64,
            "bridge_policy": "fixture-bridge", "profile": load_dsh_profile(),
            "profile_sha256": profile_sha256(load_dsh_profile())}

    def descriptor(self):
        return self.value


def test_default_profile_and_effective_digest_are_explicit_and_independent():
    first, second = load_dsh_profile(), load_dsh_profile()
    assert first == DEFAULT_DSH_PROFILE
    first["max_prompt_chars"] = 123
    assert second["max_prompt_chars"] == 400000
    assert profile_sha256({}) == profile_sha256(second)
    assert profile_sha256({"request_timeout_seconds": 180}) == profile_sha256({"request_timeout_seconds": 180.0})
    assert profile_sha256({"max_prompt_chars": 123}) != profile_sha256(second)


def test_profile_file_merges_only_allowlisted_limits(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text('{"max_response_chars": 8192}', encoding="utf-8")
    value = load_dsh_profile(path)
    assert value["max_response_chars"] == 8192
    assert set(value) == set(DEFAULT_DSH_PROFILE)


@pytest.mark.parametrize("value", [None, [], {"api_key": "do-not-print"}, {"plugins": []},
    {"provider": {}}, {"max_total_model_calls": 99},
    {"max_prompt_chars": True}, {"max_prompt_chars": 1.5}, {"max_prompt_chars": 0},
    {"max_prompt_chars": 2000001}, {"max_response_chars": -1}, {"max_session_events": 65537},
    {"max_event_chars": 16000001}, {"request_timeout_seconds": True},
    {"request_timeout_seconds": float("nan")}, {"request_timeout_seconds": float("inf")},
    {"request_timeout_seconds": 3601}, {"request_timeout_seconds": 10 ** 1000}])
def test_profile_rejects_runtime_extensions_and_unbounded_limits_without_values(value):
    with pytest.raises(ValueError) as caught:
        normalize_dsh_profile(value)
    assert "do-not-print" not in str(caught.value)


@pytest.mark.parametrize("raw", [b'{"max_prompt_chars":1,"max_prompt_chars":2}', b"\xff", b"{",
    b" " * (MAX_PROFILE_BYTES + 1)])
def test_profile_rejects_ambiguous_invalid_or_oversized_files(tmp_path, raw):
    path = tmp_path / "profile.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        load_dsh_profile(path)


def test_native_configuration_retains_legacy_shape():
    value = _configuration()
    assert "agent_backend" not in value
    assert value["budget"] == ContextBudget().to_dict()
    assert value["model"] == {"provider": "offline", "model": "offline"}


def test_backend_descriptor_is_copied_and_every_identity_change_invalidates_cache():
    backend = DescriptorBackend()
    original = _configuration(backend=backend)
    assert original["agent_backend"] == backend.value
    for field in ("sdk_version", "runtime_version", "plugin_sha256", "guidance_sha256", "bridge_policy"):
        changed = DescriptorBackend()
        changed.value[field] += "different"
        assert digest(_configuration(backend=changed)) != digest(original)
    changed = DescriptorBackend()
    changed.value["profile"] = normalize_dsh_profile({"max_prompt_chars": 123})
    changed.value["profile_sha256"] = profile_sha256(changed.value["profile"])
    assert digest(_configuration(backend=changed)) != digest(original)
    backend.value["budget"]["max_tool_calls"] = 1
    assert original["agent_backend"]["budget"]["max_tool_calls"] == 64


def test_descriptor_cannot_hide_a_different_context_budget():
    backend = DescriptorBackend(budget=ContextBudget(max_tool_calls=65))
    with pytest.raises(ValueError, match="does not match the Context budget"):
        _configuration(backend=backend)
    backend.value["budget"] = ContextBudget().to_dict()
    backend.value["name"] = "unregistered-backend"
    with pytest.raises(ValueError, match="does not match the Context budget"):
        _configuration(backend=backend)


class InjectedModel:
    provider = model = "offline"

    def complete(self, *_):
        raise AssertionError("argument rejection must precede any model request")


@pytest.mark.parametrize("extra", [["--dsh-profile", "never-read.json"],
    ["--agent-backend", BACKEND_NAME]])
def test_cli_rejects_backend_profile_and_injected_model_conflicts_before_artifacts(tmp_path, extra):
    artifacts = tmp_path / "not-created"
    assert main(["--artifacts", str(artifacts), *extra], model=InjectedModel()) == 1
    assert not artifacts.exists()


def test_dsh_help_does_not_import_optional_backend_or_sdk(monkeypatch):
    import builtins
    original_import = builtins.__import__
    def guarded_import(name, *args, **kwargs):
        assert not (name == "dsh_backend" or name.startswith("deepseek_harness"))
        return original_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", guarded_import)
    with pytest.raises(SystemExit) as caught:
        main(["--artifacts", "/not-read", "--agent-backend", BACKEND_NAME, "--help"])
    assert caught.value.code == 0
