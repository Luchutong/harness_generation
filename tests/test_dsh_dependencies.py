"""Offline definitions for SDK-free static dependency preflight.

Fixtures represent installed wheel inventories. They never import or launch an
optional SDK, execute its payloads, or contact a model/provider.
"""
import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from harness_generation.harness_context import dsh_dependencies as dependencies


def distributions(tmp_path, monkeypatch, *, system="linux", machine="x86_64", version="0.1.5rc1"):
    monkeypatch.setattr(dependencies.sys, "platform", system)
    monkeypatch.setattr(dependencies.platform, "machine", lambda: machine)
    monkeypatch.setattr(dependencies.os, "access", lambda _path, _mode: True)
    tag = {"linux": "linux", "darwin": "macos", "win32": "win"}.get(system, "unsupported")
    architecture = "arm64" if machine.lower() in {"arm64", "aarch64"} else "x64"
    executable = f"deepseek-harness-sdk-runtime-{tag}-{architecture}" + (".exe" if system == "win32" else "")
    sdk_files = ["deepseek_harness/" + name for name in ("__init__.py", "api.py", "client.py", "errors.py", "models.py")]
    runtime_files = ["deepseek_harness_runtime/__init__.py", "deepseek_harness_runtime/deepseek-harness-runtime.json",
        "deepseek_harness_runtime/runtime/" + executable,
        "deepseek_harness_runtime/runtime/" + (executable.removesuffix(".exe") + "-rg.exe" if system == "win32" else executable + "-rg")]
    if system == "darwin":
        runtime_files.append("deepseek_harness_runtime/runtime/" + executable + "-spawn-helper")
    records = {}
    for package, inventory in ((dependencies.SDK_PACKAGE, sdk_files), (dependencies.RUNTIME_PACKAGE, runtime_files)):
        root = tmp_path / package
        for relative in inventory:
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("unexecuted payload\n")
        records[package] = SimpleNamespace(version=version, files=inventory,
            locate_file=lambda relative, root=root: root / relative)
    monkeypatch.setattr(dependencies.metadata, "distribution", lambda name: records[name])
    return records


@pytest.mark.parametrize("system,machine,tag", [("linux", "x86_64", "linux-x64"),
    ("linux", "aarch64", "linux-arm64"), ("darwin", "arm64", "macos-arm64"),
    ("darwin", "x86_64", "macos-x64"), ("win32", "AMD64", "win-x64")])
def test_published_platform_payloads_are_static_ready(tmp_path, monkeypatch, system, machine, tag):
    distributions(tmp_path, monkeypatch, system=system, machine=machine)
    result = dependencies.probe_dsh_dependencies()
    assert result["status"] == "static_ready" and result["static_capability_available"] is True
    assert result["platform"] == tag and result["runtime_carrier"] == "bundled-exe"
    assert result["runtime_started"] is False and result["optional_sdk_imported"] is False
    assert result["provider_requests"] == 0
    assert str(tmp_path) not in json.dumps(result)


def test_missing_distribution_has_a_safe_controlled_category(monkeypatch):
    def absent(name):
        raise dependencies.metadata.PackageNotFoundError("private/path/API_KEY=private-credential")
    monkeypatch.setattr(dependencies.metadata, "distribution", absent)
    result = dependencies.probe_dsh_dependencies()
    assert result["error_category"] == "dsh_dependency_missing"
    assert result["failed_package"] == dependencies.SDK_PACKAGE
    assert "private" not in json.dumps(result)


def test_wrong_distribution_version_does_not_expose_its_value(tmp_path, monkeypatch):
    distributions(tmp_path, monkeypatch, version="Bearer private-secret")
    result = dependencies.probe_dsh_dependencies()
    assert result["error_category"] == "dsh_dependency_version_mismatch"
    assert "private-secret" not in json.dumps(result)


def test_changed_registration_pin_is_rejected_without_inspecting_packages(monkeypatch):
    monkeypatch.setattr(dependencies.metadata, "distribution", lambda _: pytest.fail("must reject unknown pins first"))
    result = dependencies.probe_dsh_dependencies(expected_sdk_version="private-secret")
    assert result["error_category"] == "dsh_registered_dependency_pin_mismatch"
    assert "private-secret" not in json.dumps(result)


@pytest.mark.parametrize("system,machine", [("freebsd", "x86_64"), ("win32", "ARM64"), ("linux", "riscv64")])
def test_unsupported_platform_is_explicit_without_exposing_machine_values(tmp_path, monkeypatch, system, machine):
    distributions(tmp_path, monkeypatch, system=system, machine=machine)
    result = dependencies.probe_dsh_dependencies()
    assert result["error_category"] == "dsh_runtime_platform_unsupported"
    assert result["platform"] is None and result["runtime_started"] is False


@pytest.mark.parametrize("role,category", [("exe", "dsh_runtime_executable_missing"),
    ("rg", "dsh_runtime_ripgrep_missing"), ("marker", "dsh_runtime_marker_missing"),
    ("sdk", "dsh_sdk_payload_missing")])
def test_missing_payload_categories_precede_any_runtime_launch(tmp_path, monkeypatch, role, category):
    records = distributions(tmp_path, monkeypatch)
    sdk, runtime = records[dependencies.SDK_PACKAGE], records[dependencies.RUNTIME_PACKAGE]
    relative = {"exe": "deepseek_harness_runtime/runtime/deepseek-harness-sdk-runtime-linux-x64",
        "rg": "deepseek_harness_runtime/runtime/deepseek-harness-sdk-runtime-linux-x64-rg",
        "marker": "deepseek_harness_runtime/deepseek-harness-runtime.json", "sdk": "deepseek_harness/client.py"}[role]
    distribution = sdk if role == "sdk" else runtime
    distribution.locate_file(relative).unlink()
    result = dependencies.probe_dsh_dependencies()
    assert result["error_category"] == category
    assert result["static_capability_available"] is False and result["provider_requests"] == 0


def test_macos_requires_the_official_spawn_helper(tmp_path, monkeypatch):
    records = distributions(tmp_path, monkeypatch, system="darwin", machine="arm64")
    records[dependencies.RUNTIME_PACKAGE].locate_file(
        "deepseek_harness_runtime/runtime/deepseek-harness-sdk-runtime-macos-arm64-spawn-helper").unlink()
    assert dependencies.probe_dsh_dependencies()["error_category"] == "dsh_runtime_spawn_helper_missing"


def test_posix_executable_permission_is_checked_without_running_the_file(tmp_path, monkeypatch):
    distributions(tmp_path, monkeypatch)
    monkeypatch.setattr(dependencies.os, "access", lambda _path, mode: mode != dependencies.os.X_OK)
    result = dependencies.probe_dsh_dependencies()
    assert result["error_category"] == "dsh_runtime_payload_not_executable"
    assert result["failed_role"] == "runtime_executable"


def test_unavailable_wheel_inventory_and_private_metadata_errors_are_safe(tmp_path, monkeypatch):
    records = distributions(tmp_path, monkeypatch)
    records[dependencies.RUNTIME_PACKAGE].files = None
    assert dependencies.probe_dsh_dependencies()["error_category"] == "dsh_dependency_inventory_unavailable"
    monkeypatch.setattr(dependencies.metadata, "distribution", lambda _: (_ for _ in ()).throw(
        OSError("private/path Authorization=Bearer private-secret")))
    result = dependencies.probe_dsh_dependencies()
    assert result["error_category"] == "dsh_dependency_metadata_error"
    assert "private" not in json.dumps(result)


def test_official_development_package_marker_is_not_confused_with_distribution_pin(tmp_path, monkeypatch):
    records = distributions(tmp_path, monkeypatch)
    records[dependencies.RUNTIME_PACKAGE].locate_file("deepseek_harness_runtime/deepseek-harness-runtime.json").write_text(
        '{"name":"deepseek-harness-runtime-bin","version":"0.0.0-dev"}')
    assert dependencies.probe_dsh_dependencies()["status"] == "static_ready"


def test_dependency_module_has_only_standard_library_imports():
    source = Path(dependencies.__file__).read_text()
    tree = ast.parse(source)
    imported = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    imported += [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
    assert set(imported) <= {"__future__", "importlib", "os", "pathlib", "platform", "sys"}
    assert not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"Popen", "run", "start_session"} for node in ast.walk(tree))
