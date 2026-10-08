"""Static capability checks for the pinned SDK and its bundled executable.

Only installed distribution metadata and files are inspected. This module never
imports the optional SDK/runtime, launches a process, or contacts a provider.
Successful checks establish payload availability; startup remains untested.
The locator layout matches upstream 0.1.5rc1's bundled_runtime_path().
"""
from __future__ import annotations

from importlib import metadata
import os
from pathlib import Path
import platform
import sys


VERSION = "dsh-static-capability-preflight-v1"
SDK_VERSION = "0.1.5rc1"
SDK_PACKAGE = "deepseek-harness-sdk"
RUNTIME_PACKAGE = "deepseek-harness-runtime-bin"
_PLATFORMS = {"linux": "linux", "darwin": "macos", "win32": "win"}
_ARCHITECTURES = {"x86_64": "x64", "amd64": "x64", "arm64": "arm64", "aarch64": "arm64"}
_SDK_MODULES = ("__init__.py", "api.py", "client.py", "errors.py", "models.py")


class _Unavailable(Exception):
    def __init__(self, category, *, package=None, role=None):
        self.category, self.package, self.role = category, package, role


def _inventory(package):
    try:
        distribution = metadata.distribution(package)
        installed = distribution.version
    except metadata.PackageNotFoundError:
        raise _Unavailable("dsh_dependency_missing", package=package) from None
    except Exception:
        raise _Unavailable("dsh_dependency_metadata_error", package=package) from None
    if installed != SDK_VERSION:
        raise _Unavailable("dsh_dependency_version_mismatch", package=package)
    try:
        files = distribution.files
        if files is None:
            raise _Unavailable("dsh_dependency_inventory_unavailable", package=package)
        inventory = {str(item).replace("\\", "/"): item for item in files}
    except _Unavailable:
        raise
    except Exception:
        raise _Unavailable("dsh_dependency_inventory_unavailable", package=package) from None
    return distribution, inventory


def _payload(distribution, inventory, relative, *, package, role, missing_category,
             executable=False, observations):
    item = inventory.get(relative)
    entry = {"package": package, "role": role, "available": False,
        "readable": False, "executable": None}
    observations.append(entry)
    if item is None:
        raise _Unavailable(missing_category, package=package, role=role)
    try:
        path = Path(distribution.locate_file(item))
        entry["available"] = path.is_file()
        if not entry["available"]:
            raise _Unavailable(missing_category, package=package, role=role)
        entry["readable"] = os.access(path, os.R_OK)
        if not entry["readable"]:
            raise _Unavailable("dsh_dependency_payload_unreadable", package=package, role=role)
        if executable:
            # Windows launch permissions differ from POSIX mode bits. The
            # published carrier uses a .exe payload and matching wheel tag.
            entry["executable"] = sys.platform == "win32" or os.access(path, os.X_OK)
            if not entry["executable"]:
                raise _Unavailable("dsh_runtime_payload_not_executable", package=package, role=role)
    except _Unavailable:
        raise
    except Exception:
        raise _Unavailable("dsh_dependency_payload_unreadable", package=package, role=role) from None


def probe_dsh_dependencies(*, expected_sdk_version=SDK_VERSION, expected_runtime_version=SDK_VERSION):
    """Return a secret-free static observation, including safe failure categories.

    Neither supplied metadata values nor installation paths enter the result.
    The runtime package marker is checked for existence, as the official locator
    does; its development JSON version is not the distribution release pin.
    """
    result = {"schema_version": 1, "policy_version": VERSION,
        "status": "static_unavailable", "static_capability_available": False,
        "sdk_version": SDK_VERSION, "runtime_version": SDK_VERSION,
        "runtime_carrier": "bundled-exe", "platform": None,
        "checks": {}, "payload_observations": [], "error_category": None,
        "runtime_started": False, "optional_sdk_imported": False, "provider_requests": 0}
    try:
        if expected_sdk_version != SDK_VERSION or expected_runtime_version != SDK_VERSION:
            raise _Unavailable("dsh_registered_dependency_pin_mismatch")
        sdk, sdk_inventory = _inventory(SDK_PACKAGE)
        result["checks"]["sdk_pinned_distribution"] = True
        runtime, runtime_inventory = _inventory(RUNTIME_PACKAGE)
        result["checks"]["runtime_pinned_distribution"] = True
        operating_system = _PLATFORMS.get(sys.platform)
        architecture = _ARCHITECTURES.get(platform.machine().lower())
        if (operating_system is None or architecture is None
                or operating_system == "win" and architecture != "x64"):
            raise _Unavailable("dsh_runtime_platform_unsupported")
        tag = f"{operating_system}-{architecture}"
        result["platform"] = tag
        result["checks"]["supported_platform"] = True
        for filename in _SDK_MODULES:
            _payload(sdk, sdk_inventory, "deepseek_harness/" + filename,
                package=SDK_PACKAGE, role="sdk_" + filename.removesuffix(".py"),
                missing_category="dsh_sdk_payload_missing", observations=result["payload_observations"])
        _payload(runtime, runtime_inventory, "deepseek_harness_runtime/__init__.py",
            package=RUNTIME_PACKAGE, role="runtime_module", missing_category="dsh_runtime_payload_missing",
            observations=result["payload_observations"])
        _payload(runtime, runtime_inventory, "deepseek_harness_runtime/deepseek-harness-runtime.json",
            package=RUNTIME_PACKAGE, role="runtime_package_marker", missing_category="dsh_runtime_marker_missing",
            observations=result["payload_observations"])
        extension = ".exe" if tag.startswith("win-") else ""
        executable = f"deepseek-harness-sdk-runtime-{tag}{extension}"
        runtime_files = [(executable, "runtime_executable", "dsh_runtime_executable_missing"),
            (executable.removesuffix(".exe") + "-rg.exe" if extension else executable + "-rg",
                "ripgrep_sidecar", "dsh_runtime_ripgrep_missing")]
        if tag.startswith("macos-"):
            runtime_files.append((executable + "-spawn-helper", "spawn_helper", "dsh_runtime_spawn_helper_missing"))
        for filename, role, missing_category in runtime_files:
            _payload(runtime, runtime_inventory, "deepseek_harness_runtime/runtime/" + filename,
                package=RUNTIME_PACKAGE, role=role, missing_category=missing_category,
                executable=True, observations=result["payload_observations"])
        result.update(status="static_ready", static_capability_available=True)
    except _Unavailable as error:
        result["error_category"] = error.category
        if error.package:
            result["failed_package"] = error.package
        if error.role:
            result["failed_role"] = error.role
    except Exception:
        # Installed metadata providers and filesystem errors can contain
        # private installation paths; preserve only a controlled category.
        result["error_category"] = "dsh_dependency_metadata_error"
    return result
