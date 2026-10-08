"""Secret-free, bounded configuration for the optional Context investigation bridge.

This module deliberately imports neither the DSH SDK nor its runtime. Profiles
configure bridge limits, while the existing Context budget controls all model
requests, repository tools, source reads and repair attempts.
"""
from __future__ import annotations

from hashlib import sha256
import json
import math
from pathlib import Path


BACKEND_NAME = "deepseek-harness"
PROFILE_VERSION = "dsh-context-profile-v1"
BRIDGE_POLICY_VERSION = "dsh-context-bridge-v3"
MAX_PROFILE_BYTES = 32768

DEFAULT_DSH_PROFILE = {
    "max_prompt_chars": 400000,
    "max_response_chars": 64000,
    "max_session_events": 4096,
    "max_event_chars": 1000000,
    "request_timeout_seconds": 180,
}
_INTEGER_LIMITS = {
    "max_prompt_chars": 2000000,
    "max_response_chars": 1000000,
    "max_session_events": 65536,
    "max_event_chars": 16000000,
}
_MAX_REQUEST_TIMEOUT_SECONDS = 3600


def normalize_dsh_profile(value):
    """Return all explicit bridge limits without accepting runtime extensions."""
    if not isinstance(value, dict):
        raise ValueError("DSH profile must be a JSON object")
    if set(value) - set(DEFAULT_DSH_PROFILE):
        raise ValueError("DSH profile contains unsupported fields")
    result = {**DEFAULT_DSH_PROFILE, **value}
    for name, maximum in _INTEGER_LIMITS.items():
        limit = result[name]
        if type(limit) is not int or not 1 <= limit <= maximum:
            raise ValueError(f"DSH profile {name} must be an integer between 1 and {maximum}")
    timeout = result["request_timeout_seconds"]
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not 0 < timeout <= _MAX_REQUEST_TIMEOUT_SECONDS or not math.isfinite(timeout)):
        raise ValueError("DSH profile request_timeout_seconds must be finite, positive and at most 3600")
    # Equal timeout values must have the same cache identity, whether JSON used
    # an integer or a decimal representation.
    result["request_timeout_seconds"] = float(timeout)
    return result


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("DSH profile contains duplicate JSON fields")
        result[key] = value
    return result


def load_dsh_profile(profile_path=None):
    """Read a small allowlisted JSON profile; never import or start the SDK."""
    if profile_path is None:
        return normalize_dsh_profile({})
    path = Path(profile_path)
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_PROFILE_BYTES + 1)
    except OSError:
        raise ValueError("cannot read DSH profile") from None
    if len(raw) > MAX_PROFILE_BYTES:
        raise ValueError("DSH profile exceeds the 32768 byte limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("DSH profile must contain valid UTF-8 JSON") from None
    return normalize_dsh_profile(value)


def profile_sha256(profile):
    """Bind effective defaults and overrides to the immutable run descriptor."""
    encoded = json.dumps(normalize_dsh_profile(profile), sort_keys=True,
        separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return sha256(encoded).hexdigest()
