"""Optional declarative protocol contracts for harness prompts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


PROTOCOL_SPEC_SCHEMA_VERSION = 1
DISCOVERY_FILENAMES = ("{stem}.protocol.json", "protocol.json", "protocol_spec.json")


class ProtocolSpecError(ValueError):
    """Raised when a supplied protocol contract is malformed."""


def discover_protocol_spec(source: str | Path) -> Path | None:
    """Find a protocol spec colocated with a target source, if one exists."""

    path = Path(source)
    for pattern in DISCOVERY_FILENAMES:
        candidate = path.parent / pattern.format(stem=path.stem)
        if candidate.is_file():
            return candidate
    return None


def load_protocol_spec(path: str | Path, function: str | None = None) -> dict[str, Any]:
    """Load and minimally validate an LLM-facing protocol contract.

    The contract is intentionally user-supplied or benchmark-supplied.  It is
    not inferred from source comments, and it is kept as data so prompts can
    tell the model exactly which protocol fields to preserve.
    """

    location = Path(path)
    try:
        document = json.loads(location.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProtocolSpecError(
            f"could not read protocol spec {location}: {type(error).__name__}"
        ) from None
    if not isinstance(document, Mapping):
        raise ProtocolSpecError("protocol spec must be a JSON object")
    if document.get("schema_version") != PROTOCOL_SPEC_SCHEMA_VERSION:
        raise ProtocolSpecError("protocol spec requires schema_version 1")
    entry = document.get("entry_function")
    if not isinstance(entry, str) or not entry:
        raise ProtocolSpecError("protocol spec requires entry_function")
    if function is not None and entry != function:
        raise ProtocolSpecError(
            f"protocol spec entry_function {entry!r} does not match {function!r}"
        )
    contract = document.get("contract")
    if not isinstance(contract, Mapping):
        raise ProtocolSpecError("protocol spec requires a contract object")
    result = {
        "schema_version": PROTOCOL_SPEC_SCHEMA_VERSION,
        "source": location.name,
        "entry_function": entry,
        "contract": dict(contract),
    }
    for optional in ("requirements", "notes"):
        value = document.get(optional)
        if value is not None:
            if not isinstance(value, list) or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                raise ProtocolSpecError(f"protocol spec {optional} must be strings")
            result[optional] = list(value)
    return result
