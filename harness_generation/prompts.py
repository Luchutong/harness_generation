"""Shared rendered prompt record for frozen Context translation."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from .records import write_json

@dataclass(frozen=True)
class RenderedPrompt:
    """A concrete, auditable prompt produced from a versioned template."""

    name: str
    prompt_version: str
    content: str
    parameters: Mapping[str, Any]

    def __str__(self) -> str:
        return self.content

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "prompt_version": self.prompt_version,
            "content": self.content,
            "parameters": dict(self.parameters),
        }

    def save(self, path: str | Path) -> None:
        """Save the rendered prompt and its version as stable JSON."""

        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_json(destination, self.to_dict(), sort_keys=True, allow_nan=False)
