"""Portable resolution of source paths stored in functions artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


SUPPORTED_FUNCTIONS_SCHEMA_VERSIONS = frozenset({1, 2})


@dataclass(frozen=True)
class SourcePathResolver:
    """Resolve project-relative source records with legacy absolute support."""

    project_root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "project_root", Path(self.project_root).resolve())

    @classmethod
    def from_functions_document(
        cls,
        document: Mapping[str, Any],
        functions_path: str | Path,
        *,
        project_root: str | Path | None = None,
    ) -> "SourcePathResolver":
        version = document.get("schema_version")
        if version not in SUPPORTED_FUNCTIONS_SCHEMA_VERSIONS:
            raise ValueError("functions.json requires schema_version 1 or 2")
        if project_root is not None:
            return cls(Path(project_root))
        stored_root = document.get("project")
        if not isinstance(stored_root, str) or not stored_root.strip():
            raise ValueError(
                "project_root is required when functions.json has no project"
            )
        candidate = Path(stored_root)
        if not candidate.is_absolute():
            candidate = Path(functions_path).resolve().parent / candidate
        return cls(candidate)

    def resolve(self, stored_path: str | Path) -> Path:
        """Resolve a source path and reject project-root escapes.

        Absolute paths are accepted only as a legacy artifact compatibility
        path. Newly written functions artifacts store project-relative paths.
        """

        if not isinstance(stored_path, (str, Path)) or not str(stored_path).strip():
            raise ValueError("stored source path must be non-empty")
        candidate = Path(stored_path)
        resolved = (
            candidate.resolve()
            if candidate.is_absolute()
            else (self.project_root / candidate).resolve()
        )
        try:
            resolved.relative_to(self.project_root)
        except ValueError as error:
            raise ValueError("source path escapes project root") from error
        return resolved
