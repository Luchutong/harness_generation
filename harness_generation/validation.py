"""Shared result records for compiler and runtime validation."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from .records import write_json

VALIDATION_SCHEMA_VERSION = 1


VALIDATION_STATUSES = frozenset({
    "passed",
    "failed",
    "skipped",
    "unavailable",
    "passed_with_limitations",
    "passed_with_warnings",
})


def is_stable_eligible(status: str | None) -> bool:
    """Return whether a validation status may publish a stable artifact."""

    return status == "passed"


@dataclass(frozen=True)
class ValidationResult:
    success: bool | None
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    metadata: Mapping[str, Any]
    status: str | None = None

    def __post_init__(self) -> None:
        status = self.status
        if status is None:
            if type(self.success) is not bool:
                raise ValueError(
                    "ValidationResult.success must be boolean when status is omitted"
                )
            status = "passed" if self.success else "failed"
            object.__setattr__(self, "status", status)
        if status not in VALIDATION_STATUSES:
            raise ValueError("ValidationResult.status is invalid")
        if status in {
            "passed", "passed_with_limitations", "passed_with_warnings",
        }:
            consistent = self.success is True and not self.errors
        elif status == "failed":
            consistent = self.success is False and bool(self.errors)
        else:
            consistent = self.success is None and not self.errors
        if not consistent:
            raise ValueError(
                "ValidationResult.success/errors must agree with status"
            )

    @property
    def accepted(self) -> bool:
        """Accept only a passed policy, with declared limitations if needed."""

        return self.status in {
            "passed", "passed_with_limitations", "passed_with_warnings",
        }

    @property
    def stable_eligible(self) -> bool:
        """Stable publication requires an unqualified validation pass."""

        return is_stable_eligible(self.status)

    def to_dict(self) -> dict[str, Any]:
        validator = self.metadata.get("validator", "intermediate")
        return {
            "validator": validator,
            "status": self.status,
            "success": self.success,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
        }

    def save(self, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_json(destination, self.to_dict(), sort_keys=True, allow_nan=False)
        return destination
