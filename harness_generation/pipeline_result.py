"""Final capability-oriented result for one staged harness pipeline run."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .artifacts import ArtifactStore
from .records import write_json


PIPELINE_RESULT_SCHEMA_VERSION = 1
_ACCEPTED = frozenset({
    "passed", "passed_with_limitations", "passed_with_warnings",
})
_STAGES = (
    "STAGE_1_DOCS", "STAGE_2_SNIPPETS", "STAGE_3_ROUGH", "STAGE_4_HARNESS"
)


@dataclass(frozen=True)
class PipelineResult:
    """Report concrete closure milestones without equating files with success."""

    ft_id: str
    generated: bool
    validated: bool
    compiled: bool
    linked: bool
    runtime_checked: bool
    fuzz_smoke_completed: bool
    success: bool
    failure_reason: str | None
    stage_statuses: Mapping[str, str]
    validator_statuses: Mapping[str, str]
    rollback_count: int
    rollback_targets: tuple[str, ...]
    capability: str

    def __post_init__(self) -> None:
        for field in (
            "generated", "validated", "compiled", "linked",
            "runtime_checked", "fuzz_smoke_completed", "success",
        ):
            if type(getattr(self, field)) is not bool:
                raise ValueError(f"PipelineResult.{field} must be boolean")
        if self.success and self.failure_reason is not None:
            raise ValueError("successful PipelineResult cannot have failure_reason")
        if not self.success and not self.failure_reason:
            raise ValueError("failed PipelineResult requires failure_reason")
        if self.capability not in {"generate", "validate", "build", "e2e"}:
            raise ValueError("invalid pipeline capability")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PIPELINE_RESULT_SCHEMA_VERSION,
            "ft_id": self.ft_id,
            "capability": self.capability,
            "generated": self.generated,
            "validated": self.validated,
            "compiled": self.compiled,
            "linked": self.linked,
            "runtime_checked": self.runtime_checked,
            "fuzz_smoke_completed": self.fuzz_smoke_completed,
            "success": self.success,
            "failure_reason": self.failure_reason,
            "stage_statuses": dict(self.stage_statuses),
            "validator_statuses": dict(self.validator_statuses),
            "rollback_count": self.rollback_count,
            "rollback_targets": list(self.rollback_targets),
        }

    def save(self, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_json(destination, self.to_dict(), sort_keys=True, allow_nan=False)
        return destination

    @classmethod
    def from_run(
        cls,
        run_result: Any,
        *,
        artifacts: str | Path,
        validate_requested: bool,
        build_requested: bool,
        fuzz_requested: bool,
    ) -> "PipelineResult":
        state = run_result.state
        history = list(state.history)
        layout = ArtifactStore(Path(artifacts)).for_triplet(state.ft_id)
        stage_statuses = _stage_statuses(history)
        generated = _stage_generated(history, "STAGE_4_HARNESS")
        validators = {
            name: _document_status(path)
            for name, path in (
                ("intermediate", layout.intermediate_validation),
                ("compiler", layout.compiler_validation),
                ("linker", layout.linker_validation),
                ("runtime", layout.runtime_validation),
            )
        }
        if not validate_requested:
            validators["intermediate"] = "not_requested"
        if not build_requested:
            for name in ("compiler", "linker", "runtime"):
                validators[name] = "not_requested"
        fuzz_status = _latest_fuzz_status(layout.fuzz) if fuzz_requested else "not_requested"
        validators["fuzz_smoke"] = fuzz_status

        validated = validate_requested and all(
            stage_statuses.get(stage) in _ACCEPTED for stage in _STAGES
        ) and validators["intermediate"] in _ACCEPTED
        compiled = build_requested and validators["compiler"] == "passed"
        linked = build_requested and validators["linker"] == "passed"
        runtime_checked = build_requested and validators["runtime"] in _ACCEPTED
        fuzz_completed = fuzz_requested and fuzz_status in _ACCEPTED
        required = [generated]
        if validate_requested:
            required.append(validated)
        if build_requested:
            required.extend((compiled, linked, runtime_checked))
        if fuzz_requested:
            required.append(fuzz_completed)
        success = bool(run_result.success and all(required))
        failure_reason = None if success else _failure_reason(
            history,
            generated=generated,
            validated=validated,
            compiled=compiled,
            linked=linked,
            runtime_checked=runtime_checked,
            fuzz_smoke_completed=fuzz_completed,
            validate_requested=validate_requested,
            build_requested=build_requested,
            fuzz_requested=fuzz_requested,
        )
        rollbacks = [event for event in history if event.get("event") == "rollback"]
        capability = (
            "e2e" if fuzz_requested else "build" if build_requested
            else "validate" if validate_requested else "generate"
        )
        return cls(
            ft_id=state.ft_id,
            generated=generated,
            validated=validated,
            compiled=compiled,
            linked=linked,
            runtime_checked=runtime_checked,
            fuzz_smoke_completed=fuzz_completed,
            success=success,
            failure_reason=failure_reason,
            stage_statuses=stage_statuses,
            validator_statuses=validators,
            rollback_count=len(rollbacks),
            rollback_targets=tuple(
                str(event.get("rollback_target", "unknown")) for event in rollbacks
            ),
            capability=capability,
        )


def _stage_statuses(history: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for event in history:
        if event.get("event") == "stage_validated":
            stage = event.get("stage")
            status = event.get("status")
            if isinstance(stage, str) and isinstance(status, str):
                result[stage] = status
        elif event.get("event") == "stage_failed":
            stage = event.get("stage")
            if isinstance(stage, str):
                result[stage] = "failed"
    return {stage: result.get(stage, "not_run") for stage in _STAGES}


def _stage_generated(history: Sequence[Mapping[str, Any]], stage: str) -> bool:
    return any(
        event.get("stage") == stage and (
            event.get("event") == "checkpoint_created"
            or (
                event.get("event") == "stage_failed"
                and event.get("phase") in {"validate", "checkpoint"}
            )
        )
        for event in history
    )


def _document_status(path: Path) -> str:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return "not_run"
    status = document.get("status") if isinstance(document, Mapping) else None
    return status if isinstance(status, str) else "not_run"


def _latest_fuzz_status(root: Path) -> str:
    if not root.is_dir():
        return "not_run"
    candidates = sorted(
        path for path in root.glob("smoke_*/metadata.json") if path.is_file()
    )
    return _document_status(candidates[-1]) if candidates else "not_run"


def _failure_reason(
    history: Sequence[Mapping[str, Any]],
    **milestones: bool,
) -> str:
    for event in reversed(history):
        if event.get("event") in {"pipeline_failed", "stage_failed"}:
            reason = event.get("reason")
            if isinstance(reason, str) and reason:
                return reason
    labels = {
        "generated": "generation did not reach Stage 4",
        "validated": "validation did not pass",
        "compiled": "compiler validation did not pass",
        "linked": "link validation did not pass",
        "runtime_checked": "runtime smoke did not pass",
        "fuzz_smoke_completed": "fuzz smoke did not complete",
    }
    requested = {
        "generated": True,
        "validated": milestones["validate_requested"],
        "compiled": milestones["build_requested"],
        "linked": milestones["build_requested"],
        "runtime_checked": milestones["build_requested"],
        "fuzz_smoke_completed": milestones["fuzz_requested"],
    }
    missing = [
        labels[name] for name, required in requested.items()
        if required and not milestones[name]
    ]
    return "; ".join(missing) or "pipeline did not complete"
