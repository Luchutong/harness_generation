"""Artifact-first staged generation state machine with bounded rollback."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from .artifacts import ArtifactStore
from .records import write_json
from .validation import VALIDATION_STATUSES, ValidationResult


PIPELINE_STATE_SCHEMA_VERSION = 1


class PipelineStage(IntEnum):
    STAGE_1_DOCS = 1
    STAGE_2_SNIPPETS = 2
    STAGE_3_ROUGH = 3
    STAGE_4_HARNESS = 4


STAGE_1_DOCS = PipelineStage.STAGE_1_DOCS
STAGE_2_SNIPPETS = PipelineStage.STAGE_2_SNIPPETS
STAGE_3_ROUGH = PipelineStage.STAGE_3_ROUGH
STAGE_4_HARNESS = PipelineStage.STAGE_4_HARNESS
PIPELINE_STAGES = tuple(PipelineStage)


def StageValidation(
    success: bool,
    reason: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> ValidationResult:
    """Backward-compatible constructor backed by the canonical result type."""

    if type(success) is not bool:
        raise ValueError("StageValidation.success must be boolean")
    if not success and not reason:
        raise ValueError("failed StageValidation requires a reason")
    return ValidationResult(
        success=success,
        errors=() if success else (reason or "stage validation failed",),
        warnings=(),
        metadata=dict(metadata or {}),
    )


@dataclass(frozen=True)
class StageContext:
    ft_id: str
    stage: PipelineStage
    artifacts: Path
    attempt: int
    rollback_level: int | None
    checkpoints: Mapping[PipelineStage, Any]
    outputs: Mapping[PipelineStage, Any]

    def checkpoint(self, stage: PipelineStage) -> Any | None:
        return self.checkpoints.get(stage)


class StageHandler(Protocol):
    stage: PipelineStage

    def input(self, context: StageContext) -> Any:
        ...

    def run(self, stage_input: Any) -> Any:
        ...

    def validate(self, output: Any) -> ValidationResult:
        ...

    def persist(self, output: Any) -> Any:
        ...

    def checkpoint(self, persisted: Any) -> Any:
        ...


@dataclass(frozen=True)
class CallableStage:
    """Small adapter for existing Stage implementations and application wiring."""

    stage: PipelineStage
    input_fn: Callable[[StageContext], Any]
    run_fn: Callable[[Any], Any]
    validate_fn: Callable[[Any], ValidationResult]
    persist_fn: Callable[[Any], Any]
    checkpoint_fn: Callable[[Any], Any]

    def input(self, context: StageContext) -> Any:
        return self.input_fn(context)

    def run(self, stage_input: Any) -> Any:
        return self.run_fn(stage_input)

    def validate(self, output: Any) -> ValidationResult:
        return self.validate_fn(output)

    def persist(self, output: Any) -> Any:
        return self.persist_fn(output)

    def checkpoint(self, persisted: Any) -> Any:
        return self.checkpoint_fn(persisted)


@dataclass
class PipelineState:
    ft_id: str
    current_stage: PipelineStage = STAGE_1_DOCS
    attempt: int = 1
    rollback_level: int | None = None
    history: list[dict[str, Any]] = field(default_factory=list)
    status: str = "pending"
    attempts_by_level: dict[int, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.ft_id, str) or not self.ft_id.strip():
            raise ValueError("pipeline state ft_id must be non-empty")
        self.current_stage = PipelineStage(self.current_stage)
        if type(self.attempt) is not int or self.attempt < 1:
            raise ValueError("pipeline state attempt must be positive")
        if (self.rollback_level is not None
                and (type(self.rollback_level) is not int
                     or self.rollback_level not in range(4))):
            raise ValueError("rollback_level must be null or between 0 and 3")
        if self.status not in {
            "pending", "running", "paused", "completed", "failed"
        }:
            raise ValueError("invalid pipeline state status")

    def record(self, event: str, **details: Any) -> None:
        self.history.append({
            "sequence": len(self.history) + 1,
            "event": event,
            **details,
        })

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": PIPELINE_STATE_SCHEMA_VERSION,
            "ft_id": self.ft_id,
            "current_stage": int(self.current_stage),
            "current_stage_name": self.current_stage.name,
            "attempt": self.attempt,
            "rollback_level": self.rollback_level,
            "status": self.status,
            "attempts_by_level": {
                str(level): attempts
                for level, attempts in sorted(self.attempts_by_level.items())
            },
            "history": list(self.history),
        }

    def save(self, path: str | Path) -> Path:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        write_json(destination, self.to_dict(), sort_keys=True, allow_nan=False)
        return destination

    @classmethod
    def load(cls, path: str | Path) -> "PipelineState":
        source = Path(path)
        try:
            document = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError(
                f"cannot load pipeline state: {type(error).__name__}"
            ) from error
        if not isinstance(document, Mapping):
            raise ValueError("pipeline_state.json must contain an object")
        if document.get("schema_version") != PIPELINE_STATE_SCHEMA_VERSION:
            raise ValueError("unsupported pipeline state schema_version")
        history = document.get("history")
        attempts = document.get("attempts_by_level", {})
        if not isinstance(history, list) or any(
            not isinstance(item, dict) for item in history
        ):
            raise ValueError("pipeline state history must be an array of objects")
        if not isinstance(attempts, Mapping):
            raise ValueError("pipeline state attempts_by_level must be an object")
        try:
            parsed_attempts = {int(level): count for level, count in attempts.items()}
        except (TypeError, ValueError) as error:
            raise ValueError("invalid attempts_by_level") from error
        if any(level not in range(4) or type(count) is not int or count < 1
               for level, count in parsed_attempts.items()):
            raise ValueError("invalid attempts_by_level")
        return cls(
            ft_id=_required_text(document, "ft_id"),
            current_stage=PipelineStage(document.get("current_stage")),
            attempt=document.get("attempt"),
            rollback_level=document.get("rollback_level"),
            history=[dict(item) for item in history],
            status=document.get("status"),
            attempts_by_level=parsed_attempts,
        )


@dataclass(frozen=True)
class RollbackDecision:
    exhausted: bool
    checkpoint_level: int | None
    restart_stage: PipelineStage | None
    attempt: int


class StagedRollbackStrategy:
    """Select retry checkpoints without coupling rollback to individual stages."""

    def __init__(self, max_regen_per_level: int = 3) -> None:
        if (type(max_regen_per_level) is not int
                or max_regen_per_level < 1):
            raise ValueError("max_regen_per_level must be a positive integer")
        self.max_regen_per_level = max_regen_per_level

    def after_failure(
        self,
        failed_stage: PipelineStage,
        *,
        checkpoint_level: int | None,
        attempt: int,
    ) -> RollbackDecision:
        failed_stage = PipelineStage(failed_stage)
        if checkpoint_level is None:
            level = int(failed_stage) - 1
            return RollbackDecision(
                exhausted=False,
                checkpoint_level=level,
                restart_stage=PipelineStage(max(1, level + 1)),
                attempt=1,
            )
        if checkpoint_level not in range(4):
            raise ValueError("checkpoint_level must be between 0 and 3")
        if type(attempt) is not int or attempt < 1:
            raise ValueError("rollback attempt must be positive")
        if attempt < self.max_regen_per_level:
            return RollbackDecision(
                exhausted=False,
                checkpoint_level=checkpoint_level,
                restart_stage=PipelineStage(max(1, checkpoint_level + 1)),
                attempt=attempt + 1,
            )
        if checkpoint_level == 0:
            return RollbackDecision(True, None, None, attempt)
        level = checkpoint_level - 1
        return RollbackDecision(
            exhausted=False,
            checkpoint_level=level,
            restart_stage=PipelineStage(max(1, level + 1)),
            attempt=1,
        )


@dataclass(frozen=True)
class PipelineRunResult:
    success: bool
    state: PipelineState
    state_path: Path
    outputs: Mapping[PipelineStage, Any]
    checkpoints: Mapping[PipelineStage, Any]


class PipelineOrchestrator:
    """Run four stages and apply one centralized checkpoint rollback policy."""

    def __init__(
        self,
        ft_id: str,
        stages: Sequence[StageHandler],
        *,
        artifacts: str | Path,
        max_regen_per_level: int = 3,
        rollback_strategy: StagedRollbackStrategy | None = None,
    ) -> None:
        if not isinstance(ft_id, str) or not ft_id.strip():
            raise ValueError("ft_id must be non-empty")
        by_stage: dict[PipelineStage, StageHandler] = {}
        for handler in stages:
            stage = PipelineStage(handler.stage)
            if stage in by_stage:
                raise ValueError(f"duplicate pipeline stage: {stage.name}")
            by_stage[stage] = handler
        missing = [stage.name for stage in PIPELINE_STAGES if stage not in by_stage]
        if missing:
            raise ValueError("missing pipeline stages: " + ", ".join(missing))
        self.ft_id = ft_id
        self.stages = by_stage
        self.artifacts = Path(artifacts)
        self.state_path = ArtifactStore(self.artifacts).for_triplet(
            ft_id
        ).pipeline_state
        self.rollback_strategy = (
            rollback_strategy
            if rollback_strategy is not None
            else StagedRollbackStrategy(max_regen_per_level)
        )

    def run(
        self,
        *,
        until_stage: PipelineStage = STAGE_4_HARNESS,
        start_stage: PipelineStage = STAGE_1_DOCS,
        state: PipelineState | None = None,
        outputs: Mapping[PipelineStage, Any] | None = None,
        checkpoints: Mapping[PipelineStage, Any] | None = None,
    ) -> PipelineRunResult:
        until_stage = PipelineStage(until_stage)
        start_stage = PipelineStage(start_stage)
        if start_stage > until_stage:
            raise ValueError("start_stage must not be after until_stage")
        state = state or PipelineState(ft_id=self.ft_id)
        if state.ft_id != self.ft_id:
            raise ValueError("pipeline state belongs to a different FunctionTriplet")
        state.status = "running"
        outputs = dict(outputs or {})
        checkpoints = dict(checkpoints or {})
        stage = start_stage

        while True:
            state.current_stage = stage
            state.record(
                "stage_started",
                stage=stage.name,
                stage_number=int(stage),
                attempt=state.attempt,
                rollback_level=state.rollback_level,
            )
            state.save(self.state_path)
            handler = self.stages[stage]
            phase = "input"
            try:
                context = StageContext(
                    ft_id=self.ft_id,
                    stage=stage,
                    artifacts=self.artifacts,
                    attempt=state.attempt,
                    rollback_level=state.rollback_level,
                    checkpoints=dict(checkpoints),
                    outputs=dict(outputs),
                )
                stage_input = handler.input(context)
                phase = "run"
                output = handler.run(stage_input)
                phase = "persist"
                persisted = handler.persist(output)
                checkpoint_input = output if persisted is None else persisted
                phase = "validate"
                validation = _coerce_validation(
                    handler.validate(checkpoint_input)
                )
                state.record(
                    "stage_validated",
                    stage=stage.name,
                    stage_number=int(stage),
                    attempt=state.attempt,
                    status=validation.status,
                    validator=validation.metadata.get("validator", "stage"),
                    errors=list(validation.errors),
                    warnings=list(validation.warnings),
                )
                state.save(self.state_path)
                if not validation.accepted:
                    reason = "; ".join(
                        validation.errors or validation.warnings
                    ) or f"stage validation status is {validation.status}"
                    return_or_stage = self._handle_failure(
                        state,
                        stage,
                        phase,
                        reason,
                        outputs,
                        checkpoints,
                        validation=validation,
                    )
                    if isinstance(return_or_stage, PipelineRunResult):
                        return return_or_stage
                    stage = return_or_stage
                    continue
                phase = "checkpoint"
                checkpoint = handler.checkpoint(checkpoint_input)
            except Exception as error:
                return_or_stage = self._handle_failure(
                    state,
                    stage,
                    phase,
                    f"{type(error).__name__}: {error}",
                    outputs,
                    checkpoints,
                )
                if isinstance(return_or_stage, PipelineRunResult):
                    return return_or_stage
                stage = return_or_stage
                continue

            outputs[stage] = output
            checkpoints[stage] = checkpoint_input if checkpoint is None else checkpoint
            state.record(
                "checkpoint_created",
                stage=stage.name,
                stage_number=int(stage),
                attempt=state.attempt,
            )
            state.save(self.state_path)
            if stage == until_stage:
                final = stage == STAGE_4_HARNESS
                state.status = "completed" if final else "paused"
                state.record(
                    "pipeline_completed" if final else "pipeline_paused",
                    stage=stage.name,
                )
                state.save(self.state_path)
                return PipelineRunResult(
                    True, state, self.state_path, dict(outputs), dict(checkpoints)
                )
            stage = PipelineStage(int(stage) + 1)

    def _handle_failure(
        self,
        state: PipelineState,
        failed_stage: PipelineStage,
        phase: str,
        reason: str,
        outputs: dict[PipelineStage, Any],
        checkpoints: dict[PipelineStage, Any],
        validation: ValidationResult | None = None,
    ) -> PipelineStage | PipelineRunResult:
        validator = (
            validation.metadata.get("validator", "stage")
            if validation is not None else "orchestrator"
        )
        failure_type = (
            validation.metadata.get("failure_type", "validation_failed")
            if validation is not None else f"{phase}_exception"
        )
        decision = self.rollback_strategy.after_failure(
            failed_stage,
            checkpoint_level=state.rollback_level,
            attempt=state.attempt,
        )
        rollback_target = (
            None if decision.restart_stage is None else decision.restart_stage.name
        )
        failure = {
            "stage": failed_stage.name,
            "stage_number": int(failed_stage),
            "failed_stage": failed_stage.name,
            "failed_stage_number": int(failed_stage),
            "phase": phase,
            "attempt": state.attempt,
            "rollback_level": state.rollback_level,
            "rollback_target": rollback_target,
            "validator": validator,
            "failure_type": failure_type,
            "reason": reason,
        }
        if validation is not None:
            failure.update({
                "validation_status": validation.status,
                "validator_failed_stage": validation.metadata.get("failed_stage"),
            })
        state.record("stage_failed", **failure)
        if decision.exhausted:
            state.status = "failed"
            state.record(
                "pipeline_failed",
                **failure,
                rollback_exhausted=True,
            )
            state.save(self.state_path)
            return PipelineRunResult(
                False, state, self.state_path, dict(outputs), dict(checkpoints)
            )

        if decision.checkpoint_level is None or decision.restart_stage is None:
            raise ValueError("rollback strategy returned an incomplete decision")
        for completed_stage in tuple(checkpoints):
            if int(completed_stage) > decision.checkpoint_level:
                checkpoints.pop(completed_stage, None)
                outputs.pop(completed_stage, None)
        state.rollback_level = decision.checkpoint_level
        state.attempt = decision.attempt
        state.attempts_by_level[decision.checkpoint_level] = decision.attempt
        state.current_stage = decision.restart_stage
        state.record(
            "rollback",
            failed_stage=failed_stage.name,
            failed_stage_number=int(failed_stage),
            validator=validator,
            failure_type=failure_type,
            checkpoint_level=decision.checkpoint_level,
            checkpoint=(
                "ROOT_INPUT" if decision.checkpoint_level == 0
                else PipelineStage(decision.checkpoint_level).name
            ),
            restart_stage=decision.restart_stage.name,
            rollback_target=decision.restart_stage.name,
            rollback_target_number=int(decision.restart_stage),
            failed_attempt=failure["attempt"],
            attempt=decision.attempt,
            reason=reason,
        )
        state.save(self.state_path)
        return decision.restart_stage


def _coerce_validation(value: Any) -> ValidationResult:
    if isinstance(value, ValidationResult):
        return value
    if type(value) is bool:
        return StageValidation(value, None if value else "stage validation failed")
    if isinstance(value, Mapping):
        status = value.get("status")
        success = value.get("success")
        if status in {"skipped", "unavailable"}:
            success = None
        elif status == "passed_with_limitations":
            success = True
        elif type(success) is not bool:
            raise ValueError("stage validation mapping requires boolean success")
        reason = _validation_reason(value)
        if success is False and reason is None:
            reason = "stage validation failed"
        return ValidationResult(
            success=success,
            errors=() if success is not False else (reason,),
            warnings=tuple(value.get("warnings", ())),
            metadata=dict(value.get("metadata", {})),
            status=status if status in VALIDATION_STATUSES else None,
        )
    success = getattr(value, "success", None)
    status = getattr(value, "status", None)
    if status in {"skipped", "unavailable"}:
        success = None
    elif status == "passed_with_limitations":
        success = True
    elif type(success) is not bool:
        raise ValueError("stage validate() must return a boolean validation result")
    reason = _validation_reason(value)
    if success is False and reason is None:
        reason = "stage validation failed"
    return ValidationResult(
        success=success,
        errors=() if success is not False else (reason,),
        warnings=tuple(getattr(value, "warnings", ())),
        metadata=dict(getattr(value, "metadata", {})),
        status=status if status in VALIDATION_STATUSES else None,
    )


def _validation_reason(value: Any) -> str | None:
    if isinstance(value, Mapping):
        reason = value.get("reason")
        errors = value.get("errors")
    else:
        reason = getattr(value, "reason", None)
        errors = getattr(value, "errors", None)
    if isinstance(reason, str) and reason.strip():
        return reason
    if isinstance(errors, Sequence) and not isinstance(errors, (str, bytes)):
        messages = [str(error) for error in errors if str(error)]
        if messages:
            return "; ".join(messages)
    return None


def _required_text(value: Mapping[str, Any], field: str) -> str:
    item = value.get(field)
    if not isinstance(item, str) or not item.strip():
        raise ValueError(f"pipeline state {field} must be non-empty text")
    return item
