"""CLI wiring for staged Function Triplet harness generation."""

from __future__ import annotations

import argparse
from dataclasses import replace
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping

from .artifacts import ArtifactStore
from .llm import (LLMClient, LLMConfig, LLMError, MockLLM,
                  OpenAICompatibleLLM, RecordedResponseLLM)
from .fuzz_smoke import LibFuzzerSmokeConfig
from .orchestrator import (
    PIPELINE_STAGES,
    STAGE_1_DOCS,
    STAGE_2_SNIPPETS,
    STAGE_3_ROUGH,
    STAGE_4_HARNESS,
    CallableStage,
    PipelineOrchestrator,
    PipelineRunResult,
    PipelineStage,
    PipelineState,
)
from .pipeline_validation import (
    PipelineStageValidator,
    PipelineValidationConfig,
)
from .pipeline_result import PipelineResult
from .stage1 import Stage1Generator
from .stage2 import Stage2Generator
from .stage3 import Stage3Assembler
from .stage4 import Stage4Generator
from .triplet import FunctionTriplet, load_triplets_json


def main(
    argv: list[str] | None = None,
    *,
    llm: LLMClient | None = None,
    all_triplets: bool = False,
    validation_config: PipelineValidationConfig | None = None,
    run_command: bool = False,
) -> int:
    arguments = list(argv or [])
    parser = argparse.ArgumentParser(
        prog=("harness-generation run" if run_command
              else "harness-generation generate-all" if all_triplets
              else "harness-generation generate"),
        description="Run staged Function Triplet harness generation",
    )
    parser.add_argument(
        "--artifacts",
        type=Path,
        default=Path("."),
        help="Artifact directory (default: current directory)",
    )
    if not all_triplets:
        parser.add_argument("--ft", required=True, dest="triplet_id")
    parser.add_argument(
        "--until-stage", type=int, choices=range(1, 5), default=4
    )
    parser.add_argument(
        "--max-regen-per-level",
        type=_positive_integer,
        default=3,
        help="Maximum regeneration attempts before rolling back one more stage",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        help="Override the source root recorded by functions.json",
    )
    parser.add_argument("--resume", action="store_true")
    if run_command:
        parser.add_argument(
            "--validate", action="store_true",
            help="Run Stage and intermediate validation without building",
        )
        parser.add_argument(
            "--build", action="store_true",
            help="Run validation, compile, link, and runtime smoke",
        )
        parser.add_argument(
            "--smoke-fuzz", action="store_true",
            help="Run bounded libFuzzer smoke after build/runtime validation",
        )
        parser.add_argument(
            "--fuzz-seconds", type=_fuzz_seconds, default=60,
            help="libFuzzer smoke duration from 30 to 120 seconds (default: 60)",
        )
    providers = parser.add_mutually_exclusive_group()
    providers.add_argument(
        "--provider",
        choices=("openai-compatible",),
        help="Network LLM provider (configuration is read from the environment)",
    )
    if run_command:
        providers.add_argument(
            "--real-llm", action="store_true",
            help="Use the OpenAI-compatible provider configured by LLM_*",
        )
    providers.add_argument(
        "--mock-responses",
        type=Path,
        help="Offline JSON list/object containing deterministic response strings",
    )
    providers.add_argument(
        "--recorded-responses",
        type=Path,
        help="Replay a versioned recorded-response JSON artifact",
    )
    parser.add_argument(
        "--model",
        help="Override LLM_MODEL for the real provider",
    )
    args = parser.parse_args(arguments)
    if run_command and args.smoke_fuzz and not args.build:
        parser.error("--smoke-fuzz requires --build")

    try:
        validate_requested = (
            not run_command or args.validate or args.build
        )
        build_requested = not run_command or args.build
        effective_validation = validation_config or PipelineValidationConfig()
        if run_command:
            effective_validation = replace(
                effective_validation,
                build_enabled=build_requested,
                fuzz_smoke=(
                    LibFuzzerSmokeConfig(args.fuzz_seconds)
                    if args.smoke_fuzz else None
                ),
            )
        fuzz_requested = bool(
            validate_requested
            and build_requested
            and effective_validation.fuzz_smoke is not None
        )
        store = ArtifactStore(args.artifacts)
        store.ensure_catalogs()
        triplets = load_triplets_json(store.triplets)
        selected = (
            triplets
            if all_triplets
            else (_select_triplet(triplets, args.triplet_id),)
        )
        client = _resolve_llm(
            llm,
            provider=(
                "openai-compatible"
                if run_command and args.real_llm else args.provider
            ),
            model=args.model,
            mock_responses=args.mock_responses,
            recorded_responses=args.recorded_responses,
        )
        failures = 0
        for triplet in selected:
            result = _generate_triplet(
                triplet,
                client,
                artifacts=args.artifacts,
                until_stage=PipelineStage(args.until_stage),
                resume=args.resume,
                project_root=args.project_root,
                validation_config=effective_validation,
                validate_enabled=validate_requested,
                max_regen_per_level=args.max_regen_per_level,
            )
            if result is None:
                print(f"[GEN][{triplet.id}] already complete through requested stage")
                continue
            if args.until_stage < 4:
                print(
                    f"[GEN][{triplet.id}] stopped at "
                    f"{result.state.current_stage.name} status={result.state.status}"
                )
                if not result.success:
                    failures += 1
                continue
            final = PipelineResult.from_run(
                result,
                artifacts=args.artifacts,
                validate_requested=validate_requested,
                build_requested=build_requested,
                fuzz_requested=fuzz_requested,
            )
            final.save(store.for_triplet(triplet.id).pipeline_result)
            _print_summary(final)
            if not final.success:
                failures += 1
        return 1 if failures else 0
    except (OSError, ValueError, LLMError) as error:
        print(f"Generation failed: {error}", file=sys.stderr)
        return 1


def _generate_triplet(
    triplet: FunctionTriplet,
    llm: LLMClient,
    *,
    artifacts: Path,
    until_stage: PipelineStage,
    resume: bool,
    project_root: Path | None,
    validation_config: PipelineValidationConfig | None = None,
    validate_enabled: bool = True,
    max_regen_per_level: int = 3,
) -> PipelineRunResult | None:
    state = None
    start_stage = STAGE_1_DOCS
    outputs: dict[PipelineStage, Any] = {}
    checkpoints: dict[PipelineStage, Any] = {}
    layout = ArtifactStore(artifacts).for_triplet(triplet.id)
    state_path = layout.pipeline_state
    if resume:
        if not state_path.is_file():
            raise ValueError(f"resume state does not exist for {triplet.id}")
        state = PipelineState.load(state_path)
        if state.ft_id != triplet.id:
            raise ValueError("pipeline state FunctionTriplet mismatch")
        if state.status == "failed":
            raise ValueError(
                f"pipeline state for {triplet.id} exhausted rollback retries"
            )
        if state.status in {"paused", "completed"}:
            if state.current_stage >= until_stage:
                return None
            start_stage = PipelineStage(int(state.current_stage) + 1)
        else:
            start_stage = state.current_stage
        checkpoints = _artifact_checkpoints(
            artifacts, triplet.id, before=start_stage
        )
        outputs = dict(checkpoints)

    orchestrator = PipelineOrchestrator(
        triplet.id,
        _stage_handlers(
            triplet,
            llm,
            artifacts,
            project_root=project_root,
            validation_config=validation_config,
            validate_enabled=validate_enabled,
        ),
        artifacts=artifacts,
        max_regen_per_level=max_regen_per_level,
    )
    return orchestrator.run(
        start_stage=start_stage,
        until_stage=until_stage,
        state=state,
        outputs=outputs,
        checkpoints=checkpoints,
    )


def _stage_handlers(
    triplet: FunctionTriplet,
    llm: LLMClient,
    artifacts: Path,
    *,
    project_root: Path | None,
    validation_config: PipelineValidationConfig | None = None,
    validate_enabled: bool = True,
) -> tuple[CallableStage, ...]:
    store = ArtifactStore(artifacts)
    layout = store.for_triplet(triplet.id)
    functions_json = store.functions
    stage1 = Stage1Generator(llm)
    stage2 = Stage2Generator(llm)
    stage3 = Stage3Assembler(llm)
    stage4 = Stage4Generator(llm)
    validators = PipelineStageValidator(
        triplet,
        artifacts=artifacts,
        functions_json=functions_json,
        project_root=project_root,
        config=validation_config,
    )
    validate_stage1 = validators.validate_stage1 if validate_enabled else _generated
    validate_stage2 = validators.validate_stage2 if validate_enabled else _generated
    validate_stage3 = validators.validate_stage3 if validate_enabled else _generated
    validate_stage4 = validators.validate_stage4 if validate_enabled else _generated

    def handler(stage, run, validate, checkpoint=lambda result: result):
        def execute(context):
            print(f"[GEN][{triplet.id}][S{int(stage)}] {stage.name}")
            return run(context)

        return CallableStage(
            stage=stage,
            input_fn=lambda context: context,
            run_fn=execute,
            validate_fn=validate,
            persist_fn=lambda result: result,
            checkpoint_fn=checkpoint,
        )

    return (
        handler(
            STAGE_1_DOCS,
            lambda context: stage1.run(
                triplet,
                functions_json=functions_json,
                artifacts=artifacts,
                project_root=project_root,
                attempt=context.attempt,
                rollback_source=_rollback_source(context.rollback_level),
                retry_reason=_retry_reason(
                    context.rollback_level, layout.pipeline_state
                ),
                retry_context=_retry_context(
                    context.rollback_level, layout.pipeline_state
                ),
            ),
            validate_stage1,
        ),
        handler(
            STAGE_2_SNIPPETS,
            lambda context: stage2.run(
                triplet,
                stage1_docs=layout.stage1_docs,
                artifacts=artifacts,
                attempt=context.attempt,
                rollback_source=_rollback_source(context.rollback_level),
                retry_reason=_retry_reason(
                    context.rollback_level, layout.pipeline_state
                ),
                retry_context=_retry_context(
                    context.rollback_level, layout.pipeline_state
                ),
            ),
            validate_stage2,
        ),
        handler(
            STAGE_3_ROUGH,
            lambda context: stage3.run(
                triplet,
                snippets=layout.stage2_snippets,
                functions_json=functions_json,
                artifacts=artifacts,
                rollback_source=_rollback_source(context.rollback_level),
                retry_reason=_retry_reason(context.rollback_level, layout.pipeline_state),
                retry_context=_retry_context(
                    context.rollback_level, layout.pipeline_state
                ),
            ),
            validate_stage3,
        ),
        handler(
            STAGE_4_HARNESS,
            lambda context: stage4.run(
                triplet,
                rough_code=layout.stage3_rough,
                functions_json=functions_json,
                artifacts=artifacts,
                publish=False,
                rollback_source=_rollback_source(context.rollback_level),
                retry_reason=_retry_reason(context.rollback_level, layout.pipeline_state),
                retry_context=_retry_context(
                    context.rollback_level, layout.pipeline_state
                ),
            ),
            validate_stage4,
            lambda result: _publish_harness(layout, result),
        ),
    )


def _publish_harness(layout, result):
    layout.write_text(layout.harness, result.harness_code.rstrip() + "\n")
    return result


def _rollback_source(level: int | None) -> str | None:
    if level is None:
        return None
    return "ROOT_INPUT" if level == 0 else PipelineStage(level).name


def _retry_reason(level: int | None, state_path: Path) -> str | None:
    context = _retry_context(level, state_path)
    reason = None if context is None else context.get("reason")
    return reason if isinstance(reason, str) and reason else None


def _retry_context(
    level: int | None,
    state_path: Path,
) -> dict[str, Any] | None:
    if level is None or not state_path.is_file():
        return None
    try:
        document = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    history = document.get("history", []) if isinstance(document, dict) else []
    for event in reversed(history if isinstance(history, list) else []):
        if isinstance(event, dict) and event.get("event") == "rollback":
            return {
                key: event.get(key)
                for key in (
                    "failed_stage", "validator", "failure_type", "attempt",
                    "rollback_target", "reason",
                )
            }
    return None


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _fuzz_seconds(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer from 30 to 120") from error
    if not 30 <= parsed <= 120:
        raise argparse.ArgumentTypeError("must be an integer from 30 to 120")
    return parsed


def _generated(_result: Any):
    from .validation import ValidationResult

    return ValidationResult(
        success=True,
        errors=(),
        warnings=(),
        metadata={"validator": "generation"},
    )


def _print_summary(result: PipelineResult) -> None:
    print(f"FT: {result.ft_id}")
    for number, stage in enumerate((
        "STAGE_1_DOCS", "STAGE_2_SNIPPETS", "STAGE_3_ROUGH",
        "STAGE_4_HARNESS",
    ), start=1):
        status = result.stage_statuses[stage]
        if result.capability == "generate" and status == "passed":
            status = "generated"
        print(f"Stage{number}: {status}")
    labels = (
        ("Intermediate", "intermediate"),
        ("Compiler", "compiler"),
        ("Linker", "linker"),
        ("Runtime", "runtime"),
    )
    for label, key in labels:
        print(f"{label}: {result.validator_statuses[key]}")
    rollback = (
        "none" if result.rollback_count == 0
        else f"{result.rollback_count} ({' -> '.join(result.rollback_targets)})"
    )
    print(f"Rollback: {rollback}")
    print(f"Fuzz smoke: {result.validator_statuses['fuzz_smoke']}")
    print(f"Result: {'SUCCESS' if result.success else 'FAILED'}")
    if result.failure_reason:
        print(f"Failure reason: {result.failure_reason}")


def _artifact_checkpoints(
    artifacts: Path,
    triplet_id: str,
    *,
    before: PipelineStage,
) -> dict[PipelineStage, tuple[Path, ...]]:
    layout = ArtifactStore(artifacts).for_triplet(triplet_id)
    paths = {
        STAGE_1_DOCS: (layout.stage1_docs,),
        STAGE_2_SNIPPETS: (layout.stage2_snippets,),
        STAGE_3_ROUGH: (
            layout.stage3_rough, layout.stage3_metadata
        ),
        STAGE_4_HARNESS: (layout.stage4_harness,),
    }
    checkpoints = {}
    for stage in PIPELINE_STAGES:
        if stage >= before:
            continue
        missing = [path for path in paths[stage] if not path.is_file()]
        if missing:
            raise ValueError(
                f"cannot resume {triplet_id}; checkpoint {stage.name} is incomplete"
            )
        checkpoints[stage] = paths[stage]
    return checkpoints


def _resolve_llm(
    injected: LLMClient | None,
    *,
    provider: str | None,
    model: str | None,
    mock_responses: Path | None,
    recorded_responses: Path | None,
    environ: Mapping[str, str] | None = None,
) -> LLMClient:
    environment = os.environ if environ is None else environ
    if injected is not None:
        if (
            provider is not None
            or model is not None
            or mock_responses is not None
            or recorded_responses is not None
        ):
            raise ValueError("cannot combine an injected LLM with provider options")
        return injected
    if mock_responses is not None:
        if model is not None:
            raise ValueError("--model is only valid for a real LLM provider")
        return MockLLM(_load_mock_responses(mock_responses))
    if recorded_responses is not None:
        if model is not None:
            raise ValueError("--model is only valid for a real LLM provider")
        return RecordedResponseLLM.from_file(recorded_responses)
    selected_provider = provider or "openai-compatible"
    if selected_provider != "openai-compatible":
        raise ValueError(f"unsupported LLM provider: {selected_provider}")
    base_url = environment.get("LLM_BASE_URL", "").strip()
    api_key = environment.get("LLM_API_KEY", "").strip()
    selected_model = (model or environment.get("LLM_MODEL", "")).strip()
    thinking = environment.get("LLM_THINKING", "").strip().lower() or None
    missing = []
    if not base_url:
        missing.append("LLM_BASE_URL")
    if not api_key:
        missing.append("LLM_API_KEY")
    if not selected_model:
        missing.append("LLM_MODEL")
    if missing:
        raise ValueError(
            "missing LLM configuration: " + ", ".join(missing)
        )
    if thinking not in {None, "enabled", "disabled"}:
        raise ValueError("LLM_THINKING must be enabled or disabled")
    return OpenAICompatibleLLM(
        LLMConfig(
            model=selected_model,
            base_url=base_url,
            api_key_env_name="LLM_API_KEY",
            thinking=thinking,
        ),
        environ=environment,
    )


def _load_mock_responses(path: Path) -> tuple[str, ...]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(
            f"cannot load mock responses: {type(error).__name__}"
        ) from error
    responses = document.get("responses") if isinstance(document, dict) else document
    if not isinstance(responses, list) or any(
        not isinstance(response, str) for response in responses
    ):
        raise ValueError("mock responses must be an array of strings")
    return tuple(responses)


def _select_triplet(
    triplets: Sequence[FunctionTriplet],
    triplet_id: str,
) -> FunctionTriplet:
    selected = next((item for item in triplets if item.id == triplet_id), None)
    if selected is None:
        raise ValueError(f"unknown FunctionTriplet: {triplet_id}")
    return selected
