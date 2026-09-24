"""CLI wiring for staged Function Triplet harness generation."""

from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

from .artifacts import ArtifactStore
from .llm import (LLMClient, LLMConfig, LLMError, MockLLM,
                  OpenAICompatibleLLM, RecordedResponseLLM)
from .fuzz_smoke import LibFuzzerSmokeConfig
from .ft_selection import (FT_SELECTION_SCHEMA_VERSION, estimate_structural_units,
                           triplet_catalog_sha256)
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
    latest_unresolved_rollback,
)
from .pipeline_validation import (
    PipelineStageValidator,
    PipelineValidationConfig,
)
from .pipeline_result import PipelineResult
from .promotion import promote_harness
from .stage1 import Stage1Generator
from .stage2 import Stage2Generator
from .stage3 import Stage3Assembler
from .stage4 import Stage4Generator
from .target_contract import TargetContract
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
    else:
        parser.add_argument(
            "--selection",
            type=Path,
            help="Use triplet IDs and order from an ft_selection.json manifest",
        )
    parser.add_argument(
        "--until-stage", type=int, choices=range(1, 5), default=4
    )
    parser.add_argument("--max-ft", type=_positive_integer, default=20,
                        help="Maximum FTs in one run (default: 20)")
    parser.add_argument("--max-ft-functions", type=_positive_integer, default=20,
                        help="Maximum functions in each FT (default: 20)")
    parser.add_argument("--max-structural-units", type=_positive_integer, default=20,
                        help="Maximum Stage 2 units in each FT (default: 20)")
    parser.add_argument("--max-llm-calls", type=_positive_integer, default=300,
                        help="Hard cap on generation requests in this run (default: 300)")
    parser.add_argument("--max-catalog-mib", type=_positive_integer, default=128,
                        help="Maximum triplets.json size to load (default: 128 MiB)")
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
    parser.add_argument(
        "--target-build",
        type=Path,
        help="Load an explicit target build recipe/configuration",
    )
    parser.add_argument(
        "--target-contract", type=Path,
        help="Load an explicit typed target input/resource contract",
    )
    parser.add_argument(
        "--stage4-policy",
        choices=("strict", "hybrid"),
        default=None,
        help=(
            "Stage 4 validation policy: strict stops on intermediate policy "
            "errors; hybrid downgrades them to warnings and requires real "
            "build/runtime success"
        ),
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
    parser.add_argument(
        "--allow-unverified-semantic-artifacts", action="store_true",
        help="Allow real generation from Phase 1 artifacts lacking LLM provenance",
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
        if args.stage4_policy is not None:
            effective_validation = replace(
                effective_validation,
                stage4_policy=args.stage4_policy,
            )
        if args.target_build is not None:
            if validation_config is not None and validation_config.target_build is not None:
                raise ValueError("cannot combine --target-build with target_build config")
            effective_validation = replace(
                effective_validation,
                target_build_path=args.target_build,
            )
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
        _check_catalog_size(store.triplets, args.max_catalog_mib)
        triplets = load_triplets_json(store.triplets)
        if all_triplets:
            selected = (
                _select_from_manifest(triplets, args.selection)
                if args.selection is not None else triplets
            )
        else:
            selected = (_select_triplet(triplets, args.triplet_id),)
        _check_generation_budget(
            selected, max_ft=args.max_ft,
            max_ft_functions=args.max_ft_functions,
            max_structural_units=args.max_structural_units,
            max_llm_calls=args.max_llm_calls,
            until_stage=args.until_stage,
        )
        if args.target_contract is not None:
            contract = TargetContract.from_dict(json.loads(
                args.target_contract.read_text(encoding="utf-8")
            ))
            if any(item.isf.function != contract.entry_function for item in selected):
                raise ValueError("target contract entry_function does not match selected FT")
            store.write_target_contract(contract)
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
        if (isinstance(client, OpenAICompatibleLLM)
                and not args.allow_unverified_semantic_artifacts):
            _require_llm_semantics(store.annotations)
        client = _BudgetedLLM(client, args.max_llm_calls)
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


class _BudgetedLLM:
    """Enforce the request limit even when validation regenerates stages."""

    def __init__(self, client: LLMClient, limit: int):
        self.client = client
        self.limit = limit
        self.calls = 0

    def generate(self, prompt, *, prompt_version=None):
        if self.calls >= self.limit:
            raise LLMError(
                f"generation request budget exhausted ({self.calls}/{self.limit}); "
                "raise --max-llm-calls to continue"
            )
        self.calls += 1
        return self.client.generate(prompt, prompt_version=prompt_version)


def _check_generation_budget(
    triplets: Sequence[FunctionTriplet], *, max_ft: int,
    max_ft_functions: int, max_structural_units: int,
    max_llm_calls: int, until_stage: int,
) -> None:
    if len(triplets) > max_ft:
        raise ValueError(f"selected {len(triplets)} FTs; --max-ft is {max_ft}")
    estimated = 0
    for triplet in triplets:
        functions = len(triplet.functions)
        units = estimate_structural_units(triplet)
        if functions > max_ft_functions:
            raise ValueError(
                f"FT {triplet.id} has {functions} functions; "
                f"--max-ft-functions is {max_ft_functions}"
            )
        if units > max_structural_units:
            raise ValueError(
                f"FT {triplet.id} has {units} Stage 2 units; "
                f"--max-structural-units is {max_structural_units}"
            )
        estimated += (functions + (units if until_stage >= 2 else 0)
                      + (1 if until_stage >= 3 else 0)
                      + (2 if until_stage >= 4 else 0))
    if estimated > max_llm_calls:
        raise ValueError(
            f"selected FTs need at least {estimated} generation requests; "
            f"--max-llm-calls is {max_llm_calls}"
        )


def _require_llm_semantics(path: Path) -> None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("cannot verify Phase 1 semantic provenance") from exc
    if (not isinstance(document, dict)
            or document.get("semantic_backend") != "llm"):
        raise ValueError(
            "Phase 1 annotations were not verified as real LLM decisions; "
            "rerun sfg_builder --semantic-analyzer llm or use "
            "--allow-unverified-semantic-artifacts"
        )
    annotations = document.get("annotations")
    if not isinstance(annotations, list) or any(
        not isinstance(annotation, dict)
        or not isinstance(annotation.get("decisions"), list)
        for annotation in annotations
    ):
        raise ValueError("Phase 1 annotations have invalid semantic records")
    decisions = [decision for annotation in annotations
                 for decision in annotation["decisions"]]
    if not decisions or any(
        not isinstance(decision, dict) or decision.get("status") != "ok"
        for decision in decisions
    ):
        raise ValueError(
            "Phase 1 contains missing or failed semantic decisions; rerun "
            "sfg_builder or use --allow-unverified-semantic-artifacts"
        )


def _check_catalog_size(path: Path, max_mib: int) -> None:
    size = path.stat().st_size
    if size > max_mib * 1024 * 1024:
        raise ValueError(
            f"triplets.json is {size / 1024 / 1024:.1f} MiB; "
            f"--max-catalog-mib is {max_mib}. Regenerate with "
            "triplets --max-functions-per-ft or raise the limit"
        )


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
    contract_identity = (
        store.load_target_contract() or TargetContract.from_triplet(triplet)
    ).id
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
            lambda result: _publish_harness(
                layout, result,
                recipe_identity=(
                    validators.target_build.to_recipe().identity
                    if validators.target_build is not None else None
                ),
                contract_identity=contract_identity,
                stage4_policy=(
                    validation_config.stage4_policy
                    if validation_config is not None else "strict"
                ),
            ),
        ),
    )


def _publish_harness(
    layout, result, *, recipe_identity=None, contract_identity=None,
    stage4_policy="strict",
):
    summary_path = layout.validation_summary
    summary = {}
    if summary_path.is_file():
        try:
            loaded = json.loads(summary_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                summary = loaded
        except (OSError, UnicodeError, json.JSONDecodeError):
            summary = {}
    promoted = promote_harness(
        layout,
        harness_code=result.harness_code,
        harness_plan=result.harness_plan,
        validation_summary=summary,
        recipe_identity=recipe_identity,
        contract_identity=contract_identity,
        stage4_policy=stage4_policy,
    )
    if promoted:
        return replace(result, stable_path=layout.harness)

    overall = summary.get("overall")
    source_hash = hashlib.sha256(result.harness_code.encode("utf-8")).hexdigest()
    plan_hash = hashlib.sha256(
        json.dumps(result.harness_plan, sort_keys=True).encode("utf-8")
    ).hexdigest()
    layout.write_json(layout.generation / "quarantine.json", {
        "schema_version": 1,
        "status": "quarantined",
        "reason": "formal validation did not reach passed",
        "validation_status": overall or "not_recorded",
        "component_statuses": {
            key: value for key, value in summary.items()
            if key in {"intermediate", "compiler", "linker", "runtime"}
        },
        "source_sha256": source_hash,
        "plan_sha256": plan_hash,
        "source": str(result.harness_path),
    })
    return replace(result, stable_path=None)


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
    event = latest_unresolved_rollback(history if isinstance(history, list) else [])
    if event is None:
        return None
    return {
        key: event.get(key)
        for key in (
            "failed_stage", "validator", "failure_type", "attempt",
            "rollback_target", "reason",
        )
    }


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
    max_tokens_value = environment.get("LLM_MAX_TOKENS", "").strip()
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
    max_tokens = None
    if max_tokens_value:
        try:
            max_tokens = int(max_tokens_value)
        except ValueError as error:
            raise ValueError("LLM_MAX_TOKENS must be a positive integer") from error
        if max_tokens <= 0:
            raise ValueError("LLM_MAX_TOKENS must be a positive integer")
    overrides = {} if max_tokens is None else {"max_tokens": max_tokens}
    return OpenAICompatibleLLM(
        LLMConfig(
            model=selected_model,
            base_url=base_url,
            api_key_env_name="LLM_API_KEY",
            thinking=thinking,
            **overrides,
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


def _select_from_manifest(
    triplets: Sequence[FunctionTriplet], manifest_path: Path
) -> tuple[FunctionTriplet, ...]:
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(
            f"cannot load FT selection manifest: {type(error).__name__}"
        ) from error
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != FT_SELECTION_SCHEMA_VERSION
    ):
        raise ValueError("unsupported or missing FT selection schema_version")
    inputs = document.get("inputs")
    if not isinstance(inputs, dict) or not isinstance(
        inputs.get("triplets_sha256"), str
    ):
        raise ValueError("FT selection is missing the triplets catalog fingerprint")
    if inputs["triplets_sha256"] != triplet_catalog_sha256(triplets):
        raise ValueError("FT selection does not match the current triplets catalog")
    records = document.get("selection")
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise ValueError("FT selection must be an array of objects")
    ids = [item.get("triplet_id") for item in records]
    if any(not isinstance(ft_id, str) or not ft_id for ft_id in ids):
        raise ValueError("every FT selection entry requires triplet_id")
    if len(ids) != len(set(ids)):
        raise ValueError("FT selection contains duplicate triplet_id values")
    by_id = {str(item.id): item for item in triplets}
    unknown = [ft_id for ft_id in ids if ft_id not in by_id]
    if unknown:
        raise ValueError("FT selection references unknown triplet: " + ", ".join(unknown))
    selected = tuple(by_id[ft_id] for ft_id in ids)
    actual_calls = sum(
        len(item.functions) + estimate_structural_units(item) + 3
        for item in selected
    )
    summary = document.get("summary")
    if summary is not None and (
        not isinstance(summary, dict)
        or summary.get("selected_count") != len(selected)
        or summary.get("estimated_llm_calls") != actual_calls
    ):
        raise ValueError("FT selection summary does not match the selected catalog entries")
    constraints = document.get("constraints", {})
    if not isinstance(constraints, dict):
        raise ValueError("FT selection constraints must be an object")
    for name in ("max_ft", "max_calls", "max_functions", "max_structural_units"):
        value = constraints.get(name)
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError(f"FT selection {name} must be a non-negative integer")
    if constraints.get("max_ft") is not None and len(selected) > constraints["max_ft"]:
        raise ValueError("FT selection exceeds its max_ft constraint")
    if constraints.get("max_calls") is not None and actual_calls > constraints["max_calls"]:
        raise ValueError("FT selection exceeds its max_calls constraint")
    if (constraints.get("max_functions") is not None
            and any(len(item.functions) > constraints["max_functions"]
                    for item in selected)):
        raise ValueError("FT selection exceeds its max_functions constraint")
    if (constraints.get("max_structural_units") is not None
            and any(estimate_structural_units(item) > constraints["max_structural_units"]
                    for item in selected)):
        raise ValueError("FT selection exceeds its max_structural_units constraint")
    return selected
