"""Generation-first entry: one typed strategy, preflight and execution."""
import argparse
from pathlib import Path
import re
import sys
from uuid import uuid4

from ..artifacts import ArtifactStore
from ..harness_strategy.models import StrategyBudget
from ..minimal_ft.models import ProjectSnapshot
from ..minimal_ft.persistence import _load_json, _owned
from ..semantic_discovery.models import ValidationBudget, canonical, digest
from ..semantic_discovery.provider_config import agent_configuration, LazyAgentModel, load_environment_file
from ..sfg_adapter import load_sfg_artifacts
from ..target_build import TargetBuildConfig
from .checkpoint import Checkpoint, _exclusive
from .models import ControllerBudget, VERSION
from .model_budget import SharedBudgetModel
from .generation_services import NativeGenerationServices
from .generation_base import load_minimal_ft
from .single_generation import SingleGenerationController
from .trial_ledger import TrialLedger

CLI_FAILURE_POLICY = "harness-run-cli-boundary-feedback-v1"


def _observed_result(directory):
    if directory is None:
        return None, True
    path = Path(directory) / "result.json"
    try:
        return str(path) if path.is_file() else None, True
    except OSError:
        return None, False


def _diagnostic_record(args, failure, *, directory=None):
    """Publish a separate reviewable record; never touch the result or chain."""
    response = {**failure, "failure_persisted": False, "diagnostic_record": None}
    try:
        artifact_root = Path(args.artifacts).resolve()
        destination = _owned(artifact_root / "orchestration_failures", artifact_root)
        destination.mkdir(parents=True, exist_ok=True)
        path = _owned(destination / ("cli_failure_" + uuid4().hex + ".json"), artifact_root)
        _exclusive(path, {"schema_version": 1, "policy_version": CLI_FAILURE_POLICY,
                          "failure": failure, "failure_digest": digest(failure)})
        response.update(failure_persisted=True, diagnostic_record=str(path))
    except Exception as error:
        response["failure_persistence_error"] = {"error": type(error).__name__, "detail": str(error)}
    return response


def _initialization_failure(args, phase, error, *, run_id=None, directory=None, checkpoint=None):
    pending_verified, pending_error = checkpoint is not None, None
    try:
        pending = checkpoint.pending_actions() if checkpoint is not None else []
    except Exception as state_error:
        pending, pending_verified = [], False
        pending_error = {"error": type(state_error).__name__, "detail": str(state_error)}
    try:
        cost = TrialLedger(checkpoint, include_completed=True).totals() if checkpoint is not None else None
    except Exception:
        cost = None
    observed_result, result_presence_verified = _observed_result(directory)
    failure = {"schema_version": 1, "policy_version": CLI_FAILURE_POLICY, "status": "initialization_failed",
        "success": False, "generation_allowed": False, "cost": cost, "accounting_complete": False,
        "diagnoses": [{"root_cause": "cli_initialization_failed", "code": "cli_" + phase + "_failed",
            "phase": phase, "error": type(error).__name__, "detail": str(error), "recovery_allowed": False}],
        "requested_ft": args.ft, "requested_target": args.target, "requested_resume_run": args.resume_run, "run_id": run_id,
        "run_directory": str(directory) if directory is not None else None,
        "pending_action_ids": pending, "pending_state_verified": pending_verified,
        "requires_explicit_action_reconciliation": bool(pending) or bool(args.resume_run) or pending_error is not None,
        "automatic_action_replay_allowed": False,
        "observed_result_path": observed_result, "result_presence_verified": result_presence_verified,
        "result_authenticated": False}
    if pending_error is not None:
        failure["pending_state_error"] = pending_error
    if cost is not None and (pending or not pending_verified):
        cost["usage_complete"] = cost["provider_requests_complete"] = False
        cost["ledger_digest"] = digest({key: value for key, value in cost.items() if key != "ledger_digest"})
    return _diagnostic_record(args, failure, directory=directory)


def _report_result(result, args, *, ft_id, run_id, directory):
    # A completed historical result has its original labels and a separate
    # current quality view. Use the current view for this invocation's status.
    quality = result.get("current_quality")
    status = quality.get("status", result.get("status")) if isinstance(quality, dict) else result.get("status")
    cost = result.get("cost")
    cost = cost if isinstance(cost, dict) else {}
    result_path, result_presence_verified = _observed_result(directory)
    recorded_path = result_path or ("not_written" if result_presence_verified else "presence_unknown")
    print(f"[HARNESS RUN] mode={args.mode} context={ft_id} status={status} "
          f"verified={len(result.get('verified_harnesses', []))} experimental={len(result.get('experimental_harnesses', []))} "
          f"candidates={len(result.get('candidate_harnesses', []))} "
          f"model_calls={cost.get('model_calls', 'unknown')} tool_calls={cost.get('tool_calls', 'unknown')} "
          f"build_success={result.get('build_success', 'unknown')} runtime_passed={result.get('runtime_passed', 'unknown')} "
          f"fuzz_effective={result.get('fuzz_effective', 'unknown')} semantic_verified={result.get('semantic_verified', 'unknown')} "
          f"generation_allowed={str(result.get('generation_allowed') is True).lower()} run_id={run_id} result={recorded_path}")
    if result.get("diagnoses") or status in {"rejected", "controller_failed", "persistence_failed", "interrupted"}:
        failure = {**result, "cli_failure_policy": CLI_FAILURE_POLICY, "run_id": run_id,
            "run_directory": str(directory), "observed_result_path": result_path,
            "result_presence_verified": result_presence_verified}
        print(canonical(_diagnostic_record(args, failure, directory=directory)), file=sys.stderr)
    return 0 if status in {"verified_success", "experimental_success", "runtime_passed"} else 1


def main(argv=None, *, model=None):
    parser = argparse.ArgumentParser(prog="harness-generation harness-run",
        description="Generate one typed harness, compile it and execute sanitizer fixed inputs")
    parser.add_argument("--mode", choices=("generate",), default="generate",
                        help="Single preflight, deterministic translation and build/runtime execution")
    parser.add_argument("--artifacts", type=Path, required=True)
    context_selection = parser.add_mutually_exclusive_group(required=True)
    context_selection.add_argument("--ft", help="Authenticated existing Minimal FT compatibility input")
    context_selection.add_argument("--target", help="Exact current function ID for the lightweight API scope")
    parser.add_argument("--support-api", action="append", default=[],
                        help="Optional exact related API ID for the lightweight scope; live Clang validation is required")
    parser.add_argument("--target-build", type=Path, required=True)
    parser.add_argument("--strategy-run")
    parser.add_argument("--resume-run")
    parser.add_argument("--language", choices=("c", "c++"), default="c")
    parser.add_argument("--headers", action="append", default=[])
    parser.add_argument("--provider", choices=("deepseek", "openai-compatible"), default="deepseek")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--model")
    parser.add_argument("--thinking", choices=("disabled", "enabled"))
    parser.add_argument("--agent-timeout", type=float, choices=(60.0, 120.0), default=60.0)
    controller_defaults = ControllerBudget().to_dict()
    for name in ("max_model_calls", "max_source_tool_calls", "max_source_chars"):
        default = controller_defaults[name]
        flag = {"max_model_calls": "--max-controller-model-calls", "max_source_chars": "--max-controller-source-chars"}.get(name, "--" + name.replace("_", "-"))
        parser.add_argument(flag, dest="controller_" + name, type=int, default=default)
    for name, default in ValidationBudget().to_dict().items():
        parser.add_argument("--" + name.replace("_", "-"), type=int, default=default)
    parser.add_argument("--max-discovered-functions", type=int, default=16)
    parser.add_argument("--max-input-bytes", type=int, default=4096)
    parser.add_argument("--max-context-functions", type=int, default=8)
    parser.add_argument("--max-context-scan", type=int, default=1024)
    args = parser.parse_args(argv)
    phase = "validate_arguments"
    run_id, directory, checkpoint = None, None, None
    try:
        if args.support_api and not args.target:
            raise ValueError("--support-api belongs to the independent --target scope")
        phase = "load_source"
        store = ArtifactStore(args.artifacts)
        snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(store.root))
        if args.ft:
            phase = "load_minimal_ft"
            ft, metadata = load_minimal_ft(store, args.ft, snapshot)
        else:
            phase = "validate_target"
            if args.target not in snapshot.functions:
                raise ValueError("--target must be an exact function ID from the current source snapshot")
            ft, metadata = None, None
        phase = "validate_budgets"
        # Retain the complete saved budget shape so existing default generate
        # checkpoints keep their identity; only live investigation limits vary.
        budget = ControllerBudget(**{**controller_defaults,
            **{name: getattr(args, "controller_" + name)
               for name in ("max_model_calls", "max_source_tool_calls", "max_source_chars")}})
        strategy_budget = StrategyBudget(max_candidates=1, max_input_bytes=args.max_input_bytes,
            max_discovered_functions=args.max_discovered_functions,
            investigation=ValidationBudget(**{name: getattr(args, name) for name in ValidationBudget().to_dict()}))
        phase = "load_build_recipe"
        from ..semantic_discovery.tools import RepositoryIndex
        from ..entry_candidates import CandidateCatalog
        index = RepositoryIndex(snapshot.artifacts, CandidateCatalog((), snapshot.source_fingerprint), functions_path=store.functions)
        recipe = TargetBuildConfig.load(args.target_build, project_root=index.project_root)
        phase = "configure_provider"
        if args.env_file:
            load_environment_file(args.env_file)
        if model is None:
            model = LazyAgentModel(agent_configuration(args.provider, model=args.model, thinking=args.thinking, timeout=args.agent_timeout))
        elif args.model or args.thinking or args.agent_timeout != 60.0:
            raise ValueError("cannot override injected model configuration")
        descriptor = getattr(model, "config", None)
        descriptor = descriptor.to_dict() if callable(getattr(descriptor, "to_dict", None)) else {
            "provider": getattr(model, "provider", "none"), "model": getattr(model, "model", "none")}
        phase = "resolve_run_directory"
        context_key = ft["ft_id"] if ft is not None else "target_" + digest({"function_id": args.target})[:24]
        root = _owned(store.root / "orchestration" / context_key, store.root)
        prefix = "generate_run_"
        if args.resume_run and re.fullmatch(prefix + r"[0-9a-f]{32}", args.resume_run) is None:
            raise ValueError("invalid generate run ID")
        run_id = args.resume_run or prefix + uuid4().hex
        directory = _owned(root / run_id, store.root)
        initial_used, analysis_directory = 0, None
        if args.resume_run:
            phase = "load_resume_checkpoint"
            header = _load_json(directory / "checkpoint.json")
            old = Checkpoint(directory, header["identity"], resume=True)
            checkpoint = old
            initial_used = TrialLedger(old, include_completed=True).totals()["model_calls"]
            analysis_directory = header["identity"]["build_analysis_directory"]
        bounded = SharedBudgetModel(model, budget.max_model_calls, already_used=initial_used)
        phase = "construct_services"
        context_options = {}
        if args.target:
            from ..lightweight_context.models import ContextBudget
            context_options = {"target": args.target, "target_support_ids": tuple(args.support_api), "context_budget": ContextBudget(
                max_scanned_functions=args.max_context_scan, max_allowed_functions=args.max_context_functions)}
        services = NativeGenerationServices(store, ft, metadata, snapshot, bounded, recipe, directory, budget,
            strategy_budget=strategy_budget, language=args.language, headers=args.headers,
            deterministic_code=True,
            analysis_directory=analysis_directory, **context_options)
        if args.target:
            ft, metadata = services.ft, services.metadata
        phase = "authenticate_checkpoint"
        identity = {"policy_version": VERSION, "source_fingerprint": snapshot.source_fingerprint,
            "functions_fingerprint": snapshot.functions_fingerprint, "ft_id": ft["ft_id"], "ft_digest": digest(ft),
            "ft_metadata_digest": digest(metadata), "build_config": services.effective_recipe(),
            "build_config_digest": digest(services.effective_recipe()), "build_analysis_directory": str(services.analysis_directory),
            "build_analysis_digest": services.analysis.identity_digest, "strategy_budget": strategy_budget.to_dict(),
            "controller_budget": budget.to_dict(), "provider": descriptor, "language": args.language,
            "headers": sorted(set(args.headers)), "strategy_run": args.strategy_run,
            "allow_experimental": False, "deterministic_code": True,
            "mode": args.mode, "execution_policy": "single-harness-generation-v1", "feedback_iteration": 0}
        if args.target:
            identity.update(target=args.target, context_type="lightweight_api_context",
                            context_id=services.lightweight_context.context_id,
                            authorization=services.lightweight_context.scope.receipt)
        checkpoint = Checkpoint(directory, identity, resume=bool(args.resume_run))
        services.checkpoint = checkpoint
        candidates = None
        if args.strategy_run:
            phase = "load_strategy_run"
            candidates = [services.load_single_candidate(args.strategy_run)]
        phase = "run_controller"
        controller = SingleGenerationController(services, checkpoint, budget, mode=args.mode)
        result = controller.run(candidates)
        phase = "report_result"
        return _report_result(result, args, ft_id=ft["ft_id"], run_id=run_id, directory=directory)
    except Exception as error:
        failure = _initialization_failure(args, phase, error, run_id=run_id, directory=directory, checkpoint=checkpoint)
        print(canonical(failure), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
