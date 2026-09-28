"""Candidate validation only. No implicit discovery, FT or harness generation."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from ..artifacts import ArtifactStore
from ..sfg_adapter import load_sfg_artifacts
from .agent import CandidateValidationAgent
from .deepseek_client import DeepSeekAgentModel, DeepSeekConfig
from .models import AgentModelError, ValidationBudget, candidate_id
from .persistence import (load_compatible_run, run_configuration, save_run,
                          write_validated_catalog)
from .tools import RepositoryIndex, RepositoryTools


def _positive(value):
    result = int(value)
    if result < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return result


def _nonnegative(value):
    result = int(value)
    if result < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return result


def main(argv: list[str] | None = None, *, model=None) -> int:
    parser = argparse.ArgumentParser(prog="harness-generation candidate-validate",
                                     description="Bounded recall-first semantic candidate validation")
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--provider", choices=("deepseek",), default="deepseek")
    parser.add_argument("--model")
    parser.add_argument("--thinking", choices=("disabled", "enabled"), default="disabled")
    parser.add_argument("--candidate", action="append", default=[],
                        help="Explicit function ID or stable candidate ID; repeatable, permits revalidation")
    parser.add_argument("--max-candidates", type=_nonnegative)
    parser.add_argument("--max-terminal-repairs", type=int, choices=(0, 1), default=1)
    for name, default in ValidationBudget().to_dict().items():
        parser.add_argument("--" + name.replace("_", "-"), type=_positive, default=default)
    parser.add_argument("--resume", action="store_true",
                        help="Reuse compatible completed runs including unresolved; retry invalid/provider failures")
    args = parser.parse_args(argv)
    try:
        if model is not None and args.model:
            raise ValueError("cannot combine injected agent model and --model")
        budget = ValidationBudget(**{name: getattr(args, name) for name in ValidationBudget().to_dict()})
        store = ArtifactStore(args.artifacts)
        catalog = store.load_candidate_catalog()
        if catalog is None:
            raise ValueError("missing candidate_discovery/candidates.json; run candidates first")
        artifacts = load_sfg_artifacts(args.artifacts)
        catalog.validate_against(artifacts)
        index = RepositoryIndex(artifacts, catalog, functions_path=store.functions)
        config = DeepSeekConfig.from_environment(model=args.model, thinking=args.thinking)
        # A configuration-only model permits checking reusable runs without a key.
        descriptor = model or _ModelDescriptor(config)
        configuration = run_configuration(catalog, budget, descriptor, max_terminal_repairs=args.max_terminal_repairs)
        results, deferred, todo = {}, {}, []
        explicit_ids = set()
        for requested in args.candidate:
            matches = [c for c in catalog.candidates if requested in
                       {c.function_id, candidate_id(c.function_id)}]
            if len(matches) != 1:
                raise ValueError("--candidate must identify one recorded candidate")
            explicit_ids.add(matches[0].function_id)
        selected_ids = set(catalog.selected_function_ids)
        for candidate in catalog.candidates:
            prior = load_compatible_run(store, candidate, configuration, index)
            if prior:
                results[candidate.function_id] = prior
            explicit = candidate.function_id in explicit_ids
            if args.candidate and not explicit:
                if not prior:
                    deferred[candidate.function_id] = "not_requested"
                continue
            if not explicit and candidate.function_id not in selected_ids:
                if not prior:
                    deferred[candidate.function_id] = catalog.deferred_reasons[candidate.function_id]
                continue
            if not explicit and prior and (prior["verdict"] in {"accepted", "rejected"}
                                           or (args.resume and prior["run_status"] == "completed")):
                continue
            if candidate.status != "unresolved" and not explicit:
                continue
            if args.max_candidates is not None and len(todo) >= args.max_candidates:
                deferred[candidate.function_id] = "validation_candidate_budget"
                continue
            todo.append(candidate)
            deferred[candidate.function_id] = "pending_validation"
        if todo and model is None:
            model = DeepSeekAgentModel(config)
        if todo:
            agent = CandidateValidationAgent(model, budget, max_terminal_repairs=args.max_terminal_repairs)
            for candidate in todo:
                print(f"[VALIDATE] {candidate.function_id}", flush=True)
                run = agent.validate(candidate, RepositoryTools(artifacts, catalog, budget, index=index))
                results[candidate.function_id] = save_run(store, run, configuration)
                deferred.pop(candidate.function_id, None)
                # Persist after each candidate so interruption never loses completed work.
                write_validated_catalog(store, catalog, results, deferred)
                print(f"[VALIDATE] {run.result['verdict']} ({run.metadata['termination']})", flush=True)
        write_validated_catalog(store, catalog, results, deferred)
    except (OSError, ValueError, AgentModelError) as error:
        print(f"Candidate validation failed: {error}", file=sys.stderr)
        return 1
    print(f"[VALIDATE] processed={len(todo)} recorded={len(catalog.candidates)} wrote={store.validated_candidates}")
    return 1 if any(results[c.function_id]["run_status"] != "completed" for c in todo) else 0


class _ModelDescriptor:
    provider = "deepseek"

    def __init__(self, config):
        self.config, self.model = config, config.model


if __name__ == "__main__":
    raise SystemExit(main())
