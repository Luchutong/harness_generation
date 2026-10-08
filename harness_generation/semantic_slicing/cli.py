"""Standalone slice command; consumes accepted results without revalidation."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from ..artifacts import ArtifactStore
from ..semantic_discovery.cli import _ModelDescriptor, _nonnegative, _positive
from ..semantic_discovery.deepseek_client import DeepSeekAgentModel, DeepSeekConfig
from ..semantic_discovery.provider_config import agent_configuration, native_agent_model, load_environment_file
from ..semantic_discovery.models import AgentModelError, ValidationBudget, candidate_id
from ..semantic_discovery.tools import RepositoryIndex
from ..sfg_adapter import load_sfg_artifacts
from .agent import SemanticSliceAgent
from .frontier import build_frontier
from .persistence import (load_accepted_candidates, load_compatible_slice, run_configuration, save_run)
from .tools import SemanticSliceTools


def main(argv=None, *, model=None):
    parser = argparse.ArgumentParser(prog="harness-generation semantic-slice",
                                     description="Bounded semantic slices of accepted validated anchors")
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--provider", choices=("deepseek", "openai-compatible"), default="deepseek")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--model")
    parser.add_argument("--thinking", choices=("disabled", "enabled"))
    parser.add_argument("--agent-timeout", type=float, choices=(60.0, 120.0), default=60.0,
                        help="Per-request transport timeout; no additional calls or SDK retries")
    parser.add_argument("--candidate", action="append", default=[], help="Accepted function ID or candidate ID; repeatable")
    parser.add_argument("--max-candidates", type=_nonnegative)
    parser.add_argument("--max-discovered-functions", type=_nonnegative, default=32)
    for name, default in ValidationBudget().to_dict().items():
        parser.add_argument("--" + name.replace("_", "-"), type=_positive, default=default)
    parser.add_argument("--resume", action="store_true", help="Reuse compatible completed slices, including unresolved frontier")
    args = parser.parse_args(argv)
    processed, resumed, failures = 0, 0, 0
    try:
        if model is not None and args.model:
            raise ValueError("cannot combine injected agent model and --model")
        if model is not None and args.agent_timeout != 60.0:
            raise ValueError("cannot override transport timeout of an injected agent model")
        if args.env_file:
            load_environment_file(args.env_file)
        budget = ValidationBudget(**{name: getattr(args, name) for name in ValidationBudget().to_dict()})
        store = ArtifactStore(args.artifacts)
        catalog = store.load_candidate_catalog()
        if catalog is None:
            raise ValueError("missing candidate_discovery/candidates.json; run candidates first")
        artifacts = load_sfg_artifacts(store.root)
        catalog.validate_against(artifacts)
        index = RepositoryIndex(artifacts, catalog, functions_path=store.functions)
        accepted = load_accepted_candidates(store, catalog, index)
        requested_ids = set()
        for requested in args.candidate:
            matches = [c for c, _ in accepted if requested in {c.function_id, candidate_id(c.function_id)}]
            if len(matches) != 1:
                raise ValueError("--candidate must identify one accepted validated candidate")
            requested_ids.add(matches[0].function_id)
        if args.candidate:
            accepted = [(c, v) for c, v in accepted if c.function_id in requested_ids]
        config = agent_configuration(args.provider, model=args.model, thinking=args.thinking, timeout=args.agent_timeout)
        descriptor = model or _ModelDescriptor(config)
        for candidate, validation in accepted:
            frontier = build_frontier(store, artifacts, catalog, candidate, validation)
            configuration = run_configuration(catalog, frontier, budget, descriptor, args.max_discovered_functions)
            if args.resume and load_compatible_slice(store, frontier, configuration, index, budget):
                resumed += 1
                continue
            if args.max_candidates is not None and processed >= args.max_candidates:
                continue
            if model is None:
                model = native_agent_model(config)
            print(f"[SLICE] {candidate.function_id}", flush=True)
            tools = SemanticSliceTools(artifacts, catalog, frontier, budget, index=index,
                                      max_discovered_functions=args.max_discovered_functions)
            run = SemanticSliceAgent(model, budget).slice(tools)
            save_run(store, run, configuration)
            processed += 1
            failures += run.result["run_status"] in {"invalid", "error"}
            print(f"[SLICE] {run.result['run_status']} core={len(run.result['core_functions'])} "
                  f"unresolved={len(run.result['unresolved_frontier'])} ({run.metadata['termination']})", flush=True)
    except (OSError, ValueError, AgentModelError) as error:
        print(f"Semantic slice failed: {error}", file=sys.stderr)
        return 1
    print(f"[SLICE] processed={processed} resumed={resumed} accepted={len(accepted)} wrote={store.semantic_slices_directory}")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
