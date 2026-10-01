"""Standalone context mining through the completeness gate; no generation."""
import argparse
from dataclasses import replace
from pathlib import Path
import sys

from ..artifacts import ArtifactStore
from ..entry_candidates import CandidateCatalog
from ..minimal_ft.models import ProjectSnapshot
from ..minimal_ft.persistence import _load_json, _owned
from ..semantic_discovery.cli import _positive, _nonnegative
from ..semantic_discovery.deepseek_client import DeepSeekAgentModel, DeepSeekConfig
from ..semantic_discovery.provider_config import agent_configuration, LazyAgentModel, load_environment_file
from ..semantic_discovery.tools import RepositoryIndex
from ..sfg_adapter import load_sfg_artifacts
from .completeness import HarnessContextCompletenessValidator
from .loop import HarnessContextMiningLoop
from .models import ContextBudget, MiningState
from .persistence import load_minimal_ft, run_configuration, load_context_documents
from .tools import HarnessContextTools


class LazyDeepSeekModel:
    provider = "deepseek"

    def __init__(self, config):
        self.config, self.model, self._model = config, config.model, None

    def complete(self, messages, tools):
        if self._model is None:
            self._model = DeepSeekAgentModel(self.config)
        return self._model.complete(messages, tools)


def main(argv=None, *, model=None):
    parser = argparse.ArgumentParser(prog="harness-generation harness-context", description="FT-guided bounded Harness Context mining and deterministic completeness")
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--provider", choices=("deepseek", "openai-compatible"), default="deepseek")
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--model")
    parser.add_argument("--thinking", choices=("disabled", "enabled"))
    parser.add_argument("--requirement-mode", choices=("single", "grouped"),
                        help="Default: grouped for real providers, single for injected test clients")
    parser.add_argument("--ft", action="append", default=[])
    parser.add_argument("--candidate", action="append", default=[])
    parser.add_argument("--resume", action="store_true")
    for name, value in ContextBudget().to_dict().items():
        parser.add_argument("--" + name.replace("_", "-"), type=_nonnegative if name in {
            "max_discovered_functions", "max_dependency_depth", "max_terminal_repairs"} else _positive, default=value)
    args = parser.parse_args(argv)
    failed, processed, resumed = 0, 0, 0
    try:
        if model is not None and args.model:
            raise ValueError("cannot combine injected model with --model")
        if args.env_file:
            load_environment_file(args.env_file)
        budget = ContextBudget(**{name: getattr(args, name) for name in ContextBudget().to_dict()})
        store = ArtifactStore(args.artifacts)
        snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(store.root))
        catalog = CandidateCatalog((), snapshot.source_fingerprint)
        index = RepositoryIndex(snapshot.artifacts, catalog, functions_path=store.functions)
        requirement_mode = args.requirement_mode or ("single" if model is not None else "grouped")
        if model is None:
            config = agent_configuration(args.provider, model=args.model, thinking=args.thinking)
            if requirement_mode == "grouped":
                config = replace(config, max_tokens=8192)
            active_model = LazyAgentModel(config)
        else:
            active_model = model
        if not store.minimal_fts_directory.is_dir():
            raise ValueError("missing Minimal FT artifacts; run the upstream minimal-ft stage first")
        selected = []
        headers = []
        for directory in sorted(store.minimal_fts_directory.iterdir()):
            if not directory.is_dir() or not directory.name.startswith("ft_"):
                continue
            header = _load_json(_owned(store.minimal_ft_run(directory.name) / "minimal_ft.json", store.root))
            headers.append(header)
            if args.ft and header["ft_id"] not in args.ft:
                continue
            if args.candidate and not any(value in {header["candidate_id"], header["anchor_function_id"]} for value in args.candidate):
                continue
            selected.append(header["ft_id"])
        if not selected or any(value not in {h["ft_id"] for h in headers} for value in args.ft) or any(
                value not in {identity for h in headers for identity in (h["candidate_id"], h["anchor_function_id"])} for value in args.candidate):
            raise ValueError("selectors must identify existing Minimal FT artifacts by exact ID")
        for ft_id in selected:
            ft, ft_metadata = load_minimal_ft(store, ft_id, snapshot)
            configuration = run_configuration(ft, ft_metadata, snapshot, budget, active_model, requirement_mode=requirement_mode)
            prior = load_context_documents(store, ft_id, configuration, index) if args.resume else None
            if prior and prior["completeness"]["status"] == "complete":
                cached_state = MiningState(budget)
                cached_state.evidence.update({r["evidence_id"]: r for r in prior["evidence"]["records"]})
                cached_state.discoveries.update(prior["metadata"].get("discoveries", {}))
                check = HarnessContextCompletenessValidator().validate(prior["harness_context"], prior["api_closure"], ft,
                    snapshot, prior["requirements"]["requirements"], prior["resolutions"]["resolutions"], cached_state)
                if check == prior["completeness"] and prior["harness_context"]["frozen"]:
                    resumed += 1
                    print(f"[CONTEXT] {ft_id}: complete resumed model_calls=0", flush=True)
                    continue
            state = MiningState(budget)
            tools = HarnessContextTools(snapshot, catalog, ft, state, index=index)
            def progress(requirement, result, reused, current):
                print(f"[REQUIREMENT] {requirement['subject_function_id']} {requirement['kind']}: "
                      f"{result['status']} {'resumed' if reused else 'investigated'} model_calls={current.model_calls}", flush=True)
            run = HarnessContextMiningLoop(active_model, state, group_requirements=requirement_mode == "grouped").run(ft, snapshot, tools, store=store,
                configuration=configuration, resume=args.resume, on_requirement=progress)
            processed += 1
            failed += run.completeness["status"] != "complete"
            print(f"[CONTEXT] {ft_id}: {run.completeness['status']} hard_missing={len(run.completeness['hard_missing'])} "
                  f"required_support={len(run.closure['required_support_apis'])} model_calls={state.model_calls} "
                  f"termination={run.metadata['termination']}", flush=True)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Harness Context failed: {error}", file=sys.stderr)
        return 1
    print(f"[CONTEXT] processed={processed} resumed={resumed} blocked={failed} wrote={store.root / 'harness_contexts'}")
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
