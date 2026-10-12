"""Shared planning, source identity and accounting for one generation."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

from ..artifacts import ArtifactStore
from ..context_generation.build import SANITIZERS
from ..entry_candidates import CandidateCatalog
from ..harness_strategy.models import StrategyBudget
from ..harness_strategy.persistence import (run_configuration, save_run as save_strategy,
    replay_run as replay_strategy, run_directory as strategy_directory)
from ..harness_strategy.planner import StrategyPlanner, verify_source_identity
from ..harness_strategy.tools import StrategyTools
from ..minimal_ft.models import ProjectSnapshot
from ..minimal_ft.persistence import (_load_json, _owned, load_slice_input, load_legacy_inputs,
    build_configuration, load_compatible_build)
from ..records import write_json
from ..semantic_discovery.models import digest
from ..semantic_discovery.tools import RepositoryIndex
from ..sfg_adapter import load_sfg_artifacts


def load_minimal_ft(store, ft_id, snapshot):
    directory = store.minimal_ft_run(ft_id)
    metadata = _load_json(_owned(directory / "metadata.json", store.root))
    document = _load_json(_owned(directory / "minimal_ft.json", store.root))
    source = load_slice_input(store, document["candidate_id"])
    compare = metadata["configuration"]["compare_legacy"]
    legacy, manifest = load_legacy_inputs(store, {document["anchor_function_id"]}, enabled=compare)
    source.legacy = legacy[document["anchor_function_id"]]
    configuration = build_configuration(source, snapshot, manifest, compare_legacy=compare)
    valid = load_compatible_build(store, ft_id, configuration, source, snapshot)
    if valid is None:
        raise ValueError("Minimal FT is invalid, stale or missing its commit marker; rebuild it upstream")
    return valid, metadata


def load_strategy_inputs(store, ft, ft_metadata, snapshot, run_id, strategy_id=None):
    replay_strategy(store, ft, ft_metadata, snapshot, run_id)
    directory = strategy_directory(store, ft["ft_id"], run_id)
    strategies = _load_json(_owned(directory / "strategies.json", store.root))
    evidence = _load_json(_owned(directory / "evidence.json", store.root))
    selected = strategy_id or strategies["selected_strategy_id"]
    if selected is None or selected not in strategies["ranked_strategy_ids"]:
        raise ValueError("generation requires a structurally valid strategy")
    strategy = next(row["strategy"] for row in strategies["candidates"] if row["strategy"]["strategy_id"] == selected)
    return strategy, evidence


def authenticate_candidate_evidence(candidate, store, ft, metadata, snapshot):
    """Reproduce the selected strategy and its exact source-authorized evidence."""
    if candidate.get("effect_runs") or candidate.get("query_runs"):
        raise ValueError("single generation cannot extend its strategy evidence through recovery")
    strategy, upstream = load_strategy_inputs(store, ft, metadata, snapshot, candidate["strategy_run"],
                                              candidate["strategy"]["strategy_id"])
    if strategy != candidate["strategy"] or candidate["ft_digest"] != digest(ft):
        raise ValueError("generation candidate source Strategy/FT identity changed")
    records = {row["evidence_id"]: row for row in upstream["records"]}
    allowed = set(upstream["authorized_function_ids"])
    expected = {"schema_version": 1, "records": [records[eid] for eid in sorted(records)],
                "authorized_function_ids": sorted(allowed)}
    if candidate["evidence"] != expected or set(candidate["authorized_function_ids"]) != allowed:
        raise ValueError("generation evidence or API scope changed")
    index = RepositoryIndex(snapshot.artifacts, CandidateCatalog((), snapshot.source_fingerprint),
                            functions_path=store.functions)
    verify_source_identity(snapshot, index, allowed, records.values())
    return expected


class NativeGenerationBase:
    def __init__(self, store, ft, metadata, snapshot, model, recipe, directory, budget, *, strategy_budget=None,
                 language="c", headers=(), deterministic_code=False, analysis_directory=None):
        self.store, self.ft, self.metadata, self.snapshot = store, ft, metadata, snapshot
        self.model, self.recipe, self.directory, self.budget = model, recipe, Path(directory), budget
        self.strategy_budget = strategy_budget or StrategyBudget()
        self.language, self.headers, self.deterministic_code = language, tuple(headers), deterministic_code
        self.inputs_cache = {str(store.root): (store, ft, metadata, snapshot)}
        self.model_cursor, self.pending = 0, []
        self.directory.mkdir(parents=True, exist_ok=True)
        self.analysis_directory, self.analysis = self._analysis(analysis_directory)

    def _analysis(self, requested):
        from ..source_analysis.clang_index import BuildAwareIndex
        from ..source_analysis.analyzer import analyze_build, write_analysis
        if requested is not None:
            directory = Path(requested).resolve()
            analysis = BuildAwareIndex.load(directory, self.snapshot)
            analysis.validate_recipe(self.effective_recipe())
            return directory, analysis
        if (self.store.root / "compile_context.json").is_file():
            analysis = BuildAwareIndex.load(self.store.root, self.snapshot)
            try:
                analysis.validate_recipe(self.effective_recipe())
                return self.store.root, analysis
            except ValueError:
                pass
        directory = self.directory / "build_analysis"
        directory.mkdir(exist_ok=False)
        functions_document = _load_json(self.store.functions)
        functions_document["project"] = str(self.recipe.project_root)
        write_json(directory / "functions.json", functions_document, sort_keys=True)
        commands = [{"directory": str(self.recipe.project_root), "file": str(source),
            "arguments": [self.recipe.compiler, *self.recipe.compiler_flags, *SANITIZERS,
                          *(item for path in self.recipe.include_paths for item in ("-I", str(path))), "-c", str(source)]}
                    for source in self.recipe.source_files]
        write_json(directory / "compile_commands.json", commands, sort_keys=True)
        documents = analyze_build(self.recipe.project_root, directory / "compile_commands.json",
                                  functions_document, snapshot=self.snapshot)
        write_analysis(directory, documents)
        analysis = BuildAwareIndex.load(directory, self.snapshot)
        analysis.validate_recipe(self.effective_recipe())
        return directory, analysis

    def effective_recipe(self):
        return {**self.recipe.to_dict(), "effective_compiler_flags": list(self.recipe.compiler_flags + SANITIZERS)}

    def verify_identity(self):
        index = RepositoryIndex(self.snapshot.artifacts, CandidateCatalog((), self.snapshot.source_fingerprint), functions_path=self.store.functions)
        verify_source_identity(self.snapshot, index, self.ft["core_functions"] and {row["function_id"] for row in self.ft["core_functions"] + self.ft["support_candidates"]})
        self.analysis.validate_snapshot(self.snapshot)
        self.analysis.validate_recipe(self.effective_recipe())
        self.recipe.validate_inputs()

    def _inputs(self, candidate):
        path = str(Path(candidate["artifacts"]).resolve())
        if path not in self.inputs_cache:
            store = ArtifactStore(path)
            snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(store.root))
            ft, metadata = load_minimal_ft(store, candidate["ft_id"], snapshot)
            self.inputs_cache[path] = store, ft, metadata, snapshot
        store, ft, metadata, snapshot = self.inputs_cache[path]
        authenticate_candidate_evidence(candidate, store, ft, metadata, snapshot)
        index = RepositoryIndex(snapshot.artifacts, CandidateCatalog((), snapshot.source_fingerprint), functions_path=store.functions)
        return store, ft, metadata, snapshot, index

    def collect_pending_accounting(self):
        rows = self.model.events[self.model_cursor:]
        if rows:
            first, last = rows[0]["invocation"], rows[-1]["invocation"]
            usage, complete, events = {}, True, []
            counts = {"confirmed_started_requests": 0, "unknown_invocations": 0, "offline_invocations": 0, "pretransport_failures": 0}
            for row in rows:
                metadata = row.get("metadata", {})
                reported = metadata.get("usage", {})
                complete &= bool(reported) and all(type(v) is int and v >= 0 for v in reported.values())
                if reported and all(type(v) is int and v >= 0 for v in reported.values()):
                    for key, value in reported.items():
                        usage[key] = usage.get(key, 0) + value
                diagnostics = row.get("diagnostics", metadata.get("request_diagnostics", {}))
                if self.model.provider in {"fake", "recorded"}:
                    counts["offline_invocations"] += 1
                elif diagnostics.get("request_started_utc"):
                    counts["confirmed_started_requests"] += 1
                elif row.get("model_call") is False:
                    counts["pretransport_failures"] += 1
                else:
                    counts["unknown_invocations"] += 1
                events.append(deepcopy(row))
            self.pending.append({"stage_id": f"controller_model_{first}_{last}", "metadata": {
                "model_calls": len(rows), "tool_calls": 0, "tokens": usage, "usage_complete": complete,
                "provider_events": events, "provider_request_accounting": counts}})
            self.model_cursor = len(self.model.events)
        result, self.pending = self.pending, []
        return result

    def _tool_account(self, stage_id, metadata):
        self.pending.append({"stage_id": stage_id, "metadata": {
            "model_calls": 0, "tool_calls": metadata.get("tool_calls", 0),
            "source_chars": metadata.get("source_chars", 0), "tokens": {}, "provider_events": []}})

    def _stage_budget(self):
        # Pending records are accounted immediately after each service action.
        from .trial_ledger import TrialLedger
        totals = TrialLedger(self.checkpoint).totals() if hasattr(self, "checkpoint") else {"tool_calls": 0, "source_chars": 0}
        tools = self.budget.max_source_tool_calls - totals["tool_calls"] - sum(row["metadata"].get("tool_calls", 0) for row in self.pending)
        chars = self.budget.max_source_chars - totals["source_chars"] - sum(row["metadata"].get("source_chars", 0) for row in self.pending)
        rounds = self.model.maximum - self.model.used
        if min(tools, chars, rounds) <= 0:
            raise RuntimeError("shared_controller_investigation_budget_exhausted")
        return replace(self.strategy_budget, investigation=replace(self.strategy_budget.investigation,
            max_rounds=min(rounds, self.strategy_budget.investigation.max_rounds),
            max_tool_calls=min(tools, self.strategy_budget.investigation.max_tool_calls),
            max_source_chars=min(chars, self.strategy_budget.investigation.max_source_chars)))

    def plan(self, feedback, *, inputs=None):
        if feedback is not None or inputs is not None:
            raise ValueError("single generation cannot replan from execution feedback")
        store, ft, metadata, snapshot = self.store, self.ft, self.metadata, self.snapshot
        budget = self._stage_budget()
        index = RepositoryIndex(snapshot.artifacts, CandidateCatalog((), snapshot.source_fingerprint), functions_path=store.functions)
        tools = StrategyTools(snapshot, index.catalog, ft, budget, index=index, build_analysis=self.analysis)
        run = StrategyPlanner(self.model, budget).plan(ft, snapshot, tools, feedback=feedback)
        config = run_configuration(ft, metadata, snapshot, budget, self.model, feedback=feedback,
            build_analysis=self.analysis, build_analysis_directory=self.analysis_directory)
        run_id = save_strategy(store, ft["ft_id"], run, config)
        self._tool_account(run_id, run.metadata)
        rows = {row["strategy"]["strategy_id"]: row for row in run.result["candidates"]}
        evidence = {"schema_version": 1, "records": run.evidence["records"],
                    "authorized_function_ids": run.evidence["authorized_function_ids"]}
        candidates = [{"artifacts": str(store.root), "ft_id": ft["ft_id"], "ft_digest": digest(ft),
            "strategy": rows[sid]["strategy"], "strategy_run": run_id, "query_runs": [], "effect_runs": [],
            "evidence": evidence, "authorized_function_ids": evidence["authorized_function_ids"]}
                      for sid in run.result["ranked_strategy_ids"]]
        excluded = {row if isinstance(row, str) else row["function_id"] for row in ft.get("excluded_functions", [])}
        diagnoses = []
        if not candidates:
            failed = [row for attempt in run.result.get("attempts", []) for row in attempt.get("candidates", [])]
            for row in failed:
                for error in row.get("validation", {}).get("errors", []):
                    cause = "upstream_scope_blocked" if error.get("code") == "strategy_api_not_authorized" and error.get("detail") in excluded else "strategy_not_executable"
                    diagnosis = {"root_cause": cause, **error}
                    if diagnosis not in diagnoses:
                        diagnoses.append(diagnosis)
            # Schema/JSON rejection can happen before a candidate is recorded.
            # Preserve that actionable failure for a fresh bounded planning run;
            # provider failures and stale-source preflight are not proposal fixes.
            if not diagnoses:
                terminal_categories = {"terminal_schema_error", "terminal_json_parse_error", "terminal_validation_error"}
                for event in run.trace.get("events", []):
                    if event.get("kind") != "execution_error" or event.get("error_category") not in terminal_categories:
                        continue
                    diagnosis = {"root_cause": "strategy_not_executable", "code": event["error_category"],
                        "detail": {key: deepcopy(event[key]) for key in
                            ("schema_errors", "error", "detail", "json_location", "arguments_chars") if key in event}}
                    if diagnosis not in diagnoses:
                        diagnoses.append(diagnosis)
            source_errors = run.result.get("source_validation", {}).get("errors", [])
            termination = run.metadata.get("termination")
            if source_errors:
                diagnoses = [{"root_cause": "identity_ambiguous", "code": "source_identity_invalid",
                    "detail": deepcopy(source_errors), "recovery_allowed": False}]
            elif termination == "provider_error":
                errors = [event for event in run.trace.get("events", []) if event.get("kind") == "model_error"]
                diagnoses = [{"root_cause": "provider_or_protocol_failure", "code": "planning_provider_failure",
                    "detail": {key: errors[-1][key] for key in ("error_category", "http_status") if key in errors[-1]} if errors else {},
                    "recovery_allowed": False}]
            elif not diagnoses and termination in {"max_rounds", "terminal_round_without_submission", "invalid_output"}:
                diagnoses = [{"root_cause": "strategy_not_executable", "code": "planning_terminal_submission_missing",
                    "detail": {"termination": termination}}]
        return {"candidates": candidates, "strategy_run": run_id, "status": run.result["status"], "diagnoses": diagnoses,
            "planning_inputs": {"artifacts": str(store.root), "ft_id": ft["ft_id"], "ft_digest": digest(ft)},
            "previous_invalid_strategy": failed[-1]["strategy"] if not candidates and failed else None}
