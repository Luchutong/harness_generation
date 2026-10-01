"""Bounded closure/follow-up orchestration; never rerun resolved unrelated work."""
from copy import deepcopy

from ..semantic_discovery.models import canonical, digest
from .agent import HarnessContextAgent
from .api_closure import build_api_closure
from .completeness import HarnessContextCompletenessValidator, missing_requirement_tasks
from .evidence import build_context, validate_resolution_record
from .models import ContextRun, POLICY_VERSION
from .requirements import HarnessRequirementBuilder, attach_basis, requirement
from .persistence import (save_requirement, load_requirement, requirement_configuration, save_context, context_directory)


def expand_requirements(ft, snapshot, rows, closure):
    builder = HarnessRequirementBuilder()
    known = {row["requirement_id"] for row in rows}
    existing = {row["requirement_id"]: row for row in rows}
    additions = []
    for support in closure["required_support_apis"]:
        additions.extend(builder.function_requirements(ft, snapshot, support["function_id"], depth=support["depth"],
                         required_by=support["required_by"], core=False))
        for parent in support["required_by"]:
            additions.append(requirement(ft["ft_id"], parent, "call_order", depth=max(0, support["depth"] - 1)))
    for row in attach_basis(additions, ft):
        if row["requirement_id"] not in known:
            rows.append(row)
            known.add(row["requirement_id"])
            existing[row["requirement_id"]] = row
        else:
            current = existing[row["requirement_id"]]
            parents = sorted(set(current["required_by"]) | set(row["required_by"]))
            if parents != current["required_by"] or row["dependency_depth"] < current["dependency_depth"]:
                current["required_by"] = parents
                current["dependency_depth"] = min(current["dependency_depth"], row["dependency_depth"])
                current["status"] = "open"


class HarnessContextMiningLoop:
    def __init__(self, model, state, *, group_requirements=False):
        self.model, self.state = model, state
        self.group_requirements = group_requirements

    def run(self, ft, snapshot, tools, *, store=None, configuration=None, resume=False, on_requirement=None):
        frozen_digest = digest(ft)
        execution_index = 1
        if store:
            from ..minimal_ft.persistence import _load_json, _owned
            try:
                previous = _load_json(_owned(context_directory(store, ft["ft_id"]) / "metadata.json", store.root))
                execution_index += previous.get("execution_index", 0)
            except (OSError, ValueError, TypeError):
                pass
        requirements = HarnessRequirementBuilder().build(ft, snapshot)
        rows, resolutions, facts = requirements["requirements"], {}, []
        agent = HarnessContextAgent(self.model, self.state)
        followups, followup_history, resumed, diagnostics = [], [], 0, {}
        execution_failures = {}
        termination, report = "completeness_budget_exhausted", None
        attempt_inputs, unchanged_skips = {}, []
        for number in range(1, self.state.budget.max_completeness_rounds + 1):
            targeted = {task["requirement_id"] for task in followups if task["requirement_id"]}
            processed = set()
            while True:
                pending = [row for row in rows if row["requirement_id"] not in processed and (
                    row["status"] in {"open", "unresolved"} or row["requirement_id"] in targeted)]
                if number > 1:
                    pending = [row for row in pending if (row["mandatory"] or row["requirement_id"] in targeted)
                               and row["requirement_id"] not in execution_failures]
                if not pending:
                    break
                if number > 1:
                    input_digest = digest([sorted(self.state.evidence), sorted(f["fact_id"] for f in facts)])
                    unchanged = [row for row in pending if attempt_inputs.get(row["requirement_id"]) == input_digest]
                    for row in unchanged:
                        processed.add(row["requirement_id"])
                        unchanged_skips.append({"round": number, "requirement_id": row["requirement_id"],
                            "reason": "unchanged_evidence_and_facts", "input_digest": input_digest})
                    pending = [row for row in pending if row not in unchanged]
                    if not pending:
                        break
                def priority(row):
                    function = snapshot.functions[row["subject_function_id"]]
                    possible_input = any(p.get("is_pointer") and not (p.get("is_struct_like") or p.get("is_opaque_handle"))
                        for p in function["parameters"])
                    return (0 if row["kind"] == "input_binding" and possible_input else
                        1 if row["kind"] == "input_binding" else 2 if row["mandatory"] else 3,
                        row["subject_function_id"], row["kind"])
                pending.sort(key=priority)
                batch = ([row for row in pending if row["subject_function_id"] == pending[0]["subject_function_id"]][:8]
                         if self.group_requirements else [pending[0]])
                cached, configs = {}, {}
                for row in batch:
                    rid = row["requirement_id"]
                    processed.add(rid)
                    configs[rid] = requirement_configuration(configuration or {}, row)
                    prior = load_requirement(store, ft["ft_id"], row, configs[rid], tools.index, preserve_soft_unknown=True) if resume and store and rid not in targeted else None
                    if prior:
                        records = {record["evidence_id"]: record for record in prior["evidence"]["records"]}
                        discoveries = prior["metadata"].get("discoveries", {})
                        try:
                            from types import SimpleNamespace
                            cached_state = SimpleNamespace(evidence=records, discoveries=discoveries)
                            validate_resolution_record(prior["result"], row, snapshot, cached_state,
                                                       tools.initial_ids, tools.excluded)
                        except (ValueError, TypeError, KeyError):
                            prior = None
                    if prior:
                        self.state.evidence.update(records)
                        self.state.discoveries.update(deepcopy(discoveries))
                        cached[rid] = prior["result"]
                        resumed += 1
                investigated = [row for row in batch if row["requirement_id"] not in cached]
                runs = {}
                if investigated:
                    tasks = [task for task in followups if task["requirement_id"] in {r["requirement_id"] for r in investigated}]
                    investigated_runs = (agent.investigate_group(investigated, tools, facts, tasks) if self.group_requirements
                                         else [agent.investigate(investigated[0], tools, facts, tasks)])
                    runs = {run.result["requirement_id"]: run for run in investigated_runs}
                    input_digest = digest([sorted(self.state.evidence), sorted(f["fact_id"] for f in facts)])
                    for row in investigated:
                        attempt_inputs[row["requirement_id"]] = input_digest
                for row in batch:
                    rid = row["requirement_id"]
                    if rid in cached:
                        result = cached[rid]
                    else:
                        run = runs[rid]
                        diagnostics[rid] = [error for error in run.trace.get("validation_errors", [])
                                            if error.get("requirement_id", rid) == rid]
                        result = run.result
                        # Unsuccessful follow-up cannot erase earlier grounded facts.
                        if rid in resolutions and result["status"] == "unresolved" and not result["facts"]:
                            result["facts"] = deepcopy(resolutions[rid]["facts"])
                            result["discovered_api_dependencies"] = deepcopy(resolutions[rid]["discovered_api_dependencies"])
                        run.metadata["execution_index"] = execution_index
                        if run.metadata.get("resolution_attempt_failed"):
                            row["resolution_attempt_failed"] = run.metadata["resolution_attempt_failed"]
                            execution_failures[rid] = {"requirement_id": rid,
                                "execution_status": run.metadata["resolution_attempt_failed"],
                                "errors": deepcopy(run.metadata.get("execution_errors", []))}
                        else:
                            row.pop("resolution_attempt_failed", None)
                            execution_failures.pop(rid, None)
                        if store:
                            save_requirement(store, ft["ft_id"], run, configs[rid])
                    resolutions[rid] = result
                    if on_requirement:
                        on_requirement(row, result, rid in cached, self.state)
                    row["status"] = result["status"]
                    row["evidence_ids"] = sorted({eid for fact in result["facts"] for eid in fact["evidence_ids"]})
                    facts = [fact for fact in facts if fact["requirement_id"] != rid] + deepcopy(result["facts"])
                closure = build_api_closure(ft, rows, resolutions, snapshot, self.state)
                expand_requirements(ft, snapshot, rows, closure)
            closure = build_api_closure(ft, rows, resolutions, snapshot, self.state)
            context = build_context(ft, rows, facts, snapshot, self.state.evidence)
            context["dependencies"] = deepcopy(closure["unresolved_api_dependencies"])
            report = HarnessContextCompletenessValidator().validate(context, closure, ft, snapshot, rows, resolutions, self.state)
            if report["status"] == "complete":
                termination = "complete"
                break
            if report["status"] == "invalid":
                termination = "invalid_context"
                break
            followups = missing_requirement_tasks(report)
            for task in followups:
                task["validation_diagnostics"] = diagnostics.get(task["requirement_id"], [])
            followup_history.append({"round": number, "tasks": followups})
            if self.state.budget_stop:
                termination = self.state.budget_stop
                break
            if execution_failures and all(task.get("requirement_id") in execution_failures for task in followups):
                # Do not repeat identical rejected requests in another pass.
                termination = "execution_failure"
                break
        context["frozen"] = report["status"] == "complete"
        if digest(ft) != frozen_digest:
            raise ValueError("Minimal FT mutated during context mining")
        requirements["requirements"] = sorted(rows, key=lambda row: row["requirement_id"])
        metrics = {"model_calls": self.state.model_calls, "tool_calls": self.state.tool_calls, "tokens": self.state.tokens,
            "source_chars": self.state.source_chars, "evidence_cache_hits": self.state.evidence_cache_hits, "discovered_functions": len(self.state.discoveries),
            "resolved_requirements": len(report["resolved_requirements"]), "hard_missing": len(report["hard_missing"]),
            "soft_unknowns": len(report["soft_unknowns"]), "closure_size": len(closure["core_apis"]) + len(closure["required_support_apis"]) + len(closure["optional_support_apis"]),
            "required_support_count": len(closure["required_support_apis"]), "optional_support_count": len(closure["optional_support_apis"]),
            "completeness_rounds": number, "resumed_requirements": resumed}
        metrics["execution_failed_requirements"] = len(execution_failures)
        metrics["unchanged_evidence_skips"] = len(unchanged_skips)
        metadata = {"schema_version": 1, "policy_version": POLICY_VERSION, "ft_id": ft["ft_id"],
            "execution_index": execution_index,
            "termination": termination, "metrics": metrics, "followup_history": followup_history,
            "harness_generated": False, "model_decides_completeness": False}
        metadata["execution_failures"] = sorted(execution_failures.values(), key=canonical)
        metadata["unchanged_investigation_skips"] = unchanged_skips
        run = ContextRun(requirements, context, closure, report, metadata)
        if store:
            save_context(store, run, configuration, self.state, resolutions)
        return run
