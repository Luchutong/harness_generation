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
    def __init__(self, model, state):
        self.model, self.state = model, state

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
        termination, report = "completeness_budget_exhausted", None
        for number in range(1, self.state.budget.max_completeness_rounds + 1):
            targeted = {task["requirement_id"] for task in followups if task["requirement_id"]}
            processed = set()
            while True:
                pending = [row for row in rows if row["requirement_id"] not in processed and (
                    row["status"] in {"open", "unresolved"} or row["requirement_id"] in targeted)]
                if number > 1:
                    pending = [row for row in pending if row["mandatory"] or row["requirement_id"] in targeted]
                if not pending:
                    break
                row = pending[0]
                rid = row["requirement_id"]
                processed.add(rid)
                prior = None
                req_config = requirement_configuration(configuration or {}, row)
                if resume and store and rid not in targeted:
                    prior = load_requirement(store, ft["ft_id"], row, req_config, tools.index)
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
                    result = prior["result"]
                    resumed += 1
                else:
                    run = agent.investigate(row, tools, facts, [task for task in followups if task["requirement_id"] == rid])
                    diagnostics[rid] = run.trace.get("validation_errors", [])
                    result = run.result
                    # An unsuccessful follow-up cannot erase earlier grounded
                    # facts; the requirement remains unresolved and the gate
                    # still blocks its missing contract.
                    if rid in resolutions and result["status"] == "unresolved" and not result["facts"]:
                        result["facts"] = deepcopy(resolutions[rid]["facts"])
                        result["discovered_api_dependencies"] = deepcopy(resolutions[rid]["discovered_api_dependencies"])
                    run.metadata["execution_index"] = execution_index
                    if store:
                        save_requirement(store, ft["ft_id"], run, req_config)
                resolutions[rid] = result
                if on_requirement:
                    on_requirement(row, result, bool(prior), self.state)
                row["status"] = result["status"]
                row["evidence_ids"] = sorted({eid for fact in result["facts"] for eid in fact["evidence_ids"]})
                facts = [fact for fact in facts if fact["requirement_id"] != rid] + deepcopy(result["facts"])
                closure = build_api_closure(ft, rows, resolutions, snapshot, self.state)
                expand_requirements(ft, snapshot, rows, closure)
            closure = build_api_closure(ft, rows, resolutions, snapshot, self.state)
            context = build_context(ft, rows, facts)
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
        context["frozen"] = report["status"] == "complete"
        if digest(ft) != frozen_digest:
            raise ValueError("Minimal FT mutated during context mining")
        requirements["requirements"] = sorted(rows, key=lambda row: row["requirement_id"])
        metrics = {"model_calls": self.state.model_calls, "tool_calls": self.state.tool_calls, "tokens": self.state.tokens,
            "source_chars": self.state.source_chars, "discovered_functions": len(self.state.discoveries),
            "resolved_requirements": len(report["resolved_requirements"]), "hard_missing": len(report["hard_missing"]),
            "soft_unknowns": len(report["soft_unknowns"]), "closure_size": len(closure["core_apis"]) + len(closure["required_support_apis"]) + len(closure["optional_support_apis"]),
            "required_support_count": len(closure["required_support_apis"]), "optional_support_count": len(closure["optional_support_apis"]),
            "completeness_rounds": number, "resumed_requirements": resumed}
        metadata = {"schema_version": 1, "policy_version": POLICY_VERSION, "ft_id": ft["ft_id"],
            "execution_index": execution_index,
            "termination": termination, "metrics": metrics, "followup_history": followup_history,
            "harness_generated": False, "model_decides_completeness": False}
        run = ContextRun(requirements, context, closure, report, metadata)
        if store:
            save_context(store, run, configuration, self.state, resolutions)
        return run
