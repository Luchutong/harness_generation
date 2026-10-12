"""Generation-first admission using live ABI and small API usage contracts.

Unproved ownership, recursive cleanup and internal loops are recorded as
unknown. This gate never constructs the formal obligation graph or awards a
semantic certificate. A plan verifier must recompute it; saved labels alone
cannot authorize translation or execution.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from ..api_contracts.extraction import extract_api_contracts, evidence_records
from ..api_contracts.models import ContractStatus
from ..api_contracts.validation import validate_contract_proposals
from ..effectiveness.contracts import inspect_resource_entry_state
from ..harness_strategy.models import StrategyBudget
from ..harness_strategy.normalization import normalize_strategy, proposal_projection
from ..harness_strategy.validation import StrategyValidator
from ..semantic_discovery.models import canonical, digest
from .diagnostics import check, unknown

PREFLIGHT_VERSION = "execution-preflight-v1"


class ExecutionPreflightGate:
    def evaluate(self, ft, snapshot, strategy, evidence, authorized_ids, *,
                 build_analysis=None, project_root=None, contracts=None):
        violations, unresolved, checks = [], [], []
        structural = {"valid": False, "errors": [], "pending_semantic_checks": []}
        extraction = None
        typed_strategy = None
        proposal_contracts = []
        records = evidence_records(evidence)
        scope = set(authorized_ids) - set(ft.get("excluded_functions", []))

        def fail(code, step_id="", detail="", **facts):
            row = check(code, status=ContractStatus.VIOLATED, step_id=step_id, detail=detail, **facts)
            if row not in violations:
                violations.append(row)

        try:
            maximum = strategy.get("input_policy", {}).get("max_input_bytes")
            if type(maximum) is not int or not 1 <= maximum <= 16777216:
                raise ValueError("strategy_has_no_bounded_input_policy")
            budget = StrategyBudget(max_input_bytes=maximum)
            expected = normalize_strategy(proposal_projection(strategy), ft, snapshot, budget)
            if canonical(strategy) != canonical(expected):
                raise ValueError("strategy_envelope_or_source_identity_mismatch")
            extraction = extract_api_contracts(snapshot, strategy, records, scope, build_analysis)
            if project_root is not None and Path(project_root).resolve() != Path(
                    build_analysis.carrier_build_projection()["project_root"]).resolve():
                raise ValueError("execution_project_root_differs_from_current_build")
            # The original normalized envelope remains the public Strategy.
            # Clang's independently authenticated typedef expansion only enters
            # this temporary view and the resulting execution resource table.
            typed_snapshot = extraction["abi_snapshot"]
            typed_strategy = normalize_strategy(proposal_projection(strategy), ft, typed_snapshot, budget)
            structural = StrategyValidator(ft, typed_snapshot, extraction["authenticated_evidence"], scope,
                                           budget=budget).validate(typed_strategy)
            remaining_errors = []
            for error in structural["errors"]:
                if error["code"] == "resource_cleanup_missing":
                    unresolved.append(unknown("cleanup_omitted_ownership_unverified", error["detail"],
                        "The returned resource has no proven ownership contract; omission is an explicit execution assumption."))
                else:
                    remaining_errors.append(error)
            structural["errors"] = remaining_errors
            structural["valid"] = not remaining_errors
            structural["status"] = "invalid" if remaining_errors else "structurally_valid"
            structural["validation_basis"] = "original_envelope_and_live_clang_object_type_overlay"
            structural["original_strategy_digest"] = strategy["strategy_digest"]
            for error in remaining_errors:
                fail(error["code"], error.get("step_id", ""), error.get("detail", ""),
                     authority="deterministic_strategy_structure")
            unresolved.extend(unknown(row["kind"], row.get("subject_id", ""), row.get("detail", ""))
                              for row in structural["pending_semantic_checks"])
            for target in extraction["callable_targets"]:
                if target.get("verified") is not True or target.get("status") != "callable":
                    fail("execution_api_not_callable_in_current_build", detail=target["function_id"],
                         authority="live_clang", clang_evidence_id=target["evidence_id"])
                else:
                    checks.append(check("execution_callable_abi", status=ContractStatus.SATISFIED,
                        function_id=target["function_id"], clang_evidence_id=target["evidence_id"], authority="live_clang"))
            cited = {eid for step in strategy["steps"] for eid in step["evidence_ids"]}
            cited.update(eid for hypothesis in strategy["hypotheses"] for eid in hypothesis["evidence_ids"])
            cited.update(eid for step in strategy["steps"] for expression in step.get("arguments", {}).values()
                         if expression.get("kind") == "source_function" for eid in expression["evidence_ids"])
            for eid in sorted(cited - set(extraction["authenticated_evidence"])):
                fail("execution_source_evidence_invalid", detail=eid, authority="source_record_identity")
            proposal_contracts, proposal_diagnostics = validate_contract_proposals(contracts, snapshot, scope)
            unresolved.extend(unknown(row.pop("kind"), **row) for row in deepcopy(proposal_diagnostics))
            if structural["valid"] and not violations:
                self._entry_contracts(ft, snapshot, strategy, extraction, build_analysis, fail, unresolved, checks)
                self._local_lifetimes(strategy, typed_strategy, extraction, fail, unresolved, checks)
                self._callbacks(snapshot, strategy, extraction, scope, build_analysis, fail, unresolved, checks)
            build_analysis.validate_snapshot(snapshot)
        except (ValueError, TypeError, KeyError, AttributeError, OSError) as error:
            fail("execution_preflight_identity_or_schema_invalid", detail=str(error),
                 authority="current_build_or_strategy_validation")
        resources = deepcopy(typed_strategy["resources"] if typed_strategy else strategy.get("resources", [])
                             if isinstance(strategy, dict) else [])
        calls = deepcopy([step for step in strategy.get("steps", []) if step.get("kind") in {"call", "cleanup"}]
                         if isinstance(strategy, dict) else [])
        declarations = []
        if extraction:
            for fact in extraction["callable_targets"]:
                if fact.get("verified") is not True:
                    continue
                fid = fact["function_id"]
                source, typed_function = snapshot.functions[fid], extraction["abi_snapshot"].functions[fid]
                declaration = deepcopy(source)
                declaration.update(function_id=fid, return_base_type=typed_function["return_base_type"],
                                   return_pointer_depth=typed_function["return_pointer_depth"])
                for parameter, typed_parameter in zip(declaration["parameters"], typed_function["parameters"]):
                    parameter.update(base_type=typed_parameter["base_type"], pointer_depth=typed_parameter["pointer_depth"],
                                     is_pointer=typed_parameter.get("is_pointer"), canonical_type=typed_parameter["type"])
                declarations.append(declaration)
        unknowns = list({canonical(row): row for row in unresolved}.values())
        ownership = [{"value_id": row["value_id"], "ownership": row["ownership"],
                      "cleanup_step_ids": [step["step_id"] for step in calls if step.get("resource_value_id") == row["value_id"]],
                      "assumption_status": ContractStatus.UNKNOWN.value}
                     for row in resources if row["storage"] == "captured" and row["pointer_depth"] > 0]
        result = {"schema_version": 1, "artifact_kind": "execution_preflight", "policy_version": PREFLIGHT_VERSION,
            "ft_id": ft["ft_id"], "ft_digest": digest(ft), "strategy_id": strategy.get("strategy_id") if isinstance(strategy, dict) else None,
            "strategy_digest": strategy.get("strategy_digest") if isinstance(strategy, dict) else None,
            "source_fingerprint": snapshot.source_fingerprint, "functions_fingerprint": snapshot.functions_fingerprint,
            "authorized_function_ids": sorted(scope), "evidence_digest": digest(records),
            "structural_validation": structural, "build_identity": extraction["build_identity"] if extraction else None,
            "known_violations": violations, "unknown_contracts": unknowns, "contract_checks": checks,
            "allowed": not violations and structural["valid"], "semantic_verified": False, "generation_allowed": False,
            "execution_context": {"resources": resources, "calls": calls,
                "api_declarations": declarations,
                "known_contracts": extraction["contracts"] if extraction else [], "contract_proposals": proposal_contracts,
                "unknown_contracts": deepcopy(unknowns), "ownership_assumptions": ownership,
                "semantic_verified": False, "generation_allowed": False},
            "formal_semantics": {"status": "not_evaluated", "verified": False}}
        result["preflight_digest"] = digest(result)
        return result

    @staticmethod
    def _entry_contracts(ft, snapshot, strategy, extraction, index, fail, unresolved, checks):
        core = {row["function_id"] for row in ft["core_functions"]}
        zero_values = set()
        resource_table = {row["value_id"]: row for row in strategy["resources"]}
        for step in strategy["steps"]:
            if step["kind"] == "construct" and step["pointer_depth"] > 0:
                zero_values.add(step["value_id"])
            if step["kind"] not in {"call", "cleanup"}:
                continue
            arguments = deepcopy(step["arguments"])
            for name, expression in arguments.items():
                if expression.get("kind") == "value" and expression.get("value_id") in zero_values:
                    arguments[name] = {"kind": "null"}
            if step["kind"] == "call" and step["function_id"] in core:
                fact = inspect_resource_entry_state(snapshot, step["function_id"], arguments, index,
                    evidence_ids=extraction["complete_bodies"].get(step["function_id"], ()))
                if fact.get("rejection_authority") == "candidate_admission_only" and fact.get("status") == "rejected":
                    fail("execution_core_resource_entry_rejected", step["step_id"], fact["reason"],
                         authority="live_source_build_entry_contract", contract=deepcopy(fact))
                else:
                    unresolved.append(unknown("resource_entry_precondition_unverified", step["step_id"], fact["reason"],
                                              contract=deepcopy(fact)))
            for expression in step["arguments"].values():
                if expression.get("kind") == "address" and expression.get("value_id") in resource_table:
                    zero_values.discard(expression["value_id"])

    @staticmethod
    def _local_lifetimes(strategy, typed, extraction, fail, unresolved, checks):
        usages = {row["function_id"]: row for row in extraction["contracts"] if row["kind"] == "local_resource_usage"}
        resources = {row["value_id"]: row for row in typed["resources"]}
        by_step = {step["step_id"]: step for step in strategy["steps"]}
        aliases, released, zero_values = {}, {}, set()

        def expression_origin(expression):
            kind = expression["kind"]
            if kind == "fuzz_bytes":
                return "framework:fuzz_bytes", "framework"
            if kind == "address":
                return "framework:address:" + expression["value_id"], "framework"
            if kind == "value":
                value = expression["value_id"]
                if value in aliases:
                    return aliases[value]
                row = resources.get(value)
                if row:
                    return row["resource_id"], "captured" if row["storage"] == "captured" else "framework"
            return None, None

        for step in strategy["steps"]:
            if step["kind"] == "construct" and step["pointer_depth"] > 0:
                zero_values.add(step["value_id"])
            if step["kind"] == "capture":
                producer = by_step[step["call_step_id"]]
                usage = usages.get(producer["function_id"], {}).get("facts", {})
                alias = usage.get("returns_alias") if step["source"] == "return" else None
                if alias and alias in producer["arguments"]:
                    aliases[step["value_id"]] = expression_origin(producer["arguments"][alias])
                continue
            if step["kind"] not in {"call", "cleanup"}:
                continue
            origins = {expression_origin(expression)[0] for expression in step["arguments"].values()}
            for origin in origins & set(released):
                # A later call whose predicates imply the earlier release's
                # predicates executes after that release on the same path.
                if released[origin]["guards"] <= set(step["guard_ids"]):
                    fail("execution_use_after_local_release", step["step_id"], origin,
                         authority="live_finite_local_release", previous_step_id=released[origin]["step_id"])
            contract = usages.get(step["function_id"])
            if not contract:
                continue
            fact = contract["facts"]
            if fact.get("unknown_reason"):
                unresolved.append(unknown("cleanup_internal_effect_unverified" if step["kind"] == "cleanup"
                    else "local_resource_effect_unverified", step["step_id"], fact["unknown_reason"], contract_id=contract["contract_id"]))
            for name in fact.get("releases", []):
                expression = step["arguments"].get(name, {})
                if expression.get("kind") == "null" or expression.get("kind") == "value" and expression.get("value_id") in zero_values:
                    continue
                origin, storage = expression_origin(expression)
                if origin is None:
                    continue
                if storage == "framework":
                    fail("execution_release_of_framework_storage", step["step_id"], name,
                         authority="live_finite_local_release", contract_id=contract["contract_id"])
                if fact.get("release_counts", {}).get(name, 1) > 1:
                    fail("execution_repeated_local_release", step["step_id"], name,
                         authority="live_finite_local_release", contract_id=contract["contract_id"])
                released[origin] = {"step_id": step["step_id"], "guards": set(step["guard_ids"])}
                checks.append(check("execution_local_release_binding", status=ContractStatus.SATISFIED,
                    step_id=step["step_id"], parameter=name, resource_origin=origin, contract_id=contract["contract_id"]))
            for expression in step["arguments"].values():
                if expression.get("kind") == "address":
                    zero_values.discard(expression["value_id"])

    @staticmethod
    def _callbacks(snapshot, strategy, extraction, scope, index, fail, unresolved, checks):
        from ..source_analysis.callback_compatibility import SourceCallbackBindings
        callbacks = SourceCallbackBindings(index, snapshot, extraction["authenticated_evidence"], scope)
        for step in strategy["steps"]:
            for name, expression in step.get("arguments", {}).items():
                if expression.get("kind") != "source_function":
                    continue
                fact = callbacks.verify(step, name)
                if fact.get("status") == "incompatible":
                    fail("execution_callback_signature_incompatible", step["step_id"], fact["reason"],
                         authority="live_clang_callback_type", contract=fact)
                elif fact.get("verified") is True:
                    checks.append(check("execution_callback_usage", status=ContractStatus.SATISFIED,
                                        step_id=step["step_id"], parameter=name, contract=fact))
                else:
                    unresolved.append(unknown("callback_usage_unverified", step["step_id"] + ":" + name,
                                              fact.get("reason", "callback_usage_unverified"), contract=fact))
