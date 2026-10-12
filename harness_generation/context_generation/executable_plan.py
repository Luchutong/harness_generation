"""Immutable generation candidates, independent of formal Context closure.

A serialized digest permits deterministic translation, not execution authority.
The executor independently replays preflight against live, authenticated inputs
before it starts a compiler or runtime process.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
from types import SimpleNamespace

from ..semantic_discovery.models import digest
from .executable_helpers import (_headers, evidence_records, strategy_budget,
                            translation_declarations, unreachable_core_calls)

SCHEMA_VERSION = 1
POLICY_VERSION = "executable-strategy-plan-v1"


class UnsupportedTranslationError(ValueError):
    code = "unsupported_translation"


def _active(strategy):
    from ..source_analysis.callback_compatibility import source_function_ids
    return ({step["function_id"] for step in strategy["steps"]
             if step["kind"] in {"call", "cleanup"}} | source_function_ids(strategy))


def _header_identity(build_analysis, project_root, headers):
    """Every selected header is part of the authenticated build dependencies."""
    from ..source_paths import SourcePathResolver
    carrier = build_analysis.carrier_build_projection()
    root = Path(carrier["project_root"]).resolve()
    if project_root is not None and Path(project_root).resolve() != root:
        raise ValueError("executable plan project/build identity mismatch")
    resolver = SourcePathResolver(root)
    identities = []
    for header in _headers(headers):
        path = resolver.resolve(header)
        with path.open("rb") as stream:
            raw = stream.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("executable plan header exceeds source read bound")
        sha = hashlib.sha256(raw).hexdigest()
        if carrier["dependency_hashes"].get(str(path.resolve())) != sha:
            raise ValueError("executable plan header is outside authenticated build dependencies")
        identities.append({"header": header, "resolved_path": str(path.resolve()), "sha256": sha})
    return str(root), identities


def require_executable_plan(plan, *, plan_validator=None):
    """Check this artifact's own type; never grant strict FrozenPlan authority."""
    if not isinstance(plan, dict) or plan.get("artifact_kind") != "executable_plan":
        raise ValueError("expected independent executable_plan artifact")
    if plan.get("schema_version") != SCHEMA_VERSION or plan.get("policy_version") != POLICY_VERSION:
        raise ValueError("unsupported executable plan schema or policy")
    if plan.get("plan_digest") != digest({key: value for key, value in plan.items() if key != "plan_digest"}):
        raise ValueError("executable plan digest mismatch")
    content = {key: value for key, value in plan.items() if key not in {"plan_id", "plan_digest"}}
    if plan.get("plan_id") != "executable_plan_" + digest(content)[:24]:
        raise ValueError("executable plan ID mismatch")
    strategy = plan.get("strategy", {})
    if (strategy.get("strategy_digest") != digest({key: value for key, value in strategy.items()
                                                  if key != "strategy_digest"})
            or strategy.get("generation_allowed") is not False
            or any(plan.get(key) != strategy.get(key) for key in ("ft_id", "ft_digest", "source_fingerprint",
                "functions_fingerprint", "strategy_id", "strategy_digest"))):
        raise ValueError("executable plan Strategy identity mismatch")
    for field, expected in {"execution_allowed": True, "semantic_verified": False,
            "generation_allowed": False, "formal_success_statistics_allowed": False,
            "experimental_execution_allowed": False, "immutable": True, "frozen": True}.items():
        if plan.get(field) is not expected:
            raise ValueError("executable plan cannot claim formal or experimental authority")
    if plan.get("statistics_category") != "candidate":
        raise ValueError("executable plan statistics identity mismatch")
    preflight = plan.get("execution_preflight", {})
    if (preflight.get("allowed") is not True or preflight.get("known_violations")
            or preflight.get("semantic_verified") is not False or preflight.get("generation_allowed") is not False
            or preflight.get("preflight_digest") != digest({key: value for key, value in preflight.items()
                                                            if key != "preflight_digest"})):
        raise ValueError("executable plan preflight identity mismatch")
    context = preflight.get("execution_context", {})
    if plan.get("execution_context") != context or plan.get("executable_resources") != context.get("resources"):
        raise ValueError("executable plan execution context changed")
    if plan.get("unknown_contracts") != preflight.get("unknown_contracts"):
        raise ValueError("executable plan unknown contracts changed")
    if plan.get("build_identity") != preflight.get("build_identity") or not plan.get("build_identity"):
        raise ValueError("executable plan requires current build identity")
    resources = plan.get("executable_resources")
    original = {row["value_id"]: row for row in strategy.get("resources", [])}
    if (not isinstance(resources, list) or len(resources) != len(original)
            or {row.get("value_id") for row in resources} != set(original)):
        raise ValueError("executable plan resource projection does not cover Strategy")
    for row in resources:
        source = original[row["value_id"]]
        if any(row.get(key) != source.get(key) for key in ("resource_id", "origin", "storage")):
            raise ValueError("executable plan resource origin changed")
    if plan.get("language") not in {"c", "c++"}:
        raise ValueError("unsupported strategy translation language")
    if list(_headers(plan.get("headers", []))) != plan.get("headers"):
        raise ValueError("executable plan header list is not canonical")
    if [row.get("header") for row in plan.get("header_identity", [])] != plan["headers"]:
        raise ValueError("executable plan header identity mismatch")
    maximum = plan.get("input_policy", {}).get("max_bytes")
    if type(maximum) is not int or not 1 <= maximum <= strategy_budget(strategy).max_input_bytes:
        raise ValueError("invalid executable translation input bound")
    active, declarations = _active(strategy), plan.get("api_declarations", [])
    if len(declarations) != len(active) or {row.get("function_id") for row in declarations} != active:
        raise ValueError("executable declarations do not match Strategy")
    from .strategy_generation import TRANSLATION_VERSION
    if plan.get("translation_policy_version") != TRANSLATION_VERSION:
        raise ValueError("unsupported executable translation policy")
    if plan_validator is not None and (not callable(plan_validator) or plan_validator(plan) is not True):
        raise ValueError("executable plan independent revalidation failed")
    return plan


class ExecutablePlanBuilder:
    def build(self, ft, snapshot, strategy, evidence, authorized_ids, *, build_analysis,
              project_root=None, language="c", headers=(), max_input_bytes=4096, contracts=None):
        from ..execution_preflight.gate import ExecutionPreflightGate
        from .strategy_generation import TRANSLATION_VERSION, deterministic_translate
        from .strategy_validation import validate_strategy_code
        if language not in {"c", "c++"}:
            raise UnsupportedTranslationError("unsupported_translation: unsupported language")
        maximum = max_input_bytes
        if type(maximum) is not int or not 1 <= maximum <= strategy_budget(strategy).max_input_bytes:
            raise ValueError("executable input bound exceeds validated Strategy bound")
        preflight = ExecutionPreflightGate().evaluate(ft, snapshot, strategy, evidence, authorized_ids,
            build_analysis=build_analysis, project_root=project_root, contracts=contracts)
        if preflight.get("allowed") is not True:
            diagnostics = [row.get("code", "known_contract_violation") +
                           (": " + str(row["detail"]) if row.get("detail") else "")
                           for row in preflight.get("known_violations", [])]
            raise ValueError("execution preflight rejected Strategy: " + "; ".join(diagnostics))
        if unreachable_core_calls(ft, strategy, maximum):
            raise ValueError("executable input bound makes required CORE invocation unreachable")
        root, header_identity = _header_identity(build_analysis, project_root, headers)
        try:
            abi_functions = {row["id"]: row for row in preflight["execution_context"]["api_declarations"]}
            if set(abi_functions) != _active(strategy):
                raise ValueError("preflight ABI declarations do not cover selected functions")
            abi_view = SimpleNamespace(functions=abi_functions, artifacts=snapshot.artifacts)
            declarations, type_declarations = translation_declarations(abi_view, _active(strategy))
        except (ValueError, TypeError, KeyError) as exc:
            raise UnsupportedTranslationError("unsupported_translation: " + str(exc)) from exc
        context = deepcopy(preflight["execution_context"])
        plan = {"schema_version": SCHEMA_VERSION, "artifact_kind": "executable_plan", "policy_version": POLICY_VERSION,
            "ft_id": ft["ft_id"], "ft_digest": digest(ft), "source_fingerprint": snapshot.source_fingerprint,
            "functions_fingerprint": snapshot.functions_fingerprint, "strategy_id": strategy["strategy_id"],
            "strategy_digest": strategy["strategy_digest"], "strategy": deepcopy(strategy),
            "authorized_function_ids": sorted(set(authorized_ids)), "evidence_digest": digest(evidence_records(evidence)),
            "authorization_basis": {"artifact_kind": ft.get("artifact_kind", "minimal_ft"), "id": ft["ft_id"],
                "digest": digest(ft)}, "execution_preflight": preflight, "execution_context": context,
            "executable_resources": deepcopy(context["resources"]), "build_identity": deepcopy(preflight["build_identity"]),
            "project_root": root, "language": language, "headers": list(_headers(headers)), "header_identity": header_identity,
            "api_declarations": declarations, "type_declarations": type_declarations,
            "translation_policy_version": TRANSLATION_VERSION, "input_policy": {"max_bytes": maximum},
            "unknown_contracts": deepcopy(preflight["unknown_contracts"]), "execution_allowed": True,
            "semantic_verified": False, "generation_allowed": False, "formal_success_statistics_allowed": False,
            "experimental_execution_allowed": False, "statistics_category": "candidate", "immutable": True, "frozen": True}
        plan["plan_id"] = "executable_plan_" + digest(plan)[:24]
        plan["plan_digest"] = digest(plan)
        try:
            code = deterministic_translate(plan)
            validation = validate_strategy_code(code, plan)
            if validation.get("valid") is not True:
                raise ValueError(",".join(validation.get("errors", [])))
        except (ValueError, TypeError, KeyError) as exc:
            raise UnsupportedTranslationError("unsupported_translation: " + str(exc)) from exc
        return plan


class ExecutablePlanVerifier:
    def __init__(self, ft, snapshot, evidence, authorized_ids, *, build_analysis, project_root=None, contracts=None):
        self.ft, self.snapshot = deepcopy(ft), snapshot
        self.evidence, self.allowed = deepcopy(evidence), set(authorized_ids)
        self.analysis, self.project_root, self.contracts = build_analysis, project_root, contracts

    def verify(self, plan):
        try:
            require_executable_plan(plan)
            rebuilt = ExecutablePlanBuilder().build(self.ft, self.snapshot, plan["strategy"], self.evidence, self.allowed,
                build_analysis=self.analysis, project_root=self.project_root, contracts=self.contracts,
                language=plan["language"], headers=plan["headers"], max_input_bytes=plan["input_policy"]["max_bytes"])
            if rebuilt != plan:
                raise ValueError("executable plan no longer reproduces from independently authorized inputs")
        except (ValueError, TypeError, KeyError, OSError, AttributeError) as exc:
            return {"valid": False, "status": "rejected", "errors": ["executable_plan_revalidation_failed"],
                "detail": str(exc), "execution_allowed": False, "semantic_verified": False}
        return {"valid": True, "status": "executable_candidate", "errors": [], "plan_digest": plan["plan_digest"],
            "execution_allowed": True, "semantic_verified": False, "formal_success_statistics_allowed": False}

    def __call__(self, plan):
        return self.verify(plan)["valid"] is True
