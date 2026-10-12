"""Bounded deterministic API context from a confirmed exact Clang anchor."""
from __future__ import annotations

import re

from ..semantic_discovery.models import canonical, digest
from ..semantic_discovery.tools import RepositoryIndex, RepositoryTools, ToolBudgetExceeded
from ..source_analysis import BuildAwareIndex
from .models import (ARTIFACT_KIND, AUTHORIZATION_KIND, VERSION, ContextBudget,
                     LightweightAPIContext, _ISSUED)

_NON_RESOURCE = frozenset({"void", "char", "signedchar", "unsignedchar", "int8_t", "uint8_t",
    "short", "shortint", "signedshort", "signedshortint", "unsignedshort", "unsignedshortint",
    "int", "signed", "signedint", "unsigned", "unsignedint",
    "long", "longint", "signedlong", "signedlongint", "unsignedlong", "unsignedlongint",
    "longlong", "longlongint", "signedlonglong", "signedlonglongint",
    "unsignedlonglong", "unsignedlonglongint", "float", "double", "longdouble",
    "bool", "_Bool", "size_t", "wchar_t", "char8_t", "char16_t", "char32_t"})


def _resource_type(value):
    # This key authorizes investigation candidates only. It is deliberately
    # labelled as spelling association, never pointer/type identity proof.
    if not isinstance(value, str) or "*" not in value or "(" in value:
        return None
    base = re.sub(r"\b(?:const|volatile|restrict)\b", "", value).replace("*", "")
    key = re.sub(r"\s+", "", base)
    return key if key and key not in _NON_RESOURCE else None


def _types(facts):
    returned = _resource_type(facts.get("return_type"))
    parameters = {_resource_type(row.get("canonical_type")) for row in facts.get("parameters", [])}
    return returned, parameters - {None}


def _related_candidate(fid, facts, resource_types, name):
    result, params = _types(facts)
    roles = []
    if result and result in resource_types:
        roles.append("construction_candidate")
    if params & resource_types:
        roles.append("resource_use_or_cleanup_candidate")
        # Names guide bounded discovery only; they do not establish release
        # effects, ownership, or safe call order.
        words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower().split("_")
        if set(words) & {"free", "destroy", "delete", "release", "dispose", "cleanup"}:
            roles.append("cleanup_name_hint")
    if not roles:
        return None
    return {"function_id": fid, "candidate_roles": roles,
        "authorization_basis": "live_clang_callable_abi_and_type_spelling_association",
        "candidate_role_authority": "type_or_name_hint_only",
        "clang_function": facts, "type_relationship_verified": False,
        "semantic_contract_verified": False}


def _balanced_candidates(candidates, limit):
    """Reserve bounded discovery opportunities for cleanup/create/use hints."""
    ordered = sorted(candidates, key=lambda row: (
        len(row["clang_function"].get("parameters", [])), row["function_id"]))
    lanes = [[row for row in ordered if role in row["candidate_roles"]]
        for role in ("cleanup_name_hint", "construction_candidate", "resource_use_or_cleanup_candidate")]
    selected, seen = [], set()
    while len(selected) < limit:
        added = False
        for lane in lanes:
            while lane and lane[0]["function_id"] in seen:
                lane.pop(0)
            if lane and len(selected) < limit:
                row = lane.pop(0)
                selected.append(row)
                seen.add(row["function_id"])
                added = True
        if not added:
            break
    return selected


def build_context(snapshot, build_analysis, index, anchor_function_id, *, budget=None,
                  support_function_ids=()):
    """Create the independent receipt; accepts exact IDs, never friendly names.

    No Candidate acceptance, Slice, FT builder, effect interpreter or provider
    is called. ABI presence grants bounded API scope, not generation permission.
    """
    budget = budget or ContextBudget()
    if type(budget) is not ContextBudget or type(build_analysis) is not BuildAwareIndex:
        raise ValueError("lightweight context requires live BuildAwareIndex and ContextBudget")
    if type(index) is not RepositoryIndex or index.artifacts != snapshot.artifacts:
        raise ValueError("lightweight context requires matching RepositoryIndex")
    if index.catalog.source_fingerprint != snapshot.source_fingerprint:
        raise ValueError("lightweight catalog snapshot mismatch")
    if not isinstance(anchor_function_id, str) or anchor_function_id not in snapshot.functions:
        raise ValueError("lightweight anchor requires an exact indexed function ID")
    if not isinstance(support_function_ids, (list, tuple)) or any(
            not isinstance(fid, str) or fid not in snapshot.functions for fid in support_function_ids):
        raise ValueError("lightweight supports require exact indexed function IDs")
    if len(set(support_function_ids)) != len(support_function_ids):
        raise ValueError("duplicate lightweight support function ID")
    if anchor_function_id in support_function_ids:
        raise ValueError("lightweight support must not repeat the anchor")
    if len(support_function_ids) > budget.max_allowed_functions - 1:
        raise ValueError("requested lightweight supports exceed scope budget")
    requested = sorted(support_function_ids)
    build_analysis.validate_snapshot(snapshot)
    anchor = build_analysis.verify_function(anchor_function_id)
    if anchor.get("verified") is not True or anchor.get("abi_verified") is not True:
        raise ValueError("lightweight anchor is not Clang-confirmed callable")
    returned, arguments = _types(anchor)
    resource_types = arguments | ({returned} if returned else set())
    scope = [{"function_id": anchor_function_id, "candidate_roles": ["anchor"],
        "authorization_basis": "live_clang_callable_abi", "clang_function": anchor,
        "type_relationship_verified": False, "semantic_contract_verified": False}]
    candidates, scanned = [], 0
    # Explicit supports use only their exact bounded IDs. Default discovery
    # scans persisted signatures; live source reads have a separate budget.
    function_ids = requested if requested else sorted(snapshot.functions)
    for fid in function_ids:
        if fid == anchor_function_id:
            continue
        if not requested and scanned >= budget.max_scanned_functions:
            break
        scanned += 1
        # Source typedef spelling need not equal the compiler's desugared
        # spelling. Compare the live index's canonical ABI facts on both
        # sides; a source-only prefilter would omit real cleanup APIs.
        facts = build_analysis.verify_function(fid)
        if facts.get("verified") is not True or facts.get("abi_verified") is not True:
            if requested:
                raise ValueError("requested lightweight support is not Clang-confirmed callable")
            continue
        candidate = _related_candidate(fid, facts, resource_types, snapshot.functions[fid]["name"])
        if candidate:
            candidates.append(candidate)
        elif requested:
            raise ValueError("requested lightweight support has no canonical resource type association")
    selected = candidates if requested else _balanced_candidates(candidates, budget.max_allowed_functions - 1)
    scope.extend(selected)
    tools = RepositoryTools(snapshot.artifacts, index.catalog, budget.source, index=index)
    queries, tool_errors = [], []

    def query(name, arguments):
        if len(queries) >= budget.source.max_tool_calls:
            tool_errors.append({"code": "source_tool_budget_exhausted"})
            return
        try:
            response = tools.execute(name, arguments)
        except ToolBudgetExceeded as error:
            response = {"error": "tool_budget_exceeded", "reason": str(error), "evidence_ids": []}
        queries.append({"name": name, "arguments": arguments, "output": response})
        if response.get("error"):
            tool_errors.append({"code": response["error"], "tool": name,
                "function_id": arguments.get("function", "")})

    for row in scope:
        query("get_function", {"function": row["function_id"]})
    if budget.max_callsite_queries:
        query("find_callers", {"function": anchor_function_id})
    build_analysis.validate_snapshot(snapshot)
    from ..harness_strategy.planner import verify_source_identity
    verify_source_identity(snapshot, index, [row["function_id"] for row in scope], tools.evidence.values())
    body = {"schema_version": 1, "artifact_kind": ARTIFACT_KIND, "policy_version": VERSION,
        "context_type": ARTIFACT_KIND, "authorization_kind": AUTHORIZATION_KIND,
        "anchor_function_id": anchor_function_id,
        "scope_selection_policy": "explicit_related_api_ids" if requested else "bounded_role_balanced_discovery",
        "requested_support_function_ids": requested,
        "source_fingerprint": snapshot.source_fingerprint,
        "functions_fingerprint": snapshot.functions_fingerprint,
        "build_analysis": {"identity_digest": build_analysis.identity_digest,
            "projection": build_analysis.public_projection()}, "budget": budget.to_dict(),
        "allowed_api_scope": scope,
        "source_evidence": {"schema_version": 1,
            "records": [tools.evidence[eid] for eid in sorted(tools.evidence)],
            "queries": queries, "source_chars": tools.source_chars, "tool_errors": tool_errors},
        "discovery": {"scanned_functions": scanned,
            "repository_scan_performed": not bool(requested),
            "scan_truncated": not requested and len(snapshot.functions) - 1 > scanned,
            "candidate_count": len(candidates), "scope_truncated": len(candidates) > len(scope) - 1,
            "scope_expansion_policy": "none_read_only_queries_never_add_callable_apis"},
        "unknowns": ["candidate_roles_not_usage_contracts", "resource_ownership_unverified",
            "cleanup_internal_effect_unverified"],
        "cost": {"model_calls": 0, "provider_requests": 0, "tool_calls": len(queries),
            "source_chars": tools.source_chars, "semantic_verifier_calls": 0,
            "native_svf_calls": 0}, "generation_allowed": False, "semantic_verified": False}
    name = re.sub(r"[^A-Za-z0-9_]", "_", snapshot.functions[anchor_function_id]["name"])[:48] or "anchor"
    body["context_id"] = "lac_" + name + "_" + digest(body)[:24]
    # Ensure all metadata, including compiler projections, is finite as well.
    if len(canonical(body)) > budget.source.max_source_chars + 256000:
        raise ValueError("lightweight context metadata exceeds bounded envelope")
    return LightweightAPIContext(body, snapshot, build_analysis, index, budget, _token=_ISSUED)
