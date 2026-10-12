"""Small API usage facts, without complete effects or ownership proof graphs."""
from __future__ import annotations

from copy import deepcopy
import re
from types import SimpleNamespace

from ..harness_context.value_flow import body_tree
from ..orchestration.source_feedback import authenticated_records
from ..semantic_discovery.models import digest
from ..semantic_discovery.tools import _text, _walk
from ..source_analysis.index import BuildAwareIndex
from ..source_evidence import complete_bodies
from .models import APIContract, CONTRACT_VERSION


def evidence_records(evidence):
    rows = evidence.get("records", []) if isinstance(evidence, dict) and "records" in evidence else evidence
    if isinstance(rows, dict):
        return rows
    return {row.get("evidence_id"): row for row in rows or () if isinstance(row, dict)}


def canonical_type_parts(spelling):
    """Only plain Clang canonical object types can form this IR overlay."""
    if not isinstance(spelling, str) or not spelling or any(c in spelling for c in "();[]{}\n"):
        return None
    depth = spelling.count("*")
    base = " ".join(re.sub(r"\b(const|volatile|restrict)\b|\*", "", spelling).split())
    return (base, depth) if base and depth <= 4 else None


def abi_snapshot(snapshot, target_facts):
    """View current ABI object types without changing original source identity.

    The source envelope is authenticated separately. This transient view only
    supplies the existing structural validator with Clang-expanded typedefs.
    """
    functions = {fid: deepcopy(row) for fid, row in snapshot.functions.items()}
    for fact in target_facts:
        if not fact.get("verified") or fact.get("status") != "callable":
            continue
        function = functions[fact["function_id"]]
        for parameter, abi in zip(function.get("parameters", []), fact.get("parameters", [])):
            parts = canonical_type_parts(abi.get("canonical_type"))
            if parts:
                parameter.update(base_type=parts[0], pointer_depth=parts[1],
                                 is_pointer=parts[1] > 0, type=abi["canonical_type"],
                                 is_const="const" in abi["canonical_type"])
        # Clang's function canonical type starts with the canonical return type.
        spelling = fact.get("canonical_type", "").split("(", 1)[0].strip()
        parts = canonical_type_parts(spelling)
        if parts:
            function.update(return_base_type=parts[0], return_pointer_depth=parts[1], return_type=spelling)
    return SimpleNamespace(functions=functions, artifacts=snapshot.artifacts,
                           source_fingerprint=snapshot.source_fingerprint,
                           functions_fingerprint=snapshot.functions_fingerprint)


def _bare_parameter(node, raw, parameters):
    while node is not None and node.type in {"parenthesized_expression", "cast_expression"}:
        node = node.child_by_field_name("value") if node.type == "cast_expression" else node.named_children[0]
    return _text(node, raw) if node is not None and node.type == "identifier" and _text(node, raw) in parameters else None


def _nonnull_condition(node, raw, name):
    spelling = re.sub(r"\s+", "", _text(node, raw))
    return spelling.strip("()") in {name, name + "!=NULL", name + "!=0", "NULL!=" + name, "0!=" + name}


def _local_usage(function, index, complete):
    """Whole small frames only: direct libc release and direct borrowed return.

    Loops, recursion, unknown calls, stores and general branches are unknown.
    A release applies on a non-null parameter path. It says nothing about an
    owned graph, the allocation family of the caller, or complete cleanup.
    """
    result = {"releases": [], "returns_alias": None, "unknown_reason": "unsupported_local_source_frame"}
    if function["id"] not in complete:
        result["unknown_reason"] = "complete_authenticated_source_evidence_required"
        return result
    semantics = index.verify_source_semantics(function["id"])
    if semantics.get("verified") is not True or semantics.get("source_effect_compatible") is not True:
        result["unknown_reason"] = "local_source_macro_semantics_unverified"
        return result
    raw, body = body_tree(function)
    if body is None or body.has_error:
        return result
    parameters = {p["name"] for p in function.get("parameters", [])}
    statements = [child for child in body.named_children if child.type != "comment"]
    if len(statements) == 1 and statements[0].type == "return_statement" and statements[0].named_children:
        alias = _bare_parameter(statements[0].named_children[0], raw, parameters)
        if alias:
            result.update(returns_alias=alias, unknown_reason=None)
            return result
    if not index.verify_intrinsic("free").get("verified") or "free" in parameters or any(
            n.type in {"declaration", "type_definition"} and any(
                part.type == "identifier" and _text(part, raw) == "free" for part in _walk(n)) for n in _walk(body)):
        result["unknown_reason"] = "direct_libc_release_binding_unverified"
        return result
    released = []

    def visit(node, nonnull=None):
        if node.type == "compound_statement":
            children = [child for child in node.named_children if child.type != "comment"]
            if children and children[-1].type == "return_statement" and not children[-1].named_children:
                children.pop()
            return all(visit(child, nonnull) for child in children)
        if node.type == "if_statement" and node.child_by_field_name("alternative") is None:
            condition = node.child_by_field_name("condition")
            matched = next((name for name in parameters if _nonnull_condition(condition, raw, name)), None)
            return matched is not None and visit(node.child_by_field_name("consequence"), matched)
        if node.type == "return_statement":
            return False
        if node.type != "expression_statement" or len(node.named_children) != 1:
            return False
        call = node.named_children[0]
        if call.type != "call_expression" or _text(call.child_by_field_name("function"), raw) != "free":
            return False
        arguments = call.child_by_field_name("arguments").named_children
        name = _bare_parameter(arguments[0], raw, parameters) if len(arguments) == 1 else None
        if name is None or nonnull is not None and nonnull != name:
            return False
        released.append(name)
        return True

    if visit(body) and released:
        result.update(releases=sorted(set(released)), unknown_reason=None,
                      release_counts={name: released.count(name) for name in sorted(set(released))},
                      clang_evidence_ids=[semantics["evidence_id"], index.verify_intrinsic("free")["evidence_id"]])
    return result


def extract_api_contracts(snapshot, strategy, evidence, authorized_ids, build_analysis):
    """Reissue minimal facts against the caller-selected live BuildAwareIndex."""
    if not isinstance(build_analysis, BuildAwareIndex):
        raise ValueError("execution_preflight_requires_live_build_index")
    build_analysis.validate_snapshot(snapshot)
    build = build_analysis.public_projection()
    records = authenticated_records(snapshot, evidence_records(evidence))
    complete = complete_bodies(snapshot.functions, records, snapshot.artifacts.source_hashes)
    active = sorted({step["function_id"] for step in strategy.get("steps", []) if step.get("kind") in {"call", "cleanup"}})
    active.extend(expression["function_id"] for step in strategy.get("steps", []) for expression in step.get("arguments", {}).values()
                  if expression.get("kind") == "source_function")
    targets, contracts = [], []
    scope = {key: build[key] for key in ("source_fingerprint", "functions_fingerprint", "configuration_digest", "analysis_digest")}
    for fid in sorted(set(active)):
        if fid not in set(authorized_ids) or fid not in snapshot.functions:
            continue
        abi = build_analysis.verify_function(fid)
        targets.append({"function_id": fid, **abi})
        contracts.append(APIContract(fid, "callable_abi", "clang", build["analysis_digest"], scope,
                                     deepcopy(abi), (abi["evidence_id"],), "live_build").to_dict())
        if abi.get("verified") is not True or abi.get("status") != "callable":
            continue
        usage = _local_usage(snapshot.functions[fid], build_analysis, complete)
        contracts.append(APIContract(fid, "local_resource_usage", "local_source_effect", CONTRACT_VERSION,
                                     scope, usage, tuple(complete.get(fid, ())), "live_source_build").to_dict())
    build_analysis.validate_snapshot(snapshot)
    return {"build_identity": build, "callable_targets": targets, "contracts": contracts,
            "authenticated_evidence": records, "complete_bodies": complete,
            "abi_snapshot": abi_snapshot(snapshot, targets)}
