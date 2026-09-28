"""Validated callable dependency sets; CORE identity remains frozen."""
from ..semantic_discovery.models import digest, canonical
from .evidence import body_evidence, record_functions, validate_resolution_record
from .models import POLICY_VERSION


def callable_status(function):
    return "internal_static" if "static" in function.get("storage", []) else (
        "external_definition" if function.get("defined") else "linkage_unverified")


def build_api_closure(ft, requirements, resolutions, snapshot, state):
    core = {r["function_id"] for r in ft["core_functions"]}
    initial = core | {r["function_id"] for r in ft["support_candidates"]}
    grouped, unresolved = {}, []
    for rid, result in sorted(resolutions.items()):
        for proposal in result["discovered_api_dependencies"]:
            fid = proposal["function_id"]
            if fid in core:
                continue
            if fid is None or fid not in snapshot.functions or proposal["necessity"] == "unresolved" or callable_status(snapshot.functions[fid]) != "external_definition":
                unresolved.append({**proposal, "requirement_id": rid,
                    "mandatory": proposal["necessity"] == "required", "diagnostic": "dependency_identity_or_linkage_unresolved"})
                continue
            grouped.setdefault(fid, []).append((rid, proposal))
    required, optional, rejected = [], [], []
    for fid, entries in sorted(grouped.items()):
        necessity = {entry["necessity"] for _, entry in entries}
        if "required" in necessity and "rejected" in necessity:
            unresolved.append({"function_id": fid, "mandatory": True, "diagnostic": "conflicting_dependency_necessity",
                               "requirement_ids": sorted(rid for rid, _ in entries)})
            continue
        decision = "required" if "required" in necessity else "optional" if "optional" in necessity else "rejected"
        chosen = [(rid, entry) for rid, entry in entries if entry["necessity"] == decision]
        discovery = state.discoveries.get(fid, {})
        record = {"function_id": fid, "required_by": sorted({entry["required_by"] for _, entry in chosen}),
            "requirement_ids": sorted({rid for rid, _ in chosen}), "reasons": sorted({entry["reason"] for _, entry in chosen}),
            "evidence_ids": sorted({eid for _, entry in chosen for eid in entry["evidence_ids"]}),
            "discovery_evidence_ids": sorted(discovery.get("evidence_ids", [])) if fid not in initial else [],
            "depth": discovery.get("depth", 1), "callable_status": callable_status(snapshot.functions[fid])}
        {"required": required, "optional": optional, "rejected": rejected}[decision].append(record)
    # Closure depth follows semantic required_by edges, independently of the
    # bounded syntactic discovery route used to locate the API's definition.
    depths = {fid: 0 for fid in core}
    for _ in range(len(required) + len(optional)):
        for row in required + optional:
            parents = [depths[parent] for parent in row["required_by"] if parent in depths]
            if parents:
                depth = min(parents) + 1
                depths[row["function_id"]] = min(depths.get(row["function_id"], depth), depth)
    for rows, mandatory in ((required, True), (optional, False)):
        accepted = []
        for row in rows:
            depth = depths.get(row["function_id"])
            if depth is None or depth > state.budget.max_dependency_depth:
                unresolved.append({**row, "mandatory": mandatory, "diagnostic": "dependency_depth_or_core_connection_unresolved"})
            else:
                row["depth"] = depth
                accepted.append(row)
        rows[:] = accepted
    classified = {row["function_id"] for row in required + optional + rejected} | {row.get("function_id") for row in unresolved}
    for candidate in ft["support_candidates"]:
        fid = candidate["function_id"]
        if fid not in classified:
            decisions = [fact["value"]["decision"] for result in resolutions.values() for fact in result["facts"]
                         if fact["function_id"] == fid and fact["predicate"] == "support_decision"]
            # A rejection may be explicit without making the candidate callable.
            if decisions == ["rejected"]:
                matching = [result for result in resolutions.values() if any(f["function_id"] == fid for f in result["facts"])]
                rejected.append({"function_id": fid, "required_by": [], "requirement_ids": sorted(r["requirement_id"] for r in matching),
                    "reasons": sorted({f["value"]["reason"] for r in matching for f in r["facts"] if f["predicate"] == "support_decision"}),
                    "evidence_ids": sorted({eid for r in matching for f in r["facts"] for eid in f["evidence_ids"]}),
                    "discovery_evidence_ids": [], "depth": 1, "callable_status": callable_status(snapshot.functions[fid])})
            else:
                unresolved.append({"function_id": fid, "mandatory": False, "diagnostic": "support_candidate_not_decided"})
    result = {"schema_version": 1, "artifact_kind": "api_closure", "policy_version": POLICY_VERSION,
        "ft_id": ft["ft_id"], "minimal_ft_digest": digest(ft), "core_apis": sorted(core),
        "required_support_apis": sorted(required, key=canonical), "optional_support_apis": sorted(optional, key=canonical),
        "rejected_support_candidates": sorted(rejected, key=canonical), "unresolved_api_dependencies": sorted(unresolved, key=canonical)}
    result["closure_id"] = "closure_" + digest(result)[:24]
    return result


class APIClosureValidator:
    def validate(self, closure, ft, snapshot, requirements, resolutions, state):
        errors = []
        expected = build_api_closure(ft, requirements, resolutions, snapshot, state)
        if closure != expected:
            errors.append({"code": "api_closure_changed_validated_projection"})
        initial = {r["function_id"] for r in ft["core_functions"] + ft["support_candidates"]}
        excluded, seen = set(ft["excluded_functions"]), set(closure.get("core_apis", []))
        reqs = {r["requirement_id"]: r for r in requirements}
        for rid, result in resolutions.items():
            try:
                if rid not in reqs:
                    raise ValueError("resolution_outside_requirement_universe")
                validate_resolution_record(result, reqs[rid], snapshot, state, initial, excluded)
            except (ValueError, TypeError, KeyError) as error:
                errors.append({"code": str(error)[:160], "requirement_id": rid})
        if len(state.discoveries) > state.budget.max_discovered_functions:
            errors.append({"code": "discovery_budget_violated"})
        for fid, info in state.discoveries.items():
            if (fid not in snapshot.functions or info.get("depth", -1) < 1 or info["depth"] > state.budget.max_dependency_depth
                    or fid in excluded or info.get("parent_function_id") not in initial | set(state.discoveries)
                    or not info.get("requirement_ids") or any(rid not in reqs for rid in info["requirement_ids"])
                    or not info.get("evidence_ids") or any(eid not in state.evidence for eid in info["evidence_ids"])
                    or not any(fid in record_functions(state.evidence.get(eid, {}), snapshot) for eid in info.get("evidence_ids", []))):
                errors.append({"code": "invalid_discovery_identity_or_evidence", "function_id": fid})
        for category in ("required_support_apis", "optional_support_apis"):
            for row in closure.get(category, []):
                fid = row["function_id"]
                if fid not in snapshot.functions or fid in excluded or fid in seen:
                    errors.append({"code": "invalid_or_duplicate_closure_identity", "function_id": fid})
                    continue
                seen.add(fid)
                if (row["depth"] > state.budget.max_dependency_depth or not row["required_by"]
                        or any(parent not in initial | set(state.discoveries) for parent in row["required_by"])
                        or any(rid not in reqs for rid in row["requirement_ids"])):
                    errors.append({"code": "invalid_dependency_depth_or_parent", "function_id": fid})
                if not body_evidence(row["evidence_ids"], fid, state.evidence, snapshot):
                    errors.append({"code": "closure_api_lacks_source_evidence", "function_id": fid})
                if fid not in initial and (fid not in state.discoveries or not row["discovery_evidence_ids"]):
                    errors.append({"code": "closure_api_lacks_discovery_evidence", "function_id": fid})
                if callable_status(snapshot.functions[fid]) != "external_definition":
                    errors.append({"code": "required_api_not_callable", "function_id": fid})
        return errors
