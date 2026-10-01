"""Resource definitions and call-scoped state obligations are separate truths."""
from collections import defaultdict
from copy import deepcopy

from ..semantic_discovery.models import canonical, digest

VERSION = "resource-invocation-contract-v1"


def project_invocations(context):
    groups = defaultdict(list)
    preconditions, initializations, diagnostics = [], [], []
    for row in context["lifecycle_contract"]["resources"]:
        groups[row["resource_id"]].append(row)
        obligation = {key: deepcopy(row[key]) for key in
            ("function_id", "resource_id", "subject_parameter", "return_value", "initialization", "fact_id", "evidence_ids")}
        initializations.append(obligation)
        if row["initialization"]["mandatory"]:
            preconditions.append({"function_id": row["function_id"], "parameter": row["subject_parameter"],
                "return_value": row["return_value"], "resource_id": row["resource_id"],
                "kind": "initialized", "api": row["initialization"]["api"], "mandatory": True,
                "phase": "after_call" if row["return_value"] else "before_call",
                "source": "lifecycle_initialization", "fact_id": row["fact_id"], "evidence_ids": row["evidence_ids"]})
    resources = []
    for rid, rows in sorted(groups.items()):
        definitions = {canonical({k: r[k] for k in ("type", "creation", "cleanup", "reuse")}) for r in rows}
        if len(definitions) != 1:
            diagnostics.append({"code": "conflicting_resource_identity", "resource_id": rid})
        # All proposals are retained above; conflicting definitions never pass Gate.
        definition = {k: deepcopy(rows[0][k]) for k in ("type", "creation", "cleanup", "reuse")}
        resources.append({"resource_id": rid, **definition,
            "bindings": sorted([{ "function_id": r["function_id"], "parameter": r["subject_parameter"],
                "return_value": r["return_value"]} for r in rows], key=canonical),
            "evidence_ids": sorted({e for r in rows for e in r["evidence_ids"]})})
    scoped = {}
    for row in initializations:
        key = (row["function_id"], row["resource_id"], row["subject_parameter"], row["return_value"])
        if scoped.setdefault(key, row["initialization"]) != row["initialization"]:
            diagnostics.append({"code": "conflicting_invocation_initialization", "function_id": key[0], "resource_id": key[1]})
    arguments = {(r["function_id"], r["parameter"]): r for r in context["argument_contract"]["arguments"]}
    for row in context["state_contract"]["preconditions"]:
        preconditions.append({**deepcopy(row), "resource_id": arguments.get((row["function_id"], row["parameter"]), {}).get("resource_id"),
            "return_value": False, "mandatory": row["kind"] != "none", "source": "semantic_state"})
    transitions = [{**deepcopy(r), "transition_id": "transition_" + digest(r)[:24],
        "proof_kind": "same_origin_field_write_read"} for r in context["argument_graph"]["state_dependencies"]]
    context["resource_contract"] = {"version": VERSION, "resources": sorted(resources, key=canonical),
        "diagnostics": sorted({canonical(r): r for r in diagnostics}.values(), key=canonical)}
    context["invocation_contract"] = {"version": VERSION, "initializations": sorted(initializations, key=canonical),
        "preconditions": sorted(preconditions, key=canonical), "transitions": sorted(transitions, key=canonical)}
