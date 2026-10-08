"""External input propagation, without creator or ownership nodes."""
from copy import deepcopy

from ..semantic_discovery.models import canonical, digest
from .argument_graph import parameter_id
from .value_flow import body_tree
from ..semantic_discovery.tools import _walk, _text

VERSION = "external-input-flow-v3"


from ..semantic_slicing.core_proofs import returned_input_fields


def read_fields(function, parameter, snapshot=None, internal=()):
    source, body = body_tree(function)
    result = set()
    if body is None or body.has_error:
        return result
    for n in _walk(body):
        if n.type != "field_expression" or _text(n.child_by_field_name("argument"), source) != parameter:
            continue
        parent = n.parent
        if parent.type == "assignment_expression" and parent.child_by_field_name("left") == n and _text(parent.child_by_field_name("operator"), source) == "=":
            continue
        result.add(_text(n.child_by_field_name("field"), source))
    if snapshot is not None:
        for invocation in internal:
            if invocation.get('proof_status') != 'proven' or invocation['via_function_id'] != function['id']:
                continue
            for mapping in invocation['parameter_forwarding']:
                if mapping['via_parameter'] == parameter:
                    # A single certified level, with exact same pointer. Never
                    # expand arbitrary calls, cycles or shared-type endpoints.
                    result |= read_fields(snapshot.functions[invocation['function_id']], mapping['parameter'])
    return result


def project_input_flow(context, snapshot):
    graph = context["argument_graph"]
    nodes = {r["node_id"]: deepcopy(r) for r in graph["nodes"] if r["node_type"] in
        {"FuzzInput", "Parameter", "LocalValue", "StructField", "Constant"} and not r.get("resource_id")}
    edges = [deepcopy(e) for e in graph["edges"] if e["source"] in nodes and e["target"] in nodes
        and not e.get("resource_id") and e["proof_status"] == "proven" and e["kind"] in
        {"assigned_to", "passed_as", "derived_from", "stored_into", "loaded_from"}]
    roots = []
    for binding in context["input_contract"]["bindings"]:
        if binding["source"] != "fuzz_data" or binding["parameter"] is None:
            continue
        function = snapshot.functions[binding["function_id"]]
        for parameter, kind in ((binding["parameter"], "bytes"), (binding["size_parameter"], "size")):
            index = next((i for i, p in enumerate(function["parameters"]) if p["name"] == parameter), None)
            if index is None:
                continue
            pid = parameter_id(function["id"], index)
            selected = next((r for r in context["canonical_construction"]["parameters"] if r["parameter_id"] == pid), None)
            adapted = kind == 'size' and (any(l['function_id'] == function['id'] and l['length_parameter'] == parameter
                and l['relation'] == 'derived' for l in context['buffer_length_contract']['links']) or
                selected and (selected.get('recipe') or {}).get('kind') == 'derived_scalar')
            rid = "input_root_" + digest([function["id"], parameter, kind, binding["transform"]])[:24]
            root = {"node_id": rid, "node_type": "FuzzInputRoot", "kind": kind,
                "transform": binding["transform"], "function_id": function["id"], "parameter": parameter,
                "evidence_ids": binding["evidence_ids"]}
            roots.append(root); nodes[rid] = root
            if not adapted:
                edges.append({"source": rid, "target": pid, "kind": "input_binding", "evidence_ids": binding["evidence_ids"]})
            if binding["transform"] == "direct":
                edges.extend({"source": rid, "target": node["node_id"], "kind": "shared_fuzzer_input",
                    "evidence_ids": binding["evidence_ids"]} for node in graph["nodes"] if node["node_type"] == "FuzzInput"
                    and node.get("source_kind") == "fuzz_" + kind)
    reachable = {r["node_id"] for r in roots}
    while True:
        next_reachable = reachable | {e["target"] for e in edges if e["source"] in reachable}
        if next_reachable == reachable:
            break
        reachable = next_reachable
    sinks = []
    for r in context["canonical_construction"]["parameters"]:
        recipe = r.get("recipe") or {}
        if recipe.get("kind") not in {"fuzz_bytes", "fuzz_size", "derived_scalar"}:
            continue
        sinks.append({"function_id": r["function_id"], "parameter": r["parameter"], "parameter_id": r["parameter_id"],
            "resolved": r["status"] == "resolved" and r["parameter_id"] in reachable,
            "recipe_id": recipe.get("recipe_id"), "evidence_ids": r["evidence_ids"]})
    functions = {s["function_id"] for s in sinks if s["resolved"]}
    indirect = []
    for _ in range(len(context["core_apis"])):
        for binding in context["input_contract"]["bindings"]:
            fid, via = binding["function_id"], binding["via_function_id"]
            if binding["source"] not in {"context", "derived"} or via not in functions:
                continue
            proof = [e for e in context["ordering_graph"]["edges"] if e["before"] == via and e["after"] == fid
                and e["strength"] == "hard" and e["reason"] in {"input_state_write_before_read", "graph_same_origin_field_write_read", "state_precondition_data_dependence"}]
            resources = context["lifecycle_contract"]["resources"]
            consumers = [r for r in resources if r["function_id"] == fid and r["subject_parameter"] == binding["parameter"]]
            returned = [r for r in resources if r["function_id"] == via and r["return_value"]]
            input_parameters = {s["parameter"] for s in sinks if s["function_id"] == via and s["resolved"]}
            fields = returned_input_fields(snapshot.functions[via], input_parameters) & read_fields(snapshot.functions[fid], binding["parameter"], snapshot,
                                                                                                      graph.get('internal_invocations', []))
            if fields and any(a["resource_id"] == b["resource_id"] for a in returned for b in consumers):
                proof.append({"reason": "input_dependent_returned_fields", "fields": sorted(fields),
                    "evidence_ids": sorted({e for r in returned + consumers for e in r["evidence_ids"]})})
            for invocation in graph.get('internal_invocations', []):
                if invocation.get('proof_status') != 'proven' or invocation['function_id'] != fid or invocation['via_function_id'] != via:
                    continue
                for mapping in invocation['parameter_forwarding']:
                    parents = [r for r in resources if r['function_id'] == via and r['subject_parameter'] == mapping['via_parameter']]
                    input_parent = any(b['function_id'] == via and b['parameter'] == mapping['via_parameter']
                                       and b['source'] in {'context','derived'} for b in context['input_contract']['bindings'])
                    if mapping['parameter'] == binding['parameter'] and input_parent and any(
                            p['resource_id'] == c['resource_id'] for p in parents for c in consumers):
                        proof.append({'reason':'source_internal_parameter_forwarding', 'evidence_ids': invocation['evidence_ids']})
            if proof:
                functions.add(fid)
                indirect.append({"function_id": fid, "via_function_id": via, "kind": "invocation_input_dependency",
                    "proof_kinds": sorted({e["reason"] for e in proof}),
                    "evidence_ids": sorted(set(binding["evidence_ids"]) | {eid for e in proof for eid in e["evidence_ids"]})})
    context["external_input_flow"] = {"version": VERSION, "roots": sorted(roots, key=canonical),
        "nodes": sorted(nodes.values(), key=canonical), "edges": sorted(edges, key=canonical),
        "sinks": sorted(sinks, key=canonical), "reachable_functions": sorted(functions),
        "indirect_invocation_paths": sorted({canonical(r): r for r in indirect}.values(), key=canonical),
        "diagnostics": [{"code": "external_input_root_missing", "function_id": fid} for fid in sorted(set(context["core_apis"]) - functions)]}
