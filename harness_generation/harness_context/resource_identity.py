"""Framework-owned identities, leaving model facts and their hashes untouched."""
from collections import defaultdict

from ..semantic_discovery.models import canonical, digest
from .value_flow import complete_bodies, resource_flows, body_tree, unique_callee
from ..semantic_discovery.tools import _walk, _text

VERSION = "resource-identity-v1"


def endpoint(row):
    return (row["function_id"], row.get("subject_parameter", row.get("parameter")),
            row.get("return_value", False))


def releases_parameter(function, name, snapshot, bodies, depth=0):
    if function["id"] not in bodies or depth > 2:
        return False
    source, body = body_tree(function)
    if body is None or body.has_error:
        return False
    for call in _walk(body):
        if call.type != "call_expression":
            continue
        target = call.child_by_field_name("function")
        args = call.child_by_field_name("arguments").named_children
        if target.type != "identifier":
            continue
        callee_name = _text(target, source)
        if callee_name == "free" and len(args) == 1 and _text(args[0], source) == name and not any(f["name"] == "free" for f in snapshot.functions.values()):
            return True
        callee = unique_callee(snapshot, callee_name, function)
        if callee:
            for i, arg in enumerate(args):
                if i < len(callee["parameters"]) and _text(arg, source) == name and releases_parameter(callee, callee["parameters"][i]["name"], snapshot, bodies, depth+1):
                    return True
    return False


def allocated_return(function, snapshot):
    source, body = body_tree(function)
    if body is None or body.has_error:
        return False
    allocated = set()
    for declaration in _walk(body):
        if declaration.type != "init_declarator":
            continue
        value = declaration.child_by_field_name("value")
        while value is not None and value.type in {"cast_expression", "parenthesized_expression"}:
            value = value.child_by_field_name("value") if value.type == "cast_expression" else value.named_children[0]
        name = _text(value.child_by_field_name("function"), source) if value is not None and value.type == "call_expression" else None
        if name in {"malloc", "calloc"} and not any(f["name"] == name for f in snapshot.functions.values()):
            allocated.update(_text(n, source) for n in _walk(declaration.child_by_field_name("declarator")) if n.type == "identifier")
    if any(n.type == "assignment_expression" and _text(n.child_by_field_name("left"), source) in allocated for n in _walk(body)):
        return False
    for node in _walk(body):
        if node.type == "return_statement" and node.named_children:
            value = node.named_children[0]
            while value.type in {"cast_expression", "parenthesized_expression"}:
                value = value.child_by_field_name("value") if value.type == "cast_expression" else value.named_children[0]
            if value.type == "call_expression":
                name = _text(value.child_by_field_name("function"), source)
                if name in {"malloc", "calloc"} and not any(f["name"] == name for f in snapshot.functions.values()):
                    return True
    return any(n.type == "return_statement" and n.named_children and n.named_children[0].type == "identifier"
               and _text(n.named_children[0], source) in allocated for n in _walk(body))


def resolve_resources(context, snapshot, records):
    resources = context["lifecycle_contract"]["resources"]
    flow = resource_flows(snapshot, records)
    observed = defaultdict(dict)
    for row in flow["observations"]:
        observed[endpoint(row)][row["resource_id"]] = row
    mapping, bindings, unresolved = {}, [], list(flow["unresolved"])
    for row in resources:
        subject = endpoint(row)
        values = observed.get(subject, {})
        if len(values) == 1:
            proof = next(iter(values.values()))
            rid, reason, eids = proof["resource_id"], "source_value_flow", proof["evidence_ids"]
        else:
            origin = {"function_id": subject[0], "kind": "return" if subject[2] else "parameter",
                      "parameter": subject[1], "type": row["type"]}
            rid, reason, eids = "resource_" + digest(origin)[:24], "distinct_subject", row["evidence_ids"]
            if len(values) > 1:
                unresolved.append({"function_id": subject[0], "parameter": subject[1],
                    "reason": "multiple_runtime_origins", "origins": sorted(values), "evidence_ids": sorted({e for v in values.values() for e in v["evidence_ids"]})})
        mapping[subject] = rid
        bindings.append({"function_id": subject[0], "parameter": subject[1], "return_value": subject[2],
                         "resource_id": rid, "reason": reason, "evidence_ids": sorted(eids)})
    # Explicit construction of a harness argument, not type-based aliasing:
    # a single requested creator invocation feeds a single constructed subject.
    # Multiple consumers are NOT collapsed without source value-flow proof.
    bodies = complete_bodies(snapshot, records)
    constructed = defaultdict(set)
    arguments = context["argument_contract"]["arguments"]
    for row in resources:
        if row["creation"]["kind"] != "creator_api" or row["return_value"]:
            continue
        api = row["creation"]["api"]
        matching = [a for a in arguments if a["function_id"] == row["function_id"]
            and a["parameter"] == row["subject_parameter"] and a["construction"] == "creator_api" and a["api"] == api]
        producer = snapshot.functions.get(api, {})
        parameter = next(p for p in snapshot.functions[row["function_id"]]["parameters"] if p["name"] == row["subject_parameter"])
        if matching and api in bodies and producer.get("return_pointer_depth") == parameter.get("pointer_depth") and producer.get("return_base_type") == row["type"]:
            constructed[(api, row["type"])].add(mapping[endpoint(row)])
    for row in resources:
        if not row["return_value"]:
            continue
        subject = endpoint(row)
        candidates = constructed.get((row["function_id"], row["type"]), set())
        if not observed.get(subject) and len(candidates) == 1:
            mapping[subject] = next(iter(candidates))
            for binding in bindings:
                if endpoint(binding) == subject:
                    binding.update(resource_id=mapping[subject], reason="unique_harness_creator_binding")
        elif not observed.get(subject) and len(candidates) > 1:
            unresolved.append({"function_id": subject[0], "parameter": None,
                "reason": "creator_invocation_multiplicity", "origins": sorted(candidates), "evidence_ids": row["evidence_ids"]})
    raw_aliases = defaultdict(set)
    raw_subjects = defaultdict(set)
    for row in resources:
        raw_aliases[row["resource_id"]].add(mapping[endpoint(row)])
        raw_subjects[row["resource_id"]].add(row["function_id"])
    # Proved use endpoints can bind construction/ownership without requiring
    # redundant lifecycle rows for cleanup/consumer SUPPORT APIs.
    for subject, values in observed.items():
        if len(values) == 1 and subject not in mapping:
            mapping[subject] = next(iter(values))
    # A unique owned producer + explicit release contract + actual deallocation
    # body fixes the harness cleanup binding. This does not equate arbitrary
    # same-type API parameters or infer ownership from a function's spelling.
    for argument in arguments:
        subject = endpoint(argument)
        if observed.get(subject):
            continue
        fid, name = subject[:2]
        function = snapshot.functions[fid]
        parameter = next(p for p in function["parameters"] if p["name"] == name)
        if not releases_parameter(function, name, snapshot, bodies):
            continue
        producers = [r for r in resources if r["return_value"] and r["cleanup"]["mandatory"] and r["cleanup"]["api"] == fid
            and r["type"] == parameter.get("base_type") and r["function_id"] in bodies and allocated_return(snapshot.functions[r["function_id"]], snapshot)
            and snapshot.functions[r["function_id"]].get("return_pointer_depth", 0) == parameter.get("pointer_depth", 0)
            and (argument["api"] is None or argument["api"] == r["function_id"])
            and any(o["function_id"] == r["function_id"] and o["return_value"] and o["ownership"] == "owned" and o["release_api"] == fid
                    for o in context["ownership_contract"]["entries"])]
        origins = {mapping[endpoint(r)] for r in producers}
        if len(origins) == 1:
            mapping[subject] = next(iter(origins))
            bindings.append({"function_id": fid, "parameter": name, "return_value": False,
                "resource_id": mapping[subject], "reason": "unique_owned_return_release_binding",
                "evidence_ids": sorted(set(bodies[fid]) | {e for r in producers for e in r["evidence_ids"]})})
            argument.update(construction="derived", api=None)
    for section, field in (("lifecycle_contract", "resources"), ("argument_contract", "arguments"),
                           ("ownership_contract", "entries"), ("ordering_contract", "constraints")):
        for row in context[section][field]:
            if section == 'ownership_contract' and row.get('subject_kind') == 'PointerParameter' and any(
                    p['name'] == row['parameter'] and p.get('pointer_depth', 0) >= 2
                    for p in snapshot.functions[row['function_id']]['parameters']):
                continue  # Pointer storage is distinct from the produced pointee.
            raw = row.get("resource_id")
            subject = endpoint(row)
            if row.get("field") is not None:
                continue
            if raw is None:
                # Only a proven flow into a real lifecycle resource; raw input
                # observations are not constructed objects.
                if section in {"argument_contract", "ownership_contract"} and mapping.get(subject) in set(mapping[endpoint(r)] for r in resources):
                    row["resource_id"] = mapping[subject]
                continue
            candidates = raw_aliases.get(raw, set())
            if subject in mapping:
                row["resource_id"] = mapping[subject]
            elif len(candidates) == 1:
                # A model ID alone cannot connect unrelated endpoints. Only
                # reuse within a subject already proved by lifecycle/flow.
                same_subject = row["function_id"] in raw_subjects[raw]
                if same_subject:
                    row["resource_id"] = next(iter(candidates))
            # Unknown IDs deliberately survive: phantom-resource Gate rejects.
    reuse_projections = []
    groups = defaultdict(list)
    for row in resources:
        groups[row["resource_id"]].append(row)
    for rid, group in groups.items():
        reuse = {r["reuse"] for r in group}
        origins = [o for o in flow["observations"] if o["resource_id"] == rid and o["return_value"]]
        released = any(o["resource_id"] == rid and any(o["function_id"] == r["cleanup"]["api"] for r in group) for o in flow["observations"])
        if reuse == {"per_input", "per_context"} and released and origins and all(allocated_return(snapshot.functions[o["function_id"]], snapshot) for o in origins):
            # Both contracts allow one freshly allocated context per input. The
            # straight-line caller allocates and releases it in this invocation.
            for row in group:
                row["reuse"] = "per_input"
            reuse_projections.append({"resource_id": rid, "scope": "per_input", "reason": "fresh_local_create_release_interval",
                "evidence_ids": sorted({e for o in flow["observations"] if o["resource_id"] == rid for e in o["evidence_ids"]})})
    return {"version": VERSION, "bindings": sorted(bindings, key=canonical), "reuse_projections": reuse_projections,
            "value_flow": flow, "unresolved": sorted(unresolved, key=canonical)}
