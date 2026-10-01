"""Framework-issued origins; a pointer declaration alone is not a resource."""
from ..semantic_discovery.models import digest
from .models import resource_id
from .value_flow import complete_bodies

VERSION = "typed-value-origins-v2"


def origin_catalog(snapshot, records, allowed_ids):
    from .argument_graph import build_argument_graph
    from .evidence import CONTRACT_FIELDS
    context = {"core_apis": [], "facts": []}
    for section, field in CONTRACT_FIELDS.values():
        context[section] = {field: []}
    ft = {"ft_id": "ft_identity_catalog", "core_functions": [],
        "support_candidates": [{"function_id": fid} for fid in sorted(allowed_ids)], "excluded_functions": []}
    graph = build_argument_graph(context, ft, [], snapshot, records)
    catalog = {r["resource_id"]: {"value_type": "Resource", "origin": r["origin"],
        "evidence_ids": r.get("evidence_ids", [])} for r in graph["resource_origins"]}
    bodies = complete_bodies(snapshot, records)
    for fid in sorted(allowed_ids & set(bodies)):
        function = snapshot.functions[fid]
        if function.get("return_pointer_depth"):
            origin = {"function_id": fid, "kind": "return", "parameter": None, "type": function.get("return_base_type"),
                "pointer_depth": function['return_pointer_depth']}
            record = {"value_type": "Resource", "origin": origin, "evidence_ids": sorted(bodies[fid])}
            catalog[resource_id(fid)] = record
            catalog["resource_" + digest(origin)[:24]] = record
        for p in function.get("parameters", []):
            if not (p.get("is_struct_like") or p.get("is_opaque_handle")):
                continue
            origin = {"function_id": fid, "kind": "parameter", "parameter": p["name"], "type": p["base_type"],
                "pointer_depth": p.get('pointer_depth', 0)}
            record = {"value_type": "StateObject" if p.get("is_struct_like") else "Resource",
                "origin": origin, "evidence_ids": sorted(bodies[fid])}
            catalog[resource_id(fid, p["name"])] = record
            catalog["resource_" + digest(origin)[:24]] = record
    return catalog


def subject_origins(subject, snapshot, catalog):
    """Resource choices respect declaration depth, including cell vs pointee."""
    function = snapshot.functions[subject['function_id']]
    if subject.get('field') is not None:
        return sorted(catalog)  # Field ABI construction is independently checked.
    p = next((p for p in function['parameters'] if p['name'] == subject.get('parameter')), None)
    base = p['base_type'] if p else function.get('return_base_type')
    depth = p.get('pointer_depth', 0) if p else function.get('return_pointer_depth', 0)
    if subject.get('subject_kind') == 'OutParameterPointee':
        depth -= 1
    result = []
    for rid, row in catalog.items():
        origin = row['origin']
        origin_depth = origin.get('pointer_depth')
        if origin_depth is None:
            producer = snapshot.functions[origin['function_id']]
            q = next((q for q in producer['parameters'] if q['name'] == origin.get('parameter')), None)
            origin_depth = (q.get('pointer_depth', 0) - (origin['kind'] == 'out_parameter')) if q else producer.get('return_pointer_depth', 0)
        if origin_depth == depth and (origin['type'] == base or base == 'void' and depth == 1):
            result.append(rid)
    return sorted(result)


def validate_value_roles(fact, snapshot, records, allowed_ids):
    catalog = origin_catalog(snapshot, records, allowed_ids)
    fid = fact["function_id"]
    if fact['predicate'] == 'ownership':
        from .proposals import ownership_subject
        for row in fact['value']['entries']:
            subject = ownership_subject(row, fid, snapshot)
            if row.get('resource_id') is not None and row['resource_id'] not in subject_origins(subject, snapshot, catalog):
                raise ValueError('ownership_resource_subject_mismatch')
    if fact["predicate"] == "input_binding":
        params = {p["name"]: p for p in snapshot.functions[fid]["parameters"]}
        for row in fact["value"]["bindings"]:
            p = params.get(row["parameter"], {})
            if row["source"] == "fuzz_data" and (p.get("is_struct_like") or p.get("is_opaque_handle")):
                raise ValueError("state_object_cannot_be_direct_fuzz_input")
    if fact["predicate"] == "argument_construction":
        for row in fact["value"]["arguments"]:
            if row["construction"] in {"input", "constant", "callback"} and row["resource_id"] is not None:
                raise ValueError("value_role_resource_id_forbidden")
            origin = catalog.get(row["resource_id"], {}).get("origin", {})
            if row["construction"] == "creator_api" and origin.get("kind") in {"return", "out_parameter"} and row["api"] != origin["function_id"]:
                raise ValueError("resource_origin_api_conflict")
    if fact["predicate"] == "lifecycle":
        for row in fact["value"]["resources"]:
            if row["creation"]["kind"] == "input":
                raise ValueError("fuzz_input_is_not_a_resource")
    def inspect(value):
        if isinstance(value, list):
            for row in value:
                inspect(row)
        elif isinstance(value, dict):
            rid = value.get("resource_id")
            if rid is not None and rid not in catalog:
                raise ValueError("unissued_resource_identity")
            for child in value.values():
                inspect(child)
    inspect(fact["value"])
    return catalog


def parameter_roles(function, graph, canonical, catalog):
    result = []
    for p in function.get("parameters", []):
        selected = next((r for r in canonical["parameters"] if r["function_id"] == function["id"] and r["parameter"] == p["name"]), None)
        recipe = selected.get("recipe") if selected else None
        kind = recipe.get("kind") if recipe else None
        category = ("FuzzInput" if kind in {"fuzz_bytes", "fuzz_size", "derived_scalar"} else "Constant" if kind == "constant"
            else "CallbackObject" if kind == "callback_object" else "Resource" if recipe and recipe.get("resource_id")
            else "StateObject" if p.get("is_struct_like") else "Value")
        permitted = [rid for rid, entry in catalog.items() if entry["origin"]["function_id"] == function["id"]
            and entry["origin"].get("parameter") == p["name"]]
        if recipe and recipe.get('kind') == 'out_parameter_storage':
            category, permitted = 'PointerStorage', []
        elif recipe and recipe.get("resource_id"):
            permitted = [recipe["resource_id"]]
        if category in {"FuzzInput", "Constant", "CallbackObject"}:
            permitted = []
        result.append({"parameter": p["name"], "value_type": category, "permitted_resource_origins": sorted(permitted),
            "identity_fixed_by_framework": bool(recipe and recipe.get("resource_id") and category != 'PointerStorage')})
    return result
