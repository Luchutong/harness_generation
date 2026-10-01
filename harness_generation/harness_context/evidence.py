"""Strict evidence grounding; validators reject semantics, never repair them."""
import json
import re
from functools import lru_cache

from ..semantic_discovery.models import digest, canonical
from .models import fact_id, resolution_schema, validate_shape, VALUE_SCHEMAS


@lru_cache(maxsize=256)
def declared_fields(declaration):
    from tree_sitter import Parser, Language
    import tree_sitter_c
    from ..semantic_discovery.tools import _walk, _text
    source = declaration.encode()
    tree = Parser(Language(tree_sitter_c.language())).parse(source)
    return frozenset(_text(node, source) for node in _walk(tree.root_node) if node.type == "field_identifier")


@lru_cache(maxsize=256)
def callback_abis(declaration):
    """Compare declared C types, ignoring only names, whitespace and comments.

    Typedef expansion and language-specific calling conventions stay unknown;
    this deliberately does not guess ABI equivalence.
    """
    from tree_sitter import Parser, Language
    import tree_sitter_c
    from ..semantic_discovery.tools import _walk
    source = (declaration.rstrip().rstrip(";") + ";").encode()
    root = Parser(Language(tree_sitter_c.language())).parse(source).root_node
    signatures = set()
    for node in _walk(root):
        if node.type not in {"declaration", "field_declaration"} or not any(
                child.type == "function_declarator" for child in _walk(node)):
            continue
        removals = [(child.start_byte, child.end_byte) for child in _walk(node)
                    if child.type in {"identifier", "field_identifier", "comment"}]
        content = source[node.start_byte:node.end_byte]
        for start, end in sorted(removals, reverse=True):
            content = content[:start - node.start_byte] + content[end - node.start_byte:]
        normalized = re.sub(r"\s+", "", content.decode()).rstrip(";")
        signatures.add(normalized.replace("(*)", "", 1))
    return frozenset(signatures)


def declared_callback_abis(function, parameter_name, snapshot):
    from .callbacks import callback_declarations, callback_matches
    candidates = callback_matches({"parameter": parameter_name}, callback_declarations(function, snapshot))
    return set().union(*(callback_abis(c["signature"]) for c in candidates)) if candidates else set()


def record_functions(record, snapshot):
    ids = {record.get("function_id"), record.get("caller_id"), *record.get("possible_callee_ids", [])}
    if record.get("tool") == "read_source_range":
        ids.update(fid for fid, function in snapshot.functions.items() if function["file"] == record.get("source")
            and function["start_line"] <= record.get("line_end", 0) and function["end_line"] >= record.get("line_start", 0))
    return {fid for fid in ids if isinstance(fid, str) and fid in snapshot.functions}


def body_evidence(eids, fid, records, snapshot):
    return any(eid in records and fid in record_functions(records[eid], snapshot)
        and records[eid].get("tool") in {"get_function", "read_source_range", "find_function_argument_usages"}
        and records[eid].get("content") and not records[eid].get("truncated") for eid in eids)


def api_roles(fact):
    value, roles = fact["value"], {}
    def add(api, role):
        if api:
            roles.setdefault(api, set()).add(role)
    for resource in value.get("resources", []):
        add(resource["creation"]["api"], "creation")
        add(resource["initialization"]["api"], "initialization")
        add(resource["cleanup"]["api"], "cleanup")
    for entry in value.get("entries", []):
        add(entry["release_api"], "cleanup")
    for argument in value.get("arguments", []):
        add(argument["api"], "callback" if argument["construction"] == "callback" else "creation")
    for callback in value.get("callbacks", []):
        add(callback["setup_api"], "callback")
    for state in value.get("preconditions", []):
        add(state["api"], "initialization" if state["kind"] == "initialized" else "other")
    return roles


def validate_fact(fact, requirement, snapshot, records, allowed_ids, visible_ids=None):
    required = {"function_id", "predicate", "value", "evidence_ids"}
    if set(fact) - (required | {"fact_id", "requirement_id"}) or not required <= set(fact):
        raise ValueError("invalid_fact_fields")
    fid = fact["function_id"]
    if fid != requirement["subject_function_id"] or fid not in snapshot.functions or fact["predicate"] != requirement["kind"]:
        raise ValueError("fact_outside_requirement")
    validate_shape(fact["value"], VALUE_SCHEMAS[fact["predicate"]], repairable=False)
    eids = fact["evidence_ids"]
    if (not isinstance(eids, list) or not eids or len(eids) != len(set(eids))
            or any(eid not in records or visible_ids is not None and eid not in visible_ids for eid in eids)):
        raise ValueError("unissued_or_unrelated_fact_evidence")
    if not body_evidence(eids, fid, records, snapshot):
        raise ValueError("semantic_fact_requires_untruncated_subject_source")
    parameters = {p["name"] for p in snapshot.functions[fid].get("parameters", [])}
    if fact["predicate"] == "callback":
        from .callbacks import callback_declarations
        for entry in callback_declarations(snapshot.functions[fid], snapshot):
            if entry["field"]:
                path = entry.get("field_path", entry["field"])
                parameters.update({entry["field"], entry["parameter"] + "." + path, entry["parameter"] + "->" + path})
    def inspect(value):
        if isinstance(value, list):
            for item in value:
                inspect(item)
        elif isinstance(value, dict):
            for key, item in value.items():
                if key in {"parameter", "subject_parameter", "buffer_parameter", "length_parameter", "size_parameter"} and item is not None and item not in parameters:
                    raise ValueError("unknown_parameter")
                if key in {"api", "release_api", "setup_api", "via_function_id", "before", "after"} and item is not None and item not in allowed_ids:
                    raise ValueError("fact_api_outside_discovered_scope")
                if key == "resource_id" and item is not None and not re.fullmatch(r"resource_[A-Za-z0-9_]{1,64}", item):
                    raise ValueError("invalid_resource_identity")
                inspect(item)
    inspect(fact["value"])
    if "fact_id" in fact and fact["fact_id"] != fact_id(fact):
        raise ValueError("fact_identity_mismatch")
    if fact["predicate"] == "callback":
        for callback in fact["value"]["callbacks"]:
            if callback["signature"] is not None:
                submitted = callback_abis(callback["signature"])
                declared = declared_callback_abis(snapshot.functions[fid], callback["parameter"], snapshot)
                if len(submitted) != 1 or not submitted <= declared:
                    raise ValueError("callback_abi_not_supported_by_declaration")
    if fact["predicate"] == "ownership":
        from .proposals import ownership_subject
        for entry in fact["value"]["entries"]:
            subject = ownership_subject(entry, fid, snapshot)
            if entry["ownership"] in {"borrowed", "static"} and entry["release_api"] is not None:
                raise ValueError("borrowed_or_static_resource_cannot_have_release_api")
            if entry["return_value"] and (entry["parameter"] is not None or not snapshot.functions[fid].get("return_pointer_depth", 0)):
                raise ValueError("invalid_return_ownership_subject: scalar returns are not pointer resources")
            if not entry["return_value"]:
                parameter = next((p for p in snapshot.functions[fid].get("parameters", []) if p["name"] == entry["parameter"]), None)
                if parameter is None or not (parameter.get("is_pointer") or parameter.get("is_opaque_handle")
                        or parameter.get("is_struct_like") and subject['subject_kind'] == "ResourceObject" or entry["field"] is not None):
                    raise ValueError(f"invalid_ownership_subject: {entry['parameter']} is not a pointer/handle/struct field")
            if entry["field"] is not None:
                parameter = next((p for p in snapshot.functions[fid].get("parameters", []) if p["name"] == entry["parameter"]), None)
                if parameter is None or not any(entry["field"] in declared_fields(struct["declaration"])
                    for struct in snapshot.artifacts.structs if parameter["base_type"] in {struct["name"], *struct.get("aliases", [])}):
                    raise ValueError("unknown_ownership_field")
    if fact["predicate"] == "return_semantics" and not snapshot.functions[fid].get("return_pointer_depth"):
        if fact["value"]["owned"] is not None or fact["value"]["nullable"] is not None:
            raise ValueError("scalar_return_cannot_have_pointer_semantics")
    if fact["predicate"] == "lifecycle":
        for resource in fact["value"]["resources"]:
            function = snapshot.functions[fid]
            parameter = next((p for p in function.get("parameters", []) if p["name"] == resource["subject_parameter"]), None)
            if resource["return_value"]:
                if resource["subject_parameter"] is not None or not function.get("return_pointer_depth", 0):
                    raise ValueError("invalid_return_resource_subject")
                type_name = function.get("return_base_type")
            else:
                if parameter is None:
                    raise ValueError("invalid_parameter_resource_subject")
                type_name = parameter.get("base_type")
            if resource["type"] != type_name:
                raise ValueError("resource_type_mismatch")
    from .value_roles import validate_value_roles
    validate_value_roles(fact, snapshot, records, allowed_ids)


def parse_resolution(text, tools):
    if not isinstance(text, str) or len(text) > 64000:
        raise ValueError("invalid_resolution_json")
    from ..minimal_ft.persistence import _unique_object, _bad_constant
    try:
        result = json.loads(text, object_pairs_hook=_unique_object, parse_constant=_bad_constant)
    except ValueError:
        from ..semantic_discovery.models import DecisionSchemaError
        raise DecisionSchemaError("$", "malformed JSON", ["structured terminal object"]) from None
    requirement = tools.requirement
    validate_shape(result, resolution_schema(requirement["kind"]))
    if result["requirement_id"] != requirement["requirement_id"]:
        raise ValueError("requirement_identity_changed")
    if result["status"] == "unresolved":
        if not result["open_questions"]:
            raise ValueError("unresolved_requires_questions")
    else:
        from ..semantic_discovery.models import DecisionSchemaError
        if not result["facts"]:
            raise DecisionSchemaError("facts", [], ["nonempty for resolved/not_applicable"])
        if result["open_questions"]:
            raise DecisionSchemaError("open_questions", result["open_questions"], ["empty for resolved/not_applicable; genuine gaps use unresolved"])
        if result["status"] == "not_applicable" and requirement["kind"] in {"input_binding", "argument_construction", "return_semantics"}:
            raise ValueError("required_core_contract_cannot_be_not_applicable")
    for fact in result["facts"]:
        validate_fact(fact, requirement, tools.snapshot, tools.evidence, tools.scope_ids, tools.visible_ids)
        if fact["predicate"] == "ownership":
            from .proposals import ownership_subject
            for entry in fact["value"]["entries"]:
                subject = ownership_subject(entry, fact["function_id"], tools.snapshot)
                entry.update({k: subject[k] for k in ("subject_id", "subject_kind")})
    from .argument_graph import issued_resource_ids
    identity_catalog = issued_resource_ids(tools.snapshot, tools.evidence, tools.scope_ids)
    def check_identities(value):
        if isinstance(value,list):
            for item in value:
                check_identities(item)
        elif isinstance(value,dict):
            if value.get('resource_id') is not None and value['resource_id'] not in identity_catalog:
                raise ValueError('unissued_resource_identity')
            for item in value.values():
                check_identities(item)
    check_identities(result['facts'])
    from .terminal import derive_selections
    from .proposals import registry
    # The expanded compatibility format and persisted artifacts obey the same
    # issued API/parent/role boundary as the native wire format.
    selections = derive_selections(result['facts'], requirement, registry(tools, [requirement]))
    seen = set()
    for proposal in result["discovered_api_dependencies"]:
        fid, parent = proposal["function_id"], proposal["required_by"]
        from .proposals import match_dependency
        candidate = match_dependency(proposal, requirement, tools)
        if parent not in {requirement["subject_function_id"], *requirement["required_by"]}:
            raise ValueError("dependency_without_requirement_parent")
        if fid == parent and proposal["necessity"] in {"required", "optional"}:
            raise ValueError("self_dependency_is_not_a_support_api")
        if fid is not None:
            key = (fid, parent, proposal['reason'])
            if fid not in tools.scope_ids or fid in tools.excluded or key in seen:
                raise ValueError("dependency_identity_not_discovered_or_excluded")
            seen.add(key)
            if not body_evidence(proposal["evidence_ids"], fid, tools.evidence, tools.snapshot):
                raise ValueError("dependency_requires_api_source_evidence")
            if fid not in tools.initial_ids and fid not in tools.state.discoveries:
                raise ValueError("new_api_without_discovery_evidence")
        elif not proposal["symbol"]:
            raise ValueError("missing_dependency_reference")
        if not proposal["evidence_ids"] or any(eid not in tools.visible_ids for eid in proposal["evidence_ids"]):
            raise ValueError("unissued_dependency_evidence")
        if proposal["necessity"] in {"required", "optional"} and fid is not None:
            roles = set().union(*(api_roles(fact).get(fid, set()) for fact in result["facts"]))
            decisions = [fact["value"] for fact in result["facts"] if fact["predicate"] == "support_decision"]
            justified = proposal["reason"] in roles or any(fid == requirement["subject_function_id"]
                and decision["decision"] == proposal["necessity"] and decision["reason"] == proposal["reason"]
                and parent in decision["required_by"] for decision in decisions)
            if not justified:
                raise ValueError("dependency_role_not_supported_by_facts")
        if candidate:
            proposal["candidate_id"] = candidate["candidate_id"]
            derived = next((s for s in selections if all(s[k] == proposal[k] for k in ('function_id','required_by','reason'))), None)
            bindings = derived['subject_bindings'] if derived else candidate['subject_bindings']
            if 'subject_bindings' in proposal and proposal['subject_bindings'] != bindings:
                raise ValueError('dependency_subject_effect_changed')
            proposal['subject_bindings'] = bindings
    # Framework-owned identifiers; terminal content cannot assign them.
    for fact in result["facts"]:
        fact["requirement_id"] = requirement["requirement_id"]
        fact["evidence_ids"] = sorted(fact["evidence_ids"])
        fact["fact_id"] = fact_id(fact)
    result["facts"] = sorted(result["facts"], key=lambda fact: fact["fact_id"])
    result["discovered_api_dependencies"] = sorted(result["discovered_api_dependencies"], key=canonical)
    return result


def validate_resolution_record(result, requirement, snapshot, state, initial_ids, excluded):
    """Revalidate persisted facts AND proposals, including their semantic roles."""
    from types import SimpleNamespace
    raw = {**result, "facts": [{k: v for k, v in fact.items() if k not in {"fact_id", "requirement_id"}}
                               for fact in result["facts"]]}
    view = SimpleNamespace(requirement=requirement, snapshot=snapshot, state=state, evidence=state.evidence,
        scope_ids=initial_ids | set(state.discoveries), visible_ids=set(state.evidence),
        initial_ids=initial_ids, excluded=excluded)
    parsed = parse_resolution(canonical(raw), view)
    if parsed != result:
        raise ValueError("persisted_resolution_changed_canonical_identity")


CONTRACT_FIELDS = {"input_binding": ("input_contract", "bindings"), "argument_construction": ("argument_contract", "arguments"),
    "buffer_length": ("buffer_length_contract", "links"), "lifecycle": ("lifecycle_contract", "resources"),
    "ownership": ("ownership_contract", "entries"), "call_order": ("ordering_contract", "constraints"),
    "callback": ("callback_contract", "callbacks"), "state": ("state_contract", "preconditions"),
    "return_semantics": ("return_contract", "functions")}


def build_context(ft, requirements, facts, snapshot=None, records=None):
    from .models import POLICY_VERSION
    context = {"schema_version": 1, "artifact_kind": "harness_context", "policy_version": POLICY_VERSION,
        "ft_id": ft["ft_id"], "minimal_ft_digest": digest(ft),
        "core_apis": sorted(row["function_id"] for row in ft["core_functions"]),
        "facts": sorted(facts, key=lambda fact: fact["fact_id"]),
        "open_requirements": sorted(row["requirement_id"] for row in requirements if row["status"] in {"open", "unresolved"}),
        "evidence_ids": sorted({eid for fact in facts for eid in fact["evidence_ids"]}), "frozen": False}
    for kind, (section, field) in CONTRACT_FIELDS.items():
        entries = []
        for fact in context["facts"]:
            if fact["predicate"] != kind:
                continue
            values = [fact["value"]] if kind == "return_semantics" else fact["value"].get(field, [])
            entries.extend({**value, "function_id": fact["function_id"], "fact_id": fact["fact_id"],
                            "evidence_ids": fact["evidence_ids"]} for value in values)
        context[section] = {field: sorted(entries, key=canonical)}
    context["dependencies"] = []
    if snapshot is not None:
        from .resource_identity import resolve_resources
        from .callbacks import enrich_callbacks
        from .input_contracts import project_inputs
        from .ordering import ordering_graph
        from .construction import project_construction, covered_requirements
        enrich_callbacks(context, snapshot)
        project_inputs(context, snapshot, records or {})
        from .input_pairs import project_pairs
        project_pairs(context)
        from .value_flow import complete_bodies
        allowed = ({r["function_id"] for r in ft["core_functions"] + ft["support_candidates"]}
                   | set(complete_bodies(snapshot, records or {}))) - set(ft["excluded_functions"])
        context["construction_contract"] = project_construction(context, snapshot, records or {}, allowed)
        context["resource_identity"] = resolve_resources(context, snapshot, records or {})
        from .argument_graph import build_argument_graph
        context["argument_graph"] = build_argument_graph(context, ft, requirements, snapshot, records or {})
        from .parameter_semantics import project_parameter_relations
        project_parameter_relations(context, snapshot, records or {})
        graph_nodes = {n["node_id"]: n for n in context["argument_graph"]["nodes"]}
        context["resource_identity"]["argument_bindings"] = [{"function_id": graph_nodes[p["target_parameter"]]["function_id"],
            "parameter_id": p["target_parameter"], "parameter": graph_nodes[p["target_parameter"]]["name"],
            "resource_id": p["resource_id"], "proof_digest": digest(p), "evidence_ids": p["evidence_ids"]}
            for p in context["argument_graph"]["dependency_graph"]["resolved_parameters"] if p.get("resource_id")]
        from .reconciliation import GraphContractReconciler, project_canonical_construction
        context["canonical_construction"] = GraphContractReconciler().reconcile(
            context, context["argument_graph"], requirements, snapshot)
        graph_satisfied = project_canonical_construction(context, context["canonical_construction"], requirements, snapshot)
        from .invocations import project_invocations
        project_invocations(context)
        context["ordering_graph"] = ordering_graph(context, snapshot, records or {})
        from .input_flow import project_input_flow
        project_input_flow(context, snapshot)
        context["framework_satisfied_requirements"] = sorted(covered_requirements(context, requirements, snapshot) + graph_satisfied,key=canonical)
    return context


class HarnessContextValidator:
    def validate(self, context, ft, snapshot, requirements, records, allowed_ids):
        errors, requirements_by_id = [], {row["requirement_id"]: row for row in requirements}
        seen = set()
        try:
            submitted_arguments={}
            for fact in context["facts"]:
                req = requirements_by_id.get(fact["requirement_id"])
                if req is None or fact["fact_id"] in seen:
                    raise ValueError("invalid_or_duplicate_fact_identity")
                seen.add(fact["fact_id"])
                validate_fact(fact, req, snapshot, records, allowed_ids)
                if fact['predicate']=='argument_construction':
                    for argument in fact['value']['arguments']:
                        key=fact['function_id'],argument['parameter']
                        if submitted_arguments.setdefault(key,argument)!=argument:
                            raise ValueError('conflicting_argument_contract')
            expected = build_context(ft, requirements, context["facts"], snapshot, records)
            expected["frozen"] = context["frozen"]
            expected["dependencies"] = context["dependencies"]
            if context != expected:
                raise ValueError("context_changed_canonical_projection")
            if any(r["reason"]=="semantic_recipe_conflict" for r in context["canonical_construction"]["parameters"]):
                raise ValueError("conflicting_argument_contract")
            owners = {}
            for fact in context["ownership_contract"]["entries"]:
                key = fact["function_id"], fact["parameter"], fact["return_value"], fact["field"], fact.get("subject_kind")
                shape = {k: v for k, v in fact.items() if k not in {"fact_id", "evidence_ids"}}
                previous = owners.setdefault(key, shape)
                if previous != shape:
                    raise ValueError("conflicting_ownership_facts")
            for section, field, keys in (
                ("argument_contract", "arguments", ("function_id", "parameter")),
                ("input_contract", "bindings", ("function_id", "parameter")),
                ("buffer_length_contract", "links", ("function_id", "buffer_parameter", "length_parameter")),
                ("return_contract", "functions", ("function_id",)),
            ):
                contracts = {}
                for row in context[section][field]:
                    key = tuple(row[k] for k in keys)
                    shape = {k: v for k, v in row.items() if k not in {"fact_id", "evidence_ids"}}
                    if contracts.setdefault(key, shape) != shape:
                        raise ValueError(f"conflicting_{section}")
            diagnostics = context["resource_contract"]["diagnostics"]
            if diagnostics:
                raise ValueError(diagnostics[0]["code"])
        except (ValueError, TypeError, KeyError) as error:
            errors.append({"code": str(error)[:160]})
        return errors
