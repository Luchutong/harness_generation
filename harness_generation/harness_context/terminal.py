"""Context-bound wire format; canonical resolutions still use strict validators."""
from copy import deepcopy
import json

from .models import obj, arr, enum, EIDS, STRING, DEPENDENCY_SCHEMA, VALUE_SCHEMAS
from .models import validate_shape

VERSION = 9


def constrain_origins(schema, catalog):
    """Restrict wire identities to origins available in the current evidence."""
    if not isinstance(schema, dict):
        return
    for name, child in schema.get("properties", {}).items():
        if name == "resource_id":
            types = child.get("type", "string")
            values = sorted(catalog)
            permitted = ([None] if isinstance(types, list) and "null" in types else []) + values
            child["enum"] = [v for v in permitted if 'enum' not in child or v in child['enum']]
        else:
            constrain_origins(child, catalog)
    if "items" in schema:
        constrain_origins(schema["items"], catalog)
    for child in schema.get("anyOf", []):
        constrain_origins(child, catalog)


def scoped_value_schema(req, signed, snapshot):
    # Canonical schemas reuse NULL_STRING/API_ACTION objects. Wire restrictions
    # are per property; preserve no aliases when installing scoped enums.
    value = json.loads(json.dumps(VALUE_SCHEMAS[req["kind"]]))
    fid = req["subject_function_id"]
    function = snapshot.functions[fid]
    from .callbacks import callback_declarations
    callback_names = [name for c in callback_declarations(function, snapshot)
        for name in ([c['parameter'] + '.' + c.get('field_path', c['field']),
                      c['parameter'] + '->' + c.get('field_path', c['field'])] if c['field'] else [c['parameter']])]
    candidates = signed["support_candidates"]
    def api_choices(reasons):
        return sorted({c["function_id"] for c in candidates
            if c["required_by"] == fid and c["reason"] in reasons})
    if req["kind"] == "ownership":
        original = value["properties"]["entries"]["items"]["properties"]
        alternatives = []
        for subject in signed["ownership_subjects"]:
                kind = subject['subject_kind']
                row = obj({"subject_id": enum(subject['subject_id']), **{k: deepcopy(original[k]) for k in
                    ("resource_id", "ownership", "release_api", "lifetime")}})
                from .value_roles import subject_origins
                if 'origin_catalog' in signed:
                    row['properties']['resource_id']['enum'] = [None] + subject_origins(subject, snapshot, signed['origin_catalog'])
                candidates_for_subject = [c['function_id'] for c in candidates if c['required_by'] == fid and c['reason'] == 'cleanup'
                    and any(b['parameter'] == subject['parameter'] and b.get('subject_kind') == kind for b in c['subject_bindings'])]
                row['properties']['release_api']['enum'] = [None] + sorted(set(candidates_for_subject))
                row["description"] = kind + ": select a framework-issued declaration subject. Scalars have no subject."
                alternatives.append(row)
        value["properties"]["entries"] = arr({"anyOf": alternatives}) if alternatives else arr(obj({}), 0)
    def constrain(schema, path=()):
        for name, child in schema.get("properties", {}).items():
            if name in {"parameter", "subject_parameter", "buffer_parameter", "length_parameter", "size_parameter"}:
                choices = signed["parameter_names"]
                if req["kind"] == "callback" and name == "parameter":
                    choices = sorted(set(callback_names))
                if name in {"length_parameter", "size_parameter"}:
                    choices = [p["name"] for p in function["parameters"] if not p.get("is_pointer") and not p.get("is_struct_like")]
                types = child.get("type")
                permitted = ([None] if isinstance(types, list) and "null" in types else []) + choices
                child["enum"] = [v for v in permitted if 'enum' not in child or v in child['enum']]
            elif name in {"api", "release_api", "setup_api", "via_function_id", "before", "after"}:
                reasons = ({"cleanup"} if name == "release_api" or "cleanup" in path else
                    {"creation"} if "creation" in path else
                    {"callback"} if name == "setup_api" else
                    {"initialization", "other"} if "preconditions" in path or "initialization" in path else
                    {"creation", "callback"})
                choices = api_choices(reasons)
                if name in {"via_function_id", "before", "after"}:
                    choices = signed["issued_function_ids"]
                if name == "api" and "creation" in path and function.get("return_pointer_depth"):
                    choices = sorted(set(choices) | {fid})
                types = child.get("type")
                child["enum"] = ([None] if isinstance(types, list) and "null" in types else []) + choices
            else:
                constrain(child, path + (name,))
        if "items" in schema:
            constrain(schema["items"], path)
        for child in schema.get("anyOf", []):
            constrain(child, path)
    constrain(value)
    # API fields are alternatives for this exact declaration subject, rather
    # than a union of every API supporting some other parameter of the function.
    field = {'argument_construction': 'arguments', 'state': 'preconditions', 'lifecycle': 'resources'}.get(req['kind'])
    if field:
        original = value['properties'][field]['items']
        alternatives = []
        subjects = [(p['name'], p['base_type'], False) for p in function['parameters']]
        if req['kind'] == 'lifecycle' and function.get('return_pointer_depth'):
            subjects.append((None, function['return_base_type'], True))
        for name, base, returned in subjects:
            row = deepcopy(original)
            props = row['properties']
            props['subject_parameter' if req['kind'] == 'lifecycle' else 'parameter']['enum'] = [name]
            def choices_for(reasons):
                return [None] + sorted({c['function_id'] for c in candidates if c['required_by'] == fid and c['reason'] in reasons
                    and any(b['parameter'] == name for b in c['subject_bindings'])})
            if req['kind'] == 'lifecycle':
                props['return_value']['enum'] = [returned]
                props['type']['enum'] = [base]
                for key in ('creation', 'initialization', 'cleanup'):
                    allowed = choices_for({key})
                    if key == 'creation' and returned:
                        allowed.append(fid)
                    props[key]['properties']['api']['enum'] = sorted(set(allowed), key=lambda x: x or '')
            else:
                props['api']['enum'] = choices_for({'creation', 'callback'} if req['kind'] == 'argument_construction' else {'initialization', 'other'})
                parameter = next(p for p in function['parameters'] if p['name'] == name)
                if req['kind'] == 'argument_construction' and parameter.get('pointer_depth', 0) >= 2:
                    props['resource_id']['enum'] = [None]
            if req['kind'] in {'argument_construction', 'state'}:
                branch_field = 'construction' if req['kind'] == 'argument_construction' else 'kind'
                groups = ([(['creator_api', 'derived'], {'creation'}),
                    (['input', 'zero_init', 'stack', 'constant', 'unknown'], set())] if req['kind'] == 'argument_construction' else
                    [(['initialized'], {'initialization'}), (['input_fed', 'reset'], {'other'}), (['none', 'unknown'], set())])
                if req['kind'] == 'argument_construction' and name in callback_names:
                    groups.append((['callback'], {'callback'}))
                for kinds, reasons in groups:
                    branch = deepcopy(row)
                    branch['properties'][branch_field]['enum'] = kinds
                    branch['properties']['api']['enum'] = choices_for(reasons)
                    alternatives.append(branch)
            else:
                alternatives.append(row)
        value['properties'][field]['items'] = {'anyOf': alternatives} if alternatives else obj({})
    from .input_pairs import constrain_pairs
    constrain_pairs(value, req['kind'], function)
    if req["kind"] == "return_semantics" and not function.get("return_pointer_depth"):
        value["properties"]["nullable"] = {"type": "null"}
        value["properties"]["owned"] = {"type": "null"}
    if req["kind"] == "support_decision":
        parents = sorted({req["subject_function_id"], *req["required_by"]})
        value["properties"]["required_by"]["items"] = enum(*parents)
        choices = sorted({c['reason'] for c in candidates if c['function_id'] == fid
            and c['required_by'] in req['required_by']})
        original = deepcopy(value)
        rejected = deepcopy(value)
        rejected['properties']['decision']['enum'] = ['rejected', 'unresolved']
        alternatives = [rejected]
        for reason in choices:
            branch = deepcopy(original)
            branch['properties']['reason']['enum'] = [reason]
            branch['properties']['decision']['enum'] = ['required', 'optional']
            branch['properties']['required_by']['items']['enum'] = sorted({c['required_by'] for c in candidates
                if c['function_id'] == fid and c['reason'] == reason and c['required_by'] in req['required_by']})
            alternatives.append(branch)
        value = {'anyOf': alternatives}
    return value


def terminal_schema(requirements, signed=None, snapshot=None):
    slots = {}
    for number, req in enumerate(requirements):
        parents = sorted({req["subject_function_id"], *req["required_by"]})
        dep = deepcopy(DEPENDENCY_SCHEMA)
        if len(parents) == 1:
            del dep["properties"]["required_by"]
            dep["required"].remove("required_by")
        else:
            dep["properties"]["required_by"] = enum(*parents)
        reasons = {"lifecycle": ("creation", "initialization", "cleanup"), "ownership": ("cleanup",),
            "argument_construction": ("creation", "callback"), "callback": ("callback",), "state": ("initialization", "other")}
        if req["kind"] in reasons:
            dep["properties"]["reason"] = enum(*reasons[req["kind"]])
        no_dependencies = req["kind"] in {"input_binding", "buffer_length", "return_semantics", "call_order"}
        value = scoped_value_schema(req, signed, snapshot) if signed is not None else deepcopy(VALUE_SCHEMAS[req["kind"]])
        if req["kind"] == "support_decision" and 'properties' in value:
            value["properties"]["required_by"]["items"] = enum(*parents)
        if signed is not None and req['kind'] == 'buffer_length' and any(
                r['kind'] == 'input_binding' and r['subject_function_id'] == req['subject_function_id'] for r in requirements):
            properties = value['properties']['links']['items']['properties']
            for field in ('length_parameter', 'requires_nul_termination', 'binary_zero_allowed'):
                properties.pop(field)
                value['properties']['links']['items']['required'].remove(field)
            value['properties']['links']['description'] = 'Reuse buffer_parameter from this group input binding; extent, NUL and binary-zero constraints are projected from that same binding.'
        evidence = arr(enum(*signed['evidence_ids'])) if signed is not None else EIDS
        if signed is not None:
            evidence['contains'] = enum(*signed['subject_evidence_ids'])
            evidence['minContains'] = 1
            evidence['description'] = 'Include this subject complete-source evidence; additional issued API/caller evidence is allowed. Source membership is also checked independently by the semantic validator.'
        slots["r" + str(number)] = obj({"status": enum("resolved", "unresolved", "not_applicable"),
            "facts": arr(obj({"value": value, "evidence_ids": evidence})),
            "discovered_api_dependencies": arr(obj({}) if no_dependencies or signed is not None else dep, 0 if no_dependencies or signed is not None else 32),
            "open_questions": arr(STRING)})
    return obj({"resolutions": obj(slots)})


def derive_selections(facts, req, signed):
    """One semantic choice is one activation truth; no duplicate LLM dependency."""
    choices = { (c["function_id"], c["required_by"], c["reason"]): c for c in signed["support_candidates"]}
    selected = {}
    for fact in facts:
        if fact["predicate"] == "support_decision":
            v = fact["value"]
            requests = [(fact["function_id"], parent, v["reason"], v["decision"], None, None)
                for parent in v["required_by"] if v["decision"] in {"required", "optional"}]
        else:
            v = fact['value']
            requests = []
            def add(api, reason, mandatory=True, parameter=None, subject_kind=None):
                if api and api != fact['function_id']:
                    requests.append((api, fact['function_id'], reason, 'required' if mandatory else 'optional', parameter, subject_kind))
            for resource in v.get('resources', []):
                parameter = resource.get('subject_parameter')
                kind = 'PointerReturn' if resource.get('return_value') else None
                add(resource['creation']['api'], 'creation', parameter=parameter, subject_kind=kind)
                for key in ('initialization', 'cleanup'):
                    add(resource[key]['api'], key, resource[key]['mandatory'], parameter, kind)
            for entry in v.get('entries', []):
                add(entry['release_api'], 'cleanup', parameter=entry.get('parameter'), subject_kind=entry.get('subject_kind'))
            for argument in v.get('arguments', []):
                add(argument['api'], 'callback' if argument['construction'] == 'callback' else 'creation', parameter=argument['parameter'])
            for callback in v.get('callbacks', []):
                add(callback['setup_api'], 'callback', callback['mandatory'], callback['parameter'])
            for state in v.get('preconditions', []):
                add(state['api'], 'initialization' if state['kind'] == 'initialized' else 'other', parameter=state['parameter'])
        for api, parent, reason, necessity, parameter, kind in requests:
            candidate = choices.get((api, parent, reason))
            if candidate is None:
                raise ValueError('support_activation_candidate_not_signed')
            matching = candidate['subject_bindings']
            if parameter is not None or kind == 'PointerReturn':
                matching = [b for b in candidate['subject_bindings'] if b['parameter'] == parameter
                    and (kind is None or b.get('subject_kind') == kind)]
                if not matching:
                    raise ValueError('support_activation_subject_effect_mismatch')
            if selected.get((api, parent, reason), {}).get('necessity') == 'required':
                necessity = 'required'
            previous = selected.get((api, parent, reason), {}).get('subject_bindings', [])
            selected[api, parent, reason] = {"function_id": api, "symbol": None, "required_by": parent,
                "reason": reason, "necessity": necessity, "candidate_id": candidate["candidate_id"],
                "evidence_ids": candidate["evidence_ids"],
                'subject_bindings': sorted({json.dumps(b, sort_keys=True): b for b in previous + matching}.values(), key=lambda b: json.dumps(b, sort_keys=True))}
    return sorted(selected.values(), key=lambda p: p["candidate_id"])


def expand_submission(value, requirements, signed=None, snapshot=None):
    validate_shape(value, terminal_schema(requirements, signed, snapshot))
    results = []
    input_values = {req['subject_function_id']: [b for f in value['resolutions']['r'+str(number)]['facts'] for b in f['value']['bindings']]
        for number, req in enumerate(requirements) if req['kind'] == 'input_binding'}
    for number, req in enumerate(requirements):
        result = deepcopy(value["resolutions"]["r" + str(number)])
        result["requirement_id"] = req["requirement_id"]
        result["facts"] = [{"function_id": req["subject_function_id"], "predicate": req["kind"], **f} for f in result["facts"]]
        if signed is not None and req['kind'] == 'buffer_length' and req['subject_function_id'] in input_values:
            from ..semantic_discovery.models import DecisionSchemaError
            for fact in result['facts']:
                for link in fact['value']['links']:
                    matches = [b for b in input_values[req['subject_function_id']] if b['parameter'] == link['buffer_parameter']]
                    if len(matches) != 1:
                        raise DecisionSchemaError('buffer_length.links', link['buffer_parameter'], ['one selected input binding in the same group'])
                    binding = matches[0]
                    link.update(length_parameter=binding['size_parameter'], requires_nul_termination=binding['nul_terminated'],
                        binary_zero_allowed=binding['binary_zero_allowed'])
        if signed is not None:
            from .proposals import expand_ownership
            for fact in result["facts"]:
                if fact["predicate"] == "ownership":
                    expand_ownership(fact["value"], signed)
            result["discovered_api_dependencies"] = derive_selections(result["facts"], req, signed)
        for dependency in result["discovered_api_dependencies"]:
            dependency.setdefault("required_by", req["subject_function_id"])
        results.append(result)
    return {"resolutions": results}


def compact_submission(results, requirements, signed=None):
    """Offline fixture encoder; never used to alter a real model's submission."""
    by_id = {r["requirement_id"]: r for r in results}
    slots = {}
    for number, req in enumerate(requirements):
        result = deepcopy(by_id[req["requirement_id"]])
        del result["requirement_id"]
        for fact in result["facts"]:
            if signed is not None and req['kind'] == 'buffer_length' and any(
                    r['kind'] == 'input_binding' and r['subject_function_id'] == req['subject_function_id'] for r in requirements):
                for link in fact['value']['links']:
                    for field in ('length_parameter', 'requires_nul_termination', 'binary_zero_allowed'):
                        link.pop(field, None)
            if signed is not None and fact["predicate"] == "ownership":
                for entry in fact["value"]["entries"]:
                    subjects = [s for s in signed["ownership_subjects"] if all(s[k] == entry[k] for k in ("parameter", "return_value", "field"))
                        and s["subject_kind"] == entry.get("subject_kind", "PointerReturn" if entry["return_value"] else "ResourceObject" if entry["field"] else "PointerParameter")]
                    entry["subject_id"] = subjects[0]["subject_id"] if subjects else "ownership_subject_not_issued"
                    for k in ("parameter", "return_value", "field", "subject_kind"):
                        entry.pop(k, None)
            del fact["function_id"], fact["predicate"]
        if signed is not None:
            result["discovered_api_dependencies"] = []
        if not req["required_by"] or set(req["required_by"]) <= {req["subject_function_id"]}:
            for dependency in result["discovered_api_dependencies"]:
                del dependency["required_by"]
        slots["r" + str(number)] = result
    return {"resolutions": slots}
