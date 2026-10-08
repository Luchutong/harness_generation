"""Input representation and NUL proof, independent of parameter spelling."""
from ..semantic_discovery.tools import _walk, _text
from .value_flow import body_tree, complete_bodies

VERSION = "input-representation-v2"


def nul_evidence(function, parameter, snapshot):
    source, body = body_tree(function)
    if body is None or body.has_error:
        return False
    # Calls to project functions named like libc are not libc evidence.
    shadowed = {f["name"] for f in snapshot.functions.values() if f.get("defined")}
    for node in _walk(body):
        if node.type == "call_expression":
            target = node.child_by_field_name("function")
            if target.type != "identifier":
                continue
            name = _text(target, source)
            if name in shadowed:
                continue
            positions = {"strlen": (0,), "strcmp": (0, 1), "strchr": (0,)}.get(name, ())
            args = node.child_by_field_name("arguments").named_children
            if any(i < len(args) and args[i].type == "identifier" and _text(args[i], source) == parameter for i in positions):
                return True
        if node.type in {"while_statement", "for_statement"}:
            condition = node.child_by_field_name("condition")
            if condition:
                while condition.type == "parenthesized_expression" and len(condition.named_children) == 1:
                    condition = condition.named_children[0]
                subscripts = [n for n in _walk(condition) if n.type == "subscript_expression"
                    and _text(n.child_by_field_name("argument"), source) == parameter]
                text = _text(condition, source).replace(" ", "")
                if subscripts and (condition.type == "subscript_expression" or "!=0" in text or "!='\\0'" in text):
                    return True
    return False


def project_inputs(context, snapshot, records):
    bodies = complete_bodies(snapshot, records)
    links = context["buffer_length_contract"]["links"]
    for row in context["input_contract"]["bindings"]:
        function = snapshot.functions[row["function_id"]]
        parameter = next((p for p in function["parameters"] if p["name"] == row["parameter"]), {})
        is_nul = (row["function_id"] in bodies and row["source"] == "fuzz_data" and row["size_parameter"] is None
            and row["transform"] == "nul_terminate" and row["nul_terminated"]
            and parameter.get("base_type") in {"char", "unsigned char", "signed char"}
            and nul_evidence(function, row["parameter"], snapshot))
        row["input_kind"] = ("nul_terminated_string" if is_nul else "context_indirect_input" if row["source"] == "context"
            else "fixed_scalar" if parameter and not parameter.get("is_pointer") else "structured_input" if parameter.get("is_struct_like")
            else "explicit_length_buffer" if row["size_parameter"] else "binary_buffer")
        if is_nul:
            # No length argument is a complete NUL relation, not a guessed byte
            # count. Existing contradictory links remain visible to the Gate.
            row["size_relation"] = "nul_exclusive"
            if not any(l["function_id"] == row["function_id"] and l["buffer_parameter"] == row["parameter"] for l in links):
                links.append({"function_id": row["function_id"], "buffer_parameter": row["parameter"],
                    "length_parameter": None, "relation": "nul_exclusive", "element_type": None,
                    "requires_nul_termination": True, "binary_zero_allowed": row["binary_zero_allowed"],
                    "fact_id": row["fact_id"], "evidence_ids": row["evidence_ids"], "derived_by": VERSION})


def project_callback_inputs(context, requirements):
    """Forward an existing byte/length contract through a proved dispatcher.

    A callback gets the same arguments at invocation time; it does not need a
    second independent fuzz input proposal. Ownership is never forwarded here.
    Explicit conflicting callback contracts are retained for validation.
    """
    from copy import deepcopy
    from ..semantic_discovery.models import digest
    selected={(r['function_id'],r['parameter']):r for r in context['canonical_construction']['parameters'] if r['status']=='resolved'}
    bindings=context['input_contract']['bindings'];links=context['buffer_length_contract']['links']
    forwarded={}
    for dispatch in context['argument_graph'].get('callback_dispatches', []):
        fid,via=dispatch['function_id'],dispatch['via_function_id']
        maps={r['via_parameter']:r['parameter'] for r in dispatch['parameter_forwarding']}
        bound=selected.get((via,dispatch['callback_parameter']),{}).get('recipe',{})
        if bound.get('kind')!='callback_object' or bound.get('producer_api')!=fid:
            continue
        for binding in list(bindings):
            source,length=binding['parameter'],binding['size_parameter']
            if binding['function_id']!=via or binding['source']!='fuzz_data' or binding['transform']!='direct' or source not in maps or length not in maps:
                continue
            same=True
            for name in [source,length]:
                a=selected.get((via,name),{}).get('recipe');b=selected.get((fid,maps[name]),{}).get('recipe')
                strip=lambda r:{k:v for k,v in r.items() if k not in {'recipe_id','version'}} if r else None
                same &= a is not None and strip(a)==strip(b)
            parent_links=[l for l in links if l['function_id']==via and l['buffer_parameter']==source and l['length_parameter']==length]
            if not same or len(parent_links)!=1:
                continue
            if any(b['function_id']==fid and b['parameter']==maps[source] for b in bindings):
                continue
            eids=sorted(set(dispatch['evidence_ids'])|set(binding['evidence_ids'])|set(parent_links[0]['evidence_ids']))
            proof='callback_input_'+digest([dispatch,binding,parent_links[0]])[:24]
            forwarded[fid]=dict(proof_digest=proof,evidence_ids=eids)
            row=deepcopy(binding);row.update(function_id=fid,parameter=maps[source],size_parameter=maps[length],
                source='derived',via_function_id=via,fact_id=proof,evidence_ids=eids,derived_by=VERSION,
                input_kind='explicit_length_buffer')
            bindings.append(row)
            if not any(l['function_id']==fid and l['buffer_parameter']==maps[source] for l in links):
                link=deepcopy(parent_links[0]);link.update(function_id=fid,buffer_parameter=maps[source],
                    length_parameter=maps[length],fact_id=proof,evidence_ids=eids,derived_by=VERSION)
                links.append(link)
    # Lowering pins the final derived input view as well as the graph recipes.
    context['canonical_construction']['input_contract_digest'] = digest(context['input_contract'])
    return [dict(requirement_id=r['requirement_id'],predicate=r['kind'],proof_kind=VERSION,**forwarded[r['subject_function_id']])
        for r in requirements if r['subject_function_id'] in forwarded and r['kind'] in {'input_binding','buffer_length'}]


def project_internal_inputs(context, requirements):
    """An internal reader receives the exact canonical context of its caller.

    This adds no fuzz root or ownership fact. Existing contradictory input
    claims remain visible; source-owned output arrays are never input bytes.
    """
    from copy import deepcopy
    from ..semantic_discovery.models import digest
    from .internal_invocations import VERSION as INTERNAL_VERSION
    selected = {(r['function_id'], r['parameter']): r for r in context['canonical_construction']['parameters'] if r['status'] == 'resolved'}
    bindings = context['input_contract']['bindings']
    forwarded = {}
    for dispatch in context['argument_graph'].get('internal_invocations', []):
        if dispatch.get('proof_status') != 'proven' or dispatch.get('version') != INTERNAL_VERSION:
            continue
        fid, via = dispatch['function_id'], dispatch['via_function_id']
        for mapping in dispatch['parameter_forwarding']:
            source, target = selected.get((via, mapping['via_parameter'])), selected.get((fid, mapping['parameter']))
            if not source or not target:
                continue
            origin = source['recipe'].get('resource_id')
            if not origin or target['recipe'].get('resource_id') != origin:
                continue
            parents = [b for b in bindings if b['function_id'] == via and b['parameter'] == mapping['via_parameter']
                       and b['source'] in {'context', 'derived'}]
            if len(parents) != 1:
                continue
            existing = [b for b in bindings if b['function_id'] == fid and b['parameter'] == mapping['parameter']]
            if existing and any(b['source'] not in {'context','derived'} or b['via_function_id'] not in {via,parents[0]['via_function_id']}
                                for b in existing):
                continue
            eids = sorted(set(dispatch['evidence_ids']) | set(parents[0]['evidence_ids']) | set(source['evidence_ids']) | set(target['evidence_ids']))
            proof = 'internal_input_' + digest([dispatch, parents[0], origin])[:24]
            if not existing:
                row = deepcopy(parents[0]); row.update(function_id=fid, parameter=mapping['parameter'], size_parameter=None,
                    source='context', via_function_id=via, fact_id=proof, evidence_ids=eids, derived_by=INTERNAL_VERSION,
                    input_kind='context_indirect_input', size_relation='none')
                bindings.append(row)
            forwarded[fid] = dict(proof_digest=proof, evidence_ids=eids)
    context['canonical_construction']['input_contract_digest'] = digest(context['input_contract'])
    return [dict(requirement_id=r['requirement_id'], predicate=r['kind'], proof_kind=INTERNAL_VERSION, **forwarded[r['subject_function_id']])
            for r in requirements if r['subject_function_id'] in forwarded and r['kind']=='input_binding']
