"""Recomputable API semantic relations, independent of harness construction.

Source field dependence proves a possible API relation, not runtime object
identity, callability, ownership or a required invocation schedule.
"""
from tree_sitter import Language, Parser
import tree_sitter_c

from ..semantic_discovery.models import digest, canonical
from ..semantic_discovery.tools import _walk, _text

VERSION = "core-inclusion-proof-v2"


def source_evidence(fid, functions, records):
    from ..source_evidence import complete_bodies
    return sorted(complete_bodies({fid: functions[fid]}, records).get(fid, []))


def tree(function):
    source = ("void __core__(void) " + function.get("body", "")).encode()
    root = Parser(Language(tree_sitter_c.language())).parse(source).root_node
    body = next((n for n in _walk(root) if n.type == "compound_statement"), None)
    return source, body if body is not None and not body.has_error else None


def accesses(function):
    source, body = tree(function)
    reads, writes = {}, {}
    params = {p["name"] for p in function.get("parameters", [])}
    if body is None:
        return reads, writes
    for n in _walk(body):
        if n.type != "field_expression":
            continue
        base = _text(n.child_by_field_name("argument"), source)
        field = _text(n.child_by_field_name("field"), source)
        if base not in params:
            continue
        parent = n.parent
        assignment = parent.type == "assignment_expression" and parent.child_by_field_name("left") == n
        if assignment or parent.type == "update_expression":
            rhs = parent.child_by_field_name("right")
            inputs = { _text(x, source) for x in _walk(rhs) if x.type == "identifier"} if rhs is not None else {base}
            writes.setdefault(base, {})[field] = inputs & params
        if not assignment or _text(parent.child_by_field_name("operator"), source) != "=":
            reads.setdefault(base, set()).add(field)
    return reads, writes


def processes_parameters(function):
    source, body = tree(function)
    params = {p["name"] for p in function.get("parameters", [])}
    return body is not None and any(n.type in {"subscript_expression", "field_expression", "binary_expression"}
        and any(x.type == "identifier" and _text(x, source) in params for x in _walk(n)) for n in _walk(body))


def returned_input_fields(function, input_parameters):
    source, body = tree(function)
    if body is None or body.has_error:
        return set()
    returned = {_text(n.named_children[0], source) for n in _walk(body)
        if n.type == "return_statement" and n.named_children and n.named_children[0].type == "identifier"}
    if len(returned) != 1:
        return set()
    if any(n.type in {"for_statement", "while_statement", "do_statement", "goto_statement", "preproc_if"}
            or n.type == "assignment_expression" and _text(n.child_by_field_name("left"), source) in returned
            for n in _walk(body)):
        return set()
    assignments = {}
    for n in _walk(body):
        if n.type != "assignment_expression":
            continue
        left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
        if left.type != "field_expression" or _text(left.child_by_field_name("argument"), source) not in returned:
            continue
        field = _text(left.child_by_field_name("field"), source)
        relevant = any(x.type == "identifier" and _text(x, source) in input_parameters for x in _walk(right))
        assignments.setdefault(field, []).append(relevant)
    return {f for f, values in assignments.items() if values == [True]}


def inclusion_proofs(anchor, fid, functions, records, anchor_evidence=()):
    def proof(kind, eids, **detail):
        row = {"version": VERSION, "kind": kind, "anchor_function_id": anchor,
            "function_id": fid, "evidence_ids": sorted(set(eids)), **detail}
        return {**row, "proof_id": "core_proof_" + digest(row)[:24]}
    if fid == anchor:
        return [proof("accepted_anchor", anchor_evidence)]
    target, function = functions[anchor], functions[fid]
    own = source_evidence(fid, functions, records)
    anchor_source = source_evidence(anchor, functions, records)
    if not own or not anchor_source:
        return []
    eids = own + anchor_source
    rows = []
    target_reads, _ = accesses(target)
    reads, writes = accesses(function)
    # An exact field written from an input and observed by the target is stronger
    # than type membership. Constants/configuration alone do not establish CORE.
    for p in function.get("parameters", []):
        for q in target.get("parameters", []):
            if not p.get("is_pointer") or not q.get("is_pointer") or p["base_type"] != q["base_type"]:
                continue
            fields = sorted(f for f, inputs in writes.get(p["name"], {}).items()
                if inputs and f in target_reads.get(q["name"], set()))
            if fields:
                rows.append(proof("anchor_observed_field_transition", eids,
                    writer_parameter=p["name"], anchor_parameter=q["name"], fields=fields))
    target_source, target_body = tree(target)
    if target_body is None:
        return rows
    target_params = {p["name"] for p in target.get("parameters", [])}
    for call in (n for n in _walk(target_body) if n.type == "call_expression"):
        if _text(call.child_by_field_name("function"), target_source) != function["name"]:
            continue
        if function['name'] in target_params:
            continue
        identities = [f["id"] for f in functions.values() if f["name"] == function["name"]]
        if identities != [fid] or not processes_parameters(function):
            continue
        args = call.child_by_field_name("arguments")
        inputs = {_text(n, target_source) for n in _walk(args) if n.type == "identifier"} & target_params
        if inputs and call.parent.type != "expression_statement":
            rows.append(proof("anchor_observed_processing_result", eids, input_parameters=sorted(inputs)))
    # Pointer-return output fields must depend on a real target input and be
    # read by this API. Cleanup-only functions cannot pass this test.
    if target.get("return_pointer_depth"):
        output_fields = returned_input_fields(target, target_params)
        for p in function.get("parameters", []):
            fields = sorted(output_fields & reads.get(p["name"], set()))
            if fields and p.get("is_pointer") and p["base_type"] == target.get("return_base_type"):
                rows.append(proof("consumes_input_dependent_anchor_output", eids,
                    parameter=p["name"], fields=fields))
    # Bind an indirect callback through issued caller source, not its spelling.
    indirect = {_text(n.child_by_field_name("function"), target_source) for n in _walk(target_body)
        if n.type == "call_expression"} & target_params
    if indirect and processes_parameters(function):
        for caller_id, caller in functions.items():
            caller_eids = source_evidence(caller_id, functions, records)
            if not caller_eids:
                continue
            source, body = tree(caller)
            if body is None:
                continue
            for call in (n for n in _walk(body) if n.type == "call_expression"):
                if _text(call.child_by_field_name("function"), source) != target["name"]:
                    continue
                args = call.child_by_field_name("arguments").named_children
                if len(args) != len(target.get("parameters", [])):
                    continue
                for p, arg in zip(target["parameters"], args):
                    if p["name"] in indirect and _text(arg, source) == function["name"]:
                        rows.append(proof("bound_anchor_callback_processing", eids + caller_eids,
                            caller_function_id=caller_id, callback_parameter=p["name"]))
    return sorted({canonical(row): row for row in rows}.values(), key=canonical)
