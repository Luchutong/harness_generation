"""Bounded, source-owned repeated calls over an unchanged context parameter.

This certifies where a project call executes, not whether the callee is safe,
owns its inputs, or terminates. Arbitrary branches, escaped buffers, pointer
rebinding, VLAs and unknown calls remain outside this proof boundary.
"""
import re

from ..semantic_discovery.models import canonical, digest
from ..semantic_discovery.tools import _text, _walk
from .value_flow import body_tree, unique_callee

VERSION = "source-internal-invocation-v3"
BYTE_TYPES = {"char", "signed char", "unsigned char"}
MAX_LOCAL_BYTES = 4096


def unwrap(node):
    while node is not None and node.type == "parenthesized_expression" and len(node.named_children) == 1:
        node = node.named_children[0]
    return node


def byte_array(declaration, source):
    """One fixed plain C byte array; sizeof is portable without an ABI guess."""
    if declaration.type != "declaration":
        return None
    text = _text(declaration, source)
    match = re.fullmatch(r"\s*((?:unsigned\s+|signed\s+)?char)\s+([A-Za-z_]\w*)\s*\[\s*([1-9][0-9]*)\s*\]\s*(=\s*\{\s*0\s*\})?\s*;\s*", text)
    if not match or not 1 <= int(match[3]) <= MAX_LOCAL_BYTES:
        return None
    return {"name": match[2], "element_type": re.sub(r"\s+", " ", match[1]),
            "elements": int(match[3]), "initialization": "all_zero" if match[4] else "storage_only"}


def sizeof_array(node, source, arrays):
    if node is None or node.type != "sizeof_expression":
        return None
    value = unwrap(node.child_by_field_name("value"))
    if value is None and node.named_children:
        value = unwrap(node.named_children[-1])
    return arrays.get(_text(value, source)) if value is not None and value.type == "identifier" else None


def _non_escaping_arguments(callee, snapshot, protected, arrays):
    """Local certificate for the pointer lifetime, separate from ownership."""
    source, body = body_tree(callee)
    if body is None or body.has_error:
        return False
    shadowed = {f['name'] for f in snapshot.functions.values() if f.get('defined')} | {p['name'] for p in callee['parameters']}
    # A local function pointer can have an intrinsic's spelling too. The
    # spelling alone does not prove that the call is the memory intrinsic.
    for declaration in (n for n in _walk(body) if n.type == 'declaration'):
        for declarator in declaration.named_children:
            if declarator.type == 'init_declarator':
                declarator = declarator.child_by_field_name('declarator')
            if declarator is not None and (declarator.type.endswith('declarator') or declarator.type == 'identifier'):
                shadowed.update(_text(n, source) for n in _walk(declarator) if n.type == 'identifier')
    for node in _walk(body):
        if node.type in {'goto_statement', 'preproc_if', 'preproc_ifdef'}:
            return False
        if node.type == 'update_expression' and node.named_children:
            operand = unwrap(node.named_children[0])
            if operand.type == 'identifier' and _text(operand, source) in protected:
                return False
        if node.type == 'call_expression':
            arguments = node.child_by_field_name('arguments').named_children
            involved = [i for i, argument in enumerate(arguments) if any(n.type == 'identifier'
                and _text(n, source) in protected for n in _walk(argument))]
            if not involved:
                continue
            target = node.child_by_field_name('function')
            name = _text(target, source)
            allowed = {'memcpy':{0,1}, 'memmove':{0,1}, 'memset':{0}}.get(name, set())
            if target.type != 'identifier' or name in shadowed or not set(involved) <= allowed:
                return False
        if node.type in {'assignment_expression', 'init_declarator', 'return_statement'}:
            left = unwrap(node.child_by_field_name('left')) if node.type == 'assignment_expression' else None
            if left is not None and left.type == 'identifier' and _text(left, source) in protected:
                return False
            right = (node.child_by_field_name('right') if node.type == 'assignment_expression' else
                     node.child_by_field_name('value') if node.type == 'init_declarator' else
                     node.named_children[0] if node.named_children else None)
            if right is None:
                continue
            for identifier in (n for n in _walk(right) if n.type == 'identifier' and _text(n, source) in protected):
                parent = identifier.parent
                # Dereference/member/subscript values may be stored. A bare
                # pointer (including cast/alias arithmetic) may not escape.
                if parent.type not in {'field_expression','subscript_expression'} or parent.child_by_field_name('argument') != identifier:
                    return False
        if node.type == 'pointer_expression' and _text(node, source).lstrip().startswith('&') and any(
                n.type == 'identifier' and _text(n, source) in protected for n in _walk(node)):
            return False
    return True


def repeated_invocations(function, snapshot, bodies, excluded=()):
    """Certify a single direct read in a top-level while condition.

    Every argument is either an exact caller context pointer, a function-local
    fixed byte array, or sizeof that same array. The condition executes once on
    entry, and repetition stays inside the caller. No ownership is projected.
    """
    fid = function["id"]
    if fid not in bodies or not function["file"].endswith(".c"):
        return []
    source, body = body_tree(function)
    if body is None or body.has_error:
        return []
    statements = [n for n in body.named_children if n.type != "comment"]
    loops = [n for n in statements if n.type == "while_statement"]
    if len(loops) != 1:
        return []
    loop = loops[0]
    at = statements.index(loop)
    if any(n.type != "declaration" for n in statements[:at]) or any(n.type != "return_statement" for n in statements[at + 1:]):
        return []
    if len(statements[at + 1:]) > 1:
        return []
    parameters = {p["name"]: p for p in function.get("parameters", [])}
    names = [_text(n, source) for s in statements[:at] for n in _walk(s)
             if n.type == "identifier" and n.parent.type in {"init_declarator", "array_declarator", "declaration"}]
    if len(names) != len(set(names)) or set(names) & set(parameters):
        return []
    arrays = {a["name"]: a for s in statements[:at] if (a := byte_array(s, source))}
    condition = unwrap(loop.child_by_field_name("condition"))
    if condition is None:
        return []
    if condition.type == "assignment_expression":
        left = condition.child_by_field_name("left")
        if left is None or left.type != "identifier" or _text(left, source) not in names or _text(left, source) in arrays:
            return []
        if _text(condition.child_by_field_name("operator"), source) != "=":
            return []
        condition = unwrap(condition.child_by_field_name("right"))
    if condition is None or condition.type != "call_expression":
        return []
    call = condition
    target = call.child_by_field_name("function")
    if target is None or target.type != "identifier" or _text(target, source) in set(names) | set(parameters):
        return []
    callee = unique_callee(snapshot, _text(target, source), function)
    if not callee or callee["id"] not in bodies or callee["id"] in excluded or callee["id"] == fid or callee.get("return_pointer_depth", 0):
        return []
    calls = [n for n in _walk(body) if n.type == "call_expression"]
    if calls != [call]:
        return []  # No hidden calls before/after/in the body can escape storage.
    arguments = call.child_by_field_name("arguments").named_children
    if len(arguments) != len(callee.get("parameters", [])):
        return []
    forwarding, locals_, protected = [], [], set()
    storage, capacities = set(), set()
    for parameter, argument in zip(callee["parameters"], arguments):
        argument = unwrap(argument)
        name = _text(argument, source)
        if argument.type == "identifier" and name in parameters:
            parent = parameters[name]
            if (not parent.get("is_pointer") or not parent.get("is_struct_like")
                    or parent.get("pointer_depth") != 1 or parameter.get("pointer_depth") != 1
                    or parent["base_type"] != parameter["base_type"]):
                return []
            forwarding.append({"parameter": parameter["name"], "via_parameter": name})
            protected.add(name)
        elif argument.type == "identifier" and name in arrays:
            array = arrays[name]
            if parameter.get("pointer_depth") != 1 or parameter["base_type"] != array["element_type"]:
                return []
            locals_.append({"parameter": parameter["name"], "kind": "byte_array_storage", **array})
            storage.add(name); protected.add(name)
        else:
            array = sizeof_array(argument, source, arrays)
            if array is None or parameter.get("is_pointer") or parameter.get("is_struct_like"):
                return []
            locals_.append({"parameter": parameter["name"], "kind": "array_capacity", "name": array["name"], "value": array["elements"]})
            capacities.add(array["name"])
    if not forwarding or not storage or storage != capacities:
        return []
    if not _non_escaping_arguments(callee, snapshot,
            {r['parameter'] for r in forwarding} | {r['parameter'] for r in locals_ if r['kind']=='byte_array_storage'},
            {r['parameter'] for r in locals_ if r['kind']=='byte_array_storage'}):
        return []
    for node in _walk(body):
        if node.type in {"goto_statement", "if_statement", "switch_statement", "do_statement", "preproc_if", "preproc_ifdef"}:
            return []
        if node.type in {"assignment_expression", "update_expression"}:
            left = node.child_by_field_name("left") if node.type == "assignment_expression" else node.named_children[0]
            if any(n.type == "identifier" and _text(n, source) in protected for n in _walk(left)):
                return []
        if node.type == "pointer_expression" and _text(node, source).lstrip().startswith("&") and any(
                n.type == "identifier" and _text(n, source) in protected for n in _walk(node)):
            return []
    descriptor = {"version": VERSION, "function_id": callee["id"], "via_function_id": fid,
        "call_offset": call.start_byte, "invocation_kind": "internal", "multiplicity": "source_loop",
        "calls_per_invocation": {"min": 1, "max": None}, "storage_lifetime": "via_invocation",
        "parameter_forwarding": forwarding, "local_arguments": locals_,
        "evidence_ids": sorted(bodies[fid] | bodies[callee["id"]]), "proof_status": "proven"}
    return [{**descriptor, "invocation_proof_id": "internal_" + digest(descriptor)[:24]}]
