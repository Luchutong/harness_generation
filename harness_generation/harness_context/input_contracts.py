"""Input representation and NUL proof, independent of parameter spelling."""
from ..semantic_discovery.tools import _walk, _text
from .value_flow import body_tree, complete_bodies

VERSION = "input-representation-v1"


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
