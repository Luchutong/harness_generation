"""Exact callback declaration identities and source-backed userdata links."""
import re
from tree_sitter import Language, Parser
import tree_sitter_c

from ..semantic_discovery.models import digest
from ..semantic_discovery.tools import _walk, _text
from .value_flow import body_tree

VERSION = "callback-declarations-v1"


def parse_declaration(declaration):
    source = (declaration.rstrip().rstrip(";") + ";").encode()
    root = Parser(Language(tree_sitter_c.language())).parse(source).root_node
    return source, root


def exact_signature(declaration, typedefs):
    source, root = parse_declaration(declaration)
    if root.has_error:
        return None
    function = next((n for n in _walk(root) if n.type == "function_declarator"), None)
    if function is None:
        types = [n for n in _walk(root) if n.type == "type_identifier"]
        aliases = [t for t in typedefs if types and t["name"] == _text(types[0], source)]
        alias = aliases[0] if len({re.sub(r"\s+", "", t["declaration"]) for t in aliases}) == 1 else None
        return exact_signature(alias["declaration"], ()) if alias else None
    parent = next((n for n in _walk(root) if n.type in {"declaration", "field_declaration", "type_definition", "parameter_declaration"}), None)
    if parent is None:
        return None
    content = _text(parent, source).removeprefix("typedef ").rstrip(";")
    params = function.child_by_field_name("parameters")
    if params is None or any(n.type in {"variadic_parameter", "ERROR"} for n in _walk(params)):
        return None
    # Preserve all type qualifiers and pointer levels. Only parameter identifiers
    # are removed for the ABI form, as in the strict legacy ABI comparator.
    parameter_types = []
    for param in params.named_children:
        if param.type != "parameter_declaration":
            return None
        value = _text(param, source)
        for name in sorted((n for n in _walk(param) if n.type == "identifier"), key=lambda n: n.start_byte, reverse=True):
            value = value[:name.start_byte-param.start_byte] + value[name.end_byte-param.start_byte:]
        parameter_types.append(value.strip())
    return_type = parent.child_by_field_name("type")
    if return_type is None:
        return None
    prefix = re.split(r"\(\s*\*", content, maxsplit=1)[0].strip()
    return {"signature": content, "return_type": prefix or _text(return_type, source), "parameter_types": parameter_types}


def callback_declarations(function, snapshot):
    typedefs = snapshot.artifacts.callback_typedefs
    entries = []
    for parameter in function.get("parameters", []):
        declaration = parameter.get("declaration", "")
        abi = exact_signature(declaration, typedefs)
        if abi:
            entries.append({"parameter": parameter["name"], "field": None, "owner_type": None,
                "declared_type": declaration, **abi})
        for struct in snapshot.artifacts.structs:
            if parameter["base_type"] not in {struct["name"], *struct.get("aliases", [])}:
                continue
            source, root = parse_declaration(struct["declaration"])
            if root.has_error:
                continue
            for node in _walk(root):
                if node.type != "field_declaration":
                    continue
                names = [n for n in _walk(node.child_by_field_name("declarator")) if n.type == "field_identifier"] if node.child_by_field_name("declarator") else []
                if len(names) != 1:
                    continue
                abi = exact_signature(_text(node, source), typedefs)
                if abi:
                    entries.append({"parameter": parameter["name"], "field": _text(names[0], source),
                        "owner_type": struct["name"], "declared_type": _text(node, source), **abi})
                else:
                    # One level of a declared callback-table field. Preserve the
                    # exact owner and full field path; do not match by spelling.
                    field_type = node.child_by_field_name("type")
                    nested = next((s for s in snapshot.artifacts.structs if field_type is not None
                        and _text(field_type, source) in {s["name"], *s.get("aliases", [])}), None)
                    if nested:
                        nested_source, nested_root = parse_declaration(nested["declaration"])
                        if nested_root.has_error:
                            continue
                        for field in _walk(nested_root):
                            if field.type != "field_declaration":
                                continue
                            nested_abi = exact_signature(_text(field, nested_source), typedefs)
                            field_decl = field.child_by_field_name("declarator")
                            nested_names = [n for n in _walk(field_decl) if n.type == "field_identifier"] if field_decl else []
                            if nested_abi and len(nested_names) == 1:
                                path = _text(names[0], source) + "." + _text(nested_names[0], nested_source)
                                entries.append({"parameter": parameter["name"], "field": _text(nested_names[0], nested_source),
                                    "field_path": path, "owner_path": parameter["name"] + "." + _text(names[0], source),
                                    "owner_type": nested["name"], "declared_type": _text(field, nested_source), **nested_abi})
    for entry in entries:
        entry["callback_id"] = "callback_" + digest({"function_id": function["id"], **entry})[:24]
    return entries


def callback_matches(submitted, declarations):
    label = submitted["parameter"].replace("->", ".")
    return [entry for entry in declarations if label in {
        entry["parameter"], entry["field"], entry["parameter"] + "." + (entry.get("field_path", entry["field"]) or "") }]


def enrich_callbacks(context, snapshot):
    for row in context["callback_contract"]["callbacks"]:
        declarations = callback_declarations(snapshot.functions[row["function_id"]], snapshot)
        candidates = callback_matches(row, declarations)
        if len(candidates) != 1:
            row.update(declaration_identity=None)
            continue
        declared = candidates[0]
        row.update(parameter=declared["parameter"], declaration_identity=declared)
        # ABI is framework-owned only after the exact declaration is unambiguous.
        row["signature"] = declared["signature"]
        source, body = body_tree(snapshot.functions[row["function_id"]])
        userdata_fields = set()
        if body and declared["field"]:
            for call in _walk(body):
                if call.type != "call_expression":
                    continue
                target = call.child_by_field_name("function")
                expected = declared["parameter"] + "." + declared.get("field_path", declared["field"])
                if re.sub(r"\s+", "", _text(target, source)).replace("->", ".") != expected:
                    continue
                args = call.child_by_field_name("arguments")
                # Pointer parameters supply possible userdata arguments; require
                # exact submitted member identity to disambiguate buffer fields.
                userdata_fields.update(re.sub(r"\s+", "", _text(a, source)).replace("->", ".")
                    for i, a in enumerate(args.named_children) if a.type == "field_expression" and i < len(declared["parameter_types"])
                    and re.sub(r"\s+", "", declared["parameter_types"][i]) in {"void*", "constvoid*"})
        user = row["userdata"].replace("->", ".") if row["userdata"] else None
        if user and body and declared["field"] is None:
            for call in _walk(body):
                if call.type == "call_expression" and _text(call.child_by_field_name("function"), source) == declared["parameter"]:
                    for i, arg in enumerate(call.child_by_field_name("arguments").named_children):
                        if i < len(declared["parameter_types"]) and re.sub(r"\s+", "", declared["parameter_types"][i]) in {"void*", "constvoid*"} and _text(arg, source) == user:
                            userdata_fields.add(user)
        userdata_targets = set()
        if user and body:
            # Exact setter assignment from a declared void-pointer parameter;
            # the stored field is identified, never inferred from its name.
            parameter = next((p for p in snapshot.functions[row["function_id"]]["parameters"] if p["name"] == user), None)
            if parameter and parameter.get("base_type") == "void" and parameter.get("is_pointer") and declared["field"]:
                owner = declared.get("owner_path", declared["parameter"])
                for assignment in _walk(body):
                    if assignment.type != "assignment_expression":
                        continue
                    left, right = assignment.child_by_field_name("left"), assignment.child_by_field_name("right")
                    if left.type == "field_expression" and _text(right, source) == user:
                        target = re.sub(r"\s+", "", _text(left, source)).replace("->", ".")
                        if target.rsplit(".", 1)[0] == owner:
                            userdata_targets.add(target)
        userdata_target = next(iter(userdata_targets)) if len(userdata_targets) == 1 else None
        row["userdata_binding"] = {"identity": user, "source_verified": user in userdata_fields,
            "target": userdata_target,
            "lifetime": row["lifetime"], "until": "context_cleanup" if row["lifetime"] == "per_context" else "call_return"}
        if userdata_target:
            row["userdata_binding"]["source_verified"] = True
        row["registration"] = {"api": row["setup_api"], "kind": "api" if row["setup_api"] else "harness_field_initialization",
            "before": row["function_id"], "callback_lifetime": row["lifetime"], "userdata_lifetime": row["lifetime"]}


def field_initialization_complete(context, precondition, snapshot):
    fid, name = precondition["function_id"], precondition["parameter"]
    arguments = [a for a in context["argument_contract"]["arguments"] if a["function_id"] == fid and a["parameter"] == name]
    callbacks = [c for c in context["callback_contract"]["callbacks"] if c["function_id"] == fid and c["parameter"] == name]
    if not arguments or arguments[0]["construction"] not in {"stack", "zero_init"} or not callbacks:
        return False
    sources = context.get("construction_contract", {}).get("sources", [])
    if not any(s["function_id"] == fid and s["parameter"] == name and s["kind"] == "public_callback_object"
            and s["construction_id"] == arguments[0].get("construction_source") for s in sources):
        return False
    initialized = set()
    for callback in callbacks:
        identity = callback.get("declaration_identity")
        if not identity or not callback["signature"] or callback["lifetime"] == "unknown" or callback["null_allowed"] is None:
            return False
        initialized.add(identity["field"])
        if callback["userdata"]:
            user = callback.get("userdata_binding", {})
            if not user.get("source_verified"):
                return False
            initialized.add(user["identity"].split(".")[-1])
    source, body = body_tree(snapshot.functions[fid])
    reads = {_text(n.child_by_field_name("field"), source) for n in _walk(body) if n.type == "field_expression"
        and _text(n.child_by_field_name("argument"), source) == name}
    return bool(reads) and reads <= initialized
