"""Clang type compatibility and compiler-issued source/canonical/LLVM bridges.

The source language check runs in the original translation unit.  LLVM opaque
pointers are recorded as lowering facts and never supply type equality.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from ..semantic_discovery.models import digest
from .analyzer import AnalysisBudget, BuildAnalysisError, _location, _run, _walk

TYPE_IDENTITY_VERSION = "clang-type-identity-v1"
_SUGAR = {"TypedefType", "ElaboratedType", "ParenType", "TypeOfExprType",
          "TypeOfType", "DecayedType", "AdjustedType"}


def _type_children(node):
    return [child for child in node.get("inner", [])
            if child.get("kind", "").endswith("Type") or child.get("kind") == "QualType"]


def _declarations(ast, project):
    """Keep declaration identity, including scopes; discard Clang heap addresses."""
    declarations, current_file = {}, None
    for node in _walk(ast):
        location, current_file = _location(node, current_file, project, {})
        if node.get("kind", "").endswith("Decl") and node.get("id") and node.get("loc"):
            declarations[node["id"]] = {"node": node, "location": location}
    return declarations


def _declaration_identity(reference, declarations, tu_id):
    key, seen = reference.get("id"), set()
    while key in declarations and key not in seen:
        seen.add(key)
        previous = declarations[key]["node"].get("previousDecl")
        if previous not in declarations:
            break
        key = previous
    row = declarations.get(key)
    if row is None or row["location"] is None:
        raise BuildAnalysisError("clang_type_declaration_identity_unresolved")
    node = row["node"]
    return {"tu_id": tu_id, "kind": node["kind"], "name": node.get("name", ""),
            "tag": node.get("tagUsed"), "source": row["location"]["source"],
            "offset": row["location"]["offset"]}


def _canonical_identity(node, declarations, tu_id):
    kind, children = node["kind"], _type_children(node)
    if kind in _SUGAR:
        if not children:
            raise BuildAnalysisError("clang_canonical_type_unresolved:" + kind)
        return _canonical_identity(children[-1], declarations, tu_id)
    if kind == "AttributedType":
        # ABI attributes are retained by the actual FunctionProtoType cc.
        if not children:
            raise BuildAnalysisError("clang_canonical_type_unresolved:" + kind)
        return _canonical_identity(children[-1], declarations, tu_id)
    if kind in {"RecordType", "EnumType"}:
        return {"kind": kind, "declaration": _declaration_identity(node.get("decl", {}), declarations, tu_id)}
    facts = {"kind": kind}
    if kind == "BuiltinType":
        facts["name"] = node["type"]["qualType"]
    for name in ("qualifiers", "cc", "variadic", "size", "numElements", "isDependent", "isInstantiationDependent"):
        if name in node:
            facts[name] = node[name]
    if children:
        facts["children"] = [_canonical_identity(child, declarations, tu_id) for child in children]
    if kind in {"FunctionProtoType", "FunctionNoProtoType"}:
        facts.setdefault("cc", "cdecl")
        facts.setdefault("variadic", False)
    return facts


def _typedef_chain(node, declarations, tu_id):
    result = []
    for child in _walk(node):
        if child.get("kind") == "TypedefType":
            row = _declaration_identity(child.get("decl", {}), declarations, tu_id)
            if row not in result:
                result.append(row)
    return result


def _function_type(alias):
    current = alias
    for _ in range(32):
        if current.get("kind") in {"FunctionProtoType", "FunctionNoProtoType"}:
            return current
        children = _type_children(current)
        if not children:
            break
        current = children[-1]
    raise BuildAnalysisError("clang_function_type_unresolved")


def _parameter_segments(text):
    result, start, depth = [], 0, 0
    for index, character in enumerate(text):
        if character in "([":
            depth += 1
        elif character in ")]":
            depth -= 1
        elif character == "," and depth == 0:
            result.append(text[start:index]); start = index + 1
    result.append(text[start:])
    return result


def _source_declaration(record, name, parameter=None, source_type=None):
    signature = record.get("signature", "")
    match = re.search(r"\b" + re.escape(record["name"]) + r"\s*\(", signature)
    if not match or any(character in signature for character in "{}#"):
        raise BuildAnalysisError("source_signature_probe_unsupported")
    opening, depth, closing = match.end() - 1, 0, None
    for cursor in range(opening, len(signature)):
        if signature[cursor] == "(":
            depth += 1
        elif signature[cursor] == ")":
            depth -= 1
            if depth == 0:
                closing = cursor; break
    if closing is None:
        raise BuildAnalysisError("source_signature_probe_unsupported")
    arguments = signature[opening + 1:closing]
    if parameter is not None and source_type is not None:
        segments = _parameter_segments(arguments)
        if parameter >= len(segments):
            raise BuildAnalysisError("source_signature_probe_parameter_unresolved")
        segments[parameter] = source_type
        arguments = ", ".join(segments)
    prefix = re.sub(r"\b(?:static|extern|inline|__inline|__inline__)\b", "", signature[:match.start()])
    return prefix + name + "(" + arguments + ")" + signature[closing + 1:].rstrip("; \n") + ";"


def _constant(ast, name):
    nodes = [node for node in _walk(ast) if node.get("kind") == "EnumConstantDecl" and node.get("name") == name]
    if len(nodes) != 1:
        raise BuildAnalysisError("clang_type_compatibility_result_missing")
    constants = [node.get("value") for node in _walk(nodes[0]) if node.get("kind") == "ConstantExpr"]
    if len(constants) != 1 or constants[0] not in {"0", "1"}:
        raise BuildAnalysisError("clang_type_compatibility_result_unresolved")
    return constants[0] == "1"


def _llvm_signature(ir, symbol):
    escaped = re.escape(symbol)
    definitions = [line.strip() for line in ir.splitlines()
                   if re.match(r"^define\s+.*@(?:" + escaped + r'|"' + escaped + r'")\(', line)]
    if len(definitions) != 1:
        raise BuildAnalysisError("llvm_type_lowering_function_unresolved")
    triple = re.search(r'^target triple = "([^"]+)"', ir, re.MULTILINE)
    layout = re.search(r'^target datalayout = "([^"]+)"', ir, re.MULTILINE)
    if not triple or not layout:
        raise BuildAnalysisError("llvm_type_lowering_target_unresolved")
    # Whole function lowering is intentional: one C parameter may lower to
    # several LLVM parameters, so positional opaque ptr matching is unsound.
    return {"symbol": symbol, "definition": definitions[0], "target_triple": triple[1],
            "data_layout": layout[1], "ir_sha256": hashlib.sha256(ir.encode()).hexdigest(),
            "source_type_equivalence_authority": False}


def _ast_semantics(value):
    """Compare original TU meaning with inclusion-context probes.

    AST heap addresses, printed locations and unevaluated probe references are
    incidental.  Types, declarations, attributes, values and bodies remain.
    In particular __INCLUDE_LEVEL__/__BASE_FILE__ cannot change the original
    declaration or body while its probe receives an identity certificate.
    """
    incidental = {"id", "loc", "range", "previousDecl", "typeAliasDeclId", "parentDeclContextId",
                  "isUsed", "isReferenced", "nonOdrUseReason"}
    if isinstance(value, dict):
        return {key: _ast_semantics(item) for key, item in value.items() if key not in incidental}
    if isinstance(value, list):
        return [_ast_semantics(item) for item in value]
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]+", value):
        return "<clang-address>"
    return value


def replay_type_identity(context, record, symbol, *, parameter=None, source_type=None, retain_definition=False):
    """Produce facts from the selected trusted frontend; saved labels are unused."""
    unit = next((unit for unit in context["translation_units"] if unit["tu_id"] == symbol["tu_id"]), None)
    if unit is None:
        raise BuildAnalysisError("type_identity_translation_unit_unresolved")
    parameters = record.get("parameters", [])
    if parameter is not None:
        if isinstance(parameter, str):
            matches = [index for index, row in enumerate(parameters) if row.get("name") == parameter]
            if len(matches) != 1:
                raise BuildAnalysisError("type_identity_parameter_unresolved")
            parameter = matches[0]
        if type(parameter) is not int or not 0 <= parameter < len(parameters):
            raise BuildAnalysisError("type_identity_parameter_unresolved")
    if source_type is not None:
        if parameter is None or not isinstance(source_type, str) or not source_type.strip():
            raise BuildAnalysisError("invalid_type_identity_source_type")
        if len(source_type) > 1024 or any(character in source_type for character in ";{}#\n\r"):
            raise BuildAnalysisError("invalid_type_identity_source_type")
    stem = "__hg_type_identity_" + digest({"id": record["id"], "parameter": parameter, "type": source_type})[:16]
    actual, expected, candidate = stem + "_actual", stem + "_expected", stem + "_candidate"
    source = Path(context["project_root"]) / unit["source"]
    language = "c++" if source.suffix in {".cc", ".cpp", ".cxx"} else "c"
    is_same = (lambda left, right: "__is_same(" + left + ", " + right + ")") if language == "c++" else (
        lambda left, right: "__builtin_types_compatible_p(" + left + ", " + right + ")")
    probe = "#include " + json.dumps(str(source)) + "\n" + _source_declaration(record, expected) + "\n"
    probe += "typedef __typeof__(" + record["name"] + ") " + actual + ";\n"
    probe += "typedef __typeof__(" + expected + ") " + expected + "_type;\n"
    probe += "enum { " + stem + "_source_equal = " + is_same(actual, expected + "_type") + " };\n"
    if source_type is not None:
        probe += _source_declaration(record, candidate, parameter, source_type) + "\n"
        probe += "typedef __typeof__(" + candidate + ") " + candidate + "_type;\n"
        probe += "enum { " + stem + "_candidate_equal = " + is_same(actual, candidate + "_type") + " };\n"
    if retain_definition:
        # An unused/fully inlined static helper may not otherwise receive an
        # LLVM definition.  Retain its actual address for this type-only probe;
        # it neither adds a public symbol nor changes original body semantics.
        probe += "static __typeof__(&" + record["name"] + ") " + stem + "_address __attribute__((used)) = &" + record["name"] + ";\n"
    budget = AnalysisBudget(**context["budget"])
    arguments = [context["compiler"]["path"], *unit["arguments"], "-x", language, "-"]
    ast_arguments = [*arguments, "-fsyntax-only", "-Xclang", "-ast-dump=json"]
    code, text, diagnostics = _run(ast_arguments, unit["directory"], budget, budget.max_ast_bytes,
                                  compact_json=True, input_bytes=probe.encode())
    facts = {"policy_version": TYPE_IDENTITY_VERSION, "function_id": record["id"], "tu_id": unit["tu_id"],
             "symbol_id": symbol["symbol_id"], "parameter": parameter, "source_type": source_type,
             "source_signature": record["signature"], "probe_sha256": hashlib.sha256(probe.encode()).hexdigest(),
             "definition_retained_for_lowering": retain_definition,
             "verified": False, "status": "unknown", "reason": "clang_type_probe_failed",
             "proof_basis": "clang_same_translation_unit_type_compatibility",
             "execution_accounting": {"model_calls": 0, "provider_requests": 0, "clang_subprocess_calls": 1},
             "clang_invocations": [{"stage": "type_identity_ast", "arguments": ast_arguments,
                                     "stdin_sha256": hashlib.sha256(probe.encode()).hexdigest(), "returncode": code}]}
    if code:
        facts["diagnostics"] = diagnostics[:2048]
        return facts
    ast = json.loads(text)
    original_arguments = [context["compiler"]["path"], *unit["arguments"], str(source),
                          "-fsyntax-only", "-Xclang", "-ast-dump=json"]
    code, original_text, diagnostics = _run(original_arguments, unit["directory"], budget,
                                            budget.max_ast_bytes, compact_json=True)
    facts["execution_accounting"]["clang_subprocess_calls"] += 1
    facts["clang_invocations"].append({"stage": "type_identity_original_ast", "arguments": original_arguments,
                                      "returncode": code})
    if code:
        facts.update(reason="original_translation_unit_replay_failed", diagnostics=diagnostics[:2048])
        return facts
    original_ast = json.loads(original_text)
    original_nodes = original_ast.get("inner", [])
    # Probe declarations are appended after the original TU.  Checking the
    # entire original prefix also catches context-dependent typedef/layout
    # changes that canonical spelling alone would miss.
    probe_nodes = ast.get("inner", [])[:len(original_nodes)]
    facts["original_ast_semantics_digest"] = digest(_ast_semantics(original_nodes))
    facts["probe_original_ast_semantics_digest"] = digest(_ast_semantics(probe_nodes))
    facts["translation_unit_context_verified"] = facts["original_ast_semantics_digest"] == facts["probe_original_ast_semantics_digest"]
    if not facts["translation_unit_context_verified"]:
        facts.update(reason="type_probe_translation_unit_context_mismatch")
        return facts
    aliases = {node["name"]: node for node in _walk(ast)
               if node.get("kind") == "TypedefDecl" and node.get("name") in {actual, expected + "_type", candidate + "_type"}}
    declarations = _declarations(ast, Path(context["project_root"]))
    actual_type, expected_type = _function_type(aliases[actual]), _function_type(aliases[expected + "_type"])
    source_equal = _constant(ast, stem + "_source_equal")
    candidate_equal = _constant(ast, stem + "_candidate_equal") if source_type is not None else True
    facts.update(source_signature_verified=source_equal, candidate_type_compatible=candidate_equal,
                 canonical_identity=_canonical_identity(actual_type, declarations, unit["tu_id"]),
                 source_canonical_identity=_canonical_identity(expected_type, declarations, unit["tu_id"]),
                 typedef_chain=_typedef_chain(actual_type, declarations, unit["tu_id"]))
    children = _type_children(actual_type)
    if len(children) != len(parameters) + 1:
        facts.update(reason="clang_type_parameter_arity_unresolved")
        return facts
    facts["parameters"] = [{"index": index, "name": raw.get("name"), "source_type": raw.get("type"),
                           "canonical_type": child.get("type", {}).get("qualType", ""),
                           "canonical_identity": _canonical_identity(child, declarations, unit["tu_id"]),
                           "typedef_chain": _typedef_chain(child, declarations, unit["tu_id"])}
                          for index, (raw, child) in enumerate(zip(parameters, children[1:]))]
    facts["return"] = {"source_type": record.get("return_type"),
                       "canonical_identity": _canonical_identity(children[0], declarations, unit["tu_id"]),
                       "typedef_chain": _typedef_chain(children[0], declarations, unit["tu_id"])}
    if source_type is not None:
        candidate_type = _function_type(aliases[candidate + "_type"])
        candidate_parameter = _type_children(candidate_type)[parameter + 1]
        facts["candidate_canonical_identity"] = _canonical_identity(candidate_parameter, declarations, unit["tu_id"])
        facts["candidate_typedef_chain"] = _typedef_chain(candidate_parameter, declarations, unit["tu_id"])
    llvm_arguments = [*arguments, "-S", "-emit-llvm", "-o", "-"]
    code, ir, diagnostics = _run(llvm_arguments, unit["directory"], budget, budget.max_ast_bytes, input_bytes=probe.encode())
    facts["execution_accounting"]["clang_subprocess_calls"] += 1
    facts["clang_invocations"].append({"stage": "type_identity_llvm", "arguments": llvm_arguments,
                                      "stdin_sha256": facts["probe_sha256"], "returncode": code})
    if code:
        facts.update(reason="llvm_type_lowering_failed", diagnostics=diagnostics[:2048])
        return facts
    facts["llvm_type"] = {"tu_id": unit["tu_id"], **_llvm_signature(ir, symbol["symbol_identity"])}
    facts.update(verified=source_equal and candidate_equal,
                 status="verified" if source_equal and candidate_equal else "incompatible",
                 reason="clang_source_canonical_llvm_type_identity" if source_equal and candidate_equal else
                        "source_signature_type_mismatch" if not source_equal else "candidate_type_incompatible")
    return facts
