"""Conservative entry rejection predicates, without API-name heuristics."""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
import re
import shutil
from typing import Mapping

UNKNOWN = object()


def _walk(node):
    yield node
    for child in node.named_children:
        yield from _walk(child)


def _span(node):
    return {"start_byte": node.start_byte, "end_byte": node.end_byte,
            "start_line": node.start_point.row + 1, "start_column": node.start_point.column + 1,
            "end_line": node.end_point.row + 1, "end_column": node.end_point.column + 1}


def _returns(node):
    if node.type == "return_statement":
        return True
    if node.type == "compound_statement":
        children = [child for child in node.named_children if child.type != "comment"]
        # Do not infer termination through loops, goto, or preprocessor branches.
        if any(child.type not in {"return_statement", "expression_statement", "if_statement",
                                  "compound_statement", "declaration", "comment"} for child in children):
            return False
        return bool(children) and _returns(children[-1])
    if node.type == "if_statement":
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")
        return consequence is not None and alternative is not None and _returns(consequence) and _returns(alternative)
    return False


def _constant(node, source, arguments, null_macro_is_zero):
    if node is None:
        return UNKNOWN
    spelling = source[node.start_byte:node.end_byte].decode("utf-8")
    if node.type in {"parenthesized_expression", "condition_clause"}:
        children = node.named_children
        return _constant(children[0], source, arguments, null_macro_is_zero) if len(children) == 1 else UNKNOWN
    if node.type in {"identifier", "null"}:
        value = arguments.get(spelling, UNKNOWN)
        if spelling == "NULL" and null_macro_is_zero:
            return 0
        if value is None:
            return 0
        # A non-null symbolic object or caller expression is not a known integer.
        # Integer argument conversion is build/ABI dependent. In particular,
        # Python -1 must not be used as a C unsigned argument value.
        return UNKNOWN
    if node.type == "number_literal":
        try:
            return 0 if spelling == "0" else UNKNOWN
        except ValueError:
            return UNKNOWN
    if node.type == "unary_expression":
        operator = node.child_by_field_name("operator")
        argument = node.child_by_field_name("argument")
        if operator is not None and source[operator.start_byte:operator.end_byte] == b"!":
            value = _constant(argument, source, arguments, null_macro_is_zero)
            return not value if value is not UNKNOWN else UNKNOWN
        return UNKNOWN
    if node.type != "binary_expression":
        return UNKNOWN
    operator_node = node.child_by_field_name("operator")
    if operator_node is None:
        return UNKNOWN
    operator = source[operator_node.start_byte:operator_node.end_byte].decode()
    left = _constant(node.child_by_field_name("left"), source, arguments, null_macro_is_zero)
    if operator == "||" and left is not UNKNOWN and bool(left):
        return True
    if operator == "&&" and left is not UNKNOWN and not bool(left):
        return False
    right = _constant(node.child_by_field_name("right"), source, arguments, null_macro_is_zero)
    if operator == "||":
        if left is not UNKNOWN and right is not UNKNOWN and bool(right):
            return True
        return UNKNOWN if left is UNKNOWN or right is UNKNOWN else bool(left or right)
    if operator == "&&":
        if left is not UNKNOWN and right is not UNKNOWN and not bool(right):
            return False
        return UNKNOWN if left is UNKNOWN or right is UNKNOWN else bool(left and right)
    if left is UNKNOWN or right is UNKNOWN:
        return UNKNOWN
    operations = {"==": lambda: left == right, "!=": lambda: left != right}
    return operations[operator]() if operator in operations else UNKNOWN


def _nonprocessing_branch(node, source, arguments, null_macro_is_zero, forbidden_parameter_reads=()):
    """Ignore only independently constant-false branches; reject input reads."""
    if node.type == "if_statement":
        condition = node.child_by_field_name("condition")
        value = _constant(condition, source, arguments, null_macro_is_zero)
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")
        if value is not UNKNOWN:
            selected = consequence if bool(value) else alternative
            return selected is None or _nonprocessing_branch(selected, source, arguments, null_macro_is_zero, forbidden_parameter_reads)
    if node.type == "identifier" and source[node.start_byte:node.end_byte].decode() in forbidden_parameter_reads:
        return False
    if node.type in {"call_expression", "subscript_expression", "field_expression",
                     "goto_statement", "while_statement", "for_statement", "do_statement"}:
        return False
    if node.type == "pointer_expression" and source[node.start_byte:node.end_byte].lstrip().startswith(b"*"):
        return False
    return all(_nonprocessing_branch(child, source, arguments, null_macro_is_zero, forbidden_parameter_reads) for child in node.named_children)


def inspect_entry_rejection(source: str, function_name: str, arguments: Mapping[str, object], *,
                            null_macro_is_zero: bool = False, forbidden_parameter_reads=()) -> dict:
    """Prove a known call hits a supported leading unconditional-return guard.

    ``source`` is a complete C function definition or a translation unit.
    ``arguments`` maps source parameter names to known null (None).
    Integer values and other expressions remain unknown. The caller must independently validate
    the build/source identity and NULL expansion before setting the optional
    ``null_macro_is_zero`` flag. This does not prove any object lifecycle.
    """
    import tree_sitter
    import tree_sitter_c

    raw = source.encode("utf-8")
    parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_c.language()))
    tree = parser.parse(raw)
    candidates = []
    for node in _walk(tree.root_node):
        if node.type != "function_definition":
            continue
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            continue
        for nested in _walk(declarator):
            if nested.type == "function_declarator":
                name = nested.child_by_field_name("declarator")
                if name is not None and raw[name.start_byte:name.end_byte].decode() == function_name:
                    candidates.append(node)
                break
    result = {"schema_version": 1, "status": "unsupported", "function_name": function_name,
              "source_sha256": hashlib.sha256(raw).hexdigest(), "guards": [],
              "proof_scope": "known constant call reaches a source entry rejection; no lifecycle authority",
              "rejection_authority": "none_without_authenticated_build_wrapper",
              "null_macro_is_zero": null_macro_is_zero}
    if len(candidates) != 1 or candidates[0].has_error:
        result["reason"] = "function_definition_unresolved_or_parse_error"
        return result
    if re.search(r"^\s*#\s*define\s+NULL\b", source, re.MULTILINE):
        null_macro_is_zero = False
    body = candidates[0].child_by_field_name("body")
    children = [node for node in body.named_children if node.type != "comment"]
    uncertain_before = False
    for statement in children:
        if statement.type != "if_statement" or statement.child_by_field_name("alternative") is not None:
            break
        consequence = statement.child_by_field_name("consequence")
        condition = statement.child_by_field_name("condition")
        if consequence is None or not _returns(consequence):
            break
        value = _constant(condition, raw, arguments, null_macro_is_zero)
        if value is not UNKNOWN and bool(value) and not _nonprocessing_branch(consequence, raw, arguments,
                null_macro_is_zero, forbidden_parameter_reads):
            break
        guard = {"condition": raw[condition.start_byte:condition.end_byte].decode(),
                 "condition_span": _span(condition), "statement_span": _span(statement),
                 "return_spans": [_span(node) for node in _walk(consequence) if node.type == "return_statement"],
                 "constant_result": None if value is UNKNOWN else bool(value)}
        result["guards"].append(guard)
        # If an earlier condition is unknown, even reaching this guard is not
        # proved, and its condition may invoke unsupported effects.
        if value is not UNKNOWN and bool(value) and not uncertain_before:
            result.update(status="rejected", matched_guard=guard,
                          reason="known_arguments_hit_unconditional_entry_return")
            return result
        if value is UNKNOWN:
            uncertain_before = True
    result.update(status="not_proved" if result["guards"] else "unsupported",
                  reason="entry_predicate_not_constant" if result["guards"] else "no_supported_leading_rejection_guard")
    return result


ENTRY_STATE_POLICY = "source-build-bound-entry-state-v1"
_CONSTANT_MACRO_AST = {"IntegerLiteral", "ParenExpr", "CStyleCastExpr", "ImplicitCastExpr",
                       "ConstantExpr", "GNUNullExpr", "CXXNullPtrLiteralExpr"}


def _effect_free_macro_node(node):
    # C enum members are compile-time constants. A self-aliasing macro may
    # legitimately expand to one; globals/parameters with identical spelling
    # must retain unknown authority. Clang's bound declaration kind decides.
    if node["ast_kind"] == "DeclRefExpr":
        return node.get("referenced_kind") == "EnumConstantDecl" and bool(node.get("referenced_name"))
    return node["ast_kind"] in _CONSTANT_MACRO_AST and not node.get("referenced_name")


def _ast_walk(node):
    yield node
    for child in node.get("inner", []):
        yield from _ast_walk(child)


def _replay_macro_tokens(function, carrier, expected_compiler, tokens):
    """Use complete expansion subtrees, excluding boundary-sharing ancestors."""
    from ..source_analysis.analyzer import AnalysisBudget, _run
    from ..semantic_discovery.models import digest
    selected = shutil.which("clang")
    if not selected:
        raise ValueError("selected_clang_unavailable")
    compiler = Path(selected).resolve()
    if hashlib.sha256(compiler.read_bytes()).hexdigest() != expected_compiler:
        raise ValueError("selected_clang_identity_mismatch")
    units = [unit for unit in carrier["translation_units"] if unit["source"] == function["file"]]
    if not units:
        raise ValueError("target_translation_unit_unresolved")
    budget = AnalysisBudget(max_ast_bytes=8 * 1024 * 1024, max_ast_stream_bytes=64 * 1024 * 1024)
    witnesses, executions = [], []
    for unit in units:
        source = Path(carrier["project_root"]) / unit["source"]
        command = [str(compiler), *unit["arguments"], "-fsyntax-only", "-Xclang", "-ast-dump=json",
                   "-Xclang", "-ast-dump-filter=" + function["name"], str(source)]
        code, text, _ = _run(command, unit["directory"], budget, budget.max_ast_bytes, compact_json=True)
        if code:
            raise ValueError("entry_macro_clang_replay_failed")
        cursor, decoder, definitions = 0, json.JSONDecoder(), []
        while cursor < len(text):
            while cursor < len(text) and text[cursor].isspace():
                cursor += 1
            if cursor >= len(text):
                break
            node, cursor = decoder.raw_decode(text, cursor)
            if node.get("kind") == "FunctionDecl" and node.get("name") == function["name"] and any(
                    child.get("kind") == "CompoundStmt" for child in node.get("inner", [])):
                location = node.get("loc", {}).get("expansionLoc", node.get("loc", {}))
                if function["start_line"] <= location.get("line", 0) <= function["end_line"]:
                    definitions.append(node)
        if len(definitions) != 1:
            raise ValueError("entry_macro_target_ast_not_unique")
        nodes = []
        for part in _ast_walk(definitions[0]):
            boundaries = part.get("range", {})
            begin = boundaries.get("begin", {}).get("expansionLoc", {})
            end = boundaries.get("end", {}).get("expansionLoc", {})
            # An outer p==NULL BinaryOperator has only one expanded boundary.
            # It must not be mistaken for arithmetic inside the NULL macro.
            if begin.get("offset") == end.get("offset") and begin.get("offset") in tokens:
                nodes.append({"name": tokens[begin["offset"]], "offset": begin["offset"],
                    "ast_kind": part.get("kind"), "value": part.get("value"), "opcode": part.get("opcode"),
                    "cast_kind": part.get("castKind"), "referenced_name": part.get("referencedDecl", {}).get("name"),
                    "referenced_kind": part.get("referencedDecl", {}).get("kind")})
        executions.append({"source": unit["source"], "macro_digest": unit["macro_digest"],
                           "command": command, "macro_nodes_digest": digest(nodes)})
        witnesses.append(nodes)
    return {"translation_unit_replays": executions, "macro_nodes_by_translation_unit": witnesses}


def _file_span(span, prefix_bytes, body_start, raw):
    first, last = span["start_byte"] - prefix_bytes + body_start, span["end_byte"] - prefix_bytes + body_start
    def point(offset):
        prefix = raw[:offset]
        return prefix.count(b"\n") + 1, offset - prefix.rfind(b"\n")
    start_line, start_column = point(first)
    end_line, end_column = point(last)
    return {"start_byte": first, "end_byte": last, "start_line": start_line, "start_column": start_column,
            "end_line": end_line, "end_column": end_column}


def inspect_resource_entry_state(snapshot, function_id, arguments, build_analysis, *, evidence_ids=()):
    """Candidate admission authority for a null resource's exact CORE call.

    Only a live authenticated BuildAwareIndex can certify source/macros/types.
    The caller supplies complete authenticated source evidence IDs. This rule
    proves ENTRY_REJECTED for selected null bindings, never CREATED/RELEASED,
    non-null validity, full lifecycle, or formal semantic closure.
    """
    result = {"schema_version": 1, "policy_version": ENTRY_STATE_POLICY,
        "status": "unknown", "function_id": function_id, "resource_state": "unknown",
        "rejection_authority": "none", "evidence_ids": sorted(set(evidence_ids)),
        "preconditions": [], "guards": [], "proof_scope": "selected null invocation's non-processing source entry return only"}
    try:
        from ..source_analysis.clang_index import BuildAwareIndex
        if not isinstance(build_analysis, BuildAwareIndex):
            result["reason"] = "authenticated_build_index_required"
            return result
        build_analysis.validate_snapshot(snapshot)
        build = build_analysis.public_projection()
        function = snapshot.functions.get(function_id, {})
        abi = build_analysis.verify_function(function_id)
        semantics = build_analysis.verify_source_semantics(function_id)
        if not evidence_ids or not function.get("defined") or not function.get("body"):
            result["reason"] = "complete_authenticated_source_evidence_required"
            return result
        if abi.get("verified") is not True or abi.get("status") != "callable" or semantics.get("verified") is not True:
            result["reason"] = "target_build_abi_unverified"
            return result
        result["build_identity"] = {key: deepcopy(build[key]) for key in
            ("source_fingerprint", "functions_fingerprint", "configuration_digest", "analysis_digest",
             "dependency_digest", "compiler_digest")}
        result["clang_evidence_ids"] = [abi["evidence_id"], semantics["evidence_id"]]
        parameters = {parameter["name"]: parameter["canonical_type"] for parameter in abi["parameters"]}
        known_null = {name: None for name, expression in arguments.items()
            if expression.get("kind") == "null" and "*" in parameters.get(name, "") and "(" not in parameters.get(name, "")}
        result["known_null_parameters"] = sorted(known_null)
        result["argument_types"] = parameters
        if not known_null:
            result["reason"] = "no_known_null_resource_binding"
            return result
        carrier = build_analysis.carrier_build_projection()
        root = Path(carrier["project_root"]).resolve()
        source_path = (root / function["file"]).resolve()
        if not source_path.is_relative_to(root):
            result["reason"] = "source_path_outside_authenticated_project"
            return result
        raw = source_path.read_bytes()
        source_hash = hashlib.sha256(raw).hexdigest()
        if carrier["dependency_hashes"].get(str(source_path)) != source_hash or snapshot.artifacts.source_hashes.get(function["file"]) != source_hash:
            result["reason"] = "source_hash_not_bound_to_current_build"
            return result
        body = function["body"].encode()
        lines = raw.splitlines(keepends=True)
        first = sum(map(len, lines[:function["start_line"] - 1]))
        last = sum(map(len, lines[:function["end_line"]]))
        body_start = raw.find(body, first, last)
        if body_start < 0 or raw.find(body, body_start + 1, last) >= 0:
            result["reason"] = "source_body_identity_unresolved"
            return result
        # The carrier only supplies neutral grammar; all facts come from the
        # exact live body and verified canonical pointer parameters above.
        prefix = "int __hg_entry__(void) "
        neutral = prefix + function["body"]
        proof = inspect_entry_rejection(neutral, "__hg_entry__", known_null, null_macro_is_zero=True,
            forbidden_parameter_reads=set(parameters) - set(known_null))
        result.update(source_file=function["file"], source_sha256=source_hash, source_body_sha256=hashlib.sha256(body).hexdigest())
        for guard in proof["guards"]:
            converted = deepcopy(guard)
            for key in ("condition_span", "statement_span"):
                converted[key] = _file_span(guard[key], len(prefix.encode()), body_start, raw)
            converted["return_spans"] = [_file_span(span, len(prefix.encode()), body_start, raw) for span in guard["return_spans"]]
            result["guards"].append(converted)
        if proof["status"] != "rejected":
            result.update(status="not_proved", reason=proof["reason"])
            return result
        selected = result["guards"][:len(proof["guards"])]
        expansions = semantics.get("body_macro_expansions", [])
        macros = semantics.get("macros", {})
        macro_witnesses, tokens = [], {}
        # Validate every macro token in the guards used by this proof, including
        # macro-valued returns. Final -dM text alone is insufficient: a token
        # may have been redefined at the use site and undefined afterwards.
        for guard in selected:
            span = guard["statement_span"]
            piece = raw[span["start_byte"]:span["end_byte"]]
            for match in re.finditer(rb"\b[A-Za-z_][A-Za-z0-9_]*\b", piece):
                name, offset = match[0].decode(), span["start_byte"] + match.start()
                observations = [row for row in expansions if row.get("name") == name and row.get("offset") == offset]
                defined = any(name in definitions for definitions in macros.values())
                if name == "NULL" or observations or defined:
                    if not observations:
                        result["reason"] = "guard_macro_expansion_not_effect_free_constant:" + name
                        return result
                    # Non-null numeric macro values in comparisons are not
                    # interpreted by the raw-source rule. At return sites they
                    # only witness an effect-free terminating expression.
                    macro_witnesses.extend(deepcopy(observations))
                    tokens[offset] = name
        if tokens:
            replay = _replay_macro_tokens(function, carrier, build["compiler_digest"], tokens)
            result["macro_replay"] = replay
            for nodes in replay["macro_nodes_by_translation_unit"]:
                for offset, name in tokens.items():
                    observations = [row for row in nodes if row["offset"] == offset and row["name"] == name]
                    if not observations or any(not _effect_free_macro_node(row) for row in observations):
                        result["reason"] = "guard_macro_expansion_not_effect_free_constant:" + name
                        return result
                    if name == "NULL" and (not any(row.get("ast_kind") == "IntegerLiteral" and row.get("value") == "0" for row in observations)
                            or any(row.get("value") not in {None, "0"} for row in observations)):
                        result["reason"] = "null_macro_not_zero_at_guard_use"
                        return result
        result["macro_witnesses"] = macro_witnesses
        build_analysis.validate_snapshot(snapshot)
        if build_analysis.public_projection() != build:
            result["reason"] = "build_identity_changed_during_entry_check"
            return result
        matched = result["guards"][-1]
        bound = [name for name in sorted(known_null) if re.search(r"\b" + re.escape(name) + r"\b", matched["condition"])]
        result["preconditions"] = [{"kind": "entry_rejection_predicate_false", "parameters": bound,
            "canonical_types": {name: parameters[name] for name in bound}, "source_condition": matched["condition"],
            "source_span": matched["condition_span"], "applicability": "this selected invocation",
            "observed_bindings": {name: "null" for name in bound}, "satisfied": False}]
        result.update(status="rejected", reason="known_null_resource_hits_nonprocessing_entry_return",
            resource_state="ENTRY_REJECTED", rejection_authority="candidate_admission_only")
        return result
    except (ValueError, TypeError, KeyError, AttributeError, OSError, ImportError):
        result.update(status="unknown", reason="source_compiler_or_macro_identity_unverified", rejection_authority="none")
        return result
