"""Plan-scoped syntax, ABI, call-site and order checks, without ProtocolIR."""
import re
from collections import Counter

from ..harness_context.evidence import callback_abis
from ..semantic_discovery.tools import _walk, _text

MEMORY_HELPERS = {"malloc", "calloc", "realloc", "free", "memcpy", "memmove", "memset", "memcmp",
                  "strlen", "strnlen", "strcmp", "strncmp"}
HEADERS = {"stddef.h", "stdint.h", "stdlib.h", "string.h", "limits.h", "stdbool.h", "stddef", "cstddef", "cstdint", "cstdlib", "cstring"}
CODE_VALIDATOR_VERSION = "frozen_plan_code_v3"


def _known_guards(code, language):
    """Resolve only the known C/C++ linkage guard before syntax inspection.

    Tree-sitter cannot parse an extern block split across #ifdef directives;
    arbitrary feature macros remain unsupported rather than guessed.
    """
    stack, enabled, lines, errors = [], True, [], []
    for line in code.splitlines(keepends=True):
        directive = re.match(r'^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)', line)
        if not directive:
            lines.append(line if enabled else "\n" if line.endswith("\n") else "")
            continue
        kind, condition = directive.groups()
        condition = re.sub(r'/\*.*?\*/|//.*', '', condition).strip()
        if kind in {"if", "ifdef", "ifndef"}:
            known = condition == "__cplusplus" if kind != "if" else bool(re.fullmatch(r'defined\s*(?:\(\s*__cplusplus\s*\)|\s+__cplusplus)', condition))
            if not known:
                errors.append("unsupported_preprocessor_condition")
            selected = language == "c++"
            if kind == "ifndef":
                selected = not selected
            stack.append([enabled, selected, False])
            enabled = enabled and selected
        elif kind == "else" and stack and not stack[-1][2]:
            stack[-1][2] = True
            enabled = stack[-1][0] and not stack[-1][1]
        elif kind == "endif" and stack:
            enabled = stack.pop()[0]
        else:
            errors.append("unsupported_preprocessor_condition")
        lines.append("\n" if line.endswith("\n") else "")
    if stack:
        errors.append("unterminated_preprocessor_condition")
    return "".join(lines), errors


def _name(node, source):
    if node is None:
        return ""
    if node.type in {"identifier", "field_identifier", "qualified_identifier"}:
        return _text(node, source).removeprefix("::")
    return _name(node.child_by_field_name("declarator"), source) or next(
        (_name(child, source) for child in node.named_children if _name(child, source)), "")


def _abi(declaration):
    declaration = re.sub(r'\bextern\s*(?:"C"\s*)?', '', declaration).replace("std::", "")
    declaration = re.sub(r'\b(?:static|inline)\s+', '', declaration)
    return callback_abis(declaration)


def validate_code(code, plan):
    from tree_sitter import Parser, Language
    import tree_sitter_c, tree_sitter_cpp
    filtered, errors = _known_guards(code, plan["language"])
    source = filtered.encode()
    module = tree_sitter_cpp if plan["language"] == "c++" else tree_sitter_c
    root = Parser(Language(module.language())).parse(source).root_node
    if root.has_error:
        errors.append("syntax_error")
    includes = re.findall(r'^\s*#\s*include\s*[<"]([^>"\n]+)[>"]', code, re.MULTILINE)
    if any(header not in HEADERS | set(plan["headers"]) for header in includes):
        errors.append("include_outside_plan")
    if re.search(r'^\s*#\s*(?:define|include_next|import|pragma)\b', code, re.MULTILINE):
        errors.append("unsupported_preprocessor_directive")
    functions = list(node for node in _walk(root) if node.type == "function_definition")
    entries = [node for node in functions if _name(node.child_by_field_name("declarator"), source) == plan["entrypoint"]]
    if len(entries) != 1:
        return {"status": "invalid", "errors": errors + ["exactly_one_fuzzer_entry_required"]}
    entry = entries[0]
    entry_decl = entry.child_by_field_name("declarator")
    entry_signature = source[entry.start_byte:entry.child_by_field_name("body").start_byte].decode()
    valid_entries = _abi("int LLVMFuzzerTestOneInput(const uint8_t *, size_t);") | _abi("int LLVMFuzzerTestOneInput(const unsigned char *, size_t);")
    if not _abi(entry_signature) or not _abi(entry_signature) <= valid_entries:
        errors.append("invalid_fuzzer_entry_abi")
    parameters = entry_decl.child_by_field_name("parameters")
    if parameters is None or len([n for n in parameters.named_children if n.type == "parameter_declaration"]) != 2:
        errors.append("invalid_fuzzer_entry_arity")
    expected_apis = {row["symbol"]: row for row in plan["api_declarations"]}
    expected_callbacks = set().union(*(_abi(row["signature"]) for row in plan["contracts"]["callback_contract"]["callbacks"] if row["signature"]))
    helper_names = set()
    for function in functions:
        name = _name(function.child_by_field_name("declarator"), source)
        if function == entry:
            continue
        body = function.child_by_field_name("body")
        signature = source[function.start_byte:body.start_byte].decode()
        if name in expected_apis or not expected_callbacks or not _abi(signature) <= expected_callbacks or not _abi(signature):
            errors.append("function_definition_outside_plan")
        else:
            helper_names.add(name)
    declared = set()
    for node in _walk(root):
        if node.type != "declaration":
            continue
        declarator = node.child_by_field_name("declarator")
        if declarator is None or not any(child.type == "function_declarator" for child in _walk(declarator)):
            continue
        name = _name(declarator, source)
        if name in expected_apis:
            declared.add(name)
            if _abi(_text(node, source)) != _abi(expected_apis[name]["signature"]):
                errors.append("api_declaration_abi_mismatch")
    if not plan["headers"] and set(expected_apis) - declared:
        errors.append("api_declarations_missing")
    callback_fields = set()
    for declaration in plan["type_declarations"]:
        field_pattern = r'\(\s*\*\s*(\w+)\s*\)'
        callback_fields.update(re.findall(field_pattern, declaration))
    calls, positions = Counter(), {}
    for node in _walk(root):
        if node.type != "call_expression":
            continue
        callee = node.child_by_field_name("function")
        name = _text(callee, source).removeprefix("std::").removeprefix("::") if callee else ""
        if callee and callee.type == "field_expression":
            field = callee.child_by_field_name("field")
            if field and _text(field, source) in callback_fields:
                continue
        if name in expected_apis:
            if not entry.start_byte < node.start_byte < entry.end_byte:
                errors.append("project_api_outside_fuzzer_entry")
            else:
                calls[name] += 1
                positions.setdefault(name, []).append(node.start_byte)
                ancestor = node.parent
                while ancestor != entry and ancestor is not None:
                    if ancestor.type in {"for_statement", "while_statement", "do_statement"}:
                        errors.append("project_call_loop_not_in_plan")
                    ancestor = ancestor.parent
                args = node.child_by_field_name("arguments")
                if args is None or len(args.named_children) != len(expected_apis[name]["parameters"]):
                    errors.append("api_call_arity_mismatch")
        elif name not in MEMORY_HELPERS | helper_names:
            errors.append("call_outside_plan")
    expected_calls = Counter(row["symbol"] for row in plan["call_sequence"] + plan["cleanup_sequence"])
    if calls != expected_calls:
        errors.append("required_invocation_count_mismatch")
    names = {row["function_id"]: row["symbol"] for row in plan["api_declarations"]}
    for before, after in plan["ordering_edges"]:
        if positions.get(names[before]) and positions.get(names[after]) and max(positions[names[before]]) >= min(positions[names[after]]):
            errors.append("required_call_order_violated")
    from .recipe_validation import validate_recipe_bindings
    errors += validate_recipe_bindings(entry,source,plan)
    return {"status": "invalid" if errors else "valid", "errors": sorted(set(errors)),
            "observed_calls": dict(sorted(calls.items())), "validator": CODE_VALIDATOR_VERSION}
