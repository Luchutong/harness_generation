"""Uncertain effects cannot certify an unrelated returned-object consumer.

These questions neither prove cleanup nor select a role. Only complete issued
bodies and the existing bounded source interpreter participate; no source is
read, authorized or charged while constructing this diagnostic projection.
"""
from copy import deepcopy

from ..semantic_discovery.models import DecisionSchemaError, digest
from .core_proofs import source_evidence

VERSION = "returned-resource-effect-questions-v1"


class SliceExclusionEffectError(DecisionSchemaError):
    terminal_extra_repair_allowed = False

    def __init__(self, index, received, questions):
        self.questions = deepcopy(questions)
        super().__init__(f"classification[{index}]", received,
            ["inspect the missing effect", "explicit UNRESOLVED with a missing-proof question"])

    def to_dict(self):
        return {**super().to_dict(), "error": "slice_exclusion_effect_unproven",
            "effect_questions": deepcopy(self.questions),
            "repair_instruction": "An uncertain effect on this exact returned-object type does not prove "
                "unrelated behavior. Investigate the source dependency or select the issued UNRESOLVED "
                "choice. SUPPORT still requires its own source effect and necessity decision."}


def returned_resource_questions(tools):
    from ..harness_context.proof_grounding import VERSION as SOURCE_INTERPRETER_VERSION
    identity = digest([VERSION, SOURCE_INTERPRETER_VERSION, sorted(tools.authorized_ids), tools.evidence])
    cached = getattr(tools, "_returned_resource_questions", None)
    if cached and cached[0] == identity:
        return deepcopy(cached[1])
    result = _questions(tools)
    tools._returned_resource_questions = identity, deepcopy(result)
    return result


def _questions(tools):
    from ..minimal_ft.models import ProjectSnapshot
    from ..harness_context.proof_grounding import analyze

    anchor = tools.frontier.candidate.function_id
    functions = tools.index.functions
    target = functions[anchor]
    if target.get("return_pointer_depth") != 1:
        return {}
    bodies = {fid: source_evidence(fid, functions, tools.evidence) for fid in tools.authorized_ids}
    bodies = {fid: ids for fid, ids in bodies.items() if ids}
    if anchor not in bodies:
        return {}
    snapshot = ProjectSnapshot.from_artifacts(tools.index.artifacts)
    result = {}
    for fid in sorted(bodies):
        if fid == anchor:
            continue
        function = functions[fid]
        parameters = [p for p in function["parameters"] if p.get("pointer_depth") == 1
            and p["base_type"] == target["return_base_type"]]
        for parameter in parameters:
            if not _forwards_pointer(function, parameter["name"]):
                continue
            summary = analyze(function, snapshot, bodies, _nonnull_parameters={parameter["name"]})
            if summary["paths"] and not any(p["uncertain"] for p in summary["paths"]):
                continue
            # A type match alone is insufficient. The complete body must leave
            # its source effect uncertain under the bounded transfer function.
            source_ids = sorted(set(summary["source_function_ids"]) & bodies.keys() | {anchor, fid})
            question = {"version": VERSION, "kind": "unresolved_return_resource_effect",
                "anchor_function_id": anchor, "function_id": fid,
                "subject_parameter": parameter["name"], "return_type": target["return_base_type"],
                "proof_status": "missing", "reason": "bounded_source_parameter_effect_uncertain",
                "source_function_ids": source_ids,
                "evidence_ids": sorted({eid for source in source_ids for eid in bodies[source]}),
                "next_query": {"tool": "find_callees", "arguments": {"function": fid}},
                "scope": "no cleanup, ownership, necessity or role is inferred"}
            question["question_id"] = "slice_effect_question_" + digest(question)[:24]
            result.setdefault(fid, []).append(question)
    return result


def _forwards_pointer(function, parameter):
    """Track possible pointer forwarding, including assignment and shadowing.

    This only withholds an unrelated choice; it never certifies an effect.
    Branch and loop joins retain possible flows rather than invent certainty.
    """
    from ..semantic_discovery.tools import _walk, _text
    from .core_proofs import tree

    source, body = tree(function)
    if body is None:
        return False
    found = False
    def alias(node, env):
        while node is not None and node.type in {"cast_expression", "parenthesized_expression"}:
            node = node.child_by_field_name("value") if node.type == "cast_expression" else node.named_children[0]
        if node is None:
            return False
        if node.type == "identifier":
            return env.get(_text(node, source), False)
        if node.type == "binary_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            operator = _text(node.child_by_field_name("operator"), source)
            return ((operator in {"+", "-"} and alias(left, env) and _text(right, source) == "0")
                or (operator == "+" and _text(left, source) == "0" and alias(right, env)))
        if node.type == "pointer_expression" and _text(node.child_by_field_name("operator"), source) == "&":
            argument = node.child_by_field_name("argument")
            return argument is not None and argument.type == "subscript_expression" and alias(
                argument.child_by_field_name("argument"), env) and _text(argument.child_by_field_name("index"), source) == "0"
        return False
    def forwarded(node, env):
        if alias(node, env):
            return True
        while node is not None and node.type in {"cast_expression", "parenthesized_expression"}:
            node = node.child_by_field_name("value") if node.type == "cast_expression" else node.named_children[0]
        if node is not None and node.type == "pointer_expression" and _text(
                node.child_by_field_name("operator"), source) == "&":
            argument = node.child_by_field_name("argument")
            # An unknown callee can affect the pointed-to object through its
            # cell/subobject address. A scalar field value alone is no flow.
            if alias(argument, env):
                return True
            if argument is not None and argument.type in {"field_expression", "subscript_expression"}:
                return alias(argument.child_by_field_name("argument"), env)
        return False
    def identifier(declarator):
        nodes = [n for n in _walk(declarator) if n.type == "identifier"]
        return _text(nodes[0], source) if nodes else None
    def join(left, right):
        return {name:left.get(name, False) or right.get(name, False) for name in left.keys() | right.keys()}
    def visit(node, env):
        nonlocal found
        if node is None:
            return env
        if node.type == "compound_statement":
            # Restore only locally declared names; outer assignments survive.
            original, local = dict(env), set()
            for child in node.named_children:
                if child.type == "declaration":
                    for declarator in child.children_by_field_name("declarator"):
                        name = identifier(declarator)
                        if name:
                            local.add(name)
                env = visit(child, env)
            for name in local:
                if name in original:
                    env[name] = original[name]
                else:
                    env.pop(name, None)
            return env
        if node.type == "declaration":
            for declarator in node.children_by_field_name("declarator"):
                name = identifier(declarator)
                value = declarator.child_by_field_name("value")
                env = visit(value, env)
                if name:
                    env[name] = alias(value, env)
            return env
        if node.type == "assignment_expression":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            env = visit(right, env)
            if left is not None and left.type == "identifier":
                # Compound assignment cannot establish exact pointer identity.
                operator = node.child_by_field_name("operator")
                env[_text(left, source)] = alias(right, env) if _text(operator, source) == "=" else False
            return env
        if node.type == "if_statement":
            env = visit(node.child_by_field_name("condition"), env)
            yes = visit(node.child_by_field_name("consequence"), dict(env))
            no = visit(node.child_by_field_name("alternative"), dict(env))
            return join(yes, no)
        if node.type in {"for_statement", "while_statement", "do_statement", "switch_statement"}:
            # Conservative may-flow: include zero iterations and executed body.
            branch = dict(env)
            for child in node.named_children:
                branch = visit(child, branch)
            return join(env, branch)
        if node.type == "call_expression":
            arguments = node.child_by_field_name("arguments")
            if arguments is not None and any(forwarded(argument, env) for argument in arguments.named_children):
                found = True
        if node.type == "update_expression":
            argument = node.child_by_field_name("argument")
            if argument is not None and argument.type == "identifier":
                env[_text(argument, source)] = False
        for child in node.named_children:
            env = visit(child, env)
        return env
    visit(body, {parameter:True})
    return found


def validate_effect_exclusions(rows, tools):
    questions = returned_resource_questions(tools)
    for index, row in enumerate(rows):
        if row["role"] == "exclude" and row["function_id"] in questions:
            raise SliceExclusionEffectError(index, row["function_id"], questions[row["function_id"]])
