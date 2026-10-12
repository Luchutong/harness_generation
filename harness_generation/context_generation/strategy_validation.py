"""Validate immutable typed-step translation, without promoting experimental runs."""
from __future__ import annotations

from ..semantic_discovery.models import digest
from .executable_helpers import require_strategy_plan

CODE_VALIDATOR_VERSION = "typed-strategy-code-v1"


def _tokens(code, language):
    from tree_sitter import Language, Parser
    import tree_sitter_c
    import tree_sitter_cpp
    source = code.encode("utf-8")
    grammar = tree_sitter_cpp.language() if language == "c++" else tree_sitter_c.language()
    root = Parser(Language(grammar)).parse(source).root_node
    tokens = []

    def visit(node):
        if node.type == "comment":
            return
        if not node.children:
            tokens.append((node.type, source[node.start_byte:node.end_byte].decode("utf-8")))
        else:
            for child in node.children:
                visit(child)
    visit(root)
    return tokens, root.has_error


def validate_strategy_code(code, plan, *, plan_validator=None):
    """Whitespace/comments are free; every executable token is frozen by the IR.

    A deliberately finite translator makes compiler repair diagnosable. Changing
    recipes, ABI declarations, constants or bounds requires a new upstream plan,
    rather than letting a code model silently weaken the selected experiment.
    """
    from .strategy_generation import deterministic_translate, lower_strategy
    errors = []
    if not isinstance(code, str) or not code or len(code) > 131072:
        errors.append("invalid_strategy_translation_size")
    try:
        require_strategy_plan(plan, plan_validator=plan_validator)
        expected = deterministic_translate(plan, plan_validator=plan_validator)
        lowering = lower_strategy(plan, plan_validator=plan_validator)
    except (ValueError, TypeError, KeyError) as exc:
        return {"schema_version": 1, "validator_version": CODE_VALIDATOR_VERSION, "valid": False,
            "status": "rejected", "errors": ["strategy_plan_invalid"], "detail": str(exc),
            "generation_allowed": False, "experimental_execution_allowed": False}
    actual_tokens, syntax_error = _tokens(code if isinstance(code, str) else "", plan["language"])
    expected_tokens, expected_error = _tokens(expected, plan["language"])
    if syntax_error:
        errors.append("strategy_translation_syntax_error")
    if expected_error:
        errors.append("canonical_strategy_abi_unrepresentable_use_project_header")
    if actual_tokens != expected_tokens:
        errors.append("immutable_strategy_translation_mismatch")
    result = {"schema_version": 1, "validator_version": CODE_VALIDATOR_VERSION,
        "plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"], "strategy_id": plan["strategy_id"],
        "strategy_digest": plan["strategy_digest"], "code_digest": digest(code),
        "canonical_translation_digest": digest(expected), "lowering_digest": digest(lowering),
        "valid": not errors, "status": "accepted_translation" if not errors else "rejected", "errors": errors,
        "required_calls": lowering["calls"], "fuzz_input_binding_preserved": not errors,
        "resource_cleanup_preserved": not errors, "formal_success_statistics_allowed": plan["generation_allowed"],
        "generation_allowed": plan["generation_allowed"],
        "experimental_execution_allowed": not errors and plan.get("experimental_execution_allowed", False)}
    if plan["artifact_kind"] == "executable_plan":
        result.update(execution_allowed=not errors, semantic_verified=False, statistics_category="candidate")
    return result
