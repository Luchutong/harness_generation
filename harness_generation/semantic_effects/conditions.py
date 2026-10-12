"""Small, three-valued condition checks; unknown is never a satisfied guard.

The source interpreter accepts scalar literals and exact parameter substitutions
only.  It does not evaluate arbitrary C, dereference pointers or infer a valid
allocation from non-nullness.  Strategy guards remain explicit assumptions.
"""
from __future__ import annotations

from copy import deepcopy

from ..semantic_discovery.tools import _text


def scalar_value(node, source, bindings=None, *, depth=0):
    """Return a known integer or None for an unsupported/unknown expression."""
    bindings = bindings or {}
    if node is None or depth > 8:
        return None
    if node.type == "parenthesized_expression" and len(node.named_children) == 1:
        return scalar_value(node.named_children[0], source, bindings, depth=depth + 1)
    if node.type == "identifier":
        value = bindings.get(_text(node, source))
        return value if type(value) is int else None
    if node.type == "null":
        value = bindings.get("NULL", 0)
        return value if type(value) is int else None
    if node.type == "number_literal":
        try:
            text = _text(node, source)
            # Suffixes are deliberately unsupported; no guessing an ABI width.
            return int(text, 0) if text != "0" else 0
        except ValueError:
            return None
    if node.type == "unary_expression":
        operand = node.child_by_field_name("argument")
        value = scalar_value(operand, source, bindings, depth=depth + 1)
        operator = _text(node.child_by_field_name("operator"), source)
        if value is None:
            return None
        return {"!": lambda: int(not value), "+": lambda: value, "-": lambda: -value}.get(operator, lambda: None)()
    if node.type == "binary_expression":
        left = scalar_value(node.child_by_field_name("left"), source, bindings, depth=depth + 1)
        right = scalar_value(node.child_by_field_name("right"), source, bindings, depth=depth + 1)
        operator = _text(node.child_by_field_name("operator"), source)
        if operator == "&&" and (left == 0 or right == 0):
            return 0
        if operator == "||" and ((left is not None and left != 0) or (right is not None and right != 0)):
            return 1
        if left is None or right is None:
            return None
        comparisons = {"==": left == right, "!=": left != right, "<": left < right,
            "<=": left <= right, ">": left > right, ">=": left >= right,
            "&&": bool(left and right), "||": bool(left or right)}
        return int(comparisons[operator]) if operator in comparisons else None
    return None


def evaluate_condition(node, source, bindings=None):
    """Three-valued truth: None means that neither branch is proved selected."""
    value = scalar_value(node, source, bindings)
    return bool(value) if value is not None else None


def source_precondition(node, source, function, *, expected=True):
    """Project a supported parameter predicate, never an arbitrary C string."""
    if node is None:
        return None
    if node.type == "parenthesized_expression" and len(node.named_children) == 1:
        return source_precondition(node.named_children[0], source, function, expected=expected)
    parameters = {p["name"] for p in function.get("parameters", [])}
    if node.type == "identifier" and _text(node, source) in parameters:
        name = _text(node, source)
        parameter = next(p for p in function["parameters"] if p["name"] == name)
        subject = {"kind": "parameter", "name": name}
        return ({"kind": "nonnull" if expected else "is_null", "subject": subject}
            if parameter.get("is_pointer") else {"kind": "not_equals_integer" if expected else "equals_integer",
                "subject": subject, "value": 0})
    if node.type == "unary_expression" and _text(node.child_by_field_name("operator"), source) == "!":
        return source_precondition(node.child_by_field_name("argument"), source, function, expected=not expected)
    if node.type == "binary_expression":
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        operator = _text(node.child_by_field_name("operator"), source)
        if left.type != "identifier" or _text(left, source) not in parameters:
            left, right = right, left
        if left.type == "identifier" and _text(left, source) in parameters and operator in {"==", "!="}:
            value = scalar_value(right, source)
            if value is not None:
                equal = (operator == "==") == expected
                parameter = next(p for p in function["parameters"] if p["name"] == _text(left, source))
                if value == 0 and parameter.get("is_pointer"):
                    return {"kind": "is_null" if equal else "nonnull",
                        "subject": {"kind": "parameter", "name": parameter["name"]}}
                return {"kind": "equals_integer" if equal else "not_equals_integer",
                    "subject": {"kind": "parameter", "name": parameter["name"]}, "value": value}
    return None


def strategy_conditions(strategy, step):
    """Copy typed IR guards without treating their existence as discharge."""
    guards = {s["step_id"]: s["condition"] for s in strategy.get("steps", []) if s.get("kind") == "guard"}
    return [{"guard_id": guard_id, "condition": deepcopy(guards[guard_id]), "status": "assumed"}
        for guard_id in step.get("guard_ids", []) if guard_id in guards]
