"""Strict typed strategy IR and finite planning budgets.

Only proposal fields are accepted from a model. Artifact identity, resources,
validation status, and generation authority belong to the framework.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
import json
import re

from ..semantic_discovery.models import DecisionSchemaError, ValidationBudget

SCHEMA_VERSION = 1
POLICY_VERSION = "harness-strategy-v1"
ARTIFACT_KIND = "harness_strategy"
TERMINAL_TOOL_NAME = "submit_harness_strategies"
STEP_KINDS = ("construct", "transform_input", "call", "capture", "guard", "cleanup")
HYPOTHESIS_KINDS = ("ownership", "nullability", "input_flow", "construction", "call_order", "cleanup")
EXPRESSION_KINDS = ("fuzz_bytes", "fuzz_size", "null", "integer", "value", "address", "length", "source_function")
LOCAL_ID_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]{0,63}$"
TYPE_NAME_PATTERN = r"^(?:struct |union |enum )?[A-Za-z_][A-Za-z0-9_]*(?: [A-Za-z_][A-Za-z0-9_]*)*$"


@dataclass(frozen=True)
class StrategyBudget:
    """Configurable initial bounds, not empirically optimal parameters."""

    max_candidates: int = 3
    max_steps: int = 32
    max_hypotheses: int = 32
    max_input_bytes: int = 4096
    max_discovered_functions: int = 16
    investigation: ValidationBudget = field(default_factory=ValidationBudget)

    def __post_init__(self):
        for name in ("max_candidates", "max_steps", "max_hypotheses", "max_input_bytes"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"{name} must be a positive integer")
        if type(self.max_discovered_functions) is not int or self.max_discovered_functions < 0:
            raise ValueError("max_discovered_functions must be a nonnegative integer")
        if not isinstance(self.investigation, ValidationBudget):
            raise ValueError("investigation must be a ValidationBudget")

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, document):
        if not isinstance(document, dict) or set(document) != set(cls.__dataclass_fields__):
            raise ValueError("invalid strategy budget fields")
        values = deepcopy(document)
        if (not isinstance(values["investigation"], dict)
                or set(values["investigation"]) != set(ValidationBudget.__dataclass_fields__)):
            raise ValueError("invalid investigation budget")
        values["investigation"] = ValidationBudget(**values["investigation"])
        return cls(**values)


def _object(properties):
    return {"type": "object", "additionalProperties": False,
            "required": list(properties), "properties": properties}


def _string(*, maximum=512, minimum=1, pattern=None):
    result = {"type": "string", "minLength": minimum, "maxLength": maximum}
    if pattern:
        result["pattern"] = pattern
    return result


def _enum(values):
    return {"type": "string", "enum": list(values)}


def _strings(*, maximum=64, local=False):
    return {"type": "array", "maxItems": maximum, "uniqueItems": True,
            "items": _string(maximum=64 if local else 512, pattern=LOCAL_ID_PATTERN if local else None)}


def expression_schema():
    local = _string(maximum=64, pattern=LOCAL_ID_PATTERN)
    return {"oneOf": [
        *[_object({"kind": _enum([kind])}) for kind in ("fuzz_bytes", "fuzz_size", "null")],
        _object({"kind": _enum(["integer"]), "value": {"type": "integer", "minimum": -(2**63), "maximum": 2**63 - 1}}),
        *[_object({"kind": _enum([kind]), "value_id": deepcopy(local)}) for kind in ("value", "address")],
        _object({"kind": _enum(["length"]), "value_id": deepcopy(local), "include_terminator": {"type": "boolean"}}),
        _object({"kind": _enum(["source_function"]), "function_id": _string(), "evidence_ids": _strings()}),
    ]}


def condition_schema(budget):
    local = _string(maximum=64, pattern=LOCAL_ID_PATTERN)
    return {"oneOf": [
        _object({"kind": _enum(["nonnull"]), "value_id": deepcopy(local)}),
        _object({"kind": _enum(["status"]), "value_id": deepcopy(local), "comparison": _enum(["zero", "nonzero"])}),
        _object({"kind": _enum(["size"]), "minimum": {"type": "integer", "minimum": 0, "maximum": budget.max_input_bytes},
                 "maximum": {"type": "integer", "minimum": 0, "maximum": budget.max_input_bytes}}),
    ]}


def proposal_schema(budget=None):
    budget = budget or StrategyBudget()
    local = _string(maximum=64, pattern=LOCAL_ID_PATTERN)
    common = {"step_id": deepcopy(local), "kind": _enum(STEP_KINDS),
              "evidence_ids": _strings(), "hypothesis_ids": _strings(maximum=budget.max_hypotheses, local=True)}
    arguments = {"type": "object", "maxProperties": 64,
                 "propertyNames": {"pattern": LOCAL_ID_PATTERN}, "additionalProperties": expression_schema()}
    fields = {
        "construct": {"value_id": deepcopy(local), "type_name": _string(maximum=128, pattern=TYPE_NAME_PATTERN),
                      "pointer_depth": {"type": "integer", "minimum": 0, "maximum": 4}, "storage": _enum(["zeroed", "out_slot"])},
        "transform_input": {"value_id": deepcopy(local), "operation": _enum(["copy", "nul_terminate", "decode_integer"]),
                            "type_name": _string(maximum=128, pattern=TYPE_NAME_PATTERN), "width": {"type": "integer", "enum": [0, 1, 2, 4, 8]}},
        "call": {"function_id": _string(), "arguments": deepcopy(arguments), "guard_ids": _strings(local=True)},
        "capture": {"value_id": deepcopy(local), "call_step_id": deepcopy(local), "source": _enum(["return", "out_pointee"]),
                    "parameter": _string(maximum=64, minimum=0, pattern=r"^(?:[A-Za-z_][A-Za-z0-9_]{0,63})?$")},
        "guard": {"condition": condition_schema(budget)},
        "cleanup": {"function_id": _string(), "arguments": deepcopy(arguments), "guard_ids": _strings(local=True),
                    "resource_value_id": deepcopy(local)},
    }
    variants = []
    for kind in STEP_KINDS:
        properties = {**deepcopy(common), **fields[kind]}
        properties["kind"] = _enum([kind])
        variants.append(_object(properties))
    hypothesis = _object({"hypothesis_id": deepcopy(local), "kind": _enum(HYPOTHESIS_KINDS),
                          "subject_id": _string(), "description": _string(maximum=1024), "evidence_ids": _strings()})
    return _object({"steps": {"type": "array", "minItems": 1, "maxItems": budget.max_steps, "items": {"oneOf": variants}},
                    "hypotheses": {"type": "array", "maxItems": budget.max_hypotheses, "items": hypothesis},
                    "open_questions": {"type": "array", "maxItems": 64, "items": _string(maximum=1024)}})


def terminal_schema(budget=None):
    budget = budget or StrategyBudget()
    return {"type": "function", "function": {
        "name": TERMINAL_TOOL_NAME,
        "description": "Submit a finite set of FINAL typed harness strategy proposals. Cite issued evidence or explicit hypotheses. "
                       "Do not submit C/C++ code, certificates, or generation authorization. A callback may reference an "
                       "authorized source function_id with issued complete-body evidence; signatures and lifetime are independently verified.",
        "parameters": _object({"strategies": {"type": "array", "minItems": 1, "maxItems": budget.max_candidates,
                                                 "items": proposal_schema(budget)}}),
    }}


def _fail(path, received, expected):
    raise DecisionSchemaError(path, received, expected)


def _shape(value, fields, path):
    if not isinstance(value, dict) or set(value) != set(fields):
        _fail(path, sorted(value) if isinstance(value, dict) else type(value).__name__, sorted(fields))


def _text(value, path, *, maximum=512, minimum=1, pattern=None):
    if (not isinstance(value, str) or not minimum <= len(value) <= maximum
            or (pattern is not None and re.fullmatch(pattern, value) is None)):
        _fail(path, "invalid string", f"string length {minimum}..{maximum}" + (f", pattern {pattern}" if pattern else ""))


def _choice(value, choices, path):
    if not isinstance(value, str) or value not in choices:
        _fail(path, value, list(choices))


def _integer(value, path, *, minimum=0, maximum=2**63 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail(path, value, f"integer {minimum}..{maximum}")


def _string_list(value, path, *, maximum=64, local=False):
    if not isinstance(value, list) or len(value) > maximum:
        _fail(path, "invalid array", f"at most {maximum} strings")
    for index, item in enumerate(value):
        _text(item, f"{path}[{index}]", maximum=64 if local else 512, pattern=LOCAL_ID_PATTERN if local else None)
    if len(value) != len(set(value)):
        _fail(path, "duplicate identifiers", "unique strings")


def _expression(expression, path):
    if not isinstance(expression, dict):
        _fail(path, type(expression).__name__, "typed expression")
    kind = expression.get("kind")
    _choice(kind, EXPRESSION_KINDS, path + ".kind")
    fields = {"kind"}
    if kind == "integer":
        fields.add("value")
    if kind in ("value", "address", "length"):
        fields.add("value_id")
    if kind == "length":
        fields.add("include_terminator")
    if kind == "source_function":
        fields.update({"function_id", "evidence_ids"})
    _shape(expression, fields, path)
    if "value_id" in fields:
        _text(expression["value_id"], path + ".value_id", maximum=64, pattern=LOCAL_ID_PATTERN)
    if kind == "integer":
        _integer(expression["value"], path + ".value", minimum=-(2**63))
    if kind == "length" and type(expression["include_terminator"]) is not bool:
        _fail(path + ".include_terminator", expression["include_terminator"], "boolean")
    if kind == "source_function":
        _text(expression["function_id"], path + ".function_id")
        _string_list(expression["evidence_ids"], path + ".evidence_ids")
        if not expression["evidence_ids"]:
            _fail(path + ".evidence_ids", [], "issued complete-body source evidence")


def validate_proposal(document, budget=None):
    """Validate only IR shape. Scope/evidence/type/flow checks are separate."""
    budget = budget or StrategyBudget()
    _shape(document, {"steps", "hypotheses", "open_questions"}, "$")
    steps, hypotheses = document["steps"], document["hypotheses"]
    if not isinstance(steps, list) or not 1 <= len(steps) <= budget.max_steps:
        _fail("steps", "invalid array", f"1..{budget.max_steps} steps")
    if not isinstance(hypotheses, list) or len(hypotheses) > budget.max_hypotheses:
        _fail("hypotheses", "invalid array", f"at most {budget.max_hypotheses} hypotheses")
    common = {"step_id", "kind", "evidence_ids", "hypothesis_ids"}
    specific = {
        "construct": {"value_id", "type_name", "pointer_depth", "storage"},
        "transform_input": {"value_id", "operation", "type_name", "width"},
        "call": {"function_id", "arguments", "guard_ids"},
        "capture": {"value_id", "call_step_id", "source", "parameter"},
        "guard": {"condition"},
        "cleanup": {"function_id", "arguments", "guard_ids", "resource_value_id"},
    }
    for index, step in enumerate(steps):
        path = f"steps[{index}]"
        if not isinstance(step, dict):
            _fail(path, type(step).__name__, "typed step")
        kind = step.get("kind")
        _choice(kind, STEP_KINDS, path + ".kind")
        _shape(step, common | specific[kind], path)
        _text(step["step_id"], path + ".step_id", maximum=64, pattern=LOCAL_ID_PATTERN)
        _string_list(step["evidence_ids"], path + ".evidence_ids")
        _string_list(step["hypothesis_ids"], path + ".hypothesis_ids", maximum=budget.max_hypotheses, local=True)
        if "value_id" in step:
            _text(step["value_id"], path + ".value_id", maximum=64, pattern=LOCAL_ID_PATTERN)
        if kind in ("construct", "transform_input"):
            _text(step["type_name"], path + ".type_name", maximum=128, pattern=TYPE_NAME_PATTERN)
        if kind == "construct":
            _integer(step["pointer_depth"], path + ".pointer_depth", maximum=4)
            _choice(step["storage"], ("zeroed", "out_slot"), path + ".storage")
        if kind == "transform_input":
            _choice(step["operation"], ("copy", "nul_terminate", "decode_integer"), path + ".operation")
            _integer(step["width"], path + ".width", maximum=8)
            if step["width"] not in (0, 1, 2, 4, 8):
                _fail(path + ".width", step["width"], [0, 1, 2, 4, 8])
        if kind in ("call", "cleanup"):
            _text(step["function_id"], path + ".function_id")
            _string_list(step["guard_ids"], path + ".guard_ids", local=True)
            arguments = step["arguments"]
            if not isinstance(arguments, dict) or len(arguments) > 64:
                _fail(path + ".arguments", "invalid argument mapping", "at most 64 typed parameters")
            for name, expression in arguments.items():
                _text(name, path + ".arguments.parameter", maximum=64, pattern=LOCAL_ID_PATTERN)
                _expression(expression, path + ".arguments." + name)
            if kind == "cleanup":
                _text(step["resource_value_id"], path + ".resource_value_id", maximum=64, pattern=LOCAL_ID_PATTERN)
        if kind == "capture":
            _text(step["call_step_id"], path + ".call_step_id", maximum=64, pattern=LOCAL_ID_PATTERN)
            _choice(step["source"], ("return", "out_pointee"), path + ".source")
            _text(step["parameter"], path + ".parameter", maximum=64, minimum=0,
                  pattern=r"(?:[A-Za-z_][A-Za-z0-9_]{0,63})?")
        if kind == "guard":
            condition = step["condition"]
            if not isinstance(condition, dict):
                _fail(path + ".condition", type(condition).__name__, "typed condition")
            condition_kind = condition.get("kind")
            _choice(condition_kind, ("nonnull", "status", "size"), path + ".condition.kind")
            fields = {"kind", "minimum", "maximum"} if condition_kind == "size" else {"kind", "value_id"}
            if condition_kind == "status":
                fields.add("comparison")
            _shape(condition, fields, path + ".condition")
            if condition_kind == "size":
                _integer(condition["minimum"], path + ".condition.minimum", maximum=budget.max_input_bytes)
                _integer(condition["maximum"], path + ".condition.maximum", maximum=budget.max_input_bytes)
            else:
                _text(condition["value_id"], path + ".condition.value_id", maximum=64, pattern=LOCAL_ID_PATTERN)
            if condition_kind == "status":
                _choice(condition["comparison"], ("zero", "nonzero"), path + ".condition.comparison")
    for index, hypothesis in enumerate(hypotheses):
        path = f"hypotheses[{index}]"
        _shape(hypothesis, {"hypothesis_id", "kind", "subject_id", "description", "evidence_ids"}, path)
        _text(hypothesis["hypothesis_id"], path + ".hypothesis_id", maximum=64, pattern=LOCAL_ID_PATTERN)
        _choice(hypothesis["kind"], HYPOTHESIS_KINDS, path + ".kind")
        _text(hypothesis["subject_id"], path + ".subject_id")
        _text(hypothesis["description"], path + ".description", maximum=1024)
        _string_list(hypothesis["evidence_ids"], path + ".evidence_ids")
    questions = document["open_questions"]
    if not isinstance(questions, list) or len(questions) > 64:
        _fail("open_questions", "invalid array", "at most 64 questions")
    for index, question in enumerate(questions):
        _text(question, f"open_questions[{index}]", maximum=1024)
    return deepcopy(document)


def validate_submission(document, budget=None):
    budget = budget or StrategyBudget()
    if isinstance(document, str):
        if len(document) > 256000:
            _fail("$", "document too large", "at most 256000 characters")
        def object_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate object key")
                result[key] = value
            return result

        def reject_constant(value):
            raise ValueError("non-finite JSON constant")

        try:
            document = json.loads(document, object_pairs_hook=object_pairs, parse_constant=reject_constant)
        except (ValueError, TypeError):
            _fail("$", "malformed JSON", "JSON object")
    _shape(document, {"strategies"}, "$")
    proposals = document["strategies"]
    if not isinstance(proposals, list) or not 1 <= len(proposals) <= budget.max_candidates:
        _fail("strategies", "invalid array", f"1..{budget.max_candidates} proposals")
    return {"strategies": [validate_proposal(proposal, budget) for proposal in proposals]}
