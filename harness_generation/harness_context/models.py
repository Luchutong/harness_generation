"""Versioned contracts and global budgets, reusing the existing AgentModel API."""
from dataclasses import asdict, dataclass, field

from ..semantic_discovery.models import canonical, digest, DecisionSchemaError

POLICY_VERSION = "ft-guided-harness-context-v1"
REQUIREMENT_VERSION = "harness-requirements-v1"
PROMPT_VERSION = "ft-requirement-agent-v1"
TOOL_VERSION = "ft-scoped-repository-v1"
SCHEMA_VERSION = 1
KINDS = ("input_binding", "argument_construction", "lifecycle", "return_semantics", "ownership",
         "buffer_length", "call_order", "callback", "state", "support_decision")
STATUSES = ("open", "resolved", "unresolved", "not_applicable")
SUPPORT_REASONS = ("creation", "initialization", "cleanup", "allocator", "callback", "configuration", "other")


@dataclass(frozen=True)
class ContextBudget:
    max_rounds_per_requirement: int = 4
    max_total_model_calls: int = 24
    max_tool_calls: int = 64
    max_discovered_functions: int = 16
    max_dependency_depth: int = 2
    max_source_chars: int = 96000
    max_completeness_rounds: int = 3
    max_references_per_query: int = 6
    max_lines_per_read: int = 80
    max_chars_per_record: int = 12000
    max_terminal_repairs: int = 1

    def __post_init__(self):
        for name, value in asdict(self).items():
            minimum = 0 if name in {"max_discovered_functions", "max_dependency_depth", "max_terminal_repairs"} else 1
            if type(value) is not int or value < minimum:
                raise ValueError(f"{name} must be an integer >= {minimum}")
        if self.max_terminal_repairs not in (0, 1):
            raise ValueError("max_terminal_repairs must be 0 or 1")

    def to_dict(self):
        return asdict(self)


@dataclass
class MiningState:
    budget: ContextBudget
    model_calls: int = 0
    tool_calls: int = 0
    tokens: dict = field(default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
    discoveries: dict = field(default_factory=dict)
    evidence: dict = field(default_factory=dict)
    source_chars: int = 0
    budget_stop: str | None = None


def obj(properties):
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


def arr(items, limit=32):
    return {"type": "array", "items": items, "maxItems": limit}


def enum(*values):
    return {"type": "string", "enum": list(values)}


STRING = {"type": "string", "minLength": 1, "maxLength": 1000}
NULL_STRING = {"type": ["string", "null"], "maxLength": 1000}
BOOL = {"type": "boolean"}
NULL_BOOL = {"type": ["boolean", "null"]}
EIDS = arr(STRING)
API_ACTION = obj({"api": NULL_STRING, "mandatory": BOOL})

VALUE_SCHEMAS = {
    "input_binding": obj({"bindings": arr(obj({
        "parameter": NULL_STRING, "source": enum("fuzz_data", "derived", "context", "none"),
        "transform": enum("direct", "copy", "nul_terminate", "field", "scalar_decode", "none"),
        "size_parameter": NULL_STRING, "size_relation": enum("bytes", "elements", "nul_inclusive", "nul_exclusive", "none", "unknown"),
        "nul_terminated": BOOL, "binary_zero_allowed": NULL_BOOL, "mutable": BOOL,
        "alignment": enum("none", "natural", "explicit", "unknown"), "via_function_id": NULL_STRING}))}),
    "argument_construction": obj({"arguments": arr(obj({"parameter": STRING,
        "construction": enum("input", "zero_init", "stack", "creator_api", "constant", "derived", "callback", "unknown"),
        "api": NULL_STRING, "resource_id": NULL_STRING,
        "constant": {"type": ["string", "integer", "boolean", "null"], "maxLength": 128}}))}),
    "buffer_length": obj({"applicable": BOOL, "links": arr(obj({"buffer_parameter": STRING,
        "length_parameter": NULL_STRING, "relation": enum("bytes", "elements", "nul_inclusive", "nul_exclusive", "capacity", "derived", "unknown"),
        "element_type": NULL_STRING, "requires_nul_termination": BOOL, "binary_zero_allowed": NULL_BOOL}))}),
    "lifecycle": obj({"resources": arr(obj({"resource_id": STRING,
        "type": {**STRING, "description": "Exact Phase 1 base_type without pointer stars or qualifiers."},
        "subject_parameter": NULL_STRING, "return_value": BOOL,
        "creation": obj({"kind": enum("stack", "creator_api", "borrowed", "static", "input", "unknown"), "api": NULL_STRING}),
        "initialization": API_ACTION, "cleanup": API_ACTION, "reuse": enum("per_input", "per_context", "static", "unknown")}))}),
    "ownership": obj({"entries": arr(obj({"parameter": NULL_STRING, "return_value": BOOL,
        "field": NULL_STRING,
        "resource_id": NULL_STRING, "ownership": enum("owned", "borrowed", "transferred", "static", "unknown"),
        "release_api": NULL_STRING, "lifetime": enum("during_call", "until_release", "until_context_cleanup", "static", "unknown")}))}),
    "return_semantics": obj({"success": enum("zero", "nonzero", "nonnull", "nonnegative", "always", "void", "unknown"),
        "nullable": NULL_BOOL, "owned": NULL_BOOL, "error_cleanup": NULL_BOOL}),
    "call_order": obj({"constraints": arr(obj({"before": STRING, "after": NULL_STRING,
        "kind": enum("must_precede", "must_follow", "repeatable", "once_per_context", "once_per_input", "independent"),
        "resource_id": NULL_STRING}))}),
    "callback": obj({"callbacks": arr(obj({"parameter": STRING, "signature": NULL_STRING,
        "mandatory": BOOL, "setup_api": NULL_STRING, "userdata": NULL_STRING,
        "lifetime": enum("during_call", "per_context", "static", "unknown"), "null_allowed": NULL_BOOL}))}),
    "state": obj({"preconditions": arr(obj({"parameter": STRING,
        "kind": enum("initialized", "input_fed", "reset", "none", "unknown"), "api": NULL_STRING}))}),
    "support_decision": obj({"decision": enum("required", "optional", "rejected", "unresolved"),
        "reason": enum(*SUPPORT_REASONS), "required_by": arr(STRING)}),
}
DEPENDENCY_SCHEMA = obj({"function_id": NULL_STRING, "symbol": NULL_STRING,
    "necessity": enum("required", "optional", "rejected", "unresolved"), "reason": enum(*SUPPORT_REASONS),
    "required_by": STRING, "evidence_ids": EIDS})


def resolution_schema(kind):
    return obj({"requirement_id": STRING, "status": enum("resolved", "unresolved", "not_applicable"),
        "facts": arr(obj({"function_id": STRING, "predicate": enum(kind),
                          "value": VALUE_SCHEMAS[kind], "evidence_ids": EIDS})),
        "discovered_api_dependencies": arr(DEPENDENCY_SCHEMA, 0 if kind in {
            "input_binding", "buffer_length", "return_semantics", "call_order"} else 32), "open_questions": arr(STRING)})


def validate_shape(value, schema, path="$", *, repairable=True):
    """Small strict validator for the JSON schema subset exported by this module."""
    types = schema.get("type")
    types = [types] if isinstance(types, str) else types
    actual = ("null" if value is None else "boolean" if type(value) is bool else "integer" if type(value) is int
              else "string" if isinstance(value, str) else "array" if isinstance(value, list)
              else "object" if isinstance(value, dict) else "unsupported")
    def fail(allowed):
        if repairable:
            raise DecisionSchemaError(path, value, allowed)
        raise ValueError(f"invalid_schema:{path}")
    if actual not in types:
        fail(types)
    if "enum" in schema and value not in schema["enum"]:
        fail(schema["enum"])
    if actual == "object":
        properties = schema["properties"]
        if set(value) != set(schema["required"]) or set(value) - set(properties):
            fail(schema["required"])
        for key in properties:
            validate_shape(value[key], properties[key], f"{path}.{key}", repairable=repairable)
    elif actual == "array":
        if len(value) > schema.get("maxItems", 32):
            fail([f"array length <= {schema.get('maxItems', 32)}"])
        for index, item in enumerate(value):
            validate_shape(item, schema["items"], f"{path}[{index}]", repairable=repairable)
    elif actual == "string" and not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 1000):
        fail(["bounded string"])


def fact_id(fact):
    return "fact_" + digest({k: v for k, v in fact.items() if k != "fact_id"})[:32]


def resource_id(fid, parameter=None):
    return "resource_" + digest({"function_id": fid, "parameter": parameter})[:24]


@dataclass
class ContextRun:
    requirements: dict
    context: dict
    closure: dict
    completeness: dict
    metadata: dict
