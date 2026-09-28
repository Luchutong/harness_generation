"""Provider-neutral message types and strict semantic decision contracts."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

SCHEMA_VERSION = 1
POLICY_VERSION = "recall-first-entry-validation-v3"
INPUT_MODES = ("direct_buffer", "structured_input", "context_feed", "callback_stream",
               "wrapper", "processor_api", "none", "unknown")
POSITIVE_REASONS = ("external_input_sink", "buffer_length_relation", "structured_input",
                    "finite_indirect_input_path", "parser_decoder_consumer_api")
NEGATIVE_REASONS = ("constant_only_no_input", "cleanup_only", "metadata_only",
                    "clearly_not_input_processing")
UNCERTAIN_REASONS = ("insufficient_evidence", "symbol_resolution_incomplete",
                     "possible_indirect_input", "budget_exhausted", "invalid_output",
                     "provider_error", "source_unavailable")
REASON_CODES = POSITIVE_REASONS + NEGATIVE_REASONS + UNCERTAIN_REASONS


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def candidate_id(function_id: str) -> str:
    return "candidate_" + digest(function_id)[:24]


@dataclass(frozen=True)
class ValidationBudget:
    max_rounds: int = 6
    max_tool_calls: int = 24
    max_source_chars: int = 48000
    max_references_per_query: int = 10
    max_callers: int = 10
    max_callees: int = 10
    max_lines_per_read: int = 80
    max_chars_per_record: int = 12000

    def __post_init__(self):
        for name, value in asdict(self).items():
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")

    def to_dict(self) -> dict:
        return asdict(self)


class AgentModelError(RuntimeError):
    """Safe provider failure; never contains HTTP bodies, credentials or URLs."""


class DecisionSchemaError(ValueError):
    """Repairable shape/enum error; evidence and semantic invariants never use this type."""
    def __init__(self, field: str, received: Any, allowed_values: Any):
        super().__init__("schema_validation_failed")
        self.field, self.received, self.allowed_values = field, received, allowed_values

    def to_dict(self):
        return {"error": "schema_validation_failed", "field": self.field,
                "received": self.received, "allowed_values": self.allowed_values}


@dataclass(frozen=True)
class AgentToolCall:
    id: str
    name: str
    arguments: str

    def to_dict(self) -> dict:
        return {"id": self.id, "type": "function",
                "function": {"name": self.name, "arguments": self.arguments}}


@dataclass(frozen=True)
class AgentModelResponse:
    content: str | None = None
    tool_calls: tuple[AgentToolCall, ...] = ()
    reasoning_content: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def assistant_message(self) -> dict:
        message = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            message["tool_calls"] = [call.to_dict() for call in self.tool_calls]
        # DeepSeek requires this field to be replayed when thinking + tools are used.
        if self.reasoning_content is not None:
            message["reasoning_content"] = self.reasoning_content
        return message


class AgentModel(Protocol):
    provider: str
    model: str

    def complete(self, messages: Sequence[Mapping[str, Any]],
                 tools: Sequence[Mapping[str, Any]]) -> AgentModelResponse: ...


class FakeAgentModel:
    """Explicit offline model; callable steps can inspect issued evidence IDs."""
    provider = "fake"
    model = "fake-agent"

    def __init__(self, responses: Sequence[AgentModelResponse | Callable]):
        self.responses = list(responses)
        self.calls: list[dict] = []

    def complete(self, messages, tools) -> AgentModelResponse:
        self.calls.append(deepcopy({"messages": list(messages), "tools": list(tools)}))
        if not self.responses:
            raise AgentModelError("offline response sequence exhausted")
        response = self.responses.pop(0)
        return response(messages, tools) if callable(response) else response


class RecordedAgentModel(FakeAgentModel):
    provider = "recorded"
    model = "recorded-agent"

    @classmethod
    def from_file(cls, path: Path) -> "RecordedAgentModel":
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(document, list):
            raise ValueError("recorded responses must be an array")
        responses = []
        for record in document:
            if not isinstance(record, dict) or set(record) - {
                    "content", "tool_calls", "reasoning_content"}:
                raise ValueError("invalid recorded response")
            calls = tuple(AgentToolCall(**call) for call in record.get("tool_calls", []))
            responses.append(AgentModelResponse(record.get("content"), calls,
                                                record.get("reasoning_content")))
        return cls(responses)


DECISION_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["verdict", "input_mode", "reason_codes", "evidence_ids",
                 "discovered_symbols", "open_questions"],
    "properties": {
        "verdict": {"type": "string", "enum": ["accepted", "rejected", "unresolved"]},
        "input_mode": {"type": "string", "enum": list(INPUT_MODES)},
        "reason_codes": {"type": "array", "minItems": 1,
                         "items": {"type": "string", "enum": list(REASON_CODES)}},
        "evidence_ids": {"type": "array", "items": {"type": "string"}},
        "discovered_symbols": {"type": "array", "items": {"type": "string"}},
        "open_questions": {"type": "array", "items": {"type": "string"}},
    },
}

DECISION_TOOL_NAME = "submit_candidate_decision"
DECISION_TOOL_SCHEMA = {"type": "function", "function": {
    "name": DECISION_TOOL_NAME,
    "description": "Submit the FINAL structured candidate verdict and terminate. This is not a repository query. "
                   "accepted uses only positive reasons; rejected uses only affirmative negative reasons. "
                   "Reference only evidence IDs actually issued by repository tools in this run.",
    "parameters": DECISION_SCHEMA,
}}


def parse_decision(content: str | None, evidence: Mapping[str, dict]) -> dict:
    """An invalid model answer is a run failure, never a negative entry verdict."""
    if not isinstance(content, str) or len(content) > 32000:
        raise DecisionSchemaError("$", "invalid JSON length/type", ["JSON object"])
    try:
        result = json.loads(content)
    except (ValueError, TypeError):
        raise DecisionSchemaError("$", "malformed JSON", ["JSON object"]) from None
    if not isinstance(result, dict) or set(result) != set(DECISION_SCHEMA["required"]):
        raise DecisionSchemaError("$", sorted(result) if isinstance(result, dict) else type(result).__name__,
                                  DECISION_SCHEMA["required"])
    if result["verdict"] not in ("accepted", "rejected", "unresolved"):
        raise DecisionSchemaError("verdict", result["verdict"], ["accepted", "rejected", "unresolved"])
    if result["input_mode"] not in INPUT_MODES:
        raise DecisionSchemaError("input_mode", result["input_mode"], list(INPUT_MODES))
    for name in ("reason_codes", "evidence_ids", "discovered_symbols", "open_questions"):
        values = result[name]
        if (not isinstance(values, list) or len(values) > 64
                or any(not isinstance(x, str) or not x or len(x) > 1000 for x in values)):
            raise DecisionSchemaError(name, "invalid array", ["at most 64 nonempty strings, each <=1000 characters"])
    reasons = result["reason_codes"]
    if not reasons:
        raise DecisionSchemaError("reason_codes", [], list(REASON_CODES))
    for index, reason in enumerate(reasons):
        if reason not in REASON_CODES:
            raise DecisionSchemaError(f"reason_codes[{index}]", reason, list(REASON_CODES))
    if any(eid not in evidence for eid in result["evidence_ids"]):
        raise ValueError("unknown evidence reference")
    if result["verdict"] in {"accepted", "rejected"}:
        records = [evidence[eid] for eid in result["evidence_ids"]]
        if not records or not any(record.get("content") for record in records):
            raise ValueError("decisive verdict requires source evidence")
        if result["verdict"] == "rejected" and not any(record.get("content") and not record.get("truncated")
                                                       for record in records):
            raise ValueError("rejection requires complete source evidence")
        permitted = POSITIVE_REASONS if result["verdict"] == "accepted" else NEGATIVE_REASONS
        if not set(reasons).issubset(permitted):
            index = next(i for i, reason in enumerate(reasons) if reason not in permitted)
            raise DecisionSchemaError(f"reason_codes[{index}]", reasons[index], list(permitted))
        if result["verdict"] == "accepted" and result["input_mode"] in {"none", "unknown"}:
            raise ValueError("accepted verdict requires a possible input mode")
        if result["verdict"] == "rejected" and result["input_mode"] != "none":
            raise ValueError("rejected verdict requires affirmative no-input evidence")
    return result
