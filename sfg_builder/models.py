"""Serializable data contracts for parsing, annotation, flows, and graphs."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


class Serializable:
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ParameterInfo(Serializable):
    name: str | None
    type: str
    declaration: str
    is_pointer: bool
    is_const: bool
    base_type: str
    pointer_depth: int
    is_struct_like: bool = False


@dataclass(frozen=True)
class AccessHint(Serializable):
    parameter: str
    reads: bool = False
    writes: bool = False
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class FunctionInfo(Serializable):
    id: str
    name: str
    file: str
    start_line: int
    end_line: int
    return_type: str
    return_base_type: str
    return_pointer_depth: int
    return_is_struct_like: bool
    parameters: tuple[ParameterInfo, ...]
    signature: str
    body: str
    defined: bool
    storage: tuple[str, ...] = ()
    access_hints: tuple[AccessHint, ...] = ()
    labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class StructInfo(Serializable):
    name: str
    aliases: tuple[str, ...]
    declaration: str
    file: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class CandidateParameter(Serializable):
    name: str | None
    type: str
    base_type: str


@dataclass(frozen=True)
class FunctionCandidate(Serializable):
    function_id: str
    function: str
    file: str
    line: int
    isf_candidate: bool
    stream_parameters: tuple[CandidateParameter, ...]
    prf_candidate: bool
    hpf_candidate: bool
    struct_related_candidate: bool
    struct_parameters: tuple[CandidateParameter, ...]
    return_struct: str | None

    @property
    def candidate_parameters(self) -> tuple[CandidateParameter, ...]:
        """Compatibility name used by the ISF candidate discovery specification."""
        return self.stream_parameters


@dataclass(frozen=True)
class DecisionTrace(Serializable):
    function: str
    function_id: str
    file: str
    line: int
    task: str
    prompt_version: str
    prompt: str
    response: dict[str, Any]
    confidence: float
    status: str = "ok"
    error: str | None = None


@dataclass(frozen=True)
class StreamParameterAnnotation(Serializable):
    parameter: str | None
    type: str
    is_byte_stream: bool
    kind: str
    confidence: float
    reason: str
    positive_votes: int
    valid_votes: int


@dataclass(frozen=True)
class StructDirection(Serializable):
    parameter: str
    struct_type: str
    direction: str
    reason: str
    confidence: float
    access_hint: AccessHint | None = None


@dataclass(frozen=True)
class FunctionAnnotation(Serializable):
    function_id: str
    function: str
    file: str
    line: int
    labels: tuple[str, ...]
    operation: str
    stream_parameters: tuple[StreamParameterAnnotation, ...]
    struct_directions: tuple[StructDirection, ...]
    reason: str
    decisions: tuple[DecisionTrace, ...]
    output_struct_candidates: tuple[str, ...] = ()


@dataclass(frozen=True)
class FunctionFlow(Serializable):
    function_id: str
    function: str
    labels: tuple[str, ...]
    input_structs: tuple[str, ...]
    output_structs: tuple[str, ...]
    parameters: tuple[ParameterInfo, ...]
    file: str
    line: int
    complex_flow: bool = False
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["source"] = {"file": self.file, "line": self.line}
        return value


@dataclass(frozen=True)
class SFGNode(Serializable):
    id: str
    kind: str


@dataclass(frozen=True)
class SFGEdge(Serializable):
    source: str
    target: str
    function: str
    function_id: str
    labels: tuple[str, ...]
    file: str
    line: int
    inferred: bool = False
    inference_reason: str | None = None


@dataclass(frozen=True)
class StructuralFlowGraph(Serializable):
    nodes: tuple[SFGNode, ...]
    edges: tuple[SFGEdge, ...]
    functions: tuple[FunctionFlow, ...]
    warnings: tuple[str, ...] = ()
    schema_version: int = field(default=1, init=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "functions": [function.to_dict() for function in self.functions],
            "warnings": list(self.warnings),
        }
