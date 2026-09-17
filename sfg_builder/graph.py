"""FunctionFlow derivation and Structural Flow Graph construction."""

from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile

from .models import (FunctionAnnotation, FunctionFlow, FunctionInfo, SFGEdge,
                     SFGNode, StructuralFlowGraph, StructInfo)


NULL_NODE = "(null)"


class FlowBuilder:
    def build(self, functions: tuple[FunctionInfo, ...],
              annotations: tuple[FunctionAnnotation, ...]) -> tuple[FunctionFlow, ...]:
        by_id = {function.id: function for function in functions}
        flows = []
        for annotation in annotations:
            function = by_id[annotation.function_id]
            inputs = []
            outputs = []
            warnings = []
            for output in annotation.output_struct_candidates:
                _add_unique(outputs, output)
            for direction in annotation.struct_directions:
                if direction.direction in {"input", "both"}:
                    _add_unique(inputs, direction.struct_type)
                if direction.direction == "output":
                    _add_unique(outputs, direction.struct_type)
                elif direction.direction == "both":
                    # Engineering choice, not specified by SynapseFlow paper:
                    # an in-place mutation remains on the same structural level.
                    # Model it as consumed input rather than an uninformative A->A edge.
                    warnings.append(
                        f"{function.name}.{direction.parameter}: BOTH is represented as input-only in SFG"
                    )
                elif direction.direction == "unknown":
                    warnings.append(
                        f"{function.name}.{direction.parameter}: unknown struct direction omitted from edges"
                    )
            # Backward-compatible fallback for annotations produced before the
            # dedicated direction stage recorded return output candidates.
            if not annotation.output_struct_candidates and function.return_is_struct_like:
                _add_unique(outputs, function.return_base_type)
            complex_flow = len(inputs) > 1 or len(outputs) > 1
            if complex_flow:
                warnings.append(
                    f"{function.name}: multiple struct inputs/outputs use inferred Cartesian candidate edges"
                )
            flows.append(FunctionFlow(
                function.id, function.name, annotation.labels, tuple(inputs), tuple(outputs),
                function.parameters, function.file, function.start_line, complex_flow, tuple(warnings),
            ))
        return tuple(flows)


class SFGBuilder:
    def build(self, structs: tuple[StructInfo, ...],
              flows: tuple[FunctionFlow, ...]) -> StructuralFlowGraph:
        node_names = {info.name for info in structs}
        warnings = []
        edges = []
        normalized_flows = []
        for original_flow in flows:
            flow = original_flow
            node_names.update(flow.input_structs)
            node_names.update(flow.output_structs)
            inputs = flow.input_structs or (NULL_NODE,)
            outputs = flow.output_structs or (NULL_NODE,)
            has_multiple_endpoints = len(inputs) > 1 or len(outputs) > 1
            if has_multiple_endpoints and not flow.complex_flow:
                warning = (
                    f"{flow.function}: multiple struct inputs/outputs were normalized to "
                    "an inferred complex flow"
                )
                flow = replace(
                    flow,
                    complex_flow=True,
                    warnings=flow.warnings + (warning,),
                )
            normalized_flows.append(flow)
            warnings.extend(flow.warnings)
            if inputs == (NULL_NODE,) and outputs == (NULL_NODE,):
                warnings.append(f"{flow.function}: no resolved struct endpoint; no edge emitted")
                continue
            inferred = flow.complex_flow
            reason = (
                "engineering choice, not specified by SynapseFlow Phase 1: "
                "candidate Cartesian edges for a complex multi-struct flow"
            ) if inferred else None
            for source in inputs:
                for target in outputs:
                    edges.append(SFGEdge(
                        source, target, flow.function, flow.function_id, flow.labels,
                        flow.file, flow.line, inferred, reason,
                    ))
        nodes = (SFGNode(NULL_NODE, "null"),) + tuple(
            SFGNode(name, "struct") for name in sorted(node_names) if name != NULL_NODE
        )
        return StructuralFlowGraph(
            nodes, tuple(edges), tuple(normalized_flows), tuple(dict.fromkeys(warnings)),
        )


def write_flows_json(flows: tuple[FunctionFlow, ...], path: Path) -> Path:
    """Write auditable FunctionFlow records without constructing other artifacts."""
    return _write_json(path, {
        "schema_version": 1,
        "flows": [flow.to_dict() for flow in flows],
    })


def write_sfg_json(graph: StructuralFlowGraph, path: Path) -> Path:
    """Write the Structural Flow Graph JSON representation."""
    return _write_json(path, graph.to_dict())


def write_sfg_dot(graph: StructuralFlowGraph, path: Path) -> Path:
    """Write the Graphviz representation without requiring Graphviz itself."""
    return _write_text(path, to_dot(graph))


def to_dot(graph: StructuralFlowGraph) -> str:
    lines = ["digraph SFG {", "    rankdir=LR;"]
    for node in graph.nodes:
        attributes = 'shape=point,label=""' if node.kind == "null" else 'shape=box'
        lines.append(f'    "{_escape(node.id)}" [{attributes}];')
    for edge in graph.edges:
        labels = ",".join(edge.labels)
        label = edge.function + (f" [{labels}]" if labels else "")
        style = ",style=dashed" if edge.inferred else ""
        lines.append(
            f'    "{_escape(edge.source)}" -> "{_escape(edge.target)}" '
            f'[label="{_escape(label)}"{style}];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def _add_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _write_json(path: Path, value) -> Path:
    return _write_text(
        path,
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def _write_text(path: Path, value: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
    return path
