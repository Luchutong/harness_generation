"""Deterministic SynapseFlow Function Triplet extraction."""

from __future__ import annotations

from dataclasses import replace
from collections import deque
import hashlib
from pathlib import Path
import re
from typing import Any, Mapping

from sfg_builder.models import SFGEdge

from .sfg_adapter import SFGArtifacts, SFGGraphView, is_null_node
from .triplet import (FunctionTriplet, TripletBypassSemantic, TripletEdge, TripletFunction,
                      stable_triplet_id)


ALGORITHM_VERSION = "synapseflow-function-triplet-v2"
BYPASS_SEMANTICS_VERSION = "function-triplet-bypass-v1"
_ROLE_ORDER = {"ISF": 0, "PRF": 1, "HPF": 2}
_BYTE_STREAM_BASE_TYPES = {
    "void", "char", "unsigned char", "int8_t", "uint8_t"
}
_LENGTH_PARAMETER_NAMES = {
    "size", "len", "length", "n", "data_size", "buffer_size", "input_size"
}
_STATUS_RETURN_TYPES = {
    "int", "long", "short", "unsigned int", "unsigned long", "bool", "_Bool"
}


class FunctionTripletExtractionError(ValueError):
    """The loaded artifacts cannot produce a well-defined Function Triplet."""


class FunctionTripletExtractor:
    """Extract one FT per unique ISF anchor from an adapted multi-edge SFG."""

    def extract(self, artifacts: SFGArtifacts) -> tuple[FunctionTriplet, ...]:
        roles_by_function = _annotation_roles(artifacts.annotations)
        isf_ids = tuple(sorted(
            function_id for function_id, roles in roles_by_function.items()
            if "ISF" in roles
        ))
        triplets = tuple(
            self._extract_one(artifacts, anchor_id, isf_ids, roles_by_function)
            for anchor_id in isf_ids
        )
        return tuple(sorted(triplets, key=lambda triplet: triplet.id))

    def _extract_one(self, artifacts: SFGArtifacts, anchor_id: str,
                     isf_ids: tuple[str, ...],
                     roles_by_function: Mapping[str, tuple[str, ...]]) -> FunctionTriplet:
        new_graph, masked_edges, masked_isfs, removed_isfs = _role_aware_graph(
            artifacts.graph, anchor_id, frozenset(isf_ids), roles_by_function
        )
        anchor_edges = tuple(
            edge for edge in new_graph.edges if edge.function_id == anchor_id
        )
        input_structs = {edge.source for edge in anchor_edges}
        output_structs = {edge.target for edge in anchor_edges}

        in_nodes = set(input_structs)
        for node in sorted(input_structs):
            in_nodes.update(new_graph.ancestors(node))
        out_nodes = set(output_structs)
        for node in sorted(output_structs):
            out_nodes.update(new_graph.descendants(node))
        selected_nodes = in_nodes | out_nodes
        selected_edges = tuple(
            edge for edge in new_graph.edges
            if edge.source in selected_nodes and edge.target in selected_nodes
        ) + tuple(
            edge for edge in masked_edges
            if edge.source in selected_nodes and edge.target in selected_nodes
        )

        selected_roles: dict[str, set[str]] = {
            anchor_id: set(roles_by_function[anchor_id])
        }
        for edge in selected_edges:
            selected_roles.setdefault(edge.function_id, set()).update(edge.labels)

        references = {
            function_id: _function_reference(
                artifacts, function_id, _canonical_roles(roles)
            )
            for function_id, roles in sorted(selected_roles.items())
        }
        isf = references[anchor_id]
        prfs = tuple(
            reference for reference in references.values() if "PRF" in reference.roles
        )
        # SynapseFlow generation priority: PRF wins when PRF and HPF are both present.
        hpfs = tuple(
            reference for reference in references.values()
            if "HPF" in reference.roles and "PRF" not in reference.roles
        )
        functions = tuple(references.values())
        node_kinds = {node.id: node.kind for node in new_graph.nodes}
        structures = tuple(
            node for node in selected_nodes
            if not is_null_node(node, kind=node_kinds.get(node))
        )
        edges = tuple(_triplet_edge(edge) for edge in selected_edges)
        bypass_semantics = _bypass_semantics(artifacts, functions)
        metadata = {
            "algorithm": ALGORITHM_VERSION,
            "bypass_semantics_version": BYPASS_SEMANTICS_VERSION,
            "bypass_semantics_count": len(bypass_semantics),
            "anchor_function_id": anchor_id,
            "input_structs": sorted(input_structs),
            "output_structs": sorted(output_structs),
            "in_nodes": sorted(in_nodes),
            "out_nodes": sorted(out_nodes),
            "other_isfs": sorted(set(isf_ids) - {anchor_id}),
            "role_masked_isfs": list(masked_isfs),
            "removed_isfs": list(removed_isfs),
            "source_schema_versions": dict(artifacts.source_schema_versions),
            "data_chain": {
                "entry": "fuzz_input",
                "isf": isf.function,
                "structures": list(_data_chain(new_graph, anchor_edges, selected_nodes)),
            },
        }
        return FunctionTriplet(
            isf=isf,
            prfs=prfs,
            hpfs=hpfs,
            functions=functions,
            structures=structures,
            edges=edges,
            metadata=metadata,
            id=_stable_anchor_id(artifacts, anchor_id),
            bypass_semantics=bypass_semantics,
        )


def extract_function_triplets(artifacts: SFGArtifacts) -> tuple[FunctionTriplet, ...]:
    return FunctionTripletExtractor().extract(artifacts)


def _stable_anchor_id(artifacts: SFGArtifacts, anchor_id: str) -> str:
    record = artifacts.functions_by_id.get(anchor_id)
    if record is None:
        raise FunctionTripletExtractionError(
            f"function metadata is missing for {anchor_id!r}"
        )
    name = record.get("name")
    stored_file = record.get("file")
    signature = record.get("signature", "")
    if not isinstance(name, str) or not name:
        raise FunctionTripletExtractionError(f"invalid ISF name for {anchor_id!r}")
    if not isinstance(stored_file, str) or not stored_file:
        raise FunctionTripletExtractionError(f"invalid ISF source path for {anchor_id!r}")
    if not isinstance(signature, str):
        raise FunctionTripletExtractionError(f"invalid ISF signature for {anchor_id!r}")
    source_path = Path(stored_file)
    if source_path.is_absolute():
        project = Path(artifacts.project)
        if not project.is_absolute():
            raise FunctionTripletExtractionError(
                "cannot normalize a legacy absolute function path without an "
                "absolute project root"
            )
        try:
            source_path = source_path.relative_to(project)
        except ValueError as error:
            raise FunctionTripletExtractionError(
                f"ISF source path is outside project root: {stored_file}"
            ) from error
    return stable_triplet_id(
        anchor_id,
        function_name=name,
        relative_path=source_path.as_posix(),
        signature=signature,
    )


def _role_aware_graph(graph: SFGGraphView, anchor_id: str,
                      isf_ids: frozenset[str],
                      roles_by_function: Mapping[str, tuple[str, ...]],
                      ) -> tuple[SFGGraphView, tuple[SFGEdge, ...],
                                 tuple[str, ...], tuple[str, ...]]:
    """Prune other entries from traversal while retaining masked role candidates."""
    edges = []
    masked_edges = []
    other_isfs = set(isf_ids) - {anchor_id}
    for edge in graph.edges:
        roles = set(edge.labels)
        roles.update(roles_by_function.get(edge.function_id, ()))
        if edge.function_id in other_isfs:
            roles.discard("ISF")
            if roles:
                # This edge is not traversable: otherwise an alternate ISF can
                # expand the current anchor's reachable nodes. It is added back
                # later only when both endpoints are already inside the FTGraph.
                masked_edges.append(replace(edge, labels=_canonical_roles(roles)))
            continue
        edges.append(replace(edge, labels=_canonical_roles(roles)))
    masked = {edge.function_id for edge in masked_edges}
    removed = other_isfs - masked
    return (
        SFGGraphView(graph.nodes, tuple(edges), graph.warnings, graph.null_node_id),
        tuple(masked_edges),
        tuple(sorted(masked)),
        tuple(sorted(removed)),
    )


def _annotation_roles(annotations: tuple[Mapping[str, Any], ...]
                      ) -> dict[str, tuple[str, ...]]:
    result = {}
    for annotation in annotations:
        function_id = annotation.get("function_id")
        labels = annotation.get("labels")
        if not isinstance(function_id, str) or not function_id:
            raise FunctionTripletExtractionError(
                "annotation function_id must be a non-empty string"
            )
        if not isinstance(labels, list) or any(not isinstance(label, str) for label in labels):
            raise FunctionTripletExtractionError(
                f"annotation labels must be strings: {function_id}"
            )
        result[function_id] = _canonical_roles(labels)
    return result


def _function_reference(artifacts: SFGArtifacts, function_id: str,
                        roles: tuple[str, ...]) -> TripletFunction:
    record = artifacts.functions_by_id.get(function_id)
    if record is None:
        raise FunctionTripletExtractionError(
            f"function metadata is missing for {function_id!r}"
        )
    name = record.get("name")
    file = record.get("file")
    line = record.get("start_line")
    if not isinstance(name, str) or not name or not isinstance(file, str) or not file:
        raise FunctionTripletExtractionError(
            f"invalid function identity metadata for {function_id!r}"
        )
    if type(line) is not int or line < 1:
        raise FunctionTripletExtractionError(
            f"invalid function source line for {function_id!r}"
        )
    return TripletFunction(function_id, name, roles, file, line)


def _triplet_edge(edge: SFGEdge) -> TripletEdge:
    return TripletEdge(
        function_id=edge.function_id,
        function=edge.function,
        src=edge.source,
        dst=edge.target,
        roles=edge.labels,
        file=edge.file,
        line=edge.line,
        inferred=edge.inferred,
        inference_reason=edge.inference_reason,
    )


def _bypass_semantics(
    artifacts: SFGArtifacts,
    functions: tuple[TripletFunction, ...],
) -> tuple[TripletBypassSemantic, ...]:
    """Infer non-structural, non-SFG semantic hints from functions.json only."""

    semantics: list[TripletBypassSemantic] = []
    for function in functions:
        record = artifacts.functions_by_id.get(function.function_id, {})
        parameters = [
            parameter for parameter in record.get("parameters", [])
            if isinstance(parameter, Mapping)
        ]
        stream_parameters = [
            parameter for parameter in parameters
            if _is_byte_stream_parameter(parameter)
        ]
        length_parameters = [
            parameter for parameter in parameters
            if _is_length_parameter(parameter)
        ]
        if stream_parameters and length_parameters:
            stream = stream_parameters[0]
            length = length_parameters[0]
            semantics.append(_semantic(
                function,
                "fuzzer_input_binding",
                (
                    f"{function.function} binds byte stream parameter "
                    f"{stream.get('name')} with length parameter {length.get('name')}."
                ),
                (
                    _parameter_evidence(stream),
                    _parameter_evidence(length),
                ),
                {
                    "stream_parameter": stream.get("name"),
                    "length_parameter": length.get("name"),
                    "stream_type": stream.get("type"),
                    "length_type": length.get("type"),
                },
            ))
        for parameter in parameters:
            if _is_byte_stream_parameter(parameter):
                semantics.append(_semantic(
                    function,
                    "byte_stream_parameter",
                    (
                        f"{function.function} receives byte stream parameter "
                        f"{parameter.get('name')}."
                    ),
                    (_parameter_evidence(parameter),),
                    {
                        "parameter": parameter.get("name"),
                        "type": parameter.get("type"),
                        "base_type": parameter.get("base_type"),
                        "pointer_depth": parameter.get("pointer_depth"),
                        "is_const": parameter.get("is_const"),
                    },
                ))
            elif _is_scalar_parameter(parameter):
                semantics.append(_semantic(
                    function,
                    "scalar_parameter",
                    (
                        f"{function.function} has scalar parameter "
                        f"{parameter.get('name')}."
                    ),
                    (_parameter_evidence(parameter),),
                    {
                        "parameter": parameter.get("name"),
                        "type": parameter.get("type"),
                        "base_type": parameter.get("base_type"),
                    },
                ))
        return_type = record.get("return_type")
        if isinstance(return_type, str) and return_type != "void":
            return_kind = (
                "return_struct"
                if record.get("return_is_struct_like") is True
                else "return_status"
                if _base_return_type(record) in _STATUS_RETURN_TYPES
                else "return_value"
            )
            semantics.append(_semantic(
                function,
                return_kind,
                f"{function.function} returns {return_type}.",
                (f"return_type: {return_type}",),
                {
                    "return_type": return_type,
                    "return_base_type": record.get("return_base_type"),
                    "return_pointer_depth": record.get("return_pointer_depth"),
                    "return_is_struct_like": record.get("return_is_struct_like"),
                },
            ))
        for hint in record.get("access_hints", []):
            if not isinstance(hint, Mapping):
                continue
            evidence = tuple(
                item for item in hint.get("evidence", [])
                if isinstance(item, str) and item
            )
            parameter = hint.get("parameter")
            if not isinstance(parameter, str) or not parameter:
                continue
            mode = "read/write" if hint.get("reads") and hint.get("writes") else (
                "read" if hint.get("reads") else "write" if hint.get("writes") else "opaque"
            )
            semantics.append(_semantic(
                function,
                "struct_access_hint",
                f"{function.function} has {mode} access on {parameter}.",
                evidence or (f"parameter: {parameter}",),
                {
                    "parameter": parameter,
                    "reads": hint.get("reads") is True,
                    "writes": hint.get("writes") is True,
                },
            ))
        body = record.get("body")
        if isinstance(body, str) and body.strip():
            conditions, constants = _body_bypass_hints(body)
            for condition in conditions[:8]:
                semantics.append(_semantic(
                    function,
                    "guard_condition",
                    f"{function.function} has guard condition: {condition}",
                    (f"if ({condition})",),
                    {"condition": condition},
                ))
            for constant in constants[:12]:
                semantics.append(_semantic(
                    function,
                    "constant_reference",
                    f"{function.function} references constant {constant}.",
                    (constant,),
                    {"constant": constant},
                ))
    return tuple(sorted(semantics, key=lambda semantic: semantic.id))


def _semantic(
    function: TripletFunction,
    kind: str,
    summary: str,
    evidence: tuple[str, ...],
    metadata: Mapping[str, Any],
) -> TripletBypassSemantic:
    identity = "\0".join((
        function.function_id,
        kind,
        summary,
        "\0".join(sorted(evidence)),
    ))
    digest = hashlib.sha256(
        (BYPASS_SEMANTICS_VERSION + "\0" + identity).encode("utf-8")
    ).hexdigest()[:12]
    slug = re.sub(r"[^A-Za-z0-9]+", "_", kind).strip("_").lower()
    return TripletBypassSemantic(
        id=f"bs_{slug}_{digest}",
        kind=kind,
        function_id=function.function_id,
        function=function.function,
        summary=summary,
        evidence=evidence,
        metadata=metadata,
    )


def _is_byte_stream_parameter(parameter: Mapping[str, Any]) -> bool:
    return (
        parameter.get("is_pointer") is True
        and parameter.get("is_struct_like") is not True
        and parameter.get("base_type") in _BYTE_STREAM_BASE_TYPES
    )


def _is_length_parameter(parameter: Mapping[str, Any]) -> bool:
    return (
        parameter.get("is_pointer") is not True
        and str(parameter.get("name", "")).lower() in _LENGTH_PARAMETER_NAMES
    )


def _is_scalar_parameter(parameter: Mapping[str, Any]) -> bool:
    return (
        parameter.get("is_pointer") is not True
        and parameter.get("is_struct_like") is not True
        and isinstance(parameter.get("name"), str)
        and isinstance(parameter.get("type"), str)
    )


def _parameter_evidence(parameter: Mapping[str, Any]) -> str:
    declaration = parameter.get("declaration")
    if isinstance(declaration, str) and declaration:
        return "parameter: " + declaration
    return "parameter: " + str(parameter.get("name"))


def _base_return_type(record: Mapping[str, Any]) -> str:
    value = record.get("return_base_type", record.get("return_type", ""))
    return value if isinstance(value, str) else ""


def _body_bypass_hints(body: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    try:
        import tree_sitter
        import tree_sitter_c
    except ImportError:
        return (), ()
    language_value = tree_sitter_c.language()
    language = (language_value if isinstance(language_value, tree_sitter.Language)
                else tree_sitter.Language(language_value))
    try:
        parser = tree_sitter.Parser(language)
    except TypeError:
        parser = tree_sitter.Parser()
        if hasattr(parser, "set_language"):
            parser.set_language(language)
        else:
            parser.language = language
    source = ("void __hg_bypass_probe(void) " + body).encode("utf-8")
    tree = parser.parse(source)
    if tree.root_node.has_error:
        return (), ()
    conditions = []
    constants = set()
    for node in _walk_nodes(tree.root_node):
        if node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            if condition is not None:
                conditions.append(_node_text(source, condition).strip("() "))
        elif node.type == "identifier":
            name = _node_text(source, node)
            if _looks_like_constant(name):
                constants.add(name)
    return tuple(dict.fromkeys(conditions)), tuple(sorted(constants))


def _walk_nodes(node: Any):
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.children))


def _node_text(source: bytes, node: Any) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8")


def _looks_like_constant(name: str) -> bool:
    return (
        len(name) > 1
        and name not in {"NULL"}
        and any(character.isalpha() for character in name)
        and name.upper() == name
        and all(character.isupper() or character.isdigit() or character == "_"
                for character in name)
    )


def _canonical_roles(roles) -> tuple[str, ...]:
    unique = set(roles)
    return tuple(sorted(unique, key=lambda role: (_ROLE_ORDER.get(role, len(_ROLE_ORDER)), role)))


def _data_chain(graph: SFGGraphView, anchor_edges: tuple[SFGEdge, ...],
                selected_nodes: set[str]) -> tuple[str, ...]:
    """Return a deterministic breadth-first structural chain from fuzz input."""
    node_kinds = {node.id: node.kind for node in graph.nodes}
    starts = sorted({
        edge.target for edge in anchor_edges
        if edge.target in selected_nodes
        and not is_null_node(edge.target, kind=node_kinds.get(edge.target))
    })
    visited = set(starts)
    ordered = list(starts)
    pending = deque(starts)
    anchor_ids = {edge.function_id for edge in anchor_edges}
    while pending:
        current = pending.popleft()
        targets = sorted({
            edge.target for edge in graph.outgoing(current)
            if edge.function_id not in anchor_ids
            and edge.target in selected_nodes
            and not is_null_node(edge.target, kind=node_kinds.get(edge.target))
        })
        for target in targets:
            if target not in visited:
                visited.add(target)
                ordered.append(target)
                pending.append(target)
    return tuple(ordered)
