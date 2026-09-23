"""Deterministic SynapseFlow Function Triplet extraction."""

from __future__ import annotations

from dataclasses import replace
from collections import deque
import hashlib
from pathlib import Path
import re
from typing import Any, Mapping

from sfg_builder.models import SFGEdge
from sfg_builder.parser import _make_parser, _text, _walk

from .sfg_adapter import SFGArtifacts, SFGGraphView, is_null_node
from .triplet import (FunctionTriplet, TripletBypassSemantic, TripletEdge,
                      TripletFunction, TripletOwnershipRelation,
                      stable_triplet_id)


ALGORITHM_VERSION = "synapseflow-function-triplet-v5"
BYPASS_SEMANTICS_VERSION = "function-triplet-bypass-v2"
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
        triplets = []
        for anchor_id in isf_ids:
            patterns = _usage_patterns_for_anchor(artifacts, anchor_id)
            if patterns:
                triplets.extend(
                    self._extract_one(
                        artifacts, anchor_id, isf_ids, roles_by_function,
                        usage_pattern=pattern,
                    )
                    for pattern in patterns
                )
            else:
                triplets.append(self._extract_one(
                    artifacts, anchor_id, isf_ids, roles_by_function
                ))
        return tuple(sorted(triplets, key=lambda triplet: triplet.id))

    def _extract_one(self, artifacts: SFGArtifacts, anchor_id: str,
                     isf_ids: tuple[str, ...],
                     roles_by_function: Mapping[str, tuple[str, ...]],
                     usage_pattern: Mapping[str, Any] | None = None) -> FunctionTriplet:
        new_graph, masked_edges, masked_isfs, removed_isfs = _role_aware_graph(
            artifacts.graph, anchor_id, frozenset(isf_ids), roles_by_function
        )
        anchor_edges = tuple(
            edge for edge in new_graph.edges if edge.function_id == anchor_id
        )
        opaque_boundary_nodes = set(_opaque_resource_nodes(artifacts))
        if usage_pattern is not None:
            resource_type = usage_pattern.get("resource_type")
            if isinstance(resource_type, str) and resource_type:
                opaque_boundary_nodes.add(resource_type)
        opaque_boundary_nodes = frozenset(opaque_boundary_nodes)
        input_structs = {edge.source for edge in anchor_edges}
        output_structs = {edge.target for edge in anchor_edges}

        in_nodes = set(input_structs)
        for node in sorted(input_structs):
            in_nodes.update(_reachable_without_crossing(
                new_graph, node, incoming=True, boundaries=opaque_boundary_nodes
            ))
        out_nodes = set(output_structs)
        for node in sorted(output_structs):
            out_nodes.update(_reachable_without_crossing(
                new_graph, node, incoming=False, boundaries=opaque_boundary_nodes
            ))
        selected_nodes = in_nodes | out_nodes
        selected_edges = tuple(
            edge for edge in new_graph.edges
            if edge.source in selected_nodes and edge.target in selected_nodes
            and (
                edge.function_id == anchor_id
                or not ({edge.source, edge.target} & opaque_boundary_nodes)
            )
        ) + tuple(
            edge for edge in masked_edges
            if edge.source in selected_nodes and edge.target in selected_nodes
            and not ({edge.source, edge.target} & opaque_boundary_nodes)
        )

        selected_roles: dict[str, set[str]] = {
            anchor_id: set(roles_by_function[anchor_id])
        }
        for edge in selected_edges:
            selected_roles.setdefault(edge.function_id, set()).update(edge.labels)

        if usage_pattern is not None:
            closure_roles, closure_edges, closure_structures, lifecycle_closure = (
                _usage_lifecycle_closure(artifacts, usage_pattern, anchor_id)
            )
        else:
            closure_roles, closure_edges, closure_structures, lifecycle_closure = (
                _opaque_lifecycle_closure(artifacts, tuple(selected_roles))
            )
        for function_id, roles in closure_roles.items():
            selected_roles.setdefault(function_id, set()).update(roles)
        selected_edges = _merge_sfg_edges(selected_edges, closure_edges)
        selected_nodes.update(closure_structures)

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
        ownership_relations = (
            (_usage_ownership_relation(usage_pattern),)
            if usage_pattern is not None
            else _ownership_relations(artifacts, functions)
        )
        authority = _authority_summary(
            isf.function_id, bypass_semantics, ownership_relations
        )
        metadata = {
            "algorithm": ALGORITHM_VERSION,
            "bypass_semantics_version": BYPASS_SEMANTICS_VERSION,
            "bypass_semantics_count": len(bypass_semantics),
            "lifecycle_closure": list(lifecycle_closure),
            "structural_alternatives": _delegating_alternatives(
                artifacts, functions, edges
            ),
            "usage_pattern": dict(usage_pattern) if usage_pattern is not None else None,
            "authority": authority,
            "anchor_function_id": anchor_id,
            "input_structs": sorted(input_structs),
            "output_structs": sorted(output_structs),
            "in_nodes": sorted(in_nodes),
            "out_nodes": sorted(out_nodes),
            "other_isfs": sorted(set(isf_ids) - {anchor_id}),
            "role_masked_isfs": list(masked_isfs),
            "removed_isfs": list(removed_isfs),
            "opaque_boundary_nodes": sorted(opaque_boundary_nodes),
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
            id=_stable_anchor_id(
                artifacts, anchor_id,
                variant_key=(str(usage_pattern.get("id")) if usage_pattern else None),
            ),
            bypass_semantics=bypass_semantics,
            ownership_relations=ownership_relations,
        )


def _delegating_alternatives(
    artifacts: SFGArtifacts,
    functions: tuple[TripletFunction, ...],
    edges: tuple[TripletEdge, ...],
) -> list[dict[str, Any]]:
    """Prove alternatives when one same-flow API is a thin wrapper of another."""
    by_name = {function.function: function for function in functions}
    project_names = {
        str(record.get("name")) for record in artifacts.functions
        if isinstance(record.get("name"), str)
    }
    endpoints: dict[str, set[tuple[str, str]]] = {}
    for edge in edges:
        endpoints.setdefault(edge.function, set()).add((edge.src, edge.dst))
    groups = []
    for wrapper in functions:
        record = artifacts.functions_by_id.get(wrapper.function_id, {})
        body = record.get("body", "")
        if not isinstance(body, str) or not body:
            continue
        call_sites = _body_call_sites(body)
        # A wrapper with another call may perform setup, validation or a side
        # effect that the delegate does not.  Local configuration assignments
        # before a terminal delegation are still common API wrappers.
        if len(call_sites) != 1 or not call_sites[0][1]:
            continue
        delegate_name = call_sites[0][0]
        if (delegate_name == wrapper.function or delegate_name not in project_names
                or delegate_name not in by_name):
            continue
        delegate = by_name[delegate_name]
        if not endpoints.get(wrapper.function) or (
            endpoints[wrapper.function] != endpoints.get(delegate_name)
        ):
            continue
        if ("HPF" in wrapper.roles) != ("HPF" in delegate.roles):
            continue
        groups.append({
            "functions": sorted((wrapper.function, delegate_name)),
            "evidence": f"{wrapper.function} body delegates to {delegate_name}",
        })
    return sorted(groups, key=lambda item: item["functions"])


def _body_call_sites(body: str) -> tuple[tuple[str, bool], ...]:
    """Return calls and whether each is a direct terminal action."""
    source = ("void __ft_wrapper(void) " + body).encode("utf-8")
    root = _make_parser().parse(source).root_node
    if root.has_error:
        return ()
    function = next((node for node in root.named_children
                     if node.type == "function_definition"), None)
    block = function.child_by_field_name("body") if function is not None else None
    if block is None:
        return ()
    statements = block.named_children
    calls = []
    for node in _walk(block):
        if node.type != "call_expression":
            continue
        target = node.child_by_field_name("function")
        if target is None or target.type != "identifier":
            continue
        parent = node.parent
        direct_terminal = (
            bool(statements)
            and parent == statements[-1]
            and parent.type in {"return_statement", "expression_statement"}
        )
        calls.append((_text(source, target), direct_terminal))
    return tuple(calls)


def _authority_summary(
    anchor_id: str,
    semantics: tuple[TripletBypassSemantic, ...],
    ownership: tuple[TripletOwnershipRelation, ...],
) -> Mapping[str, Any]:
    required = sorted({
        str(semantic.metadata.get("resource_type"))
        for semantic in semantics
        if semantic.function_id == anchor_id
        and semantic.kind == "opaque_handle_parameter"
        and semantic.metadata.get("resource_type")
    })
    closed = sorted({relation.resource_type for relation in ownership})
    missing = sorted(set(required) - set(closed))
    status = (
        "not_required" if not required
        else "incomplete" if missing
        else "lifecycle_closed"
    )
    return {
        "status": status,
        "required_opaque_resources": required,
        "closed_opaque_resources": closed,
        "missing_opaque_resources": missing,
    }


def extract_function_triplets(artifacts: SFGArtifacts) -> tuple[FunctionTriplet, ...]:
    return FunctionTripletExtractor().extract(artifacts)


def _stable_anchor_id(
    artifacts: SFGArtifacts, anchor_id: str, *, variant_key: str | None = None
) -> str:
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
        variant_key=variant_key,
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


def _opaque_resource_nodes(artifacts: SFGArtifacts) -> frozenset[str]:
    resources = set()
    for function in artifacts.functions:
        if function.get("return_is_opaque_handle") is True:
            resource_type = function.get("return_base_type")
            if isinstance(resource_type, str) and resource_type:
                resources.add(resource_type)
        for parameter in function.get("parameters", []):
            if not isinstance(parameter, Mapping):
                continue
            resource_type = parameter.get("base_type")
            if (
                parameter.get("is_opaque_handle") is True
                and isinstance(resource_type, str)
                and resource_type
            ):
                resources.add(resource_type)
    return frozenset(resources)


def _names_resource_endpoint(
    artifacts: SFGArtifacts, anchor_id: str, resource_type: Any
) -> bool:
    """Return whether the anchor's own signature carries the resource type.

    The evidence is the anchor's declared parameter and return types. A callee
    that only receives the value through a generic ``void*`` slot holds no typed
    endpoint for it, so a caller's resource does not become part of that
    callee's API. A signature naming the type -- ``ParserParse(Parser, ...)``
    against resource ``Parser`` -- does.
    """
    if not isinstance(resource_type, str) or not resource_type:
        return False
    record = artifacts.functions_by_id.get(anchor_id)
    if not isinstance(record, Mapping):
        return False
    declared = {_type_name(record.get("return_base_type")),
                _type_name(record.get("return_type"))}
    for parameter in record.get("parameters", []):
        if not isinstance(parameter, Mapping):
            continue
        declared.add(_type_name(parameter.get("base_type")))
        declared.add(_type_name(parameter.get("type")))
    declared.discard("")
    return _type_name(resource_type) in declared


def _type_name(value: Any) -> str:
    """Reduce a declared type to its bare name so spellings can be compared."""
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+|\bconst\b|\bvolatile\b|\*", "", value)


def _usage_patterns_for_anchor(
    artifacts: SFGArtifacts, anchor_id: str
) -> tuple[Mapping[str, Any], ...]:
    """Return observed variants in which the anchor consumes the tracked value."""
    patterns: list[Mapping[str, Any]] = []
    for pattern in artifacts.usage_patterns:
        consumer_ids = pattern.get("consumer_function_ids", [])
        review = pattern.get("semantic_review")
        rejected = isinstance(review, Mapping) and review.get("status") == "rejected"
        resource_type = pattern.get("resource_type")
        # A caller can pass a resource through a generic void* userdata slot.
        # That does not make the resource lifecycle part of the callee's API:
        # md_parse accepts arbitrary userdata, even when one caller happens to
        # pass an FmtHTML containing a WBuf. Require the anchor's own signature
        # to name the resource type, so that only typed endpoints count.
        typed_resource = _names_resource_endpoint(artifacts, anchor_id, resource_type)
        if (isinstance(consumer_ids, list) and anchor_id in consumer_ids
                and not rejected and typed_resource):
            patterns.append(pattern)
    grouped: dict[str, list[Mapping[str, Any]]] = {}
    for pattern in patterns:
        review = pattern.get("semantic_review")
        group_id = (review.get("semantic_group_id")
                    if isinstance(review, Mapping) else None)
        key = group_id if isinstance(group_id, str) and group_id else str(pattern.get("id", ""))
        grouped.setdefault(key, []).append(pattern)
    views = [_semantic_pattern_view(values) for _, values in sorted(grouped.items())]
    return tuple(sorted(views, key=lambda item: str(item.get("id", ""))))


def _semantic_pattern_view(
    members: list[Mapping[str, Any]],
) -> Mapping[str, Any]:
    """Create one executable pattern from an LLM-approved equivalence group."""
    members = sorted(members, key=lambda item: str(item.get("id", "")))
    representative = members[0]
    review = representative.get("semantic_review")
    if not isinstance(review, Mapping):
        return representative
    required = review.get("required_sequence")
    if (not isinstance(required, list) or len(required) < 2
            or any(not isinstance(item, str) for item in required)):
        return representative
    required_consumers = required[1:-1]
    chosen = None
    for candidate in members:
        filtered = _filter_pattern_consumers(candidate, required_consumers)
        if filtered is not None:
            chosen = (candidate, filtered)
            break
    if chosen is None:
        return representative
    candidate, (consumer_names, consumer_ids, consumer_indices) = chosen
    group_id = review.get("semantic_group_id")
    return {
        **dict(candidate),
        "id": group_id if isinstance(group_id, str) and group_id else candidate.get("id"),
        "sequence": list(required),
        "consumers": consumer_names,
        "consumer_function_ids": consumer_ids,
        "consumer_argument_indices": consumer_indices,
        "support_total": review.get("group_support_total", candidate.get("support_total", 0)),
        "support_by_source": dict(review.get(
            "group_support_by_source", candidate.get("support_by_source", {})
        )),
        "evidence": list(review.get("group_evidence", candidate.get("evidence", []))),
        "semantic_review": dict(review),
        "member_pattern_ids": list(review.get("group_member_pattern_ids", [])),
    }


def _filter_pattern_consumers(
    pattern: Mapping[str, Any], required: list[str]
) -> tuple[list[str], list[str], list[int]] | None:
    names = pattern.get("consumers", [])
    ids = pattern.get("consumer_function_ids", [])
    indices = pattern.get("consumer_argument_indices", [])
    if not (isinstance(names, list) and isinstance(ids, list) and isinstance(indices, list)
            and len(names) == len(ids) == len(indices)):
        return None
    output_names: list[str] = []
    output_ids: list[str] = []
    output_indices: list[int] = []
    cursor = 0
    for expected in required:
        while cursor < len(names) and names[cursor] != expected:
            cursor += 1
        if cursor >= len(names):
            return None
        output_names.append(names[cursor])
        output_ids.append(ids[cursor])
        output_indices.append(indices[cursor])
        cursor += 1
    return output_names, output_ids, output_indices


def _usage_lifecycle_closure(
    artifacts: SFGArtifacts,
    pattern: Mapping[str, Any],
    anchor_id: str,
) -> tuple[
    dict[str, tuple[str, ...]], tuple[SFGEdge, ...], tuple[str, ...],
    tuple[Mapping[str, Any], ...],
]:
    """Close an FT over exactly one observed usage pattern."""
    producer_id = _required_usage_string(pattern, "producer_function_id")
    cleanup_id = _required_usage_string(pattern, "cleanup_function_id")
    consumer_ids = _usage_strings(pattern, "consumer_function_ids")
    for function_id in (producer_id, cleanup_id, *consumer_ids):
        if function_id not in artifacts.functions_by_id:
            raise FunctionTripletExtractionError(
                f"usage pattern references unknown function: {function_id}"
            )
    roles: dict[str, tuple[str, ...]] = {
        producer_id: ("PRF", "HPF"),
        cleanup_id: ("HPF",),
    }
    for consumer_id in consumer_ids:
        if consumer_id == anchor_id:
            continue
        existing = tuple(
            role for role in _annotation_roles_for_id(artifacts, consumer_id)
            if role != "ISF"
        )
        roles[consumer_id] = _canonical_roles((*existing, "PRF"))
    resource_type = _required_usage_string(pattern, "resource_type")
    null_node = artifacts.graph.null_node_id or "(null)"
    edges: list[SFGEdge] = []
    ids = {producer_id, cleanup_id, *consumer_ids}
    for edge in artifacts.graph.edges:
        if edge.function_id in ids and (
            edge.source == resource_type or edge.target == resource_type
        ):
            edges.append(replace(
                edge,
                labels=_canonical_roles((*edge.labels, *roles.get(edge.function_id, ()))),
            ))
    present = {edge.function_id for edge in edges}
    if producer_id not in present:
        edges.append(_lifecycle_edge(
            artifacts, producer_id, null_node, resource_type,
            roles[producer_id], "usage-mined resource producer",
        ))
    for consumer_id in consumer_ids:
        if consumer_id in present:
            continue
        labels = (("ISF",) if consumer_id == anchor_id
                  else roles.get(consumer_id, ("PRF",)))
        edges.append(_lifecycle_edge(
            artifacts, consumer_id, resource_type, null_node, labels,
            "usage-mined resource consumer",
        ))
    if cleanup_id not in present:
        edges.append(_lifecycle_edge(
            artifacts, cleanup_id, resource_type, null_node,
            roles[cleanup_id], "usage-mined resource cleanup",
        ))
    closure = {
        "resource_type": resource_type,
        "producer_function_id": producer_id,
        "producer_function": pattern.get("producer_function"),
        "consumer_function_ids": list(consumer_ids),
        "cleanup_function_id": cleanup_id,
        "cleanup_function": pattern.get("cleanup_function"),
        "usage_pattern_id": pattern.get("id"),
        "lifecycle_kind": pattern.get("lifecycle_kind"),
        "path_kind": pattern.get("path_kind"),
        "conditions": list(pattern.get("conditions", [])),
        "support_total": pattern.get("support_total", 0),
        "support_by_source": dict(pattern.get("support_by_source", {})),
        "source": "usage_mining",
    }
    return roles, _merge_sfg_edges((), tuple(edges)), (resource_type,), (closure,)


def _usage_ownership_relation(pattern: Mapping[str, Any]) -> TripletOwnershipRelation:
    cleanup_argument = pattern.get("cleanup_argument", "resource")
    review = pattern.get("semantic_review")
    semantic_confidence = (
        review.get("confidence") if isinstance(review, Mapping) else None
    )
    static_confidence = min(0.99, 0.82 + 0.03 * int(pattern.get("support_total", 0)))
    confidence = (
        min(0.99, 0.6 * static_confidence + 0.4 * float(semantic_confidence))
        if isinstance(semantic_confidence, (int, float))
        and not isinstance(semantic_confidence, bool)
        and isinstance(review, Mapping) and review.get("status") == "accepted"
        else static_confidence
    )
    evidence = list(_usage_strings(pattern, "evidence"))
    if isinstance(review, Mapping) and isinstance(review.get("reason"), str):
        evidence.append("semantic review: " + review["reason"])
    return TripletOwnershipRelation(
        id="own_" + _required_usage_string(pattern, "id"),
        producer_function_id=_required_usage_string(pattern, "producer_function_id"),
        producer_function=_required_usage_string(pattern, "producer_function"),
        resource_type=_required_usage_string(pattern, "resource_type"),
        cleanup_function_id=_required_usage_string(pattern, "cleanup_function_id"),
        cleanup_function=_required_usage_string(pattern, "cleanup_function"),
        cleanup_argument=(
            "address_of_return_value" if cleanup_argument == "address_of_resource"
            else "return_value"
        ),
        consumers=_usage_strings(pattern, "consumers"),
        nullable=pattern.get("nullable", False),
        evidence=tuple(evidence),
        confidence=confidence,
        source=(
            "usage_mining+llm"
            if isinstance(review, Mapping)
            and review.get("status") == "accepted"
            and review.get("backend") == "llm"
            else "usage_mining+semantic_review"
            if isinstance(review, Mapping) and review.get("status") == "accepted"
            else "usage_mining"
        ),
        producer_binding=pattern.get("producer_binding", "return_value"),
        producer_argument_index=pattern.get("producer_argument_index"),
        cleanup_argument_index=pattern.get("cleanup_argument_index", 0),
        lifecycle_kind=pattern.get("lifecycle_kind", "owned_resource"),
        conditions=_usage_strings(pattern, "conditions"),
        path_kind=pattern.get("path_kind", "normal"),
        support_total=pattern.get("support_total", 0),
        support_by_source=pattern.get("support_by_source", {}),
        usage_pattern_id=_required_usage_string(pattern, "id"),
        observed_sequence=_usage_strings(pattern, "sequence"),
    )


def _required_usage_string(record: Mapping[str, Any], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value:
        raise FunctionTripletExtractionError(
            f"usage pattern {field} must be a non-empty string"
        )
    return value


def _usage_strings(record: Mapping[str, Any], field: str) -> tuple[str, ...]:
    values = record.get(field, [])
    if not isinstance(values, list) or any(not isinstance(item, str) or not item for item in values):
        raise FunctionTripletExtractionError(
            f"usage pattern {field} must be an array of non-empty strings"
        )
    return tuple(values)


def _reachable_without_crossing(
    graph: SFGGraphView,
    start: str,
    *,
    incoming: bool,
    boundaries: frozenset[str],
) -> tuple[str, ...]:
    if start in boundaries or is_null_node(start):
        return ()
    visited = {start}
    pending = [start]
    while pending:
        current = pending.pop()
        if is_null_node(current):
            continue
        edges = graph.incoming(current) if incoming else graph.outgoing(current)
        neighbors = sorted({
            edge.source if incoming else edge.target for edge in edges
        }, reverse=True)
        for neighbor in neighbors:
            if neighbor in visited:
                continue
            visited.add(neighbor)
            if neighbor not in boundaries and not is_null_node(neighbor):
                pending.append(neighbor)
    visited.remove(start)
    return tuple(sorted(visited))


def _opaque_lifecycle_closure(
    artifacts: SFGArtifacts,
    selected_function_ids: tuple[str, ...],
) -> tuple[
    dict[str, tuple[str, ...]],
    tuple[SFGEdge, ...],
    tuple[str, ...],
    tuple[Mapping[str, Any], ...],
]:
    """Close selected opaque-handle consumers over one create/free pair per type."""
    required: dict[str, set[str]] = {}
    for function_id in selected_function_ids:
        function = artifacts.functions_by_id.get(function_id, {})
        for parameter in function.get("parameters", []):
            if not isinstance(parameter, Mapping):
                continue
            resource_type = parameter.get("base_type")
            if (
                parameter.get("is_opaque_handle") is True
                and parameter.get("is_pointer") is True
                and isinstance(resource_type, str)
                and resource_type
            ):
                required.setdefault(resource_type, set()).add(function_id)
    if not required:
        return {}, (), (), ()

    relations_by_type: dict[str, list[Mapping[str, Any]]] = {}
    for relation in artifacts.ownership:
        if not isinstance(relation, Mapping):
            continue
        resource_type = relation.get("resource_type")
        confidence = relation.get("confidence")
        if (
            resource_type in required
            and isinstance(confidence, (int, float))
            and not isinstance(confidence, bool)
            and float(confidence) >= 0.80
        ):
            relations_by_type.setdefault(str(resource_type), []).append(relation)

    roles: dict[str, tuple[str, ...]] = {}
    edges: list[SFGEdge] = []
    structures: list[str] = []
    closure_records: list[Mapping[str, Any]] = []
    null_node = artifacts.graph.null_node_id or "(null)"
    for resource_type, consumers in sorted(required.items()):
        candidates = relations_by_type.get(resource_type, [])
        if not candidates:
            continue
        candidates.sort(key=lambda relation: _lifecycle_relation_rank(artifacts, relation))
        relation = candidates[0]
        producer_id = relation.get("producer_function_id")
        cleanup_id = relation.get("cleanup_function_id")
        if not isinstance(producer_id, str) or not isinstance(cleanup_id, str):
            continue
        if producer_id not in artifacts.functions_by_id or cleanup_id not in artifacts.functions_by_id:
            continue
        roles[producer_id] = ("PRF", "HPF")
        roles[cleanup_id] = ("HPF",)
        structures.append(resource_type)

        closure_ids = {producer_id, cleanup_id, *consumers}
        for edge in artifacts.graph.edges:
            if edge.function_id in closure_ids and (
                edge.source == resource_type or edge.target == resource_type
            ):
                closure_edge_roles = roles.get(edge.function_id, ())
                edges.append(replace(
                    edge,
                    labels=_canonical_roles((*edge.labels, *closure_edge_roles)),
                ))
        existing_ids = {edge.function_id for edge in edges}
        if producer_id not in existing_ids:
            edges.append(_lifecycle_edge(
                artifacts, producer_id, null_node, resource_type,
                ("PRF", "HPF"), "opaque handle producer",
            ))
        if cleanup_id not in existing_ids:
            edges.append(_lifecycle_edge(
                artifacts, cleanup_id, resource_type, null_node,
                ("HPF",), "opaque handle cleanup",
            ))
        for consumer_id in sorted(consumers):
            if consumer_id in {edge.function_id for edge in edges}:
                continue
            consumer_roles = _annotation_roles_for_id(artifacts, consumer_id)
            edges.append(_lifecycle_edge(
                artifacts, consumer_id, resource_type, null_node,
                consumer_roles, "opaque handle consumer",
            ))
        closure_records.append({
            "resource_type": resource_type,
            "producer_function_id": producer_id,
            "producer_function": relation.get("producer_function"),
            "consumer_function_ids": sorted(consumers),
            "cleanup_function_id": cleanup_id,
            "cleanup_function": relation.get("cleanup_function"),
            "ownership_relation_id": relation.get("id"),
            "confidence": relation.get("confidence"),
            "source": relation.get("source"),
        })
    return (
        roles,
        _merge_sfg_edges((), tuple(edges)),
        tuple(sorted(set(structures))),
        tuple(closure_records),
    )


def _lifecycle_relation_rank(
    artifacts: SFGArtifacts, relation: Mapping[str, Any]
) -> tuple[Any, ...]:
    producer_id = relation.get("producer_function_id")
    producer = artifacts.functions_by_id.get(producer_id, {})
    parameters = producer.get("parameters", [])
    parameter_count = len(parameters) if isinstance(parameters, list) else 10**6
    confidence = relation.get("confidence")
    numeric_confidence = (
        float(confidence)
        if isinstance(confidence, (int, float)) and not isinstance(confidence, bool)
        else 0.0
    )
    return (
        -numeric_confidence,
        parameter_count,
        str(relation.get("producer_function", "")),
        str(producer_id),
    )


def _lifecycle_edge(
    artifacts: SFGArtifacts,
    function_id: str,
    source: str,
    target: str,
    roles: tuple[str, ...],
    reason: str,
) -> SFGEdge:
    function = artifacts.functions_by_id[function_id]
    return SFGEdge(
        source=source,
        target=target,
        function=str(function.get("name")),
        function_id=function_id,
        labels=_canonical_roles(roles),
        file=str(function.get("file")),
        line=int(function.get("start_line")),
        inferred=True,
        inference_reason=reason,
    )


def _annotation_roles_for_id(
    artifacts: SFGArtifacts, function_id: str
) -> tuple[str, ...]:
    annotation = artifacts.annotations_by_id.get(function_id, {})
    labels = annotation.get("labels", [])
    return _canonical_roles(
        label for label in labels if isinstance(label, str)
    )


def _merge_sfg_edges(
    original: tuple[SFGEdge, ...], additions: tuple[SFGEdge, ...]
) -> tuple[SFGEdge, ...]:
    by_key: dict[tuple[Any, ...], SFGEdge] = {}
    for edge in (*original, *additions):
        key = (
            edge.function_id, edge.source, edge.target, edge.labels,
            edge.file, edge.line,
        )
        previous = by_key.get(key)
        if previous is None or (previous.inferred and not edge.inferred):
            by_key[key] = edge
    return tuple(sorted(
        by_key.values(),
        key=lambda edge: (
            edge.source, edge.target, edge.function_id, edge.file, edge.line
        ),
    ))


def _ownership_relations(
    artifacts: SFGArtifacts,
    functions: tuple[TripletFunction, ...],
) -> tuple[TripletOwnershipRelation, ...]:
    """Keep only validated ownership closures whose producer is in this FT."""
    function_ids = {function.function_id for function in functions}
    function_names = {function.function_id: function.function for function in functions}
    # A function the semantic analyzer labels HPF releases a resource; it is a
    # release path, never a downstream consumer of it.  ``json_value_free_ex``
    # takes a ``json_value`` exactly as ``json_value_free`` does, and counting
    # it as a consumer of the ``json_parse`` relation demands that one
    # destructor run after the other.
    release_ids = {
        function.function_id for function in functions if "HPF" in function.roles
    }
    relations = []
    for record in artifacts.ownership:
        if not isinstance(record, Mapping):
            raise FunctionTripletExtractionError("ownership relation must be an object")
        producer_id = record.get("producer_function_id")
        if producer_id not in function_ids:
            continue
        cleanup_id = record.get("cleanup_function_id")
        cleanup_name = record.get("cleanup_function")
        if not isinstance(cleanup_id, str) or not cleanup_id:
            raise FunctionTripletExtractionError("ownership cleanup id is invalid")
        if not isinstance(cleanup_name, str) or not cleanup_name:
            raise FunctionTripletExtractionError("ownership cleanup name is invalid")
        producer_name = record.get("producer_function", function_names[producer_id])
        if producer_name != function_names[producer_id]:
            raise FunctionTripletExtractionError(
                f"ownership producer does not match FT: {producer_id}"
            )
        resource_type = _required_ownership_string(record, "resource_type")
        consumers = tuple(sorted(set(
            _ownership_strings(record, "consumers")
            + _resource_consumers(
                artifacts,
                functions,
                resource_type,
                excluded_ids={producer_id, cleanup_id} | release_ids,
            )
        )))
        unknown_consumers = sorted(set(consumers) - set(function_names.values()))
        if unknown_consumers:
            raise FunctionTripletExtractionError(
                "ownership consumers are outside the FT: "
                + ", ".join(unknown_consumers)
            )
        try:
            relation = TripletOwnershipRelation(
                id=_required_ownership_string(record, "id"),
                producer_function_id=producer_id,
                producer_function=producer_name,
                resource_type=_required_ownership_string(record, "resource_type"),
                cleanup_function_id=cleanup_id,
                cleanup_function=cleanup_name,
                cleanup_argument=record.get("cleanup_argument", "return_value"),
                consumers=consumers,
                nullable=record.get("nullable", True),
                evidence=_ownership_strings(record, "evidence"),
                confidence=record.get("confidence", 0.0),
                source=record.get("source", "static"),
            )
        except (TypeError, ValueError) as error:
            raise FunctionTripletExtractionError(
                f"invalid ownership relation {record.get('id', '<unknown>')}: {error}"
            ) from error
        relations.append(relation)
    return tuple(sorted(relations, key=lambda relation: relation.id))


def _resource_consumers(
    artifacts: SFGArtifacts,
    functions: tuple[TripletFunction, ...],
    resource_type: str,
    *,
    excluded_ids: set[str],
) -> tuple[str, ...]:
    consumers = []
    for function in functions:
        if function.function_id in excluded_ids:
            continue
        record = artifacts.functions_by_id.get(function.function_id, {})
        parameters = record.get("parameters", [])
        if not isinstance(parameters, list):
            continue
        if any(
            isinstance(parameter, Mapping)
            and parameter.get("base_type") == resource_type
            and parameter.get("is_pointer") is True
            for parameter in parameters
        ):
            consumers.append(function.function)
    return tuple(sorted(set(consumers)))


def _required_ownership_string(record: Mapping[str, Any], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"ownership {field} must be a non-empty string")
    return value


def _ownership_strings(record: Mapping[str, Any], field: str) -> tuple[str, ...]:
    values = record.get(field, ())
    if not isinstance(values, (list, tuple)) or any(
        not isinstance(value, str) or not value for value in values
    ):
        raise ValueError(f"ownership {field} must be an array of strings")
    return tuple(values)


def _bypass_semantics(
    artifacts: SFGArtifacts,
    functions: tuple[TripletFunction, ...],
) -> tuple[TripletBypassSemantic, ...]:
    """Infer non-structural, non-SFG semantic hints from functions.json only."""

    semantics: list[TripletBypassSemantic] = []
    stream_votes = {
        annotation.get("function_id"): {
            item.get("parameter") for item in annotation.get("stream_parameters", [])
            if isinstance(item, Mapping) and item.get("is_byte_stream") is True
        }
        for annotation in artifacts.annotations
        if isinstance(annotation.get("stream_parameters"), list)
    }
    for function in functions:
        record = artifacts.functions_by_id.get(function.function_id, {})
        parameters = [
            parameter for parameter in record.get("parameters", [])
            if isinstance(parameter, Mapping)
        ]
        stream_parameters = [
            parameter for parameter in parameters
            if _is_byte_stream_parameter(parameter)
            and (
                function.function_id not in stream_votes
                or parameter.get("name") in stream_votes[function.function_id]
            )
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
            if parameter.get("is_opaque_handle") is True:
                semantics.append(_semantic(
                    function,
                    "opaque_handle_parameter",
                    (
                        f"{function.function} consumes opaque handle "
                        f"{parameter.get('base_type')} via {parameter.get('name')}."
                    ),
                    (_parameter_evidence(parameter),),
                    {
                        "parameter": parameter.get("name"),
                        "type": parameter.get("type"),
                        "resource_type": parameter.get("base_type"),
                        "effective_pointer_depth": parameter.get("pointer_depth"),
                    },
                ))
            if parameter in stream_parameters:
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
            if record.get("return_is_opaque_handle") is True:
                semantics.append(_semantic(
                    function,
                    "opaque_handle_return",
                    (
                        f"{function.function} returns opaque handle "
                        f"{record.get('return_base_type')}."
                    ),
                    (f"return_type: {return_type}",),
                    {
                        "resource_type": record.get("return_base_type"),
                        "effective_pointer_depth": record.get("return_pointer_depth"),
                    },
                ))
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
