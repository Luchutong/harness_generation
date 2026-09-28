"""Construction boundary for structural propagation, separate from discovery.

The compatibility policy preserves type-reachable closure. Its selected edges
are weak structural evidence, not a claim that every API is semantically needed.
An eventual semantic slice can implement StructuralRelationPolicy instead.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sfg_builder.models import SFGEdge

from .sfg_adapter import SFGGraphView, is_null_node


@dataclass(frozen=True)
class StructuralSelection:
    input_nodes: frozenset[str]
    output_nodes: frozenset[str]
    selected_nodes: frozenset[str]
    edges: tuple[SFGEdge, ...]


class StructuralRelationPolicy(Protocol):
    name: str

    def select(self, graph: SFGGraphView, *, anchor_id: str,
               anchor_edges: tuple[SFGEdge, ...], masked_edges: tuple[SFGEdge, ...],
               boundaries: frozenset[str], owned_return_producer: bool) -> StructuralSelection: ...


class LegacyStructuralClosure:
    """Opt-in-by-compatibility type closure; it does not discover entries."""
    name = "legacy_structural_closure"

    def select(self, graph: SFGGraphView, *, anchor_id: str,
               anchor_edges: tuple[SFGEdge, ...], masked_edges: tuple[SFGEdge, ...],
               boundaries: frozenset[str], owned_return_producer: bool) -> StructuralSelection:
        input_nodes = {e.source for e in anchor_edges}
        output_nodes = {e.target for e in anchor_edges}
        if owned_return_producer:
            selected_nodes = input_nodes | output_nodes
            edges = anchor_edges
        else:
            for node in sorted(tuple(input_nodes)):
                input_nodes.update(reachable_without_crossing(graph, node, incoming=True, boundaries=boundaries))
            for node in sorted(tuple(output_nodes)):
                output_nodes.update(reachable_without_crossing(graph, node, incoming=False, boundaries=boundaries))
            selected_nodes = input_nodes | output_nodes
            edges = tuple(
                edge for edge in graph.edges
                if edge.source in selected_nodes and edge.target in selected_nodes
                and (edge.function_id == anchor_id or not ({edge.source, edge.target} & boundaries))
            ) + tuple(
                edge for edge in masked_edges
                if edge.source in selected_nodes and edge.target in selected_nodes
                and not ({edge.source, edge.target} & boundaries)
            )
        return StructuralSelection(frozenset(input_nodes), frozenset(output_nodes),
                                   frozenset(selected_nodes), edges)


def reachable_without_crossing(graph: SFGGraphView, start: str, *, incoming: bool,
                              boundaries: frozenset[str]) -> tuple[str, ...]:
    if start in boundaries or is_null_node(start):
        return ()
    visited = {start}
    pending = [start]
    while pending:
        current = pending.pop()
        if is_null_node(current):
            continue
        edges = graph.incoming(current) if incoming else graph.outgoing(current)
        neighbors = sorted({edge.source if incoming else edge.target for edge in edges}, reverse=True)
        for neighbor in neighbors:
            if neighbor in visited:
                continue
            visited.add(neighbor)
            if neighbor not in boundaries and not is_null_node(neighbor):
                pending.append(neighbor)
    visited.remove(start)
    return tuple(sorted(visited))
