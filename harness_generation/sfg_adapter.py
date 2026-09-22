"""Read-only adapters for persisted SFG Phase 1 artifacts."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping

from sfg_builder.models import SFGEdge, SFGNode
from sfg_builder.ownership import load_ownership_json


SFG_SCHEMA_VERSION = 1
CANONICAL_NULL_NODE = "(null)"
EdgePredicate = Callable[[SFGEdge], bool]


class SFGLoadError(ValueError):
    """An artifact cannot be adapted without losing required graph data."""


def is_null_node(value: object, *, kind: object = None) -> bool:
    """Recognize persisted null-node spellings without relying on one sentinel."""
    if value is None:
        return True
    if _null_token(kind) in {"null", "none"}:
        return True
    return _null_token(value) in {"null", "none"}


def normalize_null_node(value: object, *, kind: object = None,
                        canonical: str = CANONICAL_NULL_NODE) -> str:
    """Return one graph-local null ID while preserving non-null node IDs."""
    if is_null_node(value, kind=kind):
        return canonical
    if not isinstance(value, str) or not value.strip():
        raise SFGLoadError("SFG node IDs must be non-empty strings or null sentinels")
    return value.strip()


@dataclass(frozen=True)
class SFGGraphView:
    """Deterministic multi-edge graph view used by downstream traversal."""

    nodes: tuple[SFGNode, ...]
    edges: tuple[SFGEdge, ...]
    warnings: tuple[str, ...] = ()
    null_node_id: str | None = None
    _incoming: Mapping[str, tuple[SFGEdge, ...]] = field(init=False, repr=False)
    _outgoing: Mapping[str, tuple[SFGEdge, ...]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        nodes = tuple(sorted(self.nodes, key=lambda node: (node.kind != "null", node.id)))
        edges = tuple(sorted(self.edges, key=_edge_key))
        incoming: dict[str, list[SFGEdge]] = {node.id: [] for node in nodes}
        outgoing: dict[str, list[SFGEdge]] = {node.id: [] for node in nodes}
        for edge in edges:
            outgoing.setdefault(edge.source, []).append(edge)
            incoming.setdefault(edge.target, []).append(edge)
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "edges", edges)
        object.__setattr__(self, "warnings", tuple(self.warnings))
        object.__setattr__(self, "_incoming", MappingProxyType({
            node: tuple(values) for node, values in sorted(incoming.items())
        }))
        object.__setattr__(self, "_outgoing", MappingProxyType({
            node: tuple(values) for node, values in sorted(outgoing.items())
        }))

    def normalize_node(self, node: object) -> str:
        return normalize_null_node(node, canonical=self.null_node_id or CANONICAL_NULL_NODE)

    def incoming(self, node: object, *, predicate: EdgePredicate | None = None
                 ) -> tuple[SFGEdge, ...]:
        edges = self._incoming.get(self.normalize_node(node), ())
        return edges if predicate is None else tuple(edge for edge in edges if predicate(edge))

    def outgoing(self, node: object, *, predicate: EdgePredicate | None = None
                 ) -> tuple[SFGEdge, ...]:
        edges = self._outgoing.get(self.normalize_node(node), ())
        return edges if predicate is None else tuple(edge for edge in edges if predicate(edge))

    def ancestors(self, node: object, *, predicate: EdgePredicate | None = None
                  ) -> tuple[str, ...]:
        return self._reachable(node, incoming=True, predicate=predicate)

    def descendants(self, node: object, *, predicate: EdgePredicate | None = None
                    ) -> tuple[str, ...]:
        return self._reachable(node, incoming=False, predicate=predicate)

    def _reachable(self, node: object, *, incoming: bool,
                   predicate: EdgePredicate | None) -> tuple[str, ...]:
        start = self.normalize_node(node)
        visited = {start}
        pending = [start]
        while pending:
            current = pending.pop()
            # The null node is a source/terminal sentinel, not a structural
            # propagation node. Keep edges to/from it visible, but never use
            # the shared sentinel to bridge otherwise unrelated components.
            if is_null_node(current):
                continue
            edges = (self.incoming(current, predicate=predicate) if incoming
                     else self.outgoing(current, predicate=predicate))
            neighbors = sorted(
                {edge.source if incoming else edge.target for edge in edges},
                reverse=True,
            )
            for neighbor in neighbors:
                if neighbor not in visited:
                    visited.add(neighbor)
                    pending.append(neighbor)
        visited.remove(start)
        return tuple(sorted(visited))


@dataclass(frozen=True)
class SFGArtifacts:
    """The graph plus its real Phase 1 companion records, indexed by function ID."""

    graph: SFGGraphView
    project: str
    files: tuple[str, ...]
    structs: tuple[Mapping[str, Any], ...]
    function_warnings: tuple[str, ...]
    functions: tuple[Mapping[str, Any], ...]
    annotations: tuple[Mapping[str, Any], ...]
    flows: tuple[Mapping[str, Any], ...]
    embedded_flows: tuple[Mapping[str, Any], ...]
    source_schema_versions: Mapping[str, int] = field(default_factory=dict)
    ownership: tuple[Mapping[str, Any], ...] = ()
    functions_by_id: Mapping[str, Mapping[str, Any]] = field(init=False, repr=False)
    annotations_by_id: Mapping[str, Mapping[str, Any]] = field(init=False, repr=False)
    flows_by_id: Mapping[str, Mapping[str, Any]] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        functions = _sorted_records(self.functions, "id")
        structs = _sorted_records(self.structs, "name")
        annotations = _sorted_records(self.annotations, "function_id")
        flows = _sorted_records(self.flows, "function_id")
        embedded = _sorted_records(self.embedded_flows, "function_id")
        function_index = _record_index(functions, "id", "functions.json")
        annotation_index = _record_index(annotations, "function_id", "annotations.json")
        flow_index = _record_index(flows, "function_id", "flows.json")
        embedded_index = _record_index(embedded, "function_id", "sfg.json functions")

        for edge in self.graph.edges:
            for name, index in (
                ("functions.json", function_index),
                ("annotations.json", annotation_index),
                ("flows.json", flow_index),
            ):
                if edge.function_id not in index:
                    raise SFGLoadError(
                        f"SFG edge {edge.function_id!r} is missing from {name}"
                    )
        if set(embedded_index) != set(flow_index):
            raise SFGLoadError("sfg.json embedded functions do not match flows.json")

        object.__setattr__(self, "functions", functions)
        object.__setattr__(self, "files", tuple(sorted(set(self.files))))
        object.__setattr__(self, "structs", structs)
        object.__setattr__(self, "function_warnings", tuple(self.function_warnings))
        object.__setattr__(self, "annotations", annotations)
        object.__setattr__(self, "flows", flows)
        object.__setattr__(self, "embedded_flows", embedded)
        object.__setattr__(self, "source_schema_versions", MappingProxyType(
            dict(sorted(self.source_schema_versions.items()))
        ))
        object.__setattr__(self, "functions_by_id", MappingProxyType(function_index))
        object.__setattr__(self, "annotations_by_id", MappingProxyType(annotation_index))
        object.__setattr__(self, "flows_by_id", MappingProxyType(flow_index))


class SFGLoader:
    """Load a Phase 1 artifact directory without invoking the SFG pipeline."""

    def load(self, artifacts: Path) -> SFGArtifacts:
        artifacts = Path(artifacts)
        documents = {
            "functions": _load_document(artifacts / "functions.json"),
            "annotations": _load_document(artifacts / "annotations.json"),
            "flows": _load_document(artifacts / "flows.json"),
            "sfg": _load_document(artifacts / "sfg.json"),
        }
        versions = {
            name: _schema_version(document, f"{name}.json")
            for name, document in documents.items()
        }
        graph = adapt_sfg_document(documents["sfg"])
        project = documents["functions"].get("project")
        if not isinstance(project, str) or not project:
            raise SFGLoadError("functions.json project must be a non-empty string")
        files = _string_array(documents["functions"], "files", "functions.json")
        function_warnings = _string_array(
            documents["functions"], "warnings", "functions.json"
        )
        return SFGArtifacts(
            graph=graph,
            project=project,
            files=tuple(files),
            structs=tuple(_record_array(documents["functions"], "structs", "functions.json")),
            function_warnings=tuple(function_warnings),
            functions=tuple(_record_array(documents["functions"], "functions", "functions.json")),
            annotations=tuple(_record_array(
                documents["annotations"], "annotations", "annotations.json"
            )),
            flows=tuple(_record_array(documents["flows"], "flows", "flows.json")),
            embedded_flows=tuple(_record_array(documents["sfg"], "functions", "sfg.json")),
            ownership=tuple(load_ownership_json(artifacts / "ownership.json")),
            source_schema_versions=versions,
        )

    def load_graph(self, path: Path) -> SFGGraphView:
        return adapt_sfg_document(_load_document(Path(path)))


def load_sfg_artifacts(artifacts: Path) -> SFGArtifacts:
    return SFGLoader().load(artifacts)


def adapt_sfg_document(document: Mapping[str, Any]) -> SFGGraphView:
    """Adapt one parsed sfg.json object into a normalized graph view."""
    _schema_version(document, "sfg.json")
    raw_nodes = _record_array(document, "nodes", "sfg.json")
    raw_edges = _record_array(document, "edges", "sfg.json")

    nodes_by_id: dict[str, SFGNode] = {}
    null_found = False
    for record in raw_nodes:
        raw_id = record.get("id")
        raw_kind = record.get("kind")
        node_id = normalize_null_node(raw_id, kind=raw_kind)
        null_node = is_null_node(raw_id, kind=raw_kind)
        kind = "null" if null_node else _required_string(record, "kind", "SFG node")
        candidate = SFGNode(node_id, kind)
        previous = nodes_by_id.setdefault(node_id, candidate)
        if previous != candidate:
            raise SFGLoadError(f"conflicting SFG node records for {node_id!r}")
        null_found = null_found or null_node

    edges = []
    for record in raw_edges:
        source = normalize_null_node(record.get("source"))
        target = normalize_null_node(record.get("target"))
        null_found = null_found or source == CANONICAL_NULL_NODE or target == CANONICAL_NULL_NODE
        labels = record.get("labels")
        if not isinstance(labels, list) or any(not isinstance(label, str) for label in labels):
            raise SFGLoadError("SFG edge labels must be an array of strings")
        inferred = record.get("inferred", False)
        if type(inferred) is not bool:
            raise SFGLoadError("SFG edge inferred must be a boolean")
        reason = record.get("inference_reason")
        if reason is not None and not isinstance(reason, str):
            raise SFGLoadError("SFG edge inference_reason must be a string or null")
        line = record.get("line")
        if type(line) is not int or line < 1:
            raise SFGLoadError("SFG edge line must be a positive integer")
        edges.append(SFGEdge(
            source=source,
            target=target,
            function=_required_string(record, "function", "SFG edge"),
            function_id=_required_string(record, "function_id", "SFG edge"),
            labels=tuple(labels),
            file=_required_string(record, "file", "SFG edge"),
            line=line,
            inferred=inferred,
            inference_reason=reason,
        ))
        nodes_by_id.setdefault(source, SFGNode(
            source, "null" if source == CANONICAL_NULL_NODE else "struct"
        ))
        nodes_by_id.setdefault(target, SFGNode(
            target, "null" if target == CANONICAL_NULL_NODE else "struct"
        ))

    if null_found:
        nodes_by_id[CANONICAL_NULL_NODE] = SFGNode(CANONICAL_NULL_NODE, "null")
    warnings = document.get("warnings", [])
    if not isinstance(warnings, list) or any(not isinstance(item, str) for item in warnings):
        raise SFGLoadError("sfg.json warnings must be an array of strings")
    return SFGGraphView(
        tuple(nodes_by_id.values()),
        tuple(edges),
        tuple(warnings),
        CANONICAL_NULL_NODE if null_found else None,
    )


def _null_token(value: object) -> str:
    if not isinstance(value, str):
        return ""
    token = value.strip().casefold().strip("*_` ")
    while len(token) >= 2 and token[0] == "(" and token[-1] == ")":
        token = token[1:-1].strip().strip("*_` ")
    return token


def _load_document(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SFGLoadError(f"cannot load {path}: {type(exc).__name__}") from None
    if not isinstance(value, dict):
        raise SFGLoadError(f"{path} must contain a JSON object")
    return value


def _schema_version(document: Mapping[str, Any], name: str) -> int:
    version = document.get("schema_version")
    if type(version) is not int:
        raise SFGLoadError(f"{name} schema_version must be an integer")
    supported = {1, 2} if name == "functions.json" else {SFG_SCHEMA_VERSION}
    if version not in supported:
        raise SFGLoadError(f"unsupported {name} schema_version: {version}")
    return version


def _record_array(document: Mapping[str, Any], field_name: str,
                  document_name: str) -> list[Mapping[str, Any]]:
    records = document.get(field_name)
    if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
        raise SFGLoadError(f"{document_name}.{field_name} must be an array of objects")
    return records


def _string_array(document: Mapping[str, Any], field_name: str,
                  document_name: str) -> list[str]:
    values = document.get(field_name)
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise SFGLoadError(f"{document_name}.{field_name} must be an array of strings")
    return values


def _required_string(record: Mapping[str, Any], field_name: str, context: str) -> str:
    value = record.get(field_name)
    if not isinstance(value, str) or not value:
        raise SFGLoadError(f"{context} {field_name} must be a non-empty string")
    return value


def _sorted_records(records: tuple[Mapping[str, Any], ...], id_field: str
                    ) -> tuple[Mapping[str, Any], ...]:
    for record in records:
        _required_string(record, id_field, "artifact record")
    return tuple(sorted(records, key=lambda record: record[id_field]))


def _record_index(records: tuple[Mapping[str, Any], ...], id_field: str,
                  name: str) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for record in records:
        identifier = record[id_field]
        if identifier in result:
            raise SFGLoadError(f"duplicate {id_field} {identifier!r} in {name}")
        result[identifier] = record
    return result


def _edge_key(edge: SFGEdge) -> tuple[Any, ...]:
    return (
        edge.source,
        edge.target,
        edge.function_id,
        edge.function,
        edge.labels,
        edge.file,
        edge.line,
        edge.inferred,
        edge.inference_reason or "",
    )
