"""Read-only frontier construction. Every structural link remains a weak hint."""
from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property
import re

from ..ft_relations import LegacyStructuralClosure
from ..semantic_discovery.models import candidate_id, digest


def type_tokens(value):
    return set(re.findall(r"[A-Za-z_][A-Za-z_0-9]*", value or "")) - {
        "const", "struct", "union", "volatile", "restrict"}


def function_types(function):
    return set().union(type_tokens(function.get("return_type", "")),
                       *(type_tokens(p.get("base_type") or p.get("type", ""))
                         for p in function.get("parameters", [])))


def _relation_ids(record):
    return {x for x in [record.get("producer_function_id"), record.get("cleanup_function_id"),
                        *record.get("consumer_function_ids", []), *record.get("function_ids", [])]
            if isinstance(x, str)}


@dataclass
class SemanticFrontier:
    candidate: object
    validation: dict
    rows: dict
    provenance: dict

    @property
    def function_ids(self):
        return frozenset(self.rows)

    @property
    def ordered_ids(self):
        anchor = self.candidate.function_id
        return [anchor] + sorted(self.function_ids - {anchor},
                                 key=lambda fid: (not bool(self.rows[fid]["strong_relations"]), fid))

    @cached_property
    def fingerprint(self):
        return digest({"rows": self.rows, "provenance": self.provenance,
                       "validation": self.validation})


def build_frontier(store, artifacts, catalog, candidate, validation):
    """Reuse Phase 1 identities and closure as hints; never construct or write an FT."""
    anchor = candidate.function_id
    known = artifacts.functions_by_id
    rows = {}
    provenance = {"source_fingerprint": catalog.source_fingerprint,
                  "candidate_id": candidate_id(anchor), "optional_artifacts": {},
                  "warnings": [], "shared_type_is_semantic_evidence": False}

    def include(fid, origin, *, weak=None, strong=None, oversized=False):
        if fid not in known:
            raise ValueError("frontier references a function absent from Phase 1")
        f = known[fid]
        annotation = artifacts.annotations_by_id.get(fid, {})
        flow = artifacts.flows_by_id.get(fid, {})
        row = rows.setdefault(fid, {"function_id": fid, "function": f["name"], "source": f["file"],
            "line_start": f["start_line"], "line_end": f["end_line"],
            "existing_roles": {key: annotation.get(key) for key in ("labels", "is_prf", "is_hpf", "operation")
                               if key in annotation},
            "existing_flow": {key: flow.get(key) for key in ("input_structs", "output_structs", "complex_flow", "source")
                              if key in flow},
            "weak_relations": [], "strong_relations": [], "oversized_frontier": False,
            "provenance": []})
        if origin not in row["provenance"]:
            row["provenance"].append(origin)
        if weak and weak not in row["weak_relations"]:
            row["weak_relations"].append(weak)
        if strong and strong not in row["strong_relations"]:
            row["strong_relations"].append(strong)
        row["oversized_frontier"] |= oversized

    include(anchor, "accepted_candidate")
    anchor_edges = tuple(e for e in artifacts.graph.edges if e.function_id == anchor)
    selection = LegacyStructuralClosure().select(artifacts.graph, anchor_id=anchor,
        anchor_edges=anchor_edges, masked_edges=(), boundaries=frozenset(), owned_return_producer=False)
    for edge in selection.edges:
        include(edge.function_id, "sfg.json/flows.json", weak={"kind": "sfg_type_reachability",
            "source_node": edge.source, "target_node": edge.target})
    # Phase 1 may omit flows for functions that merely share a context. Preserve
    # those neighbors as hints without guessing behavioral roles from API names.
    struct_names = {name for s in artifacts.structs for name in [s["name"], *s.get("aliases", [])]}
    for f in artifacts.functions:
        if f.get("return_is_struct_like") or f.get("return_is_opaque_handle"):
            struct_names.update(type_tokens(f.get("return_base_type")))
        for parameter in f.get("parameters", []):
            if parameter.get("is_struct_like") or parameter.get("is_opaque_handle"):
                struct_names.update(type_tokens(parameter.get("base_type")))
    context_types = function_types(known[anchor]) & struct_names
    for f in artifacts.functions:
        shared = context_types & function_types(f)
        if shared:
            include(f["id"], "functions.json/structs", weak={"kind": "same_struct_type",
                                                           "types": sorted(shared)})
    producer = known[anchor]
    if producer.get("return_pointer_depth", 0):
        for function in artifacts.functions:
            if any(p.get("is_pointer") and p.get("base_type") == producer.get("return_base_type")
                   for p in function.get("parameters", [])):
                include(function["id"], "functions.json/producer-return", weak={
                    "kind": "producer_return_consumer_candidate", "producer_function_id": anchor,
                    "resource_type": producer.get("return_base_type"), "ownership_established": False})

    diagnostics = candidate.metadata.get("construction", {}).get("diagnostics", [])
    extra_relations = []

    def consume_oversized(records, origin):
        for record in records:
            if record.get("anchor_function_id") != anchor:
                continue
            frontier = record.get("frontier", {})
            for fid in frontier.get("function_ids", []):
                include(fid, origin, weak={"kind": "oversized_structural_frontier"}, oversized=True)
            extra_relations.extend(frontier.get("relation_evidence", {}).get("strong", []))

    consume_oversized(diagnostics, "candidate_discovery/construction")
    seed = set(rows)
    for kind, records, origin in (("ownership", artifacts.ownership, "ownership.json"),
                                  ("explicit_usage_pattern", artifacts.usage_patterns, "usage_patterns.json")):
        for relation in records:
            ids = _relation_ids(relation)
            if not ids & seed:
                continue
            fact = {"kind": kind, "record_id": relation.get("id"), "function_ids": sorted(ids),
                    "resource_type": relation.get("resource_type"), "source": relation.get("source"),
                    "confidence": relation.get("confidence"), "evidence": relation.get("evidence", []),
                    "provenance": origin}
            for fid in ids:
                include(fid, origin, strong=fact)
    for relation in extra_relations:
        for fid in _relation_ids(relation):
            include(fid, "existing_relation_evidence", strong=relation)
    for row in rows.values():
        for key in ("weak_relations", "strong_relations"):
            row[key] = sorted(row[key], key=digest)
        row["provenance"].sort()
    return SemanticFrontier(candidate, validation, dict(sorted(rows.items())), provenance)
