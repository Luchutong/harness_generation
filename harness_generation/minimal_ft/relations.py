"""Project persisted relationships without discovering or classifying APIs."""
from __future__ import annotations

import json

from ..semantic_discovery.models import canonical, digest
from ..sfg_adapter import is_null_node
from .models import support_kind


class UnresolvedDependencies:
    """Known IDs are references; unknown endpoints never become declared APIs."""
    def __init__(self):
        self.rows = {}

    def add(self, fid, questions, *, reference=None, provenance=None):
        row = self.rows.setdefault(fid, {"function_id": fid, "questions": set(), "references": {}})
        row["questions"].update(questions)
        if reference is not None or provenance is not None:
            ref = {"reference": reference, "provenance": provenance or {}}
            row["references"][digest(ref)] = ref

    def to_list(self):
        return [{"function_id": row["function_id"], "questions": sorted(row["questions"]),
                 "references": sorted(row["references"].values(), key=canonical)}
                for _, row in sorted(self.rows.items(), key=lambda item: (item[0] is None, item[0] or ""))]


def relation_id(relation):
    return "rel_" + digest({k: v for k, v in relation.items() if k != "relation_id"})[:32]


class RelationBuilder:
    def __init__(self, source, snapshot, dependencies):
        self.source, self.snapshot, self.dependencies = source, snapshot, dependencies
        doc = source.document
        self.core = set(doc["core_functions"])
        self.allowed = self.core | set(doc["support_functions"]) | set(doc["unresolved_frontier"])
        self.excluded = set(doc["excluded_functions"])
        self.anchor = doc["anchor_function_id"]
        self.rows = {}

    def add(self, left, right, kind, strength, provenance, evidence_ids=()):
        if (left is not None and not isinstance(left, str)) or (right is not None and not isinstance(right, str)):
            provenance = {**provenance, "malformed_endpoints": [left, right]}
            left, right = left if isinstance(left, str) else None, right if isinstance(right, str) else None
        if left in self.excluded or right in self.excluded:
            # An authoritative EXCLUDE is not converted back into uncertainty.
            return
        if not ({left, right} & self.allowed):
            return
        for fid in (left, right):
            if fid not in self.allowed:
                code = "relation_endpoint_missing" if fid is None else (
                    "relation_endpoint_unknown" if fid not in self.snapshot.functions else "relation_endpoint_outside_slice")
                self.dependencies.add(None, [code], reference=fid, provenance=provenance)
        if left not in self.allowed or right not in self.allowed or left == right:
            return
        record = {"source_function_id": left, "target_function_id": right, "kind": kind, "strength": strength,
                  "provenance": provenance, "evidence_ids": sorted(set(evidence_ids))}
        rid = relation_id(record)
        self.rows[rid] = {"relation_id": rid, **record}

    def contract(self, fact, provenance, evidence_ids=()):
        if not isinstance(fact, dict):
            return
        kind = fact.get("kind")
        producer, cleanup = fact.get("producer_function_id"), fact.get("cleanup_function_id")
        consumers = fact.get("consumer_function_ids", [])
        if not isinstance(consumers, (list, tuple)):
            consumers = []
        if producer is not None or cleanup is not None or any(isinstance(c, str) for c in consumers):
            self.add(producer, cleanup, "shares_resource", "strong", provenance, evidence_ids)
            for consumer in sorted(set(c for c in consumers if isinstance(c, str))):
                self.add(producer, consumer, "shares_resource", "strong", provenance, evidence_ids)
                self.add(consumer, cleanup, "shares_resource", "strong", provenance, evidence_ids)
        else:
            identifiers = fact.get("function_ids", [])
            if not isinstance(identifiers, list):
                return
            ids = sorted(set(fid for fid in identifiers if isinstance(fid, str)))
            if not isinstance(kind, str) or kind not in {"ownership", "lifecycle", "explicit_usage_pattern"}:
                if set(ids) & self.allowed:
                    self.dependencies.add(None, ["relation_kind_unresolved"], provenance=provenance)
                return
            if len(ids) < 2:
                self.add(ids[0] if ids else None, None, "shares_resource", "strong", provenance, evidence_ids)
            else:
                # A persisted group is an undirected resource association. Use a
                # deterministic star rather than inventing N^2 ordered calls.
                pivot = self.anchor if self.anchor in ids else next((fid for fid in ids if fid in self.allowed), ids[0])
                for fid in ids:
                    if fid != pivot:
                        self.add(pivot, fid, "shares_resource", "strong", provenance, evidence_ids)

    def build(self):
        artifacts = self.snapshot.artifacts
        for artifact, kind, facts in (("ownership.json", "ownership_relation", artifacts.ownership),
                                      ("usage_patterns.json", "usage_pattern", artifacts.usage_patterns)):
            for fact in facts:
                provenance = {"artifact": artifact, "kind": kind, "record_id": fact.get("id"),
                              "fact_digest": digest(fact), "source": fact.get("source"),
                              "resource_type": fact.get("resource_type"), "confidence": fact.get("confidence")}
                self.contract(dict(fact), provenance)
        for record in self.source.records.values():
            eid = record["evidence_id"]
            provenance = {"artifact": self.source.path.replace("slice.json", "evidence.json"),
                          "record_id": eid, "fact_digest": digest(record)}
            if record.get("tool") in {"find_callers", "find_callees"}:
                caller = record.get("caller_id")
                targets = record.get("possible_callee_ids", [])
                if not isinstance(targets, list):
                    targets = []
                if not isinstance(caller, str) or caller not in self.allowed:
                    continue
                if not record.get("direct"):
                    self.dependencies.add(caller, ["indirect_call_unresolved"], reference=record.get("callee"), provenance=provenance)
                    continue
                if len(targets) != 1:
                    self.dependencies.add(caller, ["call_target_unresolved"], reference=record.get("callee"), provenance=provenance)
                    continue
                # The existing tools explicitly report name-only, unproven
                # resolution. Preserve a weak syntactic call, never upgrade it.
                self.add(caller, targets[0], "calls", "weak",
                         {**provenance, "kind": "syntactic_call", "symbol_resolution": record.get("symbol_resolution")}, [eid])
            elif record.get("tool") == "get_semantic_frontier" and not record.get("truncated"):
                try:
                    payload = json.loads(record.get("content", ""))
                except (ValueError, TypeError):
                    continue
                if (not isinstance(payload, dict) or not isinstance(payload.get("function_id"), str)
                        or payload["function_id"] != record.get("function_id")):
                    continue
                strong, weak = payload.get("strong_relations", []), payload.get("weak_relations", [])
                if not isinstance(strong, list) or not isinstance(weak, list):
                    if payload["function_id"] in self.allowed:
                        self.dependencies.add(payload["function_id"], ["frontier_relations_malformed"], provenance=provenance)
                    continue
                for fact in strong:
                    self.contract(fact, {**provenance, "kind": "slice_strong_relation",
                                         "relation_record_id": fact.get("record_id") if isinstance(fact, dict) else None}, [eid])
                for fact in weak:
                    if isinstance(fact, dict):
                        self.add(self.anchor, payload["function_id"], "structural", "weak",
                                 {**provenance, "kind": "slice_weak_relation", "structural_fact": fact}, [eid])
        # SFG/flow endpoints are TYPE nodes. Never treat the shared null sentinel
        # as a link, and never turn those type links into behavioral dependency.
        structures = {}
        for edge in artifacts.graph.edges:
            if edge.function_id in self.allowed:
                for node in (edge.source, edge.target):
                    if not is_null_node(node):
                        structures.setdefault(("sfg.json", node), set()).add(edge.function_id)
        for flow in artifacts.flows:
            if flow["function_id"] in self.allowed:
                for node in [*flow.get("input_structs", []), *flow.get("output_structs", [])]:
                    if isinstance(node, str) and not is_null_node(node):
                        structures.setdefault(("flows.json", node), set()).add(flow["function_id"])
        for (artifact, node), ids in sorted(structures.items()):
            pivots = sorted(ids & self.core)
            if not pivots:
                continue
            pivot = self.anchor if self.anchor in ids else pivots[0]
            for fid in sorted(ids - {pivot}):
                self.add(pivot, fid, "structural", "weak", {"artifact": artifact, "kind": "type_node", "node": node})
        for item in self.source.legacy.get("relation_facts", []):
            self.contract(item["fact"], item["provenance"])
        return [self.rows[rid] for rid in sorted(self.rows)]


def project_relations_and_dependencies(source, snapshot):
    """Reproducible facts and gaps, also replayed by the output validator."""
    doc = source.document
    rows = {row["function_id"]: row for row in doc["classification"]}
    dependencies = UnresolvedDependencies()
    for fid in doc["unresolved_frontier"]:
        dependencies.add(fid, rows.get(fid, {}).get("open_questions") or ["semantic_slice_not_investigated"])
    for fid in doc["support_functions"]:
        if support_kind(rows[fid]["reason_codes"]) == "unknown":
            dependencies.add(fid, ["support_kind_unresolved"])
    if doc["budget"].get("exhausted") and not doc["unresolved_frontier"]:
        dependencies.add(None, ["semantic_slice_incomplete"], provenance={"artifact": source.path})
    relations = RelationBuilder(source, snapshot, dependencies).build()
    return relations, dependencies.to_list()


def legacy_comparison(core_ids, legacy):
    known = set(legacy.get("function_ids", []))
    core = set(core_ids)
    return {"legacy_ft_found": bool(legacy.get("found")), "core_overlap": sorted(core & known),
            "new_core_only": sorted(core - known), "legacy_only": sorted(known - core),
            "legacy_ft_ids": sorted(legacy.get("ft_ids", [])),
            "oversized_frontier": sorted(legacy.get("oversized_frontier", [])),
            "comparison_status": legacy.get("comparison_status", "absent")}
