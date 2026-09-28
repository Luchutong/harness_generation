"""One frontier tool plus a narrow scope wrapper over the six existing tools."""
from __future__ import annotations

import re

from ..semantic_discovery.models import canonical, candidate_id
from ..semantic_discovery.tools import RepositoryTools, ToolBudgetExceeded, _schema, _STRING
from .frontier import function_types, type_tokens

FRONTIER_SCHEMA = _schema("get_semantic_frontier",
    "Get a bounded page of the accepted anchor's strong/weak/oversized frontier, roles and provenance. "
    "Weak links are exploration hints ONLY. Use next_offset to inspect more; omitted APIs remain unresolved.",
    {"candidate_id": _STRING, "function_id": _STRING, "offset": {"type": "integer", "minimum": 0}},
    ["candidate_id", "function_id"])


class SemanticSliceTools(RepositoryTools):
    def __init__(self, artifacts, catalog, frontier, budget=None, *, index=None, max_discovered_functions=32):
        super().__init__(artifacts, catalog, budget, index=index)
        if type(max_discovered_functions) is not int or max_discovered_functions < 0:
            raise ValueError("max_discovered_functions must be nonnegative")
        self.frontier = frontier
        self.max_discovered_functions = max_discovered_functions
        self.discovered = set()
        self.evidence_functions = {}
        self.discovery_evidence = {}
        self.known_symbols = set()
        for fid in frontier.function_ids:
            self._learn_symbols(fid)

    @property
    def authorized_ids(self):
        return self.frontier.function_ids | self.discovered

    @property
    def schemas(self):
        import json
        return super().schemas + json.loads(canonical([FRONTIER_SCHEMA]))

    def _learn_symbols(self, fid):
        f = self.index.functions[fid]
        self.known_symbols.add(f["name"])
        self.known_symbols.update(function_types(f))
        self.known_symbols.update(p["name"] for p in f.get("parameters", []) if p.get("name"))
        types = function_types(f)
        for struct in self.index.artifacts.structs:
            if types & {struct["name"], *struct.get("aliases", [])}:
                self.known_symbols.update(re.findall(r"[A-Za-z_]\w*", struct["declaration"]))

    def _get_function(self, args):
        # Ambiguous names must not expose bodies outside the authorized universe.
        matches = [f for f in self.index.resolve_functions(args["function"]) if f["id"] in self.authorized_ids]
        records = []
        for f in matches[:self.budget.max_references_per_query]:
            records.extend(super()._get_function({"function": f["id"]})[0])
        return records, len(matches)

    def execute(self, name, arguments):
        if name == "get_semantic_frontier":
            return self._frontier(arguments)
        if not isinstance(arguments, dict):
            return super().execute(name, arguments)
        if name in {"get_function", "find_callers", "find_callees"}:
            symbol = arguments.get("function")
            if not isinstance(symbol, str):
                return {"error": "invalid_tool_arguments", "evidence_ids": []}
            matches = self.index.resolve_functions(symbol)
            if not matches or not any(f["id"] in self.authorized_ids for f in matches):
                return {"error": "outside_semantic_frontier", "evidence_ids": []}
            # Calls by a nonunique spelling could investigate unrelated APIs.
            if name != "get_function" and len(matches) != 1:
                return {"error": "ambiguous_symbol_use_exact_id", "evidence_ids": []}
        elif name in {"find_symbol_references", "get_type_definition"}:
            symbol = arguments.get("symbol" if name == "find_symbol_references" else "type")
            if not isinstance(symbol, str) or not type_tokens(symbol) <= self.known_symbols:
                return {"error": "outside_semantic_frontier", "evidence_ids": []}
        elif name == "read_source_range":
            start, end, file = arguments.get("line_start"), arguments.get("line_end"), arguments.get("file")
            if (type(start) is not int or type(end) is not int or not isinstance(file, str)
                    or not any(f["file"] == file and f["start_line"] <= end and f["end_line"] >= start
                               for fid, f in self.index.functions.items() if fid in self.authorized_ids)):
                return {"error": "outside_semantic_frontier", "evidence_ids": []}
        previous = (self.source_chars, dict(self.evidence), dict(self.live_sources), set(self.discovered),
                    dict(self.discovery_evidence), dict(self.evidence_functions), set(self.known_symbols))
        output = super().execute(name, arguments)
        for record in output.get("evidence", []):
            ids = self._record_functions(record)
            self._authorize(ids, record["evidence_id"])
            self.evidence_functions[record["evidence_id"]] = ids & self.authorized_ids
            if name in {"get_function", "read_source_range"}:
                # Identifiers observed in source can seed bounded reference queries.
                self.known_symbols.update(re.findall(r"[A-Za-z_]\w*", record.get("content", "")))
        if name == "read_source_range" and output.get("evidence"):
            identities = {}
            for record in output["evidence"]:
                for fid in sorted(self.evidence_functions[record["evidence_id"]]):
                    f = self.index.functions[fid]
                    identities[fid] = {"function_id": fid, "function": f["name"], "source": f["file"],
                        "line_start": f["start_line"], "line_end": f["end_line"],
                        "evidence_id": record["evidence_id"]}
            # Exact identities are derived from the owned source evidence, never
            # invented from model spellings. Charge this additional tool payload.
            limited = [identities[fid] for fid in sorted(identities)[:self.budget.max_references_per_query]]
            cost = len(canonical(limited))
            if cost > self.budget.max_chars_per_record or self.source_chars + cost > self.budget.max_source_chars:
                reason = ("max_chars_per_record" if cost > self.budget.max_chars_per_record else "max_source_chars")
                (self.source_chars, self.evidence, self.live_sources, self.discovered, self.discovery_evidence,
                 self.evidence_functions, self.known_symbols) = previous
                raise ToolBudgetExceeded(reason)
            self.source_chars += cost
            output["project_functions"] = limited
            output["function_identities_truncated"] = len(identities) > len(limited)
        if len(self.discovered) >= self.max_discovered_functions:
            output["discovery_limit_reached"] = True
        return output

    def _record_functions(self, record):
        ids = {record.get("function_id"), record.get("caller_id"), *record.get("possible_callee_ids", [])}
        if record["tool"] == "read_source_range":
            ids.update(fid for fid, f in self.index.functions.items() if f["file"] == record["source"]
                and f["start_line"] <= record["line_end"] and f["end_line"] >= record["line_start"])
        return {fid for fid in ids if fid in self.index.functions}

    def _authorize(self, ids, eid):
        for fid in sorted(ids - self.authorized_ids):
            if len(self.discovered) >= self.max_discovered_functions:
                break
            self.discovered.add(fid)
            self.discovery_evidence[fid] = eid
            self._learn_symbols(fid)

    def _frontier(self, args, *, page_size=None):
        anchor = self.frontier.candidate.function_id
        if (not isinstance(args, dict) or not {"candidate_id", "function_id"} <= set(args)
                or set(args) - {"candidate_id", "function_id", "offset"}
                or args["candidate_id"] != candidate_id(anchor) or args["function_id"] != anchor
                or type(args.get("offset", 0)) is not int or args.get("offset", 0) < 0):
            return {"error": "invalid_tool_arguments", "evidence_ids": []}
        offset = args.get("offset", 0)
        ids = self.frontier.ordered_ids
        previous_chars, previous_evidence = self.source_chars, dict(self.evidence)
        records = []
        try:
            for fid in ids[offset:offset + (page_size or self.budget.max_references_per_query)]:
                row = self.frontier.rows[fid]
                payload = {**row, "shared_type_is_semantic_evidence": False}
                if fid == anchor:
                    payload["accepted_validation"] = self.frontier.validation
                # Put potentially large relations in content so existing record
                # and cumulative budgets apply. A truncated relation proves nothing.
                record = self._emit("get_semantic_frontier", args, {
                    "source": "candidate_discovery/validated_candidates.json" if fid == anchor else "phase1_frontier",
                    "line_start": 1, "line_end": 1, "function_id": fid, "function": row["function"],
                    "frontier_kind": "accepted_anchor" if fid == anchor else
                                     "strong_relation" if row["strong_relations"] else "weak_hint",
                    "frontier_fingerprint": self.frontier.fingerprint, "content": canonical(payload)})
                records.append(record)
        except ToolBudgetExceeded:
            self.source_chars, self.evidence = previous_chars, previous_evidence
            raise
        for record in records:
            self.evidence_functions[record["evidence_id"]] = {record["function_id"]}
        next_offset = offset + len(records)
        return {"data_class": "untrusted_repository_evidence", "evidence": records,
                "evidence_ids": [r["evidence_id"] for r in records], "total_matches": len(ids),
                "query_truncated": next_offset < len(ids), "next_offset": next_offset if next_offset < len(ids) else None,
                "frontier_provenance": self.frontier.provenance}
