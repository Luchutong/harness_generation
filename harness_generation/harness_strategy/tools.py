"""Bounded, read-only investigation tools for proposed harness strategies.

An issued source witness can extend the callable investigation scope, but it
does not prove that the discovered API constructs, consumes, or releases a
resource.  The six underlying queries and their source authentication remain
the same as RepositoryTools.
"""
from __future__ import annotations

from copy import deepcopy
import re

from ..semantic_discovery.models import canonical
from ..semantic_discovery.tools import RepositoryTools, ToolBudgetExceeded
from ..semantic_slicing.frontier import function_types, type_tokens


def _function_ids(rows):
    return {row if isinstance(row, str) else row.get("function_id")
            for row in rows if isinstance(row, (str, dict))} - {None}


def ft_function_ids(ft):
    """Return only the FT's initial non-excluded investigation identities."""
    result = _function_ids(ft.get("core_functions", []))
    result.update(_function_ids(ft.get("support_candidates", [])))
    anchor = ft.get("anchor_function_id", ft.get("anchor_fid"))
    if isinstance(anchor, str):
        result.add(anchor)
    return result - _function_ids(ft.get("excluded_functions", []))


class StrategyTools(RepositoryTools):
    """FT-scoped RepositoryTools with transactional, witnessed discovery."""

    registry_version = "harness-strategy-tools-v1"

    def __init__(self, snapshot, catalog, ft, budget, *, index=None, build_analysis=None,
                 context_authorization=None):
        if (ft.get("context_type") == "lightweight_api_context"
                or ft.get("artifact_kind") == "lightweight_api_context_reference"):
            from ..lightweight_context.models import LightweightAPIContext
            if (type(context_authorization) is not LightweightAPIContext
                    or context_authorization.strategy_input != ft):
                raise ValueError("lightweight strategy scope requires its live context receipt")
            context_authorization.validate(snapshot, index)
        elif context_authorization is not None:
            raise ValueError("lightweight authorization cannot be attached to another context")
        self.context_authorization = context_authorization
        self.snapshot, self.ft, self.strategy_budget = snapshot, ft, budget
        super().__init__(snapshot.artifacts, catalog, budget.investigation, index=index)
        self.build_analysis = build_analysis
        if build_analysis is not None:
            from ..source_analysis import BuildAwareIndex
            if not isinstance(build_analysis, BuildAwareIndex):
                raise ValueError("compiler metadata requires authenticated BuildAwareIndex")
            build_analysis.validate_snapshot(snapshot)
        limit = budget.max_discovered_functions
        if type(limit) is not int or limit < 0:
            raise ValueError("max_discovered_functions must be nonnegative")
        self.max_discovered_functions = limit
        self.excluded = _function_ids(ft.get("excluded_functions", []))
        self.initial_ids = ft_function_ids(ft)
        if not self.initial_ids or not self.initial_ids <= self.index.functions.keys():
            raise ValueError("FT investigation scope contains unknown or no function identities")
        self.discovered = set()
        self.evidence_functions = {}
        self.discovery_evidence = {}
        self.known_symbols = set()
        self.trace = []
        for fid in sorted(self.initial_ids):
            self._learn_symbols(fid)

    @property
    def authorized_ids(self):
        return self.initial_ids | self.discovered

    def _learn_symbols(self, fid):
        function = self.index.functions[fid]
        types = function_types(function)
        self.known_symbols.add(function["name"])
        self.known_symbols.update(types)
        self.known_symbols.update(p["name"] for p in function.get("parameters", []) if p.get("name"))
        for struct in self.index.artifacts.structs:
            if types & {struct["name"], *struct.get("aliases", [])}:
                self.known_symbols.update(re.findall(r"[A-Za-z_]\w*", struct["declaration"]))

    def _scope_error(self, name, arguments):
        # Leave basic argument/schema failures to the underlying six tools.
        if not isinstance(arguments, dict):
            return None
        if name in {"get_function", "find_callers", "find_callees"}:
            symbol = arguments.get("function")
            if not isinstance(symbol, str):
                return None
            matches = self.index.resolve_functions(symbol)
            if not matches or not all(f["id"] in self.authorized_ids for f in matches):
                return "outside_strategy_scope"
            if len(matches) != 1:
                return "ambiguous_symbol_use_exact_id"
        elif name in {"find_symbol_references", "get_type_definition"}:
            symbol = arguments.get("symbol" if name == "find_symbol_references" else "type")
            if isinstance(symbol, str) and not type_tokens(symbol) <= self.known_symbols:
                return "outside_strategy_scope"
        elif name == "read_source_range":
            start, end, filename = (arguments.get("line_start"), arguments.get("line_end"),
                                    arguments.get("file"))
            if type(start) is not int or type(end) is not int or not isinstance(filename, str):
                return None
            overlapping = {fid for fid, function in self.index.functions.items()
                           if function["file"] == filename and function["start_line"] <= end
                           and function["end_line"] >= start}
            if not overlapping & self.authorized_ids or overlapping & self.excluded:
                return "outside_strategy_scope"
        return None

    def _get_function(self, arguments):
        # Scope checks guarantee one exact project identity, even for a spelling.
        function = self.index.resolve_functions(arguments["function"])[0]
        return super()._get_function({"function": function["id"]})

    def _find_callers(self, arguments):
        self.index.build_syntax_index()
        names = {f["name"] for f in self.index.resolve_functions(arguments["function"])}
        found = [call for call in self.index.calls if call["direct"] and call["callee"] in names
                 and call["caller_id"] not in self.excluded]
        return self._call_records(found[:self.budget.max_callers]), len(found)

    def _call_records(self, calls):
        records = super()._call_records(calls)
        for record in records:
            record["possible_callee_ids"] = [fid for fid in record["possible_callee_ids"]
                                              if fid not in self.excluded]
        return records

    def _find_symbol_references(self, arguments):
        self.index.build_syntax_index()
        found = [row for row in self.index.references.get(arguments["symbol"], [])
                 if row["function_id"] not in self.excluded]
        unique = list({(row["function_id"], row["line"]): row for row in found}.values())
        return [{"source": row["source"], "line_start": row["line"], "line_end": row["line"],
                 "content": row["content"], "function_id": row["function_id"],
                 "symbol_resolution": "identifier_spelling_only"}
                for row in unique[:self.budget.max_references_per_query]], len(unique)

    def _record_functions(self, record):
        ids = {record.get("function_id"), record.get("caller_id"),
               *record.get("possible_callee_ids", [])}
        if record["tool"] == "read_source_range":
            ids.update(fid for fid, function in self.index.functions.items()
                       if function["file"] == record["source"]
                       and function["start_line"] <= record["line_end"]
                       and function["end_line"] >= record["line_start"])
        return (ids & self.index.functions.keys()) - self.excluded

    def _authorize(self, ids, eid):
        if self.context_authorization is not None:
            return  # The independent Clang scope cannot expand through source queries.
        for fid in sorted(ids - self.authorized_ids - self.excluded):
            if len(self.discovered) >= self.max_discovered_functions:
                break
            self.discovered.add(fid)
            self.discovery_evidence[fid] = eid
            self._learn_symbols(fid)

    def _checkpoint(self):
        return (self.source_chars, dict(self.evidence), dict(self.live_sources), set(self.discovered),
                dict(self.discovery_evidence), dict(self.evidence_functions), set(self.known_symbols))

    def _restore(self, checkpoint):
        (self.source_chars, self.evidence, self.live_sources, self.discovered,
         self.discovery_evidence, self.evidence_functions, self.known_symbols) = checkpoint

    def execute(self, name, arguments):
        checkpoint = self._checkpoint()
        try:
            error = self._scope_error(name, arguments)
            output = ({"error": error, "evidence_ids": []} if error
                      else super().execute(name, arguments))
            if output.get("error"):
                self._restore(checkpoint)
            else:
                for record in output.get("evidence", []):
                    ids = self._record_functions(record)
                    self._authorize(ids, record["evidence_id"])
                    self.evidence_functions[record["evidence_id"]] = ids & self.authorized_ids
                    if name in {"get_function", "read_source_range"}:
                        self.known_symbols.update(re.findall(r"[A-Za-z_]\w*", record.get("content", "")))
                metadata = {"authorized_function_ids": sorted(self.authorized_ids),
                            "authorization_is_semantic_proof": False,
                            "discovery_limit_reached": len(self.discovered) >= self.max_discovered_functions}
                if name == "read_source_range" and output.get("evidence"):
                    identities = {}
                    for record in output["evidence"]:
                        for fid in sorted(self.evidence_functions[record["evidence_id"]]):
                            function = self.index.functions[fid]
                            identities[fid] = {"function_id": fid, "function": function["name"],
                                               "source": function["file"], "line_start": function["start_line"],
                                               "line_end": function["end_line"],
                                               "evidence_id": record["evidence_id"]}
                    limited = [identities[fid] for fid in sorted(identities)[:self.budget.max_references_per_query]]
                    metadata["project_functions"] = limited
                    metadata["function_identities_truncated"] = len(identities) > len(limited)
                if self.build_analysis is not None and name in {"get_function", "get_type_definition"}:
                    from ..source_analysis import agent_projection
                    # These compiler certificates accompany the response, not
                    # the raw-source EID. Scope and the same character budget
                    # apply to both source and compiler metadata.
                    projected_arguments = arguments
                    if name == "get_function":
                        projected_arguments = {"function": self.index.resolve_functions(arguments["function"])[0]["id"]}
                    metadata["build_aware"] = agent_projection(name, projected_arguments, self.build_analysis,
                        max_chars=max(1024, min(16384, self.budget.max_chars_per_record)))
                cost = len(canonical(metadata))
                if cost > self.budget.max_chars_per_record:
                    raise ToolBudgetExceeded("max_chars_per_record")
                if self.source_chars + cost > self.budget.max_source_chars:
                    raise ToolBudgetExceeded("max_source_chars")
                self.source_chars += cost
                output.update(metadata)
        except ToolBudgetExceeded as exc:
            self._restore(checkpoint)
            output = {"error": "tool_budget_exceeded", "reason": str(exc), "evidence_ids": []}
            self.trace.append({"name": name, "arguments": deepcopy(arguments), "output": output})
            raise
        except Exception:
            self._restore(checkpoint)
            raise
        self.trace.append({"name": name, "arguments": deepcopy(arguments), "output": deepcopy(output)})
        return output
