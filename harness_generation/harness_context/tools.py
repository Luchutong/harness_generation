"""Requirement-scoped read-only adapters around existing RepositoryTools."""
import json
import re

from ..semantic_discovery.models import canonical, ValidationBudget
from ..semantic_discovery.tools import RepositoryTools, _schema, _STRING, ToolBudgetExceeded
from ..semantic_slicing.frontier import function_types, type_tokens
from .models import TOOL_VERSION

EXTRA_SCHEMAS = (
    _schema("get_function_signature", "Get an authorized exact function signature and linkage metadata.", {"function": _STRING}, ["function"]),
    _schema("get_struct_fields", "Get a relevant indexed struct declaration and fields, including callback ABI.", {"type": _STRING}, ["type"]),
    *(_schema(name, "Bounded structural signature candidates for a relevant type. These are NOT lifecycle/ownership proof; inspect their bodies.",
              {"type": _STRING}, ["type"]) for name in ("find_type_usages", "find_initializers", "find_cleanup_candidates")),
    _schema("find_assignments", "Find bounded syntactic identifier/field usages for a symbol already observed in this requirement.", {"symbol": _STRING}, ["symbol"]),
    _schema("find_return_usages", "Find bounded syntactic callers of the authorized function; not proof of ownership.", {"function": _STRING}, ["function"]),
    _schema("find_function_argument_usages", "Get the authorized function body containing a real parameter; no inferred semantics.",
            {"function": _STRING, "parameter": _STRING}, ["function", "parameter"]),
)


class HarnessContextTools(RepositoryTools):
    registry_version = TOOL_VERSION

    def __init__(self, snapshot, catalog, ft, state, *, index):
        self.state, self.snapshot, self.ft = state, snapshot, ft
        limits = state.budget
        super().__init__(snapshot.artifacts, catalog, ValidationBudget(
            max_rounds=limits.max_rounds_per_requirement, max_tool_calls=limits.max_tool_calls,
            max_source_chars=limits.max_source_chars, max_references_per_query=limits.max_references_per_query,
            max_callers=limits.max_references_per_query, max_callees=limits.max_references_per_query,
            max_lines_per_read=limits.max_lines_per_read, max_chars_per_record=limits.max_chars_per_record), index=index)
        self.evidence = state.evidence
        self.initial_ids = {r["function_id"] for r in ft["core_functions"] + ft["support_candidates"]}
        self.core_ids = {r["function_id"] for r in ft["core_functions"]}
        self.excluded = set(ft["excluded_functions"])
        self.requirement = None
        self.visible_ids, self.known_symbols, self.scope_ids = set(), set(), set()

    @property
    def source_chars(self):
        return self.state.source_chars

    @source_chars.setter
    def source_chars(self, value):
        self.state.source_chars = value

    @property
    def schemas(self):
        return super().schemas + json.loads(canonical(EXTRA_SCHEMAS))

    def activate(self, requirement, facts=()):
        from .evidence import api_roles
        self.requirement = requirement
        fid = requirement["subject_function_id"]
        relevant = [fact for fact in facts if fact["function_id"] == fid or fid in api_roles(fact)]
        linked = {api for fact in relevant for api in api_roles(fact)}
        subject_allowed = fid in self.initial_ids or fid in self.state.discoveries or (
            fid in {gap["function_id"] for gap in self.ft["unresolved_dependencies"]}
            and len(self.state.discoveries) < self.state.budget.max_discovered_functions
            and self.state.budget.max_dependency_depth >= 1)
        self.scope_ids = self.initial_ids | ({fid} if subject_allowed else set()) | linked | {api for api, info in self.state.discoveries.items()
            if requirement["requirement_id"] in info["requirement_ids"] or info["parent_function_id"] == fid}
        self.known_symbols = set()
        self.visible_ids = {eid for fact in relevant for eid in fact["evidence_ids"] if eid in self.evidence}
        for api in self.scope_ids:
            self._learn(api)

    def _learn(self, fid):
        function = self.snapshot.functions[fid]
        self.known_symbols |= function_types(function) | {function["name"]}
        self.known_symbols.update(p["name"] for p in function.get("parameters", []) if p.get("name"))
        for struct in self.snapshot.artifacts.structs:
            if function_types(function) & {struct["name"], *struct.get("aliases", [])}:
                self.known_symbols.update(re.findall(r"[A-Za-z_]\w*", struct["declaration"]))

    def depth(self, fid):
        return 0 if fid in self.core_ids else self.state.discoveries.get(fid, {}).get("depth", 1)

    def _emit(self, tool, arguments, record):
        record = super()._emit(tool, arguments, {**record, "requirement_id": self.requirement["requirement_id"]})
        self.visible_ids.add(record["evidence_id"])
        return record

    def bootstrap(self):
        output = self.execute("get_function", {"function": self.requirement["subject_function_id"]})
        if output.get("error"):
            raise ValueError("tool_scope_exhausted")
        # Previous confirmed facts expose only evidence about this subject, not
        # the repository or unrelated requirement histories.
        prior = [self.evidence[eid] for eid in sorted(self.visible_ids - set(output["evidence_ids"]))]
        cost = sum(len(canonical(record)) for record in prior)
        if self.source_chars + cost > self.state.budget.max_source_chars:
            raise ToolBudgetExceeded("max_source_chars")
        self.source_chars += cost
        output["evidence"].extend(prior)
        output["evidence_ids"].extend(record["evidence_id"] for record in prior)
        return output

    def execute(self, name, arguments):
        if self.state.tool_calls >= self.state.budget.max_tool_calls:
            self.state.budget_stop = "max_tool_calls"
            raise ToolBudgetExceeded("max_tool_calls")
        self.state.tool_calls += 1
        schemas = {schema["function"]["name"]: schema["function"]["parameters"] for schema in self.schemas}
        if name not in schemas:
            return {"error": "tool_not_allowed", "evidence_ids": []}
        schema = schemas[name]
        if not isinstance(arguments, dict) or set(arguments) != set(schema["required"]):
            return {"error": "invalid_tool_arguments", "evidence_ids": []}
        for key, value in arguments.items():
            if schema["properties"][key]["type"] == "string":
                if not isinstance(value, str) or not value or len(value) > 512:
                    return {"error": "invalid_tool_arguments", "evidence_ids": []}
            elif type(value) is not int or value < 1:
                return {"error": "invalid_tool_arguments", "evidence_ids": []}
        if "function" in arguments:
            if arguments["function"] not in self.scope_ids:
                return {"error": "outside_requirement_scope_use_discovery_tool", "evidence_ids": []}
        if "type" in arguments or "symbol" in arguments:
            symbol = arguments.get("type", arguments.get("symbol"))
            if not type_tokens(symbol) or not type_tokens(symbol) <= self.known_symbols:
                return {"error": "outside_requirement_scope", "evidence_ids": []}
        if name == "read_source_range":
            start, end, file = arguments["line_start"], arguments["line_end"], arguments["file"]
            if not any(f["file"] == file and f["start_line"] <= start <= end <= f["end_line"]
                       for fid, f in self.snapshot.functions.items() if fid in self.scope_ids):
                return {"error": "outside_requirement_scope", "evidence_ids": []}
        if name not in {s["function"]["name"] for s in EXTRA_SCHEMAS}:
            visible_before = set(self.visible_ids)
            try:
                output = super().execute(name, arguments)
            except ToolBudgetExceeded:
                # RepositoryTools rolls back its local evidence mapping.
                restored = dict(self.evidence)
                self.state.evidence.clear()
                self.state.evidence.update(restored)
                self.evidence = self.state.evidence
                self.visible_ids = visible_before
                raise
        else:
            before = self.source_chars, dict(self.evidence), set(self.visible_ids)
            try:
                records, total = getattr(self, "_" + name)(arguments)
                issued = [self._emit(name, arguments, record) for record in records]
            except (OSError, ValueError):
                return {"error": "source_unavailable_or_invalid_query", "evidence_ids": []}
            except ToolBudgetExceeded:
                self.source_chars, records_before, self.visible_ids = before
                self.evidence.clear()
                self.evidence.update(records_before)
                raise
            output = {"data_class": "untrusted_repository_evidence", "evidence": issued,
                      "evidence_ids": [r["evidence_id"] for r in issued], "query_truncated": total > len(issued),
                      "total_matches": total}
        identities, blocked = [], []
        parent = arguments.get("function", self.requirement["subject_function_id"])
        if parent not in self.initial_ids and parent not in self.state.discoveries:
            parent = next(iter(self.requirement["required_by"]), self.ft["anchor_function_id"])
        for record in output.get("evidence", []):
            self.known_symbols.update(re.findall(r"[A-Za-z_]\w*", record.get("content", "")))
            ids = {record.get("function_id"), record.get("caller_id"), *record.get("possible_callee_ids", [])}
            if name == "read_source_range":
                ids.update(fid for fid, f in self.snapshot.functions.items() if f["file"] == record["source"]
                    and record["line_start"] <= f["start_line"] <= record["line_end"])
            for fid in sorted(x for x in ids if isinstance(x, str) and x in self.snapshot.functions):
                if fid in self.excluded:
                    blocked.append({"function_id": fid, "reason": "upstream_excluded"})
                    continue
                depth = self.depth(parent) + 1
                if fid not in self.initial_ids and fid not in self.state.discoveries:
                    if len(self.state.discoveries) >= self.state.budget.max_discovered_functions or depth > self.state.budget.max_dependency_depth:
                        blocked.append({"function_id": fid, "reason": "discovery_or_depth_budget"})
                        continue
                    self.state.discoveries[fid] = {"depth": depth, "parent_function_id": parent,
                        "evidence_ids": [], "requirement_ids": []}
                if fid in self.state.discoveries:
                    info = self.state.discoveries[fid]
                    if record["evidence_id"] not in info["evidence_ids"]:
                        info["evidence_ids"].append(record["evidence_id"])
                    if self.requirement["requirement_id"] not in info["requirement_ids"]:
                        info["requirement_ids"].append(self.requirement["requirement_id"])
                self.scope_ids.add(fid)
                self._learn(fid)
                identities.append({"function_id": fid, "function": self.snapshot.functions[fid]["name"],
                                   "evidence_id": record["evidence_id"], "depth": self.depth(fid)})
        output["project_functions"] = identities[:self.state.budget.max_references_per_query * 2]
        output["blocked_discoveries"] = blocked[:self.state.budget.max_references_per_query]
        return output

    def _get_function_signature(self, args):
        records, total = super()._get_function(args)
        for record in records:
            function = self.snapshot.functions[record["function_id"]]
            record["content"] = function["signature"]
            record["storage"] = function.get("storage", [])
            record["return_base_type"] = function.get("return_base_type")
            record["return_pointer_depth"] = function.get("return_pointer_depth", 0)
            record["callable_status"] = "internal_static" if "static" in function.get("storage", []) else (
                "external_definition" if function.get("defined") else "external_declaration_link_unverified")
        return records, total

    def _get_function(self, args):
        records, total = super()._get_function(args)
        for record in records:
            function = self.snapshot.functions[record["function_id"]]
            record["storage"] = function.get("storage", [])
            record["return_base_type"] = function.get("return_base_type")
            record["return_pointer_depth"] = function.get("return_pointer_depth", 0)
            record["callable_status"] = "internal_static" if "static" in function.get("storage", []) else (
                "external_definition" if function.get("defined") else "external_declaration_link_unverified")
        return records, total

    def _get_struct_fields(self, args):
        return super()._get_type_definition(args)

    def _find_type_usages(self, args):
        types = type_tokens(args["type"])
        matches = [function for function in self.snapshot.artifacts.functions
                   if types & function_types(function) and function["id"] not in self.excluded]
        records = []
        for function in matches[:self.state.budget.max_references_per_query]:
            records.append({"source": function["file"], "line_start": function["start_line"], "line_end": function["end_line"],
                "function_id": function["id"], "function": function["name"], "content": function["signature"],
                "defined": function.get("defined", False), "structural_hint_only": True})
        return records, len(matches)

    _find_initializers = _find_type_usages
    _find_cleanup_candidates = _find_type_usages
    _find_assignments = RepositoryTools._find_symbol_references
    _find_return_usages = RepositoryTools._find_callers

    def _find_function_argument_usages(self, args):
        if args["parameter"] not in {p["name"] for p in self.snapshot.functions[args["function"]].get("parameters", [])}:
            raise ValueError("unknown_parameter")
        return super()._get_function({"function": args["function"]})
