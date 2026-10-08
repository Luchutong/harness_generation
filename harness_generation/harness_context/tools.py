"""Requirement-scoped read-only adapters around existing RepositoryTools."""
import json
import re
from copy import deepcopy

from ..semantic_discovery.models import canonical, ValidationBudget
from ..semantic_discovery.tools import RepositoryTools, _schema, _STRING, ToolBudgetExceeded
from ..semantic_slicing.frontier import function_types, type_tokens
from .models import TOOL_VERSION

SCOPE_FEEDBACK_VERSION = "upstream-scope-feedback-v1"

EXTRA_SCHEMAS = (
    _schema("find_resource_flows", "Bounded complete direct caller bodies for conservative return/out/alias/field value flow. Nonlinear or ambiguous flows remain unresolved.", {"function": _STRING}, ["function"]),
    _schema("get_function_signature", "Get an authorized exact function signature and linkage metadata.", {"function": _STRING}, ["function"]),
    _schema("get_struct_fields", "Get a relevant indexed struct declaration and fields, including callback ABI.", {"type": _STRING}, ["type"]),
    *(_schema(name, "Bounded structural signature candidates for a relevant type. These are NOT lifecycle/ownership proof; inspect their bodies.",
              {"type": _STRING}, ["type"]) for name in ("find_type_usages", "find_initializers", "find_cleanup_candidates")),
    _schema("find_assignments", "Find bounded syntactic identifier/field usages for a symbol already observed in this requirement.", {"symbol": _STRING}, ["symbol"]),
    _schema("find_return_usages", "Find bounded syntactic callers of the authorized function; not proof of ownership.", {"function": _STRING}, ["function"]),
    _schema("find_function_argument_usages", "Get the authorized function body containing a real parameter; no inferred semantics.",
            {"function": _STRING, "parameter": _STRING}, ["function", "parameter"]),
    _schema("get_call_sites", "Exact call expressions, positional arguments and enclosing guards/loops in ONE authorized function. callee is an exact expression, field name, or *; target IDs are syntactic candidates, not callback/lifecycle proof.",
            {"function": _STRING, "callee": _STRING}, ["function", "callee"]),
    _schema("find_field_writes", "Explicit field assignments/designated initializers in ONE authorized function, retaining receiver, RHS and control context. field is an exact field expression or leaf name. Function-address references can be read next; they do not prove binding or release.",
            {"function": _STRING, "field": _STRING}, ["function", "field"]),
    _schema("get_control_context", "Get the smallest statement at an absolute source line in ONE authorized function, with enclosing branch/loop/switch syntax. This is not path coverage or a must-execute proof.",
            {"function": _STRING, "line": {"type": "integer", "minimum": 1}}, ["function", "line"]),
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
        self.query_cache = {}
        self.bootstrap_reads, self.bootstrap_reuses = 0, 0
        # Absolute ceilings for optional exploration. They never enlarge the
        # global budget, issue evidence, or limit mandatory/revision batches.
        self.investigation_model_limit = None
        self.investigation_tool_limit = None

    @property
    def source_chars(self):
        return self.state.source_chars

    @source_chars.setter
    def source_chars(self, value):
        self.state.source_chars = value

    @property
    def schemas(self):
        return super().schemas + json.loads(canonical(EXTRA_SCHEMAS))

    def activate(self, requirement, facts=(), *, requirement_ids=()):
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
        self.scope_ids -= self.excluded
        # Reconstruct read-only caller scope from already issued discoveries.
        # EXCLUDE remains absent from the callable discovery registry.
        caller_sources = {r.get('caller_id') for r in self.evidence.values()
            if r['tool'] in {'find_callers', 'find_resource_flows', 'find_return_usages'}
            and r.get('arguments', {}).get('function') in self.scope_ids and r.get('caller_id') in self.excluded}
        self.scope_ids |= caller_sources
        # Reuse issued source dependencies, not the entire discovery history.
        # A helper must have been discovered by an exact call/field-reference
        # query on a relevant parent. Type/signature matches cannot add edges.
        from .evidence import record_functions
        valid_records = {eid: record for eid, record in self.evidence.items()
                         if self._reusable_record(record)}
        self.query_cache = {key: output for key, output in self.query_cache.items()
                            if set(output['evidence_ids']) <= valid_records.keys()}
        # A support effect is about BOTH API and exact required_by subject.
        # Re-expose authenticated parent source already in authorized scope.
        roots = ({fid, *linked, *requirement['required_by']} | {api for api, info in self.state.discoveries.items()
            if info.get('parent_function_id') == fid or requirement['requirement_id'] in info['requirement_ids']}) & self.scope_ids
        dependency_scope = set(roots)
        dependency_edges = []
        pending = [(root, self.depth(root)) for root in sorted(roots)]
        while pending:
            pending.sort(key=lambda item: (item[1], item[0]))
            parent, parent_depth = pending.pop(0)
            for api, info in sorted(self.state.discoveries.items()):
                if api in dependency_scope or api in self.excluded:
                    continue
                if (info.get('depth', 1) > self.state.budget.max_dependency_depth
                        or parent_depth + 1 > self.state.budget.max_dependency_depth):
                    continue
                references = [eid for eid in info['evidence_ids'] if eid in valid_records
                    and valid_records[eid]['tool'] in {'find_callees', 'get_call_sites', 'find_field_writes'}
                    and valid_records[eid].get('arguments', {}).get('function') == parent
                    and api in record_functions(valid_records[eid], self.snapshot)]
                if references:
                    dependency_scope.add(api)
                    pending.append((api, min(parent_depth + 1, self.depth(api))))
                    dependency_edges.append(dict(parent_function_id=parent, function_id=api,
                        evidence_ids=sorted(references)))
        self.scope_ids |= dependency_scope
        self.source_dependency_reuse = dependency_edges
        self.known_symbols = set()
        self.visible_ids = {eid for fact in relevant for eid in fact["evidence_ids"] if eid in valid_records}
        for api in self.scope_ids:
            self._learn(api)
        # Failed/unresolved investigations can still have useful issued source.
        # Restore only this slot/group's authorized records, never a repository
        # history or another requirement's unrelated discovery results.
        rids = {requirement["requirement_id"], *requirement_ids}
        self.reused_requirement_evidence_ids = []
        self.reused_source_dependency_evidence_ids = []
        for eid, record in sorted(valid_records.items()):
            functions = record_functions(record, self.snapshot)
            source_reuse = (bool(functions) and functions <= dependency_scope
                and record['tool'] in {'get_function', 'read_source_range', 'find_function_argument_usages',
                    'get_call_sites', 'find_field_writes', 'get_control_context', 'find_callees'})
            if (record.get("requirement_id") not in rids and not source_reuse) or eid in self.visible_ids:
                continue
            if functions and not functions <= self.scope_ids:
                continue
            arguments = record.get("arguments", {})
            if arguments.get("function") and arguments["function"] not in self.scope_ids:
                continue
            symbol = arguments.get("type", arguments.get("symbol"))
            if symbol and not type_tokens(symbol) <= self.known_symbols:
                continue
            if not functions and not symbol and record.get("tool") != "read_source_range":
                continue
            self.visible_ids.add(eid)
            self.reused_requirement_evidence_ids.append(eid)
            if source_reuse and record.get('requirement_id') not in rids:
                self.reused_source_dependency_evidence_ids.append(eid)

    def _reusable_record(self, record):
        """Re-exposure never authenticates a stale or fabricated record."""
        from ..semantic_discovery.models import digest
        expected = 'ev_' + digest({'snapshot': self.snapshot.source_fingerprint,
            'record': {k: v for k, v in record.items() if k != 'evidence_id'}})[:32]
        if record.get('evidence_id') != expected:
            return False
        if record.get('source_sha256'):
            import hashlib
            try:
                with self.index.owned_path(record['source']).open('rb') as stream:
                    data = stream.read(2 * 1024 * 1024 + 1)
                if hashlib.sha256(data).hexdigest() != record['source_sha256']:
                    return False
            except (OSError, ValueError):
                return False
            self.live_sources[record['source']] = record['source_sha256']
        return True

    def _learn(self, fid):
        function = self.snapshot.functions[fid]
        self.known_symbols |= function_types(function) | {function["name"]}
        self.known_symbols.update(p["name"] for p in function.get("parameters", []) if p.get("name"))
        for struct in self.snapshot.artifacts.structs:
            if function_types(function) & {struct["name"], *struct.get("aliases", [])}:
                self.known_symbols.update(re.findall(r"[A-Za-z_]\w*", struct["declaration"]))

    def depth(self, fid):
        if fid in self.core_ids:
            return 0
        depth = self.state.discoveries.get(fid, {}).get("depth", 1)
        # A core-linked support investigation is one semantic dependency, even
        # if caller evidence happened to discover it through a longer route.
        # API closure independently validates semantic depth and callability.
        req = self.requirement
        if (req and req['kind'] == 'support_decision' and fid == req['subject_function_id']
                and set(req['required_by']) & self.core_ids):
            depth = min(depth, 1)
        if depth > 1 and req and req['subject_function_id'] in self.core_ids:
            # A complete caller can prove a direct return→consumer relation.
            # The caller is an evidence bridge, not an additional API invocation
            # between the CORE and that consumer. This licenses investigation,
            # never ownership, necessity or activation.
            from .value_flow import resource_flows
            from .evidence import record_functions
            # Activation reconstructs scope before resetting visible IDs. An
            # authenticated caller body already acquired for another predicate
            # must keep the same source-derived depth across that transition.
            records = {eid: r for eid, r in self.evidence.items()
                if record_functions(r, self.snapshot) & self.scope_ids and self._reusable_record(r)}
            flow = resource_flows(self.snapshot, records)
            if any(r['function_id'] == fid and not r['return_value'] and r['origin']['kind'] == 'return'
                    and r['origin']['function_id'] == req['subject_function_id'] for r in flow['observations']):
                depth = 1
        return depth

    def _emit(self, tool, arguments, record):
        record = super()._emit(tool, arguments, {**record, "requirement_id": self.requirement["requirement_id"]})
        self.visible_ids.add(record["evidence_id"])
        return record

    def bootstrap(self):
        fid = self.requirement["subject_function_id"]
        key = canonical(["get_function", {"function": fid}])
        reused = key in self.query_cache and fid in self.scope_ids
        if reused:
            output = deepcopy(self.query_cache[key])
            self.visible_ids.update(output["evidence_ids"])
            self.bootstrap_reuses += 1
        else:
            output = self.execute("get_function", {"function": fid})
            self.bootstrap_reads += 1
        if output.get("error"):
            raise ValueError("tool_scope_exhausted")
        # Previous confirmed facts expose only evidence about this subject, not
        # the repository or unrelated requirement histories.
        prior = [self.evidence[eid] for eid in sorted(self.visible_ids - set(output["evidence_ids"]))]
        # Source budget counts newly issued evidence; re-exposing confirmed
        # records does not issue or charge duplicate repository content.
        output["evidence"].extend(prior)
        output["evidence_ids"].extend(record["evidence_id"] for record in prior)
        output["reused_requirement_evidence_ids"] = list(self.reused_requirement_evidence_ids)
        output['reused_source_dependency_evidence_ids'] = list(self.reused_source_dependency_evidence_ids)
        output['source_dependency_reuse'] = deepcopy(self.source_dependency_reuse)
        output["bootstrap_reused"] = reused
        return output

    def execute(self, name, arguments):
        if self.state.tool_calls >= self.state.budget.max_tool_calls:
            self.state.budget_stop = "max_tool_calls"
            error = ToolBudgetExceeded("max_tool_calls")
            error.tool_executed = False
            raise error
        if (self.investigation_tool_limit is not None
                and self.state.tool_calls >= self.investigation_tool_limit):
            # A local optional cap is a scheduling boundary, not exhaustion
            # of the FT budget. Mandatory work may consume the reserved calls.
            error = ToolBudgetExceeded("optional_tool_reserve")
            error.tool_executed = False
            raise error
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
                if arguments["function"] in self.excluded:
                    return {"error": "upstream_excluded", "evidence_ids": [],
                            "function_id": arguments["function"],
                            "diagnostic_version": SCOPE_FEEDBACK_VERSION,
                            "rule": "This exact function was excluded by the frozen upstream FT. Discovery does not remove that exclusion. Record the upstream scope blocker if its effect is needed; do not invent a replacement cleanup or change ownership/resource identity."}
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
        cache_key = canonical([name, arguments])
        if cache_key in self.query_cache:
            output = deepcopy(self.query_cache[cache_key])
            self.visible_ids.update(output["evidence_ids"])
            self.state.evidence_cache_hits += 1
        elif name not in {s["function"]["name"] for s in EXTRA_SCHEMAS}:
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
        if name == "find_cleanup_candidates" and not output.get("error"):
            # These Phase-1 signature links are diagnostics only. In particular
            # they are never passed to _emit or the callable discovery loop.
            output["upstream_scope_feedback"] = self.cleanup_scope_feedback(arguments["type"])
        if not output.get("error"):
            self.query_cache[cache_key] = deepcopy(output)
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
                    caller_source = name in {'find_callers', 'find_resource_flows', 'find_return_usages'} and record.get('caller_id') == fid
                    if not caller_source:
                        blocked.append({"function_id": fid, "reason": "upstream_excluded"})
                        continue
                    self.scope_ids.add(fid)
                    self._learn(fid)
                    identities.append({'function_id': fid, 'function': self.snapshot.functions[fid]['name'],
                        'evidence_id': record['evidence_id'], 'callable_status': 'excluded_source_evidence'})
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
        from .proposals import registry_update
        output.update(registry_update(self))
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
            if function['id'] in self.excluded:
                record['callable_status'] = 'excluded_source_evidence'
        return records, total

    def _get_function(self, args):
        records, total = super()._get_function(args)
        for record in records:
            function = self.snapshot.functions[record["function_id"]]
            record["storage"] = function.get("storage", [])
            record["return_base_type"] = function.get("return_base_type")
            record["return_pointer_depth"] = function.get("return_pointer_depth", 0)
            from .argument_graph import parameter_id
            from .models import resource_id
            record["framework_parameters"] = [{"parameter_id":parameter_id(function["id"],i),
                "parameter_index":i,"name":p["name"],
                "resource_id":resource_id(function["id"],p["name"]) if p.get("is_pointer") or p.get("is_opaque_handle") else None}
                for i,p in enumerate(function["parameters"])]
            record["framework_return_resource_id"] = resource_id(function["id"]) if function.get("return_pointer_depth") else None
            record["callable_status"] = "internal_static" if "static" in function.get("storage", []) else (
                "external_definition" if function.get("defined") else "external_declaration_link_unverified")
            if function['id'] in self.excluded:
                record['callable_status'] = 'excluded_source_evidence'
            from .callbacks import callback_declarations
            declarations = callback_declarations(function, self.snapshot)
            if declarations:
                record["callback_declarations"] = declarations
        return records, total

    def _get_struct_fields(self, args):
        return super()._get_type_definition(args)

    def _get_type_definition(self, args):
        records, total = super()._get_type_definition(args)
        for declaration in self.snapshot.artifacts.callback_typedefs:
            if declaration["name"] == args["type"]:
                records.append({"source": declaration["file"], "line_start": declaration.get("start_line", 1), "line_end": declaration.get("end_line", 1),
                    "content": declaration["declaration"], "type": declaration["name"], "origin": "phase1_callback_typedef"})
                total += 1
        return records, total

    def _find_resource_flows(self, args):
        self.index.build_syntax_index()
        fid = args["function"]
        target = self.snapshot.functions[fid]
        callers = sorted({c["caller_id"] for c in self.index.calls if c["direct"] and c["callee"] == target["name"]})
        records = []
        for caller in callers[:self.state.budget.max_references_per_query]:
            function = self.snapshot.functions[caller]
            records.append({"caller_id": caller, "function_id": caller, "source": function["file"],
                "line_start": function["start_line"], "line_end": function["end_line"], "content": function["body"],
                "defined": True, "provenance": "bounded_direct_caller_body"})
        return records, len(callers)

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

    def _lifecycle_candidates(self, args, creation):
        types = type_tokens(args["type"])
        matches = [f for f in self.snapshot.artifacts.functions
                   if types & function_types(f) and f["id"] not in self.excluded]
        def rank(function):
            consumes = any(p.get("is_pointer") and types & type_tokens(p.get("base_type", ""))
                           for p in function.get("parameters", []))
            produces = bool(function.get("return_pointer_depth")) and bool(types & type_tokens(function.get("return_base_type", "")))
            output = any(p.get("pointer_depth", 0) > 1 and types & type_tokens(p.get("base_type", ""))
                         for p in function.get("parameters", []))
            hint = produces or output if creation else consumes and function.get("return_type", "").strip() == "void"
            return (not function.get("defined"), "static" in function.get("storage", []), not hint,
                    len(function.get("parameters", [])), function["id"])
        matches.sort(key=rank)
        records = [{"source": f["file"], "line_start": f["start_line"], "line_end": f["end_line"],
            "function_id": f["id"], "function": f["name"], "content": f["signature"], "defined": f.get("defined", False),
            "structural_hint_only": True} for f in matches[:self.state.budget.max_references_per_query]]
        return records, len(matches)

    def _find_initializers(self, args):
        return self._lifecycle_candidates(args, True)

    def _find_cleanup_candidates(self, args):
        return self._lifecycle_candidates(args, False)

    def cleanup_scope_feedback(self, type_name):
        """Bounded excluded signature hints, without issuing source or choices."""
        from .source_queries import DETAIL_LIMIT
        types = type_tokens(type_name)
        declared = set().union(*(function_types(self.snapshot.functions[fid])
                                 for fid in self.scope_ids if fid in self.snapshot.functions))
        trusted_types = set(declared)
        # known_symbols also contains body words and parameter/field names.
        # Only indexed declaration types can expose excluded signature hints.
        from .callbacks import parse_declaration
        from ..semantic_discovery.tools import _walk, _text
        for struct in self.snapshot.artifacts.structs:
            if not declared & {struct["name"], *struct.get("aliases", [])}:
                continue
            source, root = parse_declaration(struct["declaration"])
            if root.has_error:
                continue
            for field in (node for node in _walk(root) if node.type == "field_declaration"):
                trusted_types.update(token for node in _walk(field)
                                     if node.type in {"type_identifier", "primitive_type"}
                                     for token in type_tokens(_text(node, source)))
        if not types or not types <= self.known_symbols or not types <= trusted_types:
            return None
        matches = []
        for function in self.snapshot.artifacts.functions:
            links = [{"parameter": p["name"], "base_type": p.get("base_type"),
                      "matched_type_tokens": sorted(types & type_tokens(p.get("base_type", "")))}
                     for p in function.get("parameters", [])
                     if p.get("is_pointer") and types & type_tokens(p.get("base_type", ""))]
            if links:
                matches.append((function, links))
        excluded = sorted(((f, links) for f, links in matches if f["id"] in self.excluded),
                          key=lambda item: (item[0].get("return_type", "").strip() != "void",
                                            not item[0].get("defined"),
                                            "static" in item[0].get("storage", []), item[0]["id"]))
        limit = self.state.budget.max_references_per_query
        conflicts = [{"function_id": f["id"], "signature": f["signature"][:DETAIL_LIMIT],
                      "signature_truncated": len(f["signature"]) > DETAIL_LIMIT,
                      "type_links": links[:limit], "type_links_truncated": len(links) > limit,
                      "reason": "upstream_excluded", "diagnostic_only": True}
                     for f, links in excluded[:limit]]
        return {"version": SCOPE_FEEDBACK_VERSION, "query_type": type_name,
                "diagnostic_only": True, "excluded_structural_candidates": conflicts,
                "excluded_match_count": len(excluded), "truncated": len(excluded) > limit,
                "all_cleanup_shaped_signatures_excluded": bool(matches) and len(excluded) == len(matches),
                "rule": "These are only indexed signatures with a matching pointer parameter (void-return signatures listed first), not cleanup/necessity proof. They issue no evidence IDs, callable choices, scope extensions or semantic facts. The all-excluded flag covers only this signature shape, not all possible release paths; preserve the upstream FT and record a scope blocker only if a needed effect remains unavailable."}
    _find_assignments = RepositoryTools._find_symbol_references
    _find_return_usages = RepositoryTools._find_callers

    def _find_function_argument_usages(self, args):
        if args["parameter"] not in {p["name"] for p in self.snapshot.functions[args["function"]].get("parameters", [])}:
            raise ValueError("unknown_parameter")
        return super()._get_function({"function": args["function"]})

    def _get_call_sites(self, args):
        from .source_queries import SourceDetails
        return SourceDetails(self.snapshot, args["function"]).calls(args["callee"], self.budget.max_references_per_query)

    def _find_field_writes(self, args):
        from .source_queries import SourceDetails
        return SourceDetails(self.snapshot, args["function"]).writes(args["field"], self.budget.max_references_per_query)

    def _get_control_context(self, args):
        from .source_queries import SourceDetails
        return SourceDetails(self.snapshot, args["function"]).at_line(args["line"])
