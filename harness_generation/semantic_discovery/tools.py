"""Deterministic, read-only queries over Phase 1 records and indexed source files.

Calls/references are syntactic tree-sitter observations, not resolved dataflow.
No file discovery, shell execution, network access, or policy mutation is exposed.
"""
from __future__ import annotations

from collections import defaultdict
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from tree_sitter import Language, Parser
import tree_sitter_c

from ..entry_candidates import CandidateCatalog
from ..sfg_adapter import SFGArtifacts
from ..source_paths import SourcePathResolver
from .models import ValidationBudget, canonical, digest


class ToolBudgetExceeded(RuntimeError):
    pass


def _walk(node):
    pending = [node]
    while pending:
        current = pending.pop()
        yield current
        pending.extend(reversed(current.named_children))


def _text(node, source: bytes) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _schema(name: str, description: str, properties: dict, required: list) -> dict:
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties,
                       "required": required, "additionalProperties": False}}}


_STRING = {"type": "string", "minLength": 1, "maxLength": 512}
TOOL_SCHEMAS = (
    _schema("get_function", "Get bounded Phase 1 function source and static signals. Prefer exact function ID.",
            {"function": _STRING}, ["function"]),
    _schema("get_type_definition", "Get indexed struct/typedef declaration, aliases and fields. Missing types remain unknown.",
            {"type": _STRING}, ["type"]),
    _schema("find_callers", "Find bounded syntactic direct callers in indexed function bodies; symbol resolution may be ambiguous.",
            {"function": _STRING}, ["function"]),
    _schema("find_callees", "Find bounded syntactic direct calls from indexed function bodies; indirect calls are unresolved.",
            {"function": _STRING}, ["function"]),
    _schema("find_symbol_references", "Find bounded identifier/field references in indexed function bodies, excluding comments and strings.",
            {"symbol": _STRING}, ["symbol"]),
    _schema("read_source_range", "Read a bounded line range of an indexed C/header file owned by this project. Source must match Phase 1 bodies.",
            {"file": _STRING, "line_start": {"type": "integer", "minimum": 1},
             "line_end": {"type": "integer", "minimum": 1}},
            ["file", "line_start", "line_end"]),
)


class RepositoryIndex:
    """Reusable immutable snapshot index; each candidate has its own tool budget."""
    def __init__(self, artifacts: SFGArtifacts, catalog: CandidateCatalog, *, functions_path: Path | None = None):
        self.artifacts = artifacts
        self.catalog = catalog
        if functions_path is not None:
            self.project_root = SourcePathResolver.from_functions_document({
                "schema_version": artifacts.source_schema_versions.get("functions", 1),
                "project": artifacts.project}, functions_path).project_root
        else:
            stored = Path(artifacts.project)
            self.project_root = stored.resolve() if stored.is_absolute() else None
        self.files = frozenset(artifacts.files)
        self.candidates = {c.function_id: c for c in catalog.candidates}
        self.functions = artifacts.functions_by_id
        self.names: dict[str, list] = defaultdict(list)
        for record in artifacts.functions:
            self.names[record["name"]].append(record)
        self.calls = None
        self.references = None

    def resolve_functions(self, symbol: str) -> list:
        if symbol in self.functions:
            return [self.functions[symbol]]
        return self.names.get(symbol, [])

    def build_syntax_index(self):
        if self.calls is not None:
            return
        parser = Parser(Language(tree_sitter_c.language()))
        calls, refs = [], defaultdict(list)
        # Reparse persisted bodies only. Never enumerate or scan repository files.
        for record in self.artifacts.functions:
            if not record.get("defined") or not record.get("body"):
                continue
            # A body alone is not a C translation unit. In particular, large
            # switch/goto bodies produce invalid error trees when parsed at
            # file scope. Supply function context without changing line rows.
            prefix = b"void __snapshot__(void) "
            source = prefix + record["body"].encode()
            lines = record["body"].splitlines()
            line_starts = [0] + [i + 1 for i, byte in enumerate(source) if byte == 10]
            tree = parser.parse(source)
            line_offset = record["end_line"] - record["body"].count("\n") - 1
            for node in _walk(tree.root_node):
                if node.start_byte < len(prefix):
                    continue
                # Avoid Point accessors: py-tree-sitter 0.26 can corrupt native
                # node state while traversing this project's large JSON parser.
                # Byte offsets give exact rows, including UTF-8 source.
                row = bisect_right(line_starts, node.start_byte) - 1
                line = line_offset + row + 1
                if node.type == "call_expression":
                    target = node.child_by_field_name("function")
                    if target is not None:
                        calls.append({"caller_id": record["id"],
                                      "callee": _text(target, source),
                                      "direct": target.type == "identifier",
                                      "source": record["file"], "line": line,
                                      "content": _text(node, source)})
                if node.type in {"identifier", "field_identifier", "type_identifier"}:
                    symbol = _text(node, source)
                    snippet = lines[row] if row < len(lines) else symbol
                    refs[symbol].append({"function_id": record["id"],
                                         "source": record["file"], "line": line,
                                         "content": snippet})
        self.calls = calls
        self.references = refs

    def owned_path(self, filename: str) -> Path:
        relative = Path(filename)
        if (relative.is_absolute() or ".." in relative.parts or filename not in self.files
                or relative.suffix.lower() not in {".c", ".h", ".cc", ".cpp", ".hpp"}):
            raise ValueError("source_not_allowed")
        if self.project_root is None:
            raise ValueError("functions_artifact_path_required_for_relative_project")
        path = (self.project_root / relative).resolve()
        if not path.is_relative_to(self.project_root):
            raise ValueError("source_not_allowed")
        return path


class RepositoryTools:
    def __init__(self, artifacts: SFGArtifacts, catalog: CandidateCatalog,
                 budget: ValidationBudget | None = None, *, index: RepositoryIndex | None = None,
                 functions_path: Path | None = None):
        self.index = index or RepositoryIndex(artifacts, catalog, functions_path=functions_path)
        self.budget = budget or ValidationBudget()
        self.evidence: dict[str, dict] = {}
        self.source_chars = 0
        self.live_sources: dict[str, str] = {}

    @property
    def schemas(self) -> list[dict]:
        # Fresh JSON values prevent a model adapter from mutating shared schemas.
        return json.loads(canonical(TOOL_SCHEMAS))

    def execute(self, name: str, arguments: Any) -> dict:
        schema = next((s["function"]["parameters"] for s in TOOL_SCHEMAS
                       if s["function"]["name"] == name), None)
        if schema is None:
            return {"error": "tool_not_allowed", "evidence_ids": []}
        if not isinstance(arguments, dict) or set(arguments) != set(schema["required"]):
            return {"error": "invalid_tool_arguments", "evidence_ids": []}
        for key, value in arguments.items():
            if schema["properties"][key]["type"] == "string":
                if not isinstance(value, str) or not value or len(value) > 512:
                    return {"error": "invalid_tool_arguments", "evidence_ids": []}
            elif type(value) is not int or value < 1:
                return {"error": "invalid_tool_arguments", "evidence_ids": []}
        if self.source_chars >= self.budget.max_source_chars:
            raise ToolBudgetExceeded("max_source_chars")
        try:
            records, total = getattr(self, "_" + name)(arguments)
        except (OSError, UnicodeError):
            return {"error": "source_unavailable", "evidence_ids": []}
        except ValueError:
            return {"error": "source_not_allowed_or_stale", "evidence_ids": []}
        previous_chars, previous_evidence = self.source_chars, dict(self.evidence)
        try:
            issued = [self._emit(name, arguments, record) for record in records]
        except ToolBudgetExceeded:
            # A failed query issues no evidence; no hidden IDs can enter a verdict.
            self.source_chars, self.evidence = previous_chars, previous_evidence
            raise
        return {"data_class": "untrusted_repository_evidence", "evidence": issued,
                "evidence_ids": [record["evidence_id"] for record in issued],
                "total_matches": total, "query_truncated": total > len(records),
                "resolution": "syntactic_only" if name.startswith("find_") else
                              "owned_live_source" if name == "read_source_range" else "phase1_snapshot"}

    def _emit(self, tool: str, arguments: dict, record: dict) -> dict:
        record = {"tool": tool, "arguments": arguments, "origin": "phase1_snapshot", **record}
        source_hash = self.index.artifacts.source_hashes.get(record.get("source"))
        if source_hash:
            record.setdefault("source_sha256", source_hash)
        metadata_truncated = False
        # Enforce the entire per-record ceiling, including declarations/fields.
        for key in ("fields", "parameters", "aliases", "static_signals", "signature"):
            if len(canonical({**record, "content": ""})) + 128 <= self.budget.max_chars_per_record:
                break
            if key in record:
                record.pop(key)
                metadata_truncated = True
        overhead = len(canonical({**record, "content": ""})) + 128
        if overhead > self.budget.max_chars_per_record:
            raise ToolBudgetExceeded("max_chars_per_record")
        allowed = max(0, self.budget.max_chars_per_record - overhead)
        content = record.get("content", "")
        if len(content) > allowed:
            record = {**record, "content": content[:allowed], "truncated": True}
            record["line_end"] = min(record["line_end"], record["line_start"] + record["content"].count("\n"))
        else:
            record["truncated"] = metadata_truncated
        eid = "ev_" + digest({"snapshot": self.index.catalog.source_fingerprint,
                              "record": record})[:32]
        record["evidence_id"] = eid
        cost = len(canonical(record))
        if self.source_chars + cost > self.budget.max_source_chars:
            raise ToolBudgetExceeded("max_source_chars")
        self.source_chars += cost
        self.evidence[eid] = record
        return record

    def _get_function(self, args):
        matches = self.index.resolve_functions(args["function"])
        records = []
        for f in matches[:self.budget.max_references_per_query]:
            candidate = self.index.candidates.get(f["id"])
            records.append({"source": f["file"],
                            "line_start": f["end_line"] - f.get("body", "").count("\n"),
                            "line_end": f["end_line"], "content": f.get("body", ""),
                            "definition_start_line": f["start_line"],
                            "function_id": f["id"], "function": f["name"],
                            "signature": f["signature"][:2048], "defined": f.get("defined", False),
                            "parameters": [{k: p.get(k)[:256] if isinstance(p.get(k), str) else p.get(k)
                                            for k in ("name", "type", "base_type",
                                             "is_pointer", "pointer_depth")} for p in f.get("parameters", [])[:32]],
                            "return_type": f.get("return_type", "")[:512],
                            "static_signals": [s.kind for s in candidate.signals] if candidate else [],
                            "signals_are_hypotheses": True})
        return records, len(matches)

    def _get_type_definition(self, args):
        name = re.sub(r"\b(const|struct|union|volatile)\b|\*", " ", args["type"]).strip()
        matches = [s for s in self.index.artifacts.structs
                   if name in (s["name"], *s.get("aliases", []))]
        records = []
        parser = Parser(Language(tree_sitter_c.language()))
        for s in matches[:self.budget.max_references_per_query]:
            source = s["declaration"].encode()
            fields = [_text(node, source)[:512] for node in _walk(parser.parse(source).root_node)
                      if node.type == "field_declaration"][:32]
            records.append({"source": s["file"], "line_start": s["start_line"],
                            "line_end": s["end_line"], "content": s["declaration"],
                            "type": s["name"], "aliases": list(s.get("aliases", []))[:32],
                            "fields": fields})
        return records, len(matches)

    def _find_callers(self, args):
        self.index.build_syntax_index()
        matches = self.index.resolve_functions(args["function"])
        names = {f["name"] for f in matches} or {args["function"]}
        found = [c for c in self.index.calls if c["direct"] and c["callee"] in names]
        return self._call_records(found[:self.budget.max_callers]), len(found)

    def _find_callees(self, args):
        self.index.build_syntax_index()
        ids = {f["id"] for f in self.index.resolve_functions(args["function"])}
        found = [c for c in self.index.calls if c["caller_id"] in ids]
        return self._call_records(found[:self.budget.max_callees]), len(found)

    def _call_records(self, calls):
        return [{"source": c["source"], "line_start": c["line"],
                 "line_end": c["line"] + c["content"].count("\n"),
                 "content": c["content"], "caller_id": c["caller_id"],
                 "callee": c["callee"], "direct": c["direct"],
                 "possible_callee_ids": [f["id"] for f in self.index.resolve_functions(c["callee"])][:10],
                 "symbol_resolution": "name_only_not_a_proven_call_edge"} for c in calls]

    def _find_symbol_references(self, args):
        self.index.build_syntax_index()
        found = self.index.references.get(args["symbol"], [])
        unique = list({(r["function_id"], r["line"]): r for r in found}.values())
        return [{"source": r["source"], "line_start": r["line"], "line_end": r["line"],
                 "content": r["content"], "function_id": r["function_id"],
                 "symbol_resolution": "identifier_spelling_only"}
                for r in unique[:self.budget.max_references_per_query]], len(unique)

    def _read_source_range(self, args):
        start, end = args["line_start"], args["line_end"]
        if end < start or end - start + 1 > self.budget.max_lines_per_read:
            raise ValueError("invalid_source_range")
        path = self.index.owned_path(args["file"])
        # One explicitly requested indexed file, with a fixed I/O ceiling. A stale
        # live body must not silently contradict the Phase 1 snapshot.
        with path.open("rb") as stream:
            data = stream.read(2 * 1024 * 1024 + 1)
        if len(data) > 2 * 1024 * 1024:
            raise ValueError("source_file_too_large")
        from ..source_snapshot import authenticated_c_source, VERSION
        source = authenticated_c_source(self.index.artifacts, args["file"], data)
        sha = hashlib.sha256(data).hexdigest()
        self.live_sources[args["file"]] = sha
        lines = source.splitlines(keepends=True)
        if start > len(lines):
            return [], 0
        actual_end = min(end, len(lines))
        return [{"source": args["file"], "line_start": start, "line_end": actual_end,
                 "content": "".join(lines[start - 1:actual_end]),
                 "origin": "owned_live_source", "source_sha256": sha, "source_view": VERSION}], 1
