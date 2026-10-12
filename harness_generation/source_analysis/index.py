"""Independently replayed compilation facts, never caller-supplied certificates."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
import shutil

from ..semantic_discovery.models import canonical, digest
from .analyzer import AnalysisBudget, BuildAnalysisError, DOCUMENTS, VERSION, analyze_build, file_digest

_AUTHENTICATED = object()
_LIBC = {"free": "void (void *)", "malloc": "void *(unsigned long)",
         "calloc": "void *(unsigned long, unsigned long)", "realloc": "void *(void *, unsigned long)"}


def _plain_type(value):
    value = re.sub(r"__attribute__\s*\(\(.*?\)\)", "", value)
    return re.sub(r"\s+", "", value)


def normalized_build_arguments(arguments, directory):
    """Canonicalize include spellings while preserving argument order/multiplicity."""
    result, index = [], 0
    while index < len(arguments):
        flag = arguments[index]
        if flag in {"-I", "-isystem", "-iquote", "-idirafter", "-include", "-imacros", "-isysroot", "--sysroot", "-resource-dir"}:
            if index + 1 >= len(arguments):
                raise BuildAnalysisError("incomplete_build_recipe_flag")
            path = Path(arguments[index + 1]); path = path if path.is_absolute() else Path(directory) / path
            result.extend([flag, str(path.resolve())]); index += 2; continue
        if flag.startswith("-I") and len(flag) > 2:
            path = Path(flag[2:]); path = path if path.is_absolute() else Path(directory) / path
            result.extend(["-I", str(path.resolve())]); index += 1; continue
        result.append(flag); index += 1
    return result


class BuildAwareIndex:
    __slots__ = ("_documents", "_projection", "_source_fingerprint", "_functions_fingerprint", "_compiler_stat", "_function_records", "_type_identity_cache")

    def __init__(self, documents=None, functions_document=None, *, _token=None):
        if _token is not _AUTHENTICATED:
            raise BuildAnalysisError("BuildAwareIndex requires independent load/replay authentication")
        self._documents = deepcopy(documents)
        self._function_records = {row["id"]: deepcopy(row) for row in functions_document["functions"]}
        self._type_identity_cache = {}
        context = documents["compile_context"]
        self._source_fingerprint, self._functions_fingerprint = context["source_fingerprint"], context["functions_fingerprint"]
        self._projection = {"schema_version": 1, "policy_version": VERSION, "authenticated": True,
            "source_fingerprint": self._source_fingerprint, "functions_fingerprint": self._functions_fingerprint,
            "configuration_digest": context["configuration_digest"], "analysis_digest": context["analysis_digest"],
            "artifact_digests": {name: digest(documents[name]) for name in DOCUMENTS},
            "dependency_digest": context["dependency_digest"], "compiler_digest": context["compiler"]["sha256"]}
        stat = Path(context["compiler"]["path"]).stat()
        self._compiler_stat = (stat.st_ino, stat.st_size, stat.st_mtime_ns)

    @property
    def authenticated(self):
        return True

    @property
    def source_fingerprint(self):
        return self._source_fingerprint

    @property
    def functions_fingerprint(self):
        return self._functions_fingerprint

    @property
    def configuration_digest(self):
        return self._projection["configuration_digest"]

    @property
    def identity_digest(self):
        return digest(self._projection)

    def public_projection(self):
        self._assert_current()
        return deepcopy(self._projection)

    def carrier_build_projection(self):
        """Authenticated original TU inputs for a relocated analysis carrier."""
        self._assert_current()
        context = self._documents["compile_context"]
        return {"project_root": context["project_root"], "compiler_sha256": context["compiler"]["sha256"],
            "translation_units": [{name: deepcopy(unit[name]) for name in
                ("source", "directory", "arguments", "macro_digest")} for unit in context["translation_units"]],
            "dependency_hashes": deepcopy(context["dependency_hashes"])}

    projection = public_projection
    to_dict = public_projection

    @classmethod
    def load(cls, artifact_dir, snapshot, *, verify_live=True, clang=None):
        if verify_live is not True:
            raise BuildAnalysisError("unverified saved labels cannot become BuildAwareIndex")
        artifact_dir = Path(artifact_dir).resolve()
        documents = {}
        for name in DOCUMENTS:
            path = artifact_dir / (name + ".json")
            if not path.resolve().is_relative_to(artifact_dir) or path.stat().st_size > 64 * 1024 * 1024:
                raise BuildAnalysisError("invalid_build_artifact_path_or_size")
            documents[name] = json.loads(path.read_text())
        context = documents["compile_context"]
        if context.get("policy_version") != VERSION or context.get("schema_version") != 1:
            raise BuildAnalysisError("build_analysis_policy_mismatch")
        if context.get("source_fingerprint") != snapshot.source_fingerprint or context.get("functions_fingerprint") != snapshot.functions_fingerprint:
            raise BuildAnalysisError("build_analysis_source_identity_mismatch")
        if context.get("analysis_digest") != digest({key: value for key, value in context.items() if key != "analysis_digest"}):
            raise BuildAnalysisError("build_analysis_manifest_digest_mismatch")
        for name in DOCUMENTS[1:]:
            if context.get("document_digests", {}).get(name) != digest(documents[name]):
                raise BuildAnalysisError("build_analysis_document_digest_mismatch:" + name)
        functions_document = json.loads((artifact_dir / "functions.json").read_text())
        if context.get("functions_document_digest") != digest(functions_document):
            raise BuildAnalysisError("build_analysis_functions_document_mismatch")
        from ..source_paths import SourcePathResolver
        project = SourcePathResolver.from_functions_document(functions_document, artifact_dir / "functions.json").project_root
        if str(project) != context["project_root"]:
            raise BuildAnalysisError("build_analysis_project_root_mismatch")
        # An artifact may record a compiler, but cannot authorize executing a
        # replacement script/tool. Only an explicit caller selection can do so.
        trusted_compiler = Path(clang or shutil.which("clang") or "").resolve()
        if str(trusted_compiler) != context["compiler"]["path"]:
            raise BuildAnalysisError("build_analysis_compiler_not_selected")
        # Digests are integrity checks, not signatures. Re-execute the bounded
        # trusted frontend to reject coherent forged AST/ABI/verified labels.
        rebuilt = analyze_build(context["project_root"], context["compile_database"]["path"], functions_document,
            clang=trusted_compiler, budget=AnalysisBudget(**context["budget"]), snapshot=snapshot)
        if canonical(rebuilt) != canonical(documents):
            raise BuildAnalysisError("build_analysis_did_not_reproduce")
        return cls(documents, functions_document, _token=_AUTHENTICATED)

    def _assert_current(self):
        context = self._documents["compile_context"]
        if file_digest(context["compile_database"]["path"]) != context["compile_database"]["sha256"]:
            raise BuildAnalysisError("compile_database_changed")
        for path, target in context["dependency_links"].items():
            if str(Path(path).resolve()) != target:
                raise BuildAnalysisError("source_dependency_link_changed")
        maximum = context["budget"]["max_file_bytes"]
        for path, expected in context["dependency_hashes"].items():
            if file_digest(path, maximum) != expected:
                raise BuildAnalysisError("source_dependency_changed:" + path)
        project = Path(context["project_root"])
        for path, expected in context["tree_sitter_source_hashes"].items():
            if file_digest(project / path, maximum) != expected:
                raise BuildAnalysisError("source_snapshot_changed:" + path)
        compiler = Path(context["compiler"]["path"]).stat()
        if (compiler.st_ino, compiler.st_size, compiler.st_mtime_ns) != self._compiler_stat:
            raise BuildAnalysisError("clang_binary_changed")

    def validate_snapshot(self, snapshot):
        if self.source_fingerprint != snapshot.source_fingerprint or self.functions_fingerprint != snapshot.functions_fingerprint:
            raise BuildAnalysisError("build_index_snapshot_mismatch")
        self._assert_current()
        return True

    def _certificate(self, kind, facts):
        facts = {"kind": kind, **deepcopy(facts), "source_fingerprint": self.source_fingerprint,
            "functions_fingerprint": self.functions_fingerprint, "configuration_digest": self.configuration_digest,
            "analysis_digest": self._projection["analysis_digest"], "link_verified": False,
            "semantic_contract_verified": False}
        facts["evidence_id"] = "clang_ev_" + digest(facts)[:32]
        return facts

    def verify_function(self, function_id):
        self._assert_current()
        target = next((row for row in self._documents["callable_targets"]["targets"] if row["function_id"] == function_id), None)
        if target is None:
            return self._certificate("function", {"function_id": function_id, "status": "unknown", "verified": False,
                "abi_verified": False, "tu_ids": []})
        symbols = [s for s in self._documents["symbols"]["symbols"] if s["symbol_id"] in target["symbol_ids"]]
        symbol = symbols[0] if symbols else None
        abi_verified = bool(symbol and symbol["canonical_type"] and symbol["calling_convention"] != "unknown"
            and not symbol["variadic"] and not symbol.get("typedef_layout_unknown")
            and all(p["canonical_type"] for p in symbol["parameters"]))
        facts = {**target, "verified": target["status"] == "callable" and abi_verified, "abi_verified": abi_verified,
            "tu_ids": sorted({s["tu_id"] for s in symbols})}
        if symbol:
            facts.update({key: deepcopy(symbol[key]) for key in ("canonical_type", "return_type", "parameters", "calling_convention", "linkage")})
        return self._certificate("function", facts)

    callable_status = verify_function

    def verify_type_identity(self, function_id, parameter=None, source_type=None):
        """Certify source/canonical correspondence with the live trusted Clang.

        ``source_type`` optionally checks a concrete argument type against a
        named/indexed parameter.  Its opaque LLVM pointer lowering grants no
        compatibility authority.  Every cache hit rechecks the live build.
        """
        return self._verify_type_identity(function_id, parameter, source_type, source_definition=False)

    def verify_source_type_identity(self, function_id, parameter=None, source_type=None):
        """Authenticate a defined source function's types, including static helpers.

        A compiled internal definition can participate in summary composition
        without becoming an externally callable harness API.  Callable/ABI
        admission continues to use ``verify_function`` and the strict public
        ``verify_type_identity``; this receipt conveys source-type facts only.
        """
        return self._verify_type_identity(function_id, parameter, source_type, source_definition=True)

    def _verify_type_identity(self, function_id, parameter, source_type, *, source_definition):
        from .type_identity import TYPE_IDENTITY_VERSION, replay_type_identity
        self._assert_current()
        function = self.verify_function(function_id)
        record = self._function_records.get(function_id)
        symbols = [row for row in self._documents["symbols"]["symbols"]
                   if row["symbol_id"] in function.get("symbol_ids", [])]
        permitted = function.get("verified")
        if source_definition:
            permitted = (function.get("abi_verified") and function.get("status") in {"callable", "internal_linkage"}
                         and symbols and all(row.get("defined") and row.get("function_id") == function_id
                                            for row in symbols))
        certificate_kind = "source_type_identity" if source_definition else "type_identity"
        if not record or not permitted:
            return self._certificate(certificate_kind, {"policy_version": TYPE_IDENTITY_VERSION,
                "function_id": function_id, "parameter": parameter, "source_type": source_type,
                "verified": False, "status": "unknown", "reason": "source_definition_type_unverified" if source_definition
                else "function_not_callable_in_current_build", "callable_authority": False})
        key = digest({"function_id": function_id, "parameter": parameter, "source_type": source_type})
        if source_definition:
            key = digest({"function_id": function_id, "parameter": parameter, "source_type": source_type,
                          "source_definition": True})
        if key not in self._type_identity_cache:
            facts = [replay_type_identity(self._documents["compile_context"], record, symbol,
                                         parameter=parameter, source_type=source_type,
                                         retain_definition=source_definition) for symbol in symbols]
            self._assert_current()
            verified = bool(facts and all(row["verified"] for row in facts))
            result = deepcopy(facts[0]) if facts else {"function_id": function_id, "status": "unknown", "reason": "type_identity_symbol_unresolved"}
            result.update(verified=verified, tu_ids=sorted({row["tu_id"] for row in facts}),
                          translation_unit_proofs=deepcopy(facts))
            if facts and any(row["status"] != "verified" for row in facts):
                failed = next(row for row in facts if row["status"] != "verified")
                result.update(status=failed["status"], reason=failed["reason"])
            self._type_identity_cache[key] = result
        facts = self._type_identity_cache[key]
        if source_definition:
            facts = {**facts, "callable_authority": False, "generation_authority": False}
        return self._certificate(certificate_kind, facts)

    def verify_source_semantics(self, function_id):
        """Expose actual TU macros; raw tree-sitter effects are no expansion IR."""
        function = self.verify_function(function_id)
        units = [u for u in self._documents["compile_context"]["translation_units"] if u["tu_id"] in function["tu_ids"]]
        identifiers = set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", self._function_records.get(function_id, {}).get("body", "")))
        relevant = {name: sorted({u["macros"][name] for u in units if name in u["macros"]})
            for name in identifiers if any(name in u["macros"] for u in units)}
        # Even equal numeric macros can change branch/data semantics. Only the
        # standard null constant is shared by the bounded raw-source rules.
        safe_null = {"0", "((void *)0)", "((void*)0)", "__null"}
        incompatible = [name for name, definitions in relevant.items() if name != "NULL" or not all(v in safe_null for v in definitions)]
        symbols = [s for s in self._documents["symbols"]["symbols"] if s["function_id"] == function_id and s["defined"]]
        expansions = [row for symbol in symbols for row in symbol["body_macro_expansions"]]
        for name in {row["name"] for row in expansions}:
            observations = [row for row in expansions if row["name"] == name]
            null_constant = name == "NULL" and any(row["ast_kind"] == "IntegerLiteral" and row["value"] == "0" for row in observations)
            null_constant = null_constant and not any(row["referenced_name"] or row.get("value") not in {None, "0"} for row in observations)
            if not null_constant:
                incompatible.append(name)
            relevant.setdefault(name, ["<actual AST expansion; final macro may be undefined>"])
        return self._certificate("source_semantics", {"function_id": function_id,
            "verified": bool(function["abi_verified"]), "source_effect_compatible": not incompatible and bool(units),
            "macro_identifiers": relevant, "macros": {u["tu_id"]: deepcopy(u["macros"]) for u in units},
            "body_macro_expansions": expansions,
            "blockers": ["raw_source_macro_requires_expansion:" + name for name in sorted(set(incompatible))],
            "tu_ids": function["tu_ids"]})

    macro_identifiers = verify_source_semantics

    def validate_recipe(self, recipe):
        """Require an effective source recipe, including all implicit flags."""
        self._assert_current()
        recipe = recipe.to_dict() if callable(getattr(recipe, "to_dict", None)) else recipe
        if not isinstance(recipe, dict):
            raise BuildAnalysisError("invalid_build_recipe")
        context = self._documents["compile_context"]
        project = Path(recipe.get("project_root", "")).resolve()
        if str(project) != context["project_root"]:
            raise BuildAnalysisError("build_recipe_project_mismatch")
        sources = {str(Path(source).resolve()) for source in recipe.get("source_files", [])}
        expected_sources = {str(project / unit["source"]) for unit in context["translation_units"]}
        if sources != expected_sources:
            raise BuildAnalysisError("build_recipe_translation_units_mismatch")
        compiler = recipe.get("compiler")
        compiler_path = Path(shutil.which(compiler) or compiler).resolve() if isinstance(compiler, str) else None
        if compiler_path is None or str(compiler_path) != context["compiler"]["path"]:
            raise BuildAnalysisError("build_recipe_compiler_mismatch")
        flags = recipe.get("effective_compiler_flags", recipe.get("compiler_flags", []))
        if not isinstance(flags, list) or any(not isinstance(flag, str) for flag in flags):
            raise BuildAnalysisError("invalid_build_recipe_flags")
        include_flags = ["-I" + str(Path(path).resolve()) for path in recipe.get("include_paths", [])]
        actual = [*flags, *include_flags]
        for unit in context["translation_units"]:
            if normalized_build_arguments(actual, project) != normalized_build_arguments(unit["arguments"], unit["directory"]):
                raise BuildAnalysisError("build_recipe_compile_flags_mismatch")
        return True

    def verify_field_layout(self, type_name, path=(), source=None):
        self._assert_current()
        if isinstance(path, str):
            path = path.split(".") if path else []
        if not isinstance(path, (list, tuple)) or len(path) > 8:
            raise BuildAnalysisError("invalid_field_path")
        overridden = [unit for unit in self._documents["compile_context"]["translation_units"]
            if type_name in unit.get("typedef_layout_overrides", {})]
        if overridden:
            return self._certificate("field_layout", {"type_name": type_name, "path": list(path), "verified": False,
                "status": "typedef_layout_unknown", "tu_ids": sorted(unit["tu_id"] for unit in overridden),
                "typedef_attributes": [deepcopy(unit["typedef_layout_overrides"][type_name]) for unit in overridden]})
        layouts = [r for r in self._documents["type_layouts"]["layouts"]
            if type_name in {r["name"], r["tag"] + " " + r["name"]} and (source is None or r["source"] == source)]
        projection = lambda r: {key: r[key] for key in ("name", "tag", "fields", "size_bits", "align_bits", "layout_complete")}
        if not layouts or len({canonical(projection(r)) for r in layouts}) != 1 or not layouts[0]["layout_complete"]:
            return self._certificate("field_layout", {"type_name": type_name, "path": list(path), "verified": False,
                "status": "ambiguous" if layouts else "unknown", "tu_ids": sorted({r["tu_id"] for r in layouts})})
        root, current, offset = layouts[0], layouts[0], 0
        selected = None
        for index, member in enumerate(path):
            matching = [f for f in current["fields"] if f["name"] == member]
            if len(matching) != 1:
                return self._certificate("field_layout", {"type_name": type_name, "path": list(path), "verified": False,
                    "status": "unknown", "tu_ids": sorted({r["tu_id"] for r in layouts})})
            selected = matching[0]
            offset += selected["offset_bits"]
            if index + 1 < len(path):
                nested = [r for r in self._documents["type_layouts"]["layouts"] if r["tu_id"] == current["tu_id"]
                    and selected["canonical_type"] in {r["name"], r["tag"] + " " + r["name"]} and r["layout_complete"]]
                if len(nested) != 1:
                    return self._certificate("field_layout", {"type_name": type_name, "path": list(path), "verified": False,
                        "status": "unknown", "tu_ids": sorted({r["tu_id"] for r in layouts})})
                current = nested[0]
        facts = {"type_name": type_name, "path": list(path), "verified": True, "status": "verified",
            "size_bits": root["size_bits"], "align_bits": root["align_bits"], "fields": deepcopy(root["fields"]),
            "offset_bits": offset, "tu_ids": sorted({r["tu_id"] for r in layouts})}
        if selected:
            facts.update(deepcopy(selected))
            facts["offset_bits"] = offset
            facts["abi_verified"] = selected["callback"] and selected["calling_convention"] != "unknown"
            facts["layout_verified"] = True
            if selected["callback"] and not facts["abi_verified"]:
                facts.update(verified=False, status="abi_unknown")
        return self._certificate("field_layout", facts)

    def callback_field(self, owner_type, field, source=None):
        return self.verify_field_layout(owner_type, [field], source)

    def verify_standard_allocation_alignment(self):
        """Canonical target max_align_t, never a project over-alignment claim."""
        self._assert_current()
        units = self._documents["compile_context"]["translation_units"]
        proofs = [unit.get("standard_allocation_alignment", {}) for unit in units]
        alignments = {proof.get("align_bits") for proof in proofs if proof.get("verified")}
        verified = bool(proofs and all(proof.get("verified") for proof in proofs) and len(alignments) == 1)
        blockers = sorted({blocker for proof in proofs for blocker in proof.get("blockers", [])})
        if len(alignments) > 1:
            blockers.append("fundamental_alignment_ambiguous_across_translation_units")
        return self._certificate("standard_allocation_alignment", {"verified": verified,
            "align_bits": next(iter(alignments)) if verified else None, "blockers": blockers,
            "tu_ids": sorted(unit["tu_id"] for unit in units), "proofs": deepcopy(proofs),
            "basis": "canonical_clang_max_align_t_target_probe"})

    def verify_intrinsic(self, name):
        self._assert_current()
        symbols = [s for s in self._documents["symbols"]["symbols"] if s["name"] == name]
        expected = _LIBC.get(name)
        declarations = [s for s in symbols if not s["project_owned"] and not s["defined"] and s["linkage"] == "external"]
        macros = [unit["macros"] for unit in self._documents["compile_context"]["translation_units"]]
        valid = bool(expected and declarations and not any(s["project_owned"] and s["defined"] for s in symbols)
            and not any(name in m for m in macros) and all(_plain_type(s["canonical_type"]) == _plain_type(expected)
                and s["calling_convention"] in {"c", "cdecl"} and not s["variadic"]
                and s["symbol_identity"] == name for s in declarations))
        return self._certificate("intrinsic_declaration", {"name": name, "declared": bool(declarations),
            "verified": valid, "abi_verified": valid, "status": "verified" if valid else "unknown",
            "canonical_type": declarations[0]["canonical_type"] if declarations else "",
            "tu_ids": sorted({s["tu_id"] for s in declarations})})


def agent_projection(tool, arguments, index, *, max_chars=16 * 1024, max_fields=32):
    """Bounded compiler facts beside source records; source EIDs stay unchanged.

    The caller enforces investigation scope and charges its tool budget. No
    spelling candidate becomes a callback target or a semantic certificate.
    """
    if not isinstance(index, BuildAwareIndex):
        raise BuildAnalysisError("agent metadata requires authenticated BuildAwareIndex")
    if (type(max_chars) is not int or not 1024 <= max_chars <= 64 * 1024
            or type(max_fields) is not int or not 1 <= max_fields <= 64):
        raise BuildAnalysisError("agent_projection_budget_invalid")
    if not isinstance(arguments, dict):
        raise BuildAnalysisError("agent_projection_arguments_invalid")
    common = {"schema_version": 1, "kind": "clang_agent_metadata", "policy_version": VERSION,
        "source_fingerprint": index.source_fingerprint, "functions_fingerprint": index.functions_fingerprint,
        "configuration_digest": index.configuration_digest, "identity_digest": index.identity_digest,
        "semantic_contract_verified": False, "points_to_verified": False, "link_verified": False,
        "truncated": False}
    if tool == "get_function":
        symbol = arguments.get("function")
        if not isinstance(symbol, str):
            raise BuildAnalysisError("agent_projection_function_missing")
        matches = ([index._function_records[symbol]] if symbol in index._function_records else
            [row for row in index._function_records.values() if row["name"] == symbol])
        if len(matches) != 1:
            return {**common, "status": "ambiguous" if matches else "unknown", "verified": False}
        fid = matches[0]["id"]
        function = index.verify_function(fid)
        semantics = index.verify_source_semantics(fid)
        result = {**common, "status": function["status"], "function": function,
            "source_semantics": {key: semantics[key] for key in (
                "verified", "source_effect_compatible", "macro_identifiers", "blockers", "evidence_id")}}
    elif tool == "get_type_definition":
        type_name = arguments.get("type")
        if not isinstance(type_name, str):
            raise BuildAnalysisError("agent_projection_type_missing")
        layout = index.verify_field_layout(type_name, [])
        fields = layout.get("fields", [])
        callback_fields = [field for field in fields if field.get("callback")]
        result = {**common, "status": layout["status"], "type_layout": {key: value for key, value in layout.items() if key != "fields"},
            "fields": deepcopy(fields[:max_fields]),
            "callback_fields": [index.verify_field_layout(type_name, [field["name"]])
                for field in callback_fields[:max_fields]],
            "fields_truncated": len(fields) > max_fields,
            "callbacks_truncated": len(callback_fields) > max_fields}
    else:
        return {**common, "status": "unsupported_tool", "verified": False}
    if len(canonical(result)) > max_chars:
        result = {**common, "status": "projection_budget_exceeded", "truncated": True,
            "verified": False, "original_status": result["status"]}
    return result
