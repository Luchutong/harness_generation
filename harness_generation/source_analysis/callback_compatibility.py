"""Finite source callback bindings from real Clang prototypes and source frames.

A source function ID is a reference to an authorized inspected definition. It
is never a C expression or a user-supplied function body. These observations
authorize no effects themselves; the normal extractor, verifier and Context
must consume the exact selected target and its actual source effects.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from ..semantic_discovery.models import digest
from . import analyzer
from .index import BuildAwareIndex

VERSION = "clang-source-callback-binding-v1"
_SUGAR = {"QualType", "TypedefType", "ElaboratedType", "ParenType", "AttributedType"}
_READ_FRAME = {"CompoundStmt", "ReturnStmt", "IfStmt", "ParenExpr", "ImplicitCastExpr",
               "DeclRefExpr", "IntegerLiteral", "CharacterLiteral", "FloatingLiteral",
               "BinaryOperator", "UnaryOperator", "MemberExpr", "ArraySubscriptExpr",
               "CStyleCastExpr", "ConstantExpr", "NullStmt"}


def is_callback_parameter(snapshot, parameter):
    """Only a mechanical requirement hint; this never proves compatibility."""
    declaration = parameter.get("declaration", parameter.get("type", ""))
    if re.search(r"\(\s*[^()]*\*\s*[^()]*\)\s*\(", declaration):
        return True
    names = set(re.findall(r"[A-Za-z_]\w*", parameter.get("type", "")))
    return bool(names & {row["name"] for row in snapshot.artifacts.callback_typedefs})


def source_function_ids(strategy):
    if not isinstance(strategy, dict) or not isinstance(strategy.get("steps"), list):
        return set()
    return {expression["function_id"] for step in strategy["steps"] if isinstance(step, dict)
            and isinstance(step.get("arguments", {}), dict) for expression in step.get("arguments", {}).values()
            if isinstance(expression, dict) and expression.get("kind") == "source_function"
            and isinstance(expression.get("function_id"), str)}


def _strip_type(identity):
    for _ in range(32):
        children = identity.get("children", [])
        if identity.get("kind") in _SUGAR and len(children) == 1:
            identity = children[0]
        else:
            return identity
    return {}


def _function_pointer(identity):
    identity = _strip_type(identity)
    children = identity.get("children", [])
    if identity.get("kind") != "PointerType" or len(children) != 1:
        return None
    function = _strip_type(children[0])
    return function if function.get("kind") == "FunctionProtoType" and not function.get("variadic") else None


def _strip_expression(node):
    for _ in range(16):
        children = node.get("inner", [])
        if node.get("kind") in {"ParenExpr", "ImplicitCastExpr", "ConstantExpr"} and len(children) == 1:
            node = children[0]
        else:
            return node
    return node


class SourceCallbackBindings:
    """Process-local independent replay; saved labels cannot create an instance."""

    def __init__(self, analysis, snapshot, evidence, authorized_ids):
        self.analysis, self.snapshot = analysis, snapshot
        self.evidence, self.authorized = evidence, set(authorized_ids)
        self._ast_cache, self._cache = {}, {}

    @staticmethod
    def _finish(facts):
        facts["evidence_id"] = "clang_callback_ev_" + digest(facts)[:32]
        return deepcopy(facts)

    def _original_ast(self, context, unit, facts):
        if unit["tu_id"] not in self._ast_cache:
            arguments = [context["compiler"]["path"], *unit["arguments"],
                         str(Path(context["project_root"]) / unit["source"]),
                         "-fsyntax-only", "-Xclang", "-ast-dump=json"]
            code, text, diagnostics = analyzer._run(arguments, unit["directory"],
                analyzer.AnalysisBudget(**context["budget"]), context["budget"]["max_ast_bytes"], compact_json=True)
            facts["execution_accounting"]["callback_clang_subprocess_calls"] += 1
            if code:
                raise analyzer.BuildAnalysisError("callback_original_translation_unit_replay_failed:" + diagnostics[:1024])
            self._ast_cache[unit["tu_id"]] = json.loads(text)
        return self._ast_cache[unit["tu_id"]]

    @staticmethod
    def _source_function(ast, record, project):
        current_file, matches = None, []
        for node in analyzer._walk(ast):
            location, current_file = analyzer._location(node, current_file, project, {})
            if (node.get("kind") == "FunctionDecl" and node.get("name") == record["name"]
                    and location and location["source"] == record["file"]
                    and any(child.get("kind") == "CompoundStmt" for child in node.get("inner", []))):
                matches.append(node)
        if len(matches) != 1:
            raise analyzer.BuildAnalysisError("callback_source_function_body_unresolved")
        function = matches[0]
        body = next(node for node in function["inner"] if node.get("kind") == "CompoundStmt")
        raw = (project / record["file"]).read_bytes()
        begin, end = body.get("range", {}).get("begin", {}), body.get("range", {}).get("end", {})
        if (type(begin.get("offset")) is not int or type(end.get("offset")) is not int
                or set(begin) & {"spellingLoc", "expansionLoc"} or set(end) & {"spellingLoc", "expansionLoc"}):
            raise analyzer.BuildAnalysisError("callback_source_body_range_unresolved")
        stop = end["offset"] + end.get("tokLen", 0)
        if raw[begin["offset"]:stop] != record.get("body", "").encode():
            raise analyzer.BuildAnalysisError("callback_source_body_identity_mismatch")
        return function, body

    @staticmethod
    def _read_frame(body, *, callback_declaration=None):
        allowed = _READ_FRAME | ({"CallExpr"} if callback_declaration is not None else set())
        for node in analyzer._walk(body):
            kind, children = node.get("kind"), node.get("inner", [])
            if kind not in allowed:
                return "callback_source_control_or_storage_effect_unsupported:" + str(kind)
            if kind == "BinaryOperator" and node.get("opcode") in {"=", ","}:
                return "callback_source_retention_or_mutation_unverified"
            if kind == "UnaryOperator" and node.get("opcode") in {"++", "--", "&"}:
                return "callback_source_retention_or_mutation_unverified"
            if kind == "CStyleCastExpr" and node.get("type", {}).get("qualType") != "void":
                return "callback_source_explicit_conversion_unsupported"
            if kind == "DeclRefExpr" and node.get("referencedDecl", {}).get("kind") not in {"ParmVarDecl", "EnumConstantDecl"}:
                return "callback_source_global_or_local_state_unverified"
            if kind == "CallExpr":
                target = _strip_expression(children[0]) if children else {}
                if target.get("referencedDecl", {}).get("id") != callback_declaration:
                    return "callback_source_other_call_lifetime_unverified"
        return None

    def verify(self, step, parameter):
        expression = step.get("arguments", {}).get(parameter, {})
        facts = {"policy_version": VERSION, "function_id": step.get("function_id"), "step_id": step.get("step_id"),
                 "parameter": parameter, "callback_function_id": expression.get("function_id"),
                 "verified": False, "abi_verified": False, "synchronous_frame_verified": False,
                 "status": "unknown", "reason": "callback_binding_unverified",
                 "generation_authority": False, "semantic_effect_authority": False,
                 "source_evidence_ids": [], "forwarded_arguments": [],
                 "execution_accounting": {"model_calls": 0, "provider_requests": 0,
                                          "callback_clang_subprocess_calls": 0}}
        try:
            if type(self.analysis) is not BuildAwareIndex or not self.analysis.authenticated:
                raise analyzer.BuildAnalysisError("callback_requires_live_build_index")
            self.analysis.validate_snapshot(self.snapshot)
            if expression.get("kind") != "source_function" or set(expression) != {"kind", "function_id", "evidence_ids"}:
                raise analyzer.BuildAnalysisError("callback_requires_typed_source_function_reference")
            fid, target_id = step["function_id"], expression["function_id"]
            if not {fid, target_id} <= self.authorized or target_id not in self.snapshot.functions:
                raise analyzer.BuildAnalysisError("callback_function_outside_authorized_scope")
            from ..semantic_effects.call_resolution import _authenticated_records
            from ..harness_context.value_flow import complete_bodies
            records = _authenticated_records(self.snapshot, self.evidence)
            complete = complete_bodies(self.snapshot, records)
            if not set(expression["evidence_ids"]) & set(complete.get(target_id, [])) or fid not in complete:
                raise analyzer.BuildAnalysisError("callback_complete_authenticated_source_not_cited")
            if not set(expression["evidence_ids"]) <= records.keys():
                raise analyzer.BuildAnalysisError("callback_unissued_or_modified_source_evidence")
            key = digest({"step": step, "parameter": parameter, "evidence": records,
                          "authorized": sorted(self.authorized), "build": self.analysis.identity_digest})
            if key in self._cache:
                return deepcopy(self._cache[key])
            if not self.analysis.verify_function(target_id).get("verified"):
                raise analyzer.BuildAnalysisError("callback_target_not_callable_in_current_build")
            api_type, callback_type = self.analysis.verify_type_identity(fid), self.analysis.verify_type_identity(target_id)
            if not api_type.get("verified") or not callback_type.get("verified"):
                raise analyzer.BuildAnalysisError("callback_complete_function_type_unverified")
            parameters = [row for row in api_type["parameters"] if row["name"] == parameter]
            expected = _function_pointer(parameters[0]["canonical_identity"]) if len(parameters) == 1 else None
            actual = _strip_type(callback_type["canonical_identity"])
            facts.update(build_identity_digest=self.analysis.identity_digest,
                source_fingerprint=self.snapshot.source_fingerprint, functions_fingerprint=self.snapshot.functions_fingerprint,
                expected_function_type=expected, actual_function_type=actual,
                type_identity_evidence_ids=[api_type["evidence_id"], callback_type["evidence_id"]])
            if expected is None or actual.get("kind") != "FunctionProtoType" or expected != actual:
                facts.update(status="incompatible", reason="callback_complete_clang_function_prototype_mismatch")
                return self._finish(facts)
            facts["abi_verified"] = True
            # Nominal record types and declaration scopes are compared in the
            # original TU, never flattened to names or opaque LLVM pointers.
            if len(api_type.get("tu_ids", [])) != 1 or api_type["tu_ids"] != callback_type.get("tu_ids"):
                raise analyzer.BuildAnalysisError("callback_cross_translation_unit_frame_unsupported")
            returned = _strip_type(actual["children"][0])
            if returned.get("kind") != "BuiltinType":
                raise analyzer.BuildAnalysisError("callback_pointer_or_aggregate_return_lifetime_unverified")
            context = self.analysis._documents["compile_context"]
            unit = next(row for row in context["translation_units"] if row["tu_id"] == api_type["tu_ids"][0])
            if Path(unit["source"]).suffix != ".c":
                raise analyzer.BuildAnalysisError("callback_source_language_unsupported")
            ast = self._original_ast(context, unit, facts)
            project = Path(context["project_root"])
            api_function, api_body = self._source_function(ast, self.snapshot.functions[fid], project)
            callback_function, callback_body = self._source_function(ast, self.snapshot.functions[target_id], project)
            api_parameters = {node["name"]: node for node in api_function["inner"] if node.get("kind") == "ParmVarDecl"}
            declaration = api_parameters[parameter]["id"]
            for body, callback in ((api_body, declaration), (callback_body, None)):
                error = self._read_frame(body, callback_declaration=callback)
                if error:
                    raise analyzer.BuildAnalysisError(error)
            callback_parameters = [node for node in callback_function["inner"] if node.get("kind") == "ParmVarDecl"]
            calls, accepted_callback_refs = [], set()
            for node in analyzer._walk(api_body):
                if node.get("kind") != "CallExpr":
                    continue
                children = node["inner"]
                target = _strip_expression(children[0])
                accepted_callback_refs.add(target.get("id"))
                if len(children) - 1 != len(callback_parameters):
                    raise analyzer.BuildAnalysisError("callback_source_call_arity_unresolved")
                offset = node["range"]["begin"].get("offset")
                if type(offset) is not int:
                    raise analyzer.BuildAnalysisError("callback_source_call_coordinate_unresolved")
                row = {"body_offset": offset - api_body["range"]["begin"]["offset"], "arguments": []}
                for callback_parameter, argument in zip(callback_parameters, children[1:]):
                    argument = _strip_expression(argument)
                    reference = argument.get("referencedDecl", {})
                    matches = [name for name, declared in api_parameters.items() if declared["id"] == reference.get("id")]
                    if argument.get("kind") != "DeclRefExpr" or len(matches) != 1 or matches[0] == parameter:
                        raise analyzer.BuildAnalysisError("callback_source_argument_requires_exact_parameter_forwarding")
                    name = matches[0]
                    forwarded = {"api_parameter": name, "callback_parameter": callback_parameter["name"],
                                 "expression": deepcopy(step["arguments"][name])}
                    row["arguments"].append(forwarded)
                    if forwarded not in facts["forwarded_arguments"]:
                        facts["forwarded_arguments"].append(forwarded)
                calls.append(row)
            for node in analyzer._walk(api_body):
                if (node.get("kind") == "DeclRefExpr" and node.get("referencedDecl", {}).get("id") == declaration
                        and node.get("id") not in accepted_callback_refs):
                    raise analyzer.BuildAnalysisError("callback_function_reference_retention_unverified")
            if len(calls) > 16:
                raise analyzer.BuildAnalysisError("callback_source_call_budget_exhausted")
            compatible = all(self.analysis.verify_source_semantics(function).get("source_effect_compatible")
                             for function in (fid, target_id))
            if not compatible:
                raise analyzer.BuildAnalysisError("callback_source_preprocessed_effects_unverified")
            facts.update(verified=True, status="verified", reason="clang_exact_source_callback_and_finite_synchronous_frame",
                         synchronous_frame_verified=True, call_sites=calls,
                         source_evidence_ids=sorted(set(complete[fid]) | set(complete[target_id])),
                         source_body_sha256={function: hashlib.sha256(self.snapshot.functions[function]["body"].encode()).hexdigest()
                                             for function in (fid, target_id)})
            result = self._finish(facts)
            self._cache[key] = result
            self.analysis.validate_snapshot(self.snapshot)
            return deepcopy(result)
        except (analyzer.BuildAnalysisError, ValueError, TypeError, KeyError, AttributeError, OSError) as error:
            facts["reason"] = str(error)
            return self._finish(facts)
