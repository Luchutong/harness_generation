"""Finite Strategy-to-code translation and independently admitted execution."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from pathlib import Path
import re

from ..semantic_discovery.models import digest
from .build import SANITIZERS, build_and_run
from .executable_helpers import require_strategy_plan

TRANSLATION_VERSION = "typed-strategy-translation-v1"


def _variable(value):
    return "hg_v_" + value


def _ctype(type_name, pointer_depth):
    if not isinstance(type_name, str) or not re.fullmatch(r"(?:struct |union |enum )?[A-Za-z_]\w*(?: [A-Za-z_]\w*)*", type_name):
        raise ValueError("unrepresentable Strategy storage type")
    if type(pointer_depth) is not int or not 0 <= pointer_depth <= 4:
        raise ValueError("unrepresentable Strategy pointer depth")
    return type_name + " *" * pointer_depth


def _source_ctype(value):
    """A finite type spelling from the Plan's source-bound API declaration.

    Logical pointer depth already includes opaque typedef pointers.  It cannot
    be appended to the source spelling a second time.
    """
    if not isinstance(value, str) or len(value) > 1024:
        raise ValueError("unrepresentable source resource type")
    value = " ".join(value.split())
    qualifiers = r"(?:const|volatile|restrict|__restrict|__restrict__)"
    grammar = r"[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*(?:\s*\*\s*(?:" + qualifiers + r"\s*)*)*"
    if not re.fullmatch(grammar, value):
        raise ValueError("unrepresentable source resource type")
    return value


def _unqualified_storage(value):
    """Copyable local storage drops object qualifiers, preserving pointee CV."""
    value = _source_ctype(value)
    qualifiers = r"(?:const|volatile|restrict|__restrict|__restrict__)"
    if "*" in value:
        base, tail = value.rsplit("*", 1)
        if not tail.strip() or re.fullmatch(r"(?:" + qualifiers + r"\s*)+", tail.strip()):
            return base.rstrip() + " *"
    return re.sub(r"^(?:" + qualifiers + r"\s+)+", "", value)


def _pointee_storage(value):
    value = _source_ctype(value)
    if "*" not in value:
        # An alias hiding the *entire* out indirection requires a typedef
        # expansion witness.  Logical depth is insufficient to invent it.
        raise ValueError("out resource type has no source-spelled outer pointer")
    return _unqualified_storage(value.rsplit("*", 1)[0].rstrip())


def _resource_ctype(resource, strategy, declarations):
    """Bind storage to the exact creator endpoint or inspected API argument."""
    steps = {step["step_id"]: step for step in strategy["steps"]}
    origin = resource["origin"]
    if origin["kind"] in {"return", "out_pointee"}:
        producer = steps[origin["call_step_id"]]
        declaration = declarations[producer["function_id"]]
        if origin["kind"] == "return":
            return _unqualified_storage(declaration["return_type"])
        parameter = next((p for p in declaration["parameters"] if p["name"] == origin["parameter"]), None)
        if parameter is None:
            raise ValueError("captured output lacks its source parameter type")
        return _pointee_storage(parameter["type"])
    if origin["kind"] == "construct":
        candidates = set()
        for step in strategy["steps"]:
            if step["kind"] not in {"call", "cleanup"}:
                continue
            for parameter in declarations[step["function_id"]]["parameters"]:
                expression = step["arguments"].get(parameter["name"], {})
                if expression.get("value_id") != resource["value_id"] or expression.get("kind") not in {"value", "address"}:
                    continue
                expected_depth = resource["pointer_depth"] + int(expression["kind"] == "address")
                if parameter.get("pointer_depth") != expected_depth:
                    raise ValueError("constructed resource differs from its source pointer depth")
                spelling = _pointee_storage(parameter["type"]) if expression["kind"] == "address" else _unqualified_storage(parameter["type"])
                candidates.add(spelling)
        if len(candidates) > 1:
            raise ValueError("constructed resource has conflicting source type spellings")
        if candidates:
            return candidates.pop()
    return _ctype(resource["type_name"], resource["pointer_depth"])


def lower_strategy(plan, *, plan_validator=None):
    """Produce a fixed finite translation recipe without any source investigation."""
    require_strategy_plan(plan, plan_validator=plan_validator)
    strategy = plan["strategy"]
    declarations = {d["function_id"]: d for d in plan["api_declarations"]}
    resource_rows = plan["executable_resources"] if plan["artifact_kind"] == "executable_plan" else strategy["resources"]
    resources = {r["value_id"]: r for r in resource_rows}
    steps = {s["step_id"]: s for s in strategy["steps"]}
    capture_returns = {s["call_step_id"]: s["value_id"] for s in strategy["steps"]
                       if s["kind"] == "capture" and s["source"] == "return"}
    calls = []
    for step in strategy["steps"]:
        if step["kind"] not in {"call", "cleanup"}:
            continue
        declaration = declarations[step["function_id"]]
        calls.append({"step_id": step["step_id"], "function_id": step["function_id"],
            "symbol": declaration["symbol"], "arguments": deepcopy(step["arguments"]),
            "argument_order": [p["name"] for p in declaration["parameters"]],
            "guards": deepcopy(step["guard_ids"]), "capture_return": capture_returns.get(step["step_id"]),
            "cleanup_resource_id": resources[step["resource_value_id"]]["resource_id"] if step["kind"] == "cleanup" else None,
            "calls_per_input": 1})
    resource_bindings = [{**deepcopy(resource), "declaration_type": _resource_ctype(resource, strategy, declarations)}
                         for resource in resource_rows]
    result = {"schema_version": 1, "policy_version": TRANSLATION_VERSION,
        "plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"],
        "strategy_id": plan["strategy_id"], "strategy_digest": plan["strategy_digest"],
        "calls": calls, "resource_bindings": resource_bindings,
        "canonical_variables": {value: _variable(value) for value in resources},
        "input_policy": deepcopy(plan["input_policy"]), "generation_allowed": plan["generation_allowed"],
        "experimental_execution_allowed": plan.get("experimental_execution_allowed", False)}
    if plan["artifact_kind"] == "executable_plan":
        result.update(execution_allowed=True, semantic_verified=False, statistics_category="candidate")
    return result


def deterministic_translate(plan, *, plan_validator=None):
    """Translate only the typed grammar, preserving input/guard/lifetime identity."""
    lowering = lower_strategy(plan, plan_validator=plan_validator)
    strategy, language = plan["strategy"], plan["language"]
    resources = {r["value_id"]: r for r in strategy["resources"]}
    declarations = {d["function_id"]: d for d in plan["api_declarations"]}
    all_steps = {s["step_id"]: s for s in strategy["steps"]}
    captures = {s["call_step_id"]: s["value_id"] for s in strategy["steps"]
                if s["kind"] == "capture" and s["source"] == "return"}
    transformed = [s for s in strategy["steps"] if s["kind"] == "transform_input"]
    buffers = [s for s in transformed if s["operation"] != "decode_integer"]
    lines = ["#include <stddef.h>", "#include <stdint.h>", "#include <stdlib.h>", "#include <string.h>"]
    if plan["headers"]:
        lines += [f'#include "{header}"' for header in plan["headers"]]
    else:
        lines += [declaration.rstrip().rstrip(";") + ";" for declaration in plan["type_declarations"]]
        for declaration in plan["api_declarations"]:
            # The parser's exact prototype is source data. A macro or complex
            # ABI not representable here must use a build-owned project header.
            signature = declaration["signature"].rstrip().rstrip(";")
            prefix = 'extern "C" ' if language == "c++" and declaration["linkage"] == "c" else ""
            lines.append(prefix + signature + ";")
    prefix = 'extern "C" ' if language == "c++" else ""
    lines.append(prefix + "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {")
    lines.append(f'    if (size > {plan["input_policy"]["max_bytes"]}) return 0;')
    minimum = max((s["width"] for s in transformed if s["operation"] == "decode_integer"), default=0)
    if minimum:
        lines.append(f"    if (size < {minimum}) return 0;")
    for resource in lowering["resource_bindings"]:
        typename = resource["declaration_type"]
        initializer = "NULL" if resource["pointer_depth"] else "{}" if language == "c++" else "{0}"
        lines.append(f'    {typename} {_variable(resource["value_id"])} = {initializer};')
    for step in strategy["steps"]:
        if step["kind"] == "guard":
            lines.append(f'    int hg_g_{step["step_id"]} = 0;')
    # Every fallible harness allocation happens before any target creation.
    # Failure then releases only initialized framework buffers, never bypassing
    # target resource cleanup. All buffers stay live until target cleanup ends.
    for step in buffers:
        var = _variable(step["value_id"])
        extra = " + 1" if step["operation"] == "nul_terminate" else ""
        extent = f"size{extra}" if extra else "(size ? size : 1)"
        lines.append(f'    {var} = ({_ctype(step["type_name"], 1)})malloc({extent});')
        lines.append(f"    if (!{var}) {{")
        lines.extend(f'        free({_variable(previous["value_id"])});' for previous in buffers[:buffers.index(step)])
        lines.append("        return 0;")
        lines.append("    }")

    def expression(row, parameter=None):
        kind = row["kind"]
        if kind == "fuzz_bytes":
            if parameter is None:
                return "data"
            return "(" + parameter["type"] + ")data"
        if kind == "fuzz_size":
            return "size"
        if kind == "null":
            return "NULL"
        if kind == "integer":
            # Parentheses preserve negative values, including the minimum
            # signed 64-bit integer without a too-large positive C literal.
            value = row["value"]
            return "(-9223372036854775807LL - 1LL)" if value == -(2**63) else f"({value}LL)"
        if kind == "source_function":
            declaration = declarations.get(row["function_id"])
            if declaration is None or not re.fullmatch(r"[A-Za-z_]\w*", declaration["symbol"]):
                raise ValueError("source callback requires its exact source-bound Plan declaration")
            return "&" + declaration["symbol"]
        var = _variable(row["value_id"])
        if kind == "address":
            return "&" + var
        if kind == "length":
            return "(size + 1)" if row["include_terminator"] else "size"
        return var

    for step in strategy["steps"]:
        kind = step["kind"]
        if kind == "construct":
            # The immutable declaration already creates zeroed per-entry storage.
            continue
        if kind == "transform_input":
            var = _variable(step["value_id"])
            if step["operation"] == "decode_integer":
                lines.append(f'    memcpy(&{var}, data, {step["width"]});')
            else:
                lines.append(f"    memcpy({var}, data, size);")
                if step["operation"] == "nul_terminate":
                    lines.append(f"    {var}[size] = 0;")
        elif kind == "capture":
            if step["source"] == "out_pointee":
                creator = all_steps[step["call_step_id"]]
                slot = creator["arguments"][step["parameter"]]["value_id"]
                lines.append(f'    {_variable(step["value_id"])} = {_variable(slot)};')
            # Return assignment is the creator call's single canonical call site.
        elif kind == "guard":
            condition = step["condition"]
            if condition["kind"] == "size":
                predicate = f'size >= {condition["minimum"]} && size <= {condition["maximum"]}'
            elif condition["kind"] == "nonnull":
                predicate = _variable(condition["value_id"]) + " != NULL"
            else:
                operator = "==" if condition["comparison"] == "zero" else "!="
                predicate = _variable(condition["value_id"]) + " " + operator + " 0"
            lines.append(f'    hg_g_{step["step_id"]} = ({predicate});')
        elif kind in {"call", "cleanup"}:
            declaration = declarations[step["function_id"]]
            arguments = [expression(step["arguments"][p["name"]], p) for p in declaration["parameters"]]
            call = declaration["symbol"] + "(" + ", ".join(arguments) + ")"
            if step["step_id"] in captures:
                call = _variable(captures[step["step_id"]]) + " = " + call
            elif declaration["return_type"].strip() != "void":
                call = "(void)" + call
            if step["guard_ids"]:
                predicate = " && ".join("hg_g_" + gid for gid in step["guard_ids"])
                lines.append(f"    if ({predicate}) {{ {call}; }}")
            else:
                lines.append("    " + call + ";")
    lines.extend(f'    free({_variable(step["value_id"])});' for step in reversed(buffers))
    lines += ["    return 0;", "}", ""]
    return "\n".join(lines)



def execute_strategy_plan(plan, code, directory, recipe, *, runtime=True, ft=None, snapshot=None,
                          evidence=None, authorized_ids=None, build_analysis=None, plan_validator=None, contracts=None):
    """Revalidate executable admission before compiling/running one candidate."""
    from .strategy_validation import validate_strategy_code
    require_strategy_plan(plan, plan_validator=plan_validator)
    from .executable_plan import ExecutablePlanVerifier
    if any(value is None for value in (ft, snapshot, evidence, authorized_ids, build_analysis)):
        raise ValueError("executable execution requires independent source/scope/evidence/build inputs")
    verdict = ExecutablePlanVerifier(ft, snapshot, evidence, authorized_ids,
        build_analysis=build_analysis, project_root=recipe.project_root, contracts=contracts).verify(plan)
    if verdict["valid"] is not True:
        raise ValueError("executable plan execution revalidation failed: " + verdict["detail"])
    if snapshot is not None:
        from ..source_paths import SourcePathResolver
        from ..source_snapshot import authenticated_c_source
        resolver = SourcePathResolver(recipe.project_root)
        active = {s["function_id"] for s in plan["strategy"]["steps"] if s["kind"] in {"call", "cleanup"}}
        required_files = {snapshot.functions[fid]["file"] for fid in active}
        required_files.update(record.get("source") for record in evidence_records_for_execution(evidence)
                              if record.get("source") in snapshot.artifacts.source_hashes)
        for filename in sorted(required_files):
            with resolver.resolve(filename).open("rb") as stream:
                data = stream.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise ValueError("frozen execution source exceeds read bound")
            authenticated_c_source(snapshot.artifacts, filename, data)
    if build_analysis is not None:
        if snapshot is None:
            raise ValueError("build-aware execution requires frozen snapshot")
        from .executable_helpers import build_projection
        build_projection(build_analysis, snapshot, [s["function_id"] for s in plan["strategy"]["steps"]
                         if s["kind"] in {"call", "cleanup"}])
        build_analysis.validate_recipe({**recipe.to_dict(),
            "effective_compiler_flags": list(recipe.compiler_flags + SANITIZERS)})
    validation = validate_strategy_code(code, plan, plan_validator=plan_validator)
    if not validation["valid"]:
        raise ValueError("strategy code does not preserve immutable plan: " + ",".join(validation["errors"]))
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    harness = directory / ("harness.cpp" if plan["language"] == "c++" else "harness.c")
    harness.write_text(code, encoding="utf-8")
    target_input_digests = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (*recipe.source_files, *recipe.header_files)}
    build, replay = build_and_run(harness, directory, plan, recipe, runtime=runtime,
                                  inherit_target_flags=True)
    if target_input_digests != {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (*recipe.source_files, *recipe.header_files)}:
        raise ValueError("target build inputs changed during execution")
    # The live index also binds transitive headers, compile commands and
    # compiler identity, including inputs omitted from recipe.header_files.
    build_analysis.validate_snapshot(snapshot)
    category = "candidate"
    for report in (build, replay):
        report.update({"statistics_category": category, "artifact_kind": plan["artifact_kind"],
            "strategy_id": plan["strategy_id"], "strategy_digest": plan["strategy_digest"],
            "plan_digest": plan["plan_digest"], "generation_allowed": plan["generation_allowed"],
            "semantic_correctness_certified": False,
            "formal_success_statistics_allowed": False,
            "execution_allowed": True, "semantic_verified": False})
    build["recipe_digest"] = digest(recipe.to_dict())
    build["target_input_digests"] = target_input_digests
    from ..records import write_json
    write_json(directory / "build.json", build, sort_keys=True, allow_nan=False)
    write_json(directory / "runtime.json", replay, sort_keys=True, allow_nan=False)
    return build, replay


def evidence_records_for_execution(evidence):
    from .executable_helpers import evidence_records
    return list(evidence_records(evidence).values()) if evidence is not None else []
