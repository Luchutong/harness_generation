"""Source declarations and identity helpers for executable plans."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import re

from ..harness_strategy.models import StrategyBudget


def evidence_records(evidence):
    if isinstance(evidence, dict) and "records" in evidence:
        evidence = evidence["records"]
    return evidence if isinstance(evidence, dict) else {
        row["evidence_id"]: row for row in evidence if isinstance(row, dict) and "evidence_id" in row}


def strategy_budget(strategy):
    """Recover finite IR bounds from the strategy; never silently raise input bounds."""
    maximum = strategy.get("input_policy", {}).get("max_input_bytes")
    if type(maximum) is not int or not 1 <= maximum <= 16777216:
        raise ValueError("strategy has no valid bounded input policy")
    return StrategyBudget(max_input_bytes=maximum)


def build_projection(build_analysis, snapshot, function_ids):
    """Only the independently loaded Clang index may attest build callability."""
    if build_analysis is None:
        return None
    from ..source_analysis.clang_index import BuildAwareIndex
    if not isinstance(build_analysis, BuildAwareIndex):
        raise ValueError("build analysis requires a verified BuildAwareIndex object")
    build_analysis.validate_snapshot(snapshot)
    projection = build_analysis.public_projection()
    if (projection.get("source_fingerprint") != snapshot.source_fingerprint
            or projection.get("functions_fingerprint") != snapshot.functions_fingerprint):
        raise ValueError("build analysis source identity mismatch")
    return {**projection, "callable_targets": [
        {"function_id": fid, **build_analysis.verify_function(fid)} for fid in sorted(set(function_ids))]}


def unreachable_core_calls(ft, strategy, maximum):
    """Account for guards and decoder checks in the actual finite translator."""
    steps = strategy.get("steps", [])
    by_id = {step["step_id"]: step for step in steps}
    core = {row["function_id"] for row in ft["core_functions"]}
    decoder_minimum = max((step["width"] for step in steps if step.get("kind") == "transform_input"
                          and step.get("operation") == "decode_integer"), default=0)
    rejected = []
    for step in steps:
        if step.get("kind") != "call" or step.get("function_id") not in core:
            continue
        lower, upper = decoder_minimum, maximum
        for guard_id in step.get("guard_ids", []):
            guard = by_id[guard_id]["condition"]
            if guard["kind"] == "size":
                lower, upper = max(lower, guard["minimum"]), min(upper, guard["maximum"])
        if lower > upper:
            rejected.append((step["step_id"], lower, upper))
    return rejected


def _headers(headers):
    result = tuple(sorted(set(headers)))
    if any(not isinstance(h, str) or not re.fullmatch(r"[A-Za-z0-9_./+-]+\.(?:h|hpp|hh)", h)
           or Path(h).is_absolute() or ".." in Path(h).parts for h in result):
        raise ValueError("headers must be project-relative header names")
    return result


def translation_declarations(snapshot, active):
    """Source-owned declarations shared by the distinct plan authorities."""
    declarations = []
    for fid in sorted(set(active)):
        function = snapshot.functions[fid]
        symbol = function["name"]
        if not re.fullmatch(r"[A-Za-z_]\w*", symbol):
            raise ValueError("strategy symbols require a finite direct ABI spelling")
        declarations.append({"function_id": fid, "symbol": symbol, "signature": function["signature"],
            "parameters": deepcopy(function["parameters"]), "return_type": function["return_type"],
            "return_pointer_depth": function.get("return_pointer_depth", 0),
            "linkage": "c" if Path(function["file"]).suffix == ".c" else "c++"})
    if len({d["symbol"] for d in declarations}) != len(declarations):
        raise ValueError("ambiguous direct symbol spelling")
    needed = set()
    for row in declarations:
        needed.update(re.findall(r"[A-Za-z_]\w*", row["signature"]))
    type_declarations = []
    for _ in range(len(snapshot.artifacts.structs) + 1):
        changed = False
        for struct in snapshot.artifacts.structs:
            if needed & {struct["name"], *struct.get("aliases", [])} and struct["declaration"] not in type_declarations:
                type_declarations.append(struct["declaration"])
                needed.update(re.findall(r"[A-Za-z_]\w*", struct["declaration"]))
                changed = True
        if not changed:
            break
    for declaration in snapshot.artifacts.callback_typedefs:
        if declaration["name"] in needed:
            type_declarations.append(declaration["declaration"])
    return declarations, type_declarations


def require_strategy_plan(plan, *, plan_validator=None):
    """Require the independently revalidated generation-first plan authority."""
    from .executable_plan import require_executable_plan
    return require_executable_plan(plan, plan_validator=plan_validator)
