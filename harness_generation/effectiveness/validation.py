"""Independent build, stability, and finite input-path observations.

Input sensitivity means that two distinct supplied byte strings produce
different sets of covered *post-entry-guard* source regions/branch edges in
the target, and each set repeats in two isolated processes. Execution counts
alone, harness-only coverage, and aggregate libFuzzer profiles cannot satisfy
this criterion. No observation here certifies a full resource lifecycle.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
from typing import Callable

POLICY = "finite-target-input-path-v1"
PROBE_INSTRUMENTATION = ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
                         "-fprofile-instr-generate", "-fcoverage-mapping", "-g", "-O1"]
METRIC_DEFINITIONS = {
    "target_call_count": "Sum of target function entry counts across isolated repeated input probes, not API attempt counts.",
    "valid_state_call_count": "Entries minus executions of source-grounded leading parameter-rejection branches; only identified entry checks, not all semantic preconditions or object lifetime.",
    "target_body_coverage": "Union of covered code regions starting after the identified entry rejection guards, in the exact target source function; no threshold implies effectiveness.",
    "input_sensitive_coverage": "Distinct byte inputs yield distinct covered target-body region/branch-edge sets, with identical sets on two isolated runs of each input. Counts alone and harness coverage are excluded; finite evidence, not full dataflow proof.",
}

DRIVER = r'''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
extern int LLVMFuzzerTestOneInput(const uint8_t *, size_t);
int main(int argc, char **argv) {
  if (argc != 2) return 90;
  FILE *stream = fopen(argv[1], "rb");
  if (!stream) return 91;
  uint8_t data[4097] = {0};
  size_t size = fread(data, 1, sizeof(data), stream);
  if (ferror(stream) || size > 4096) { fclose(stream); return 92; }
  fclose(stream);
  LLVMFuzzerTestOneInput(data, size);
  return 0;
}
'''


def _write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def _hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def coverage_tools(compiler):
    """Prefer compiler siblings: PATH can omit the matching LLVM tools."""
    directory = Path(compiler).resolve().parent
    result = {}
    for name in ("llvm-profdata", "llvm-cov"):
        sibling = directory / name
        result[name] = str(sibling) if sibling.is_file() else shutil.which(name)
    return result


def _compile_configuration(recipe, source):
    cxx = str(source).endswith(".cpp")
    compiler = str(Path(recipe["compiler"]).with_name("clang++")) if cxx else recipe["compiler"]
    flags = [flag for flag in recipe.get("compiler_flags", []) if not cxx or not flag.startswith("-std=")]
    if cxx:
        flags.append("-std=c++17")
    return compiler, flags


def _dependencies(path, root):
    text = Path(path).read_text().replace("\\\n", " ")
    _, separator, dependencies = text.partition(":")
    if not separator:
        raise ValueError("compiler dependency file missing target")
    result = {}
    for filename in shlex.split(dependencies):
        path = Path(filename)
        if not path.is_absolute():
            path = Path(root) / path
        result[str(path.resolve())] = _hash(path)
    return result


def _run(command, *, cwd, log, timeout, environment=None):
    try:
        with Path(log).open("w", encoding="utf-8") as output:
            result = subprocess.run(command, cwd=cwd, stdout=output, stderr=subprocess.STDOUT,
                                    env=environment, timeout=timeout, check=False)
        return {"exit_code": result.returncode, "timed_out": False}
    except subprocess.TimeoutExpired:
        return {"exit_code": None, "timed_out": True}


def _walk(node):
    yield node
    for child in node.get("inner", []):
        yield from _walk(child)


def _point(location, source):
    location = location.get("expansionLoc", location)
    if "offset" not in location:
        raise ValueError("AST source offset absent")
    offset = location["offset"]
    prefix = source[:offset]
    return [prefix.count(b"\n") + 1, offset - prefix.rfind(b"\n")]


def _terminates(node):
    kind = node.get("kind")
    if kind == "ReturnStmt":
        return True
    if kind == "CompoundStmt":
        children = node.get("inner", [])
        if any(child.get("kind") in {"GotoStmt", "LabelStmt", "WhileStmt", "ForStmt", "DoStmt"} for child in children):
            return False
        return bool(children) and _terminates(children[-1])
    if kind == "IfStmt" and node.get("hasElse"):
        children = node.get("inner", [])
        return len(children) >= 3 and _terminates(children[-2]) and _terminates(children[-1])
    return False


def _parameter_predicate(node):
    allowed = {"ParenExpr", "ImplicitCastExpr", "CStyleCastExpr", "BinaryOperator", "UnaryOperator",
               "DeclRefExpr", "IntegerLiteral", "GNUNullExpr", "CXXNullPtrLiteralExpr"}
    for part in _walk(node):
        if part.get("kind") not in allowed:
            return False
        if part.get("kind") == "BinaryOperator" and part.get("opcode") not in {"==", "!=", "<", ">", "<=", ">=", "||", "&&"}:
            return False
        if part.get("kind") == "UnaryOperator" and part.get("opcode") != "!":
            return False
        if part.get("kind") == "DeclRefExpr" and part.get("referencedDecl", {}).get("kind") != "ParmVarDecl":
            return False
    return any(part.get("referencedDecl", {}).get("kind") == "ParmVarDecl" for part in _walk(node))


def _nonprocessing_return(node):
    # Refuse to classify a branch that calls another function or reads through
    # an input pointer as mere parameter rejection. Member stores to state are
    # permitted (e.g. setting an error field), and remain only finite evidence.
    for part in _walk(node):
        if part.get("kind") in {"CallExpr", "CXXMemberCallExpr", "ArraySubscriptExpr"}:
            return False
        if part.get("kind") == "UnaryOperator" and part.get("opcode") == "*":
            return False
    return True


def discover_entry_contract(recipe, anchor, directory, timeout=60, *, process_runner=None):
    """Find an exact target definition and conservative build-aware entry guards.

    Only consecutive leading ``if (parameter predicate) ... return`` checks
    without an else, calls, or input dereferences are supported. Their return
    sites become observed rejection witnesses; unknown predicates are never
    inferred from a project's or function's name.
    """
    run = process_runner or _run
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    definitions, commands, dependency_hashes = [], [], {}
    for number, filename in enumerate(recipe["source_files"]):
        source_path = Path(filename).resolve()
        source = source_path.read_bytes()
        log = directory / f"target_ast_{number}.json"
        dependency_file = directory / f"target_ast_{number}.d"
        compiler, flags = _compile_configuration(recipe, filename)
        command = [compiler, *flags, *PROBE_INSTRUMENTATION,
                   *(arg for include in recipe.get("include_paths", []) for arg in ("-I", include)),
                   "-MD", "-MF", str(dependency_file), "-MT", "target_ast",
                   "-fsyntax-only", "-Xclang", "-ast-dump=json", "-Xclang", "-ast-dump-filter=" + anchor,
                   str(source_path)]
        result = run(command, cwd=recipe["project_root"], log=log, timeout=timeout)
        commands.append({"command": command, **result})
        if result["exit_code"] != 0 or result.get("timed_out"):
            return {"status": "unknown", "reason": "target_ast_failed", "commands": commands}
        try:
            dependencies = _dependencies(dependency_file, recipe["project_root"])
            if any(path in dependency_hashes and dependency_hashes[path] != expected for path, expected in dependencies.items()):
                return {"status": "unknown", "reason": "source_dependencies_changed_during_ast", "commands": commands}
            dependency_hashes.update(dependencies)
        except (ValueError, OSError):
            return {"status": "unknown", "reason": "target_dependency_snapshot_failed", "commands": commands}
        text, offset, decoder = log.read_text(), 0, json.JSONDecoder()
        try:
            while offset < len(text):
                while offset < len(text) and text[offset].isspace():
                    offset += 1
                if offset >= len(text):
                    break
                node, offset = decoder.raw_decode(text, offset)
                if node.get("kind") != "FunctionDecl" or node.get("name") != anchor:
                    continue
                bodies = [part for part in node.get("inner", []) if part.get("kind") == "CompoundStmt"]
                if len(bodies) != 1:
                    continue
                location = node.get("loc", {}).get("expansionLoc", node.get("loc", {}))
                if Path(location.get("file", filename)).resolve() != source_path:
                    continue
                body, guards = bodies[0], []
                statements = body.get("inner", [])
                for statement in statements:
                    children = statement.get("inner", [])
                    if statement.get("kind") != "IfStmt" or statement.get("hasElse") or len(children) != 2:
                        break
                    condition, consequence = children
                    if not _parameter_predicate(condition) or not _terminates(consequence) or not _nonprocessing_return(consequence):
                        break
                    returns = [_point(part["range"]["begin"], source) for part in _walk(consequence) if part.get("kind") == "ReturnStmt"]
                    begin = condition["range"]["begin"].get("expansionLoc", condition["range"]["begin"])
                    end = condition["range"]["end"].get("expansionLoc", condition["range"]["end"])
                    guards.append({"condition": source[begin["offset"]:end["offset"] + end.get("tokLen", 1)].decode(),
                                   "condition_start": _point(condition["range"]["begin"], source),
                                   "rejection_region_start": _point(consequence["range"]["begin"], source),
                                   "return_sites": returns})
                post = statements[len(guards)] if len(statements) > len(guards) else None
                definitions.append({"status": "supported" if guards and post else "unknown",
                    "reason": None if guards and post else "no_supported_parameter_rejection_guard",
                    "anchor": anchor, "source_file": str(source_path), "source_sha256": _hash(source_path),
                    "definition_start": _point(node["range"]["begin"], source),
                    "definition_end": _point(node["range"]["end"], source),
                    "body_start": _point(post["range"]["begin"], source) if post else None,
                    "guards": guards, "validity_scope": "identified entry rejection checks only; full object lifecycle and other preconditions unproved"})
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return {"status": "unknown", "reason": "target_ast_unresolved", "commands": commands}
    if len(definitions) != 1:
        return {"status": "unknown", "reason": "target_definition_not_unique", "definition_count": len(definitions), "commands": commands}
    return {**definitions[0], "commands": commands, "dependency_hashes": dependency_hashes}


def export_profile(directory, executable, raw, compiler, timeout, *, anchor=None, process_runner=None):
    run = process_runner or _run
    directory, raw = Path(directory), [Path(path) for path in raw]
    found = coverage_tools(compiler)
    if not all(found.values()) or not raw or any(not path.is_file() for path in raw):
        return {"status": "unknown", "reason": "coverage_tools_or_profile_unavailable", "tools": found}
    merged = directory / "coverage.profdata"
    result = run([found["llvm-profdata"], "merge", "-sparse", *map(str, raw), "-o", str(merged)],
                 cwd=directory, log=directory / "coverage_merge.log", timeout=timeout)
    if result["exit_code"] != 0 or result.get("timed_out"):
        return {"status": "unknown", "reason": "coverage_merge_failed", "tools": found}
    exported = directory / "coverage_export.json"
    filters = ["-name=" + anchor, "-skip-expansions"] if anchor else []
    result = run([found["llvm-cov"], "export", str(executable), "-instr-profile=" + str(merged), *filters],
                 cwd=directory, log=exported, timeout=timeout)
    if result["exit_code"] != 0 or result.get("timed_out"):
        return {"status": "unknown", "reason": "coverage_export_failed", "tools": found}
    try:
        document = json.loads(exported.read_text())
    except (ValueError, OSError):
        return {"status": "unknown", "reason": "coverage_export_invalid", "tools": found}
    return {"status": "recorded", "document": document, "export": str(exported), "tools": found}


def target_profile(document, contract):
    matches = []
    for dataset in document.get("data", []):
        for function in dataset.get("functions", []):
            filenames = [str(Path(path).resolve()) for path in function.get("filenames", [])]
            if function.get("name") == contract.get("anchor") and contract.get("source_file") in filenames:
                matches.append(function)
    if len(matches) != 1:
        return {"status": "unknown", "reason": "target_coverage_identity_not_unique", "matches": len(matches)}
    function = matches[0]
    file_id = [str(Path(path).resolve()) for path in function["filenames"]].index(contract["source_file"])
    regions = [region for region in function.get("regions", []) if len(region) >= 8 and region[5] == file_id and region[7] == 0]
    calls = function.get("count")
    if not isinstance(calls, int) or calls < 0:
        return {"status": "unknown", "reason": "target_entry_count_missing"}
    result = {"status": "recorded", "target_call_count": calls, "valid_state_call_count": None,
              "body_region_ids": [], "covered_body_region_ids": [], "covered_body_edge_ids": []}
    if contract.get("status") != "supported":
        result.update(status="partial", reason=contract.get("reason", "entry_state_contract_unknown"))
        return result
    rejection_counts = []
    for guard in contract["guards"]:
        # LLVM may encode a macro return solely as an expansion region. The
        # compound rejection branch has its own ordinary code-region counter;
        # do not substitute the enclosing function's counter for that branch.
        witnesses = [guard["rejection_region_start"]] if guard.get("rejection_region_start") else guard["return_sites"]
        for site in witnesses:
            matching = [region for region in regions if region[:2] == site]
            counts = {region[4] for region in matching}
            if len(counts) != 1:
                result.update(status="partial", reason="entry_rejection_return_coverage_unresolved")
                return result
            rejection_counts.append(next(iter(counts)))
    rejected = sum(rejection_counts)
    if rejected > calls:
        result.update(status="partial", reason="entry_rejection_count_inconsistent")
        return result
    result["valid_state_call_count"] = calls - rejected
    result["rejected_entry_call_count"] = rejected
    start, end = tuple(contract["body_start"]), tuple(contract["definition_end"])
    for region in regions:
        if tuple(region[:2]) < start or tuple(region[:2]) >= end:
            continue
        identifier = ":".join(map(str, region[:4]))
        result["body_region_ids"].append(identifier)
        if region[4] > 0:
            result["covered_body_region_ids"].append(identifier)
    for branch in function.get("branches", []):
        if len(branch) < 9 or branch[6] != file_id or tuple(branch[:2]) < start or tuple(branch[:2]) >= end:
            continue
        identifier = ":".join(map(str, branch[:4]))
        if branch[4] > 0:
            result["covered_body_edge_ids"].append(identifier + ":true")
        if branch[5] > 0:
            result["covered_body_edge_ids"].append(identifier + ":false")
    for name in ("body_region_ids", "covered_body_region_ids", "covered_body_edge_ids"):
        result[name] = sorted(set(result[name]))
    return result


def evaluate_effectiveness(probes, contract, *, buildable=None, runtime_stable=None):
    """Pure evaluation of source-identified coverage probes, no success guesses."""
    result = {"schema_version": 1, "policy_version": POLICY, "buildable": buildable,
              "runtime_stable": runtime_stable, "fuzz_effective": None, "target_call_count": None,
              "valid_state_call_count": None, "target_body_coverage": {"status": "unknown"},
              "input_sensitive_coverage": {"status": "unknown", "sensitive_region_count": None},
              "metric_definitions": METRIC_DEFINITIONS, "contract": contract, "probe_count": len(probes),
              "finite_evidence_only": True, "semantic_correctness_certified": False}
    if not probes:
        result["reason"] = "isolated_input_probes_not_recorded"
        return result
    if any(probe.get("execution", {}).get("exit_code") != 0 or probe.get("execution", {}).get("timed_out") for probe in probes):
        result.update(runtime_stable=False, reason="isolated_probe_runtime_failure")
        return result
    result["runtime_stable"] = True if runtime_stable is not False else False
    profiles = [probe.get("target_profile", {}) for probe in probes]
    if all(isinstance(profile.get("target_call_count"), int) for profile in profiles):
        result["target_call_count"] = sum(profile["target_call_count"] for profile in profiles)
    if contract.get("status") != "supported" or any(profile.get("status") != "recorded" for profile in profiles):
        result["reason"] = "source_entry_contract_or_target_coverage_unknown"
        return result
    result["valid_state_call_count"] = sum(profile["valid_state_call_count"] for profile in profiles)
    total = set().union(*(set(profile["body_region_ids"]) for profile in profiles))
    covered = set().union(*(set(profile["covered_body_region_ids"]) for profile in profiles))
    result["target_body_coverage"] = {"status": "recorded", "total_regions": len(total),
        "covered_regions": len(covered), "covered_region_ids": sorted(covered),
        "fraction": len(covered) / len(total) if total else None, "source_file": contract["source_file"]}
    if result["target_call_count"] == 0 or result["valid_state_call_count"] == 0:
        result.update(fuzz_effective=False, reason="no_target_entries" if result["target_call_count"] == 0 else "all_observed_entries_rejected_by_source_guard")
        result["input_sensitive_coverage"] = {"status": "not_observed", "sensitive_region_count": 0,
            "reason": "no_observed_valid_state_target_execution"}
        return result
    by_input = {}
    for probe in probes:
        profile = probe["target_profile"]
        signature = frozenset([*("region:" + value for value in profile["covered_body_region_ids"]),
                               *("edge:" + value for value in profile["covered_body_edge_ids"])])
        by_input.setdefault(probe["input_sha256"], []).append((signature, profile["valid_state_call_count"]))
    if any(len(observations) < 2 for observations in by_input.values()):
        result["reason"] = "input_probe_repetition_missing"
        return result
    if any(len({signature for signature, _ in observations}) != 1 for observations in by_input.values()):
        result["reason"] = "same_input_coverage_not_reproducible"
        result["input_sensitive_coverage"].update(reason=result["reason"], repeated_input_stable=False)
        return result
    # Inputs rejected by the entry guard do not contribute sensitivity evidence.
    signatures = {identity: observations[0][0] for identity, observations in by_input.items()
                  if all(valid > 0 for _, valid in observations)}
    if len(signatures) < 2:
        result["reason"] = "distinct_valid_inputs_missing"
        return result
    union = set().union(*signatures.values())
    intersection = set.intersection(*(set(value) for value in signatures.values()))
    differing = sorted(union - intersection)
    result["input_sensitive_coverage"] = {"status": "observed" if differing else "not_observed",
        "sensitive_region_count": len(differing), "sensitive_region_or_edge_ids": differing,
        "distinct_valid_inputs": len(signatures), "repeated_input_stable": True,
        "input_signatures": {identity: sorted(value) for identity, value in signatures.items()}}
    if differing and covered and result["runtime_stable"] is not False:
        result.update(fuzz_effective=True, reason="repeated_input_variants_change_post_guard_target_paths")
    else:
        # No observed variation is not proof that a harness can never be useful.
        result["reason"] = "input_sensitive_target_paths_not_observed_in_finite_corpus"
    return result


def observe_harness(recipe, harness, inputs, directory, *, compiler_timeout=60,
                    probe_timeout=5, process_runner: Callable | None = None):
    """Compile a coverage/sanitizer driver and probe each input twice.

    Every input is dispatched exactly once per fresh process. No libFuzzer
    empty-input initialization or aggregate profile is counted as a probe.
    This function performs no provider calls and never changes the harness.
    """
    run = process_runner or _run
    directory, harness = Path(directory).resolve(), Path(harness).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    source_hashes = {str(Path(path).resolve()): _hash(path) for path in recipe["source_files"]}
    harness_identity = _hash(harness)
    driver = directory / "probe_driver.c"
    driver.write_text(DRIVER, encoding="utf-8")
    anchor = recipe["target_anchor"]
    contract = discover_entry_contract(recipe, anchor, directory / "contract", compiler_timeout, process_runner=run)
    objects, commands, buildable = [], [], True
    dependency_hashes = dict(contract.get("dependency_hashes", {}))
    for number, source in enumerate([*recipe["source_files"], str(harness), str(driver)]):
        compiler, flags = _compile_configuration(recipe, source)
        obj = directory / f"unit_{number}.o"
        dependency_file = directory / f"unit_{number}.d"
        command = [compiler, *flags, *PROBE_INSTRUMENTATION,
            *(arg for include in [recipe["project_root"], *recipe.get("include_paths", [])] for arg in ("-I", include)),
            "-MD", "-MF", str(dependency_file),
            "-c", source, "-o", str(obj)]
        execution = run(command, cwd=recipe["project_root"], log=directory / f"compile_{number}.log", timeout=compiler_timeout)
        commands.append({"command": command, **execution})
        if execution["exit_code"] != 0 or execution.get("timed_out"):
            buildable = False
            break
        try:
            dependencies = _dependencies(dependency_file, recipe["project_root"])
            if any(path in dependency_hashes and dependency_hashes[path] != expected for path, expected in dependencies.items()):
                contract.update(status="unknown", reason="source_dependencies_changed_between_ast_and_build")
            for path, expected in dependencies.items():
                dependency_hashes.setdefault(path, expected)
        except (ValueError, OSError):
            contract.update(status="unknown", reason="build_dependency_snapshot_failed")
        objects.append(str(obj))
    executable = directory / "probe_harness"
    if buildable:
        linker = str(Path(recipe["compiler"]).with_name("clang++")) if harness.suffix == ".cpp" else recipe["compiler"]
        command = [linker, *objects, "-fsanitize=address,undefined", "-fprofile-instr-generate",
                   *recipe.get("link_flags", []), "-o", str(executable)]
        execution = run(command, cwd=recipe["project_root"], log=directory / "link.log", timeout=compiler_timeout)
        commands.append({"command": command, **execution})
        buildable = execution["exit_code"] == 0 and not execution.get("timed_out")
    probes = []
    if buildable:
        unique = {hashlib.sha256(data).hexdigest(): data for data in inputs}
        for number, (identity, data) in enumerate(unique.items()):
            if len(data) > 4096:
                raise ValueError("effectiveness input exceeds bounded driver")
            input_path = directory / f"input_{number:02d}.bin"
            input_path.write_bytes(data)
            for repetition in (1, 2):
                probe_dir = directory / f"input_{number:02d}_r{repetition}"
                probe_dir.mkdir()
                profile = probe_dir / "coverage.profraw"
                environment = {**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1:symbolize=0",
                               "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=0", "LLVM_PROFILE_FILE": str(profile)}
                execution = run([str(executable), str(input_path)], cwd=probe_dir,
                    log=probe_dir / "probe.log", timeout=probe_timeout, environment=environment)
                exported = export_profile(probe_dir, executable, [profile], recipe["compiler"],
                    compiler_timeout, anchor=anchor, process_runner=run) if execution["exit_code"] == 0 else {"status": "unknown", "reason": "probe_failed"}
                target = target_profile(exported["document"], contract) if exported.get("document") and contract.get("source_file") else {"status": "unknown", "reason": exported.get("reason", contract.get("reason"))}
                probe = {"input_sha256": identity, "input_bytes": len(data), "input_path": str(input_path),
                         "repetition": repetition, "execution": execution, "target_profile": target,
                         "coverage": {key: value for key, value in exported.items() if key != "document"}}
                _write(probe_dir / "observation.json", probe)
                probes.append(probe)
    result = evaluate_effectiveness(probes, contract, buildable=buildable)
    unchanged = all(Path(path).is_file() and _hash(path) == expected for path, expected in
                    [*source_hashes.items(), *dependency_hashes.items()]) and _hash(harness) == harness_identity
    if not unchanged:
        result.update(fuzz_effective=None, reason="source_or_harness_changed_during_probes")
    result.update(commands=commands, probes=probes, harness_sha256=harness_identity, harness_path=str(harness),
                  source_file_hashes=source_hashes, source_identity_unchanged=unchanged,
                  build_dependency_hashes=dependency_hashes,
                  executable=str(executable), observation_directory=str(directory),
                  environment_scope="same inherited environment and sanitizer options; ambient external state is not fully controlled, repeated coverage is checked")
    _write(directory / "effectiveness.json", result)
    return result


def summarize_quality(outcomes):
    """Counts three independent axes; legacy artifacts carry unknown quality."""
    result = {"observations": len(outcomes)}
    for metric in ("buildable", "runtime_stable", "fuzz_effective"):
        counts = Counter("true" if observation.get(metric) is True else "false" if observation.get(metric) is False else "unknown" for observation in outcomes)
        result[metric] = {key: counts[key] for key in ("true", "false", "unknown")}
    result["effective_successes"] = sum(observation.get("fuzz_effective") is True for observation in outcomes)
    return result
