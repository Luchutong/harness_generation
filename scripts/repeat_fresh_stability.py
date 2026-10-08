#!/usr/bin/env python3
"""Registered fresh development repetitions with an immutable production snapshot.

The default requires the historical json_parse report fingerprint. --freeze-current
registers the complete current production inventory with the same hash algorithm.
Defaults remain the formal 5 json_parse + 3 repetitions of five development cases.
"""
from __future__ import annotations

import argparse
import ast
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "artifacts/json_parse_closure_20261003T153052Z"
CASE_COVERAGE = {
    "json_parse": ["owned-return cleanup"],
    "callback_context": ["callback construction source", "userdata lifecycle"],
    "shared_context": ["shared context lifecycle", "alias feed/core/cleanup"],
    "owned_return": ["owned-return cleanup"],
    "out_parameter": ["out-parameter creator"],
    "memory_stream": ["stream/file abstraction", "memory stream lifecycle"],
}
PRODUCTION_GLOBS = ("harness_generation/**/*.py", "harness_generation/**/*.mjs",
                    "harness_generation/**/dsh_kernel.json", "sfg_builder/**/*.py")


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def hashes(root, keys):
    return {key: sha(root / key) if (root / key).is_file() else None for key in keys}


def production_file_hashes(root):
    """Include production modules and runtime assets, not just prior manifest keys."""
    paths = {p.relative_to(root).as_posix() for pattern in PRODUCTION_GLOBS
             for p in root.glob(pattern) if p.is_file()}
    paths.add("pyproject.toml")
    result = hashes(root, sorted(paths))
    if any(value is None for value in result.values()):
        raise RuntimeError("production inventory contains missing files")
    return result


def fingerprint(file_hashes):
    return hashlib.sha256(json.dumps(file_hashes, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()


def selected_cases(cases=None):
    requested = list(CASE_COVERAGE) if cases is None else list(cases)
    if not requested or len(set(requested)) != len(requested) or any(
            name not in CASE_COVERAGE for name in requested):
        raise ValueError("cases must be a nonempty unique list of established case names")
    # Keep phase and source ordering fixed even when the CLI selector is reordered.
    return [name for name in CASE_COVERAGE if name in requested]


def build_schedule(output, cases, json_repetitions, sample_repetitions):
    if not 1 <= json_repetitions <= 10 or not 1 <= sample_repetitions <= 5:
        raise ValueError("json repetitions must be 1..10 and sample repetitions 1..5")
    schedule = []
    for phase, names, repetitions in [
        ("json_parse", [name for name in cases if name == "json_parse"], json_repetitions),
        ("structural", [name for name in cases if name != "json_parse"], sample_repetitions),
    ]:
        for repetition in range(1, repetitions + 1):
            for name in names:
                trial_id = f"{name}_r{repetition:02d}"
                trial_dir = output / trial_id
                schedule.append({"trial_id": trial_id, "case": name, "repetition": repetition, "phase": phase,
                                 "trial_dir": str(trial_dir), "artifacts": str(trial_dir / "artifacts")})
    return schedule


def budget_options(budget):
    return [argument for name, value in budget.items()
            for argument in ("--" + name.replace("_", "-"), str(value))]


def context_backend_options(output, registration):
    """Use only the backend and effective profile authenticated by registration."""
    backend = registration.get("context_agent_backend", {"name": "native"})
    name = backend.get("name") if isinstance(backend, dict) else None
    if name == "native":
        # Historical workers omitted this flag; retain their exact command.
        return []
    if name != "deepseek-harness":
        raise ValueError("registered Context backend is unsupported")
    profile = registration.get("dsh_profile", {})
    if profile.get("source") != "dsh_profile.json":
        raise ValueError("registered DSH profile is unavailable")
    return ["--agent-backend", name, "--dsh-profile", str(output / profile["source"])]


def backend_registration(model_config, *, budget, agent_backend="native", profile_path=None):
    """Describe the selected runner without SDK imports, launch or package checks."""
    if agent_backend == "native":
        if profile_path is not None:
            raise ValueError("--dsh-profile requires --agent-backend deepseek-harness")
        return {"name": "native"}
    if agent_backend != "deepseek-harness":
        raise ValueError("Context agent backend must be native or deepseek-harness")
    from harness_generation.harness_context.dsh_backend import DeepSeekHarnessContextBackend
    from harness_generation.harness_context.dsh_config import load_dsh_profile
    return DeepSeekHarnessContextBackend(model_config, budget=budget,
        profile=load_dsh_profile(profile_path)).descriptor()


def frozen_backend_descriptor(root, *, budget, profile):
    """Recover the complete descriptor contract from frozen Python syntax only."""
    directory = root / "harness_generation/harness_context"

    def literals(path):
        tree = ast.parse(path.read_text(), filename=str(path))
        values = {}
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                try:
                    value = ast.literal_eval(statement.value)
                except (ValueError, TypeError):
                    continue
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        values[target.id] = value
        return tree, values

    backend_tree, constants = literals(directory / "dsh_backend.py")
    _, config_constants = literals(directory / "dsh_config.py")
    _, policy_constants = literals(directory / "dsh_policy.py")
    constants.update({key: config_constants[key] for key in
        ("BACKEND_NAME", "PROFILE_VERSION", "BRIDGE_POLICY_VERSION")})
    constants["BOUNDED_POLICY_VERSION"] = policy_constants["VERSION"]
    if not isinstance(profile, dict) or set(profile) != set(config_constants["DEFAULT_DSH_PROFILE"]):
        raise ValueError("registered profile does not match the frozen bridge schema")
    profile = dict(profile)
    for name, maximum in config_constants["_INTEGER_LIMITS"].items():
        if type(profile[name]) is not int or not 1 <= profile[name] <= maximum:
            raise ValueError("registered profile exceeds the frozen bridge limits")
    timeout = profile["request_timeout_seconds"]
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not 0 < timeout <= config_constants["_MAX_REQUEST_TIMEOUT_SECONDS"]):
        raise ValueError("registered profile exceeds the frozen bridge limits")
    profile["request_timeout_seconds"] = float(timeout)
    definitions = [node.value for node in ast.walk(backend_tree)
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name) and target.value.id == "self"
            and target.attr == "_descriptor" for target in node.targets)]
    if len(definitions) != 1 or not isinstance(definitions[0], ast.Dict):
        raise ValueError("cannot derive the frozen backend descriptor")
    dynamic = {"budget": budget, "profile": profile, "profile_sha256": fingerprint(profile)}
    for key, constant_name in (("assets_sha256", "ASSETS"),
                               ("native_policy_sha256", "NATIVE_POLICY_FILES")):
        names = constants[constant_name]
        if (not isinstance(names, (tuple, list)) or not names
                or len(set(names)) != len(names) or not all(isinstance(name, str) for name in names)):
            raise ValueError("invalid frozen backend asset contract")
        dynamic[key] = {}
        for name in names:
            path = (directory / name).resolve()
            path.relative_to(root.resolve())
            dynamic[key][name] = sha(path)
    result = {}
    for key_node, value_node in zip(definitions[0].keys, definitions[0].values):
        key = ast.literal_eval(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError("invalid frozen backend descriptor keys")
        if key in dynamic:
            result[key] = dynamic[key]
        elif isinstance(value_node, ast.Name):
            result[key] = constants[value_node.id]
        else:
            result[key] = ast.literal_eval(value_node)
    if not set(dynamic) <= set(result):
        raise ValueError("incomplete frozen backend descriptor")
    return result


def backend_integrity(output, registration):
    """Bind the effective profile and all descriptor assets to the frozen inventory."""
    backend = registration.get("context_agent_backend", {"name": "native"})
    if not isinstance(backend, dict):
        return False
    if backend.get("name") == "native":
        return (backend == {"name": "native"} and not registration.get("dsh_profile")
            and ("context_agent_backend_fingerprint" not in registration
                 or registration["context_agent_backend_fingerprint"] == fingerprint(backend)))
    if backend.get("name") != "deepseek-harness":
        return False
    profile = registration.get("dsh_profile", {})
    if (profile.get("source") != "dsh_profile.json"
            or registration.get("context_agent_backend_fingerprint") != fingerprint(backend)
            or backend.get("budget") != registration.get("context_budget")
            or not matches_file(output / "dsh_profile.json", profile.get("sha256"))
            or profile.get("profile_sha256") != backend.get("profile_sha256")):
        return False
    try:
        effective = read(output / "dsh_profile.json")
        if (effective != backend.get("profile")
                or fingerprint(effective) != backend.get("profile_sha256")):
            return False
        if backend != frozen_backend_descriptor(output / "frozen",
                budget=registration["context_budget"], profile=effective):
            return False
        inventory = registration["production_file_hashes"]
        for key in ("assets_sha256", "native_policy_sha256"):
            assets = backend.get(key)
            if not isinstance(assets, dict) or not assets:
                return False
            for name, expected in assets.items():
                path = (ROOT / "harness_generation/harness_context" / name).resolve()
                relative = path.relative_to(ROOT.resolve()).as_posix()
                if inventory.get(relative) != expected:
                    return False
    except (OSError, ValueError, TypeError, KeyError, SyntaxError):
        return False
    return True


class CapabilityPreflightError(RuntimeError):
    """A controlled dependency category; installation paths never enter output."""
    def __init__(self, category):
        self.category = category
        super().__init__("static DSH capability preflight failed: " + category)


def dependency_preflight(output, registration, *, identity=None):
    """Check installed payload availability before any paid upstream work."""
    backend = registration.get("context_agent_backend", {"name": "native"})
    if backend.get("name") == "native":
        return None
    try:
        from harness_generation.harness_context.dsh_dependencies import probe_dsh_dependencies
        result = probe_dsh_dependencies(expected_sdk_version=backend.get("sdk_version"),
            expected_runtime_version=backend.get("runtime_version"))
    except Exception:
        result = {"schema_version": 1, "status": "static_unavailable",
            "static_capability_available": False, "error_category": "dsh_preflight_implementation_error",
            "runtime_started": False, "optional_sdk_imported": False, "provider_requests": 0}
    record = {**result, "checked_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "worker" if identity else "supervisor",
        "production_fingerprint": registration.get("production_fingerprint"),
        "context_agent_backend_fingerprint": registration.get("context_agent_backend_fingerprint"),
        **({"trial_id": identity["trial_id"]} if identity else {})}
    record["record_fingerprint"] = fingerprint(record)
    history = output / "dependency_preflight_history" / (identity["trial_id"] if identity else "supervisor")
    history.mkdir(parents=True, exist_ok=True)
    attempts = [int(path.stem.split("_")[-1]) for path in history.glob("attempt_*.json")
        if path.stem.split("_")[-1].isdigit()]
    write(history / f"attempt_{max(attempts, default=0) + 1:04d}.json", record)
    path = output / (identity["trial_id"] + "_dependency_preflight.json" if identity else "dependency_preflight.json")
    write(path, record)
    if not record["static_capability_available"]:
        if identity is None:
            write(output / "execution_preflight_failed.json", {"schema_version": 1,
                "status": "dependency_preflight_failed", "error_category": record["error_category"],
                "execution_started": False, "worker_subprocesses_started": 0, "provider_requests": 0,
                "planned_trials": registration.get("planned_trials"),
                "production_fingerprint": registration.get("production_fingerprint"),
                "context_agent_backend_fingerprint": registration.get("context_agent_backend_fingerprint")})
        raise CapabilityPreflightError(record["error_category"])
    return record


def matches_file(path, expected):
    return path.is_file() and sha(path) == expected


def matches_inventory(root, expected):
    try:
        return production_file_hashes(root) == expected
    except (OSError, RuntimeError):
        return False


def integrity(output, registration):
    expected = registration["production_file_hashes"]
    target = Path(registration["target_root"])
    target_hashes = {str(p.relative_to(target)): sha(p) for p in target.rglob("*")
                     if p.is_file() and ".git" not in p.parts}
    checks = {
        "current_production_unchanged": matches_inventory(ROOT, expected),
        "frozen_production_unchanged": matches_inventory(output / "frozen", expected),
        "target_files_unchanged": target_hashes == registration["target_file_hashes"],
        "target_head_unchanged": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=target, text=True).strip() == registration["target_head"],
        "target_git_status_clean": not subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=target, text=True).strip(),
        "runner_unchanged": matches_file(Path(__file__), registration["runner_sha256"]),
        "ancillary_dependencies_unchanged": all(
            matches_file(Path(p), value) for p, value in registration["ancillary_dependencies"].items()),
        "frozen_project_catalog_unchanged": matches_file(output / "frozen/project_catalog.py",
            registration["ancillary_dependencies"][str(ROOT / "project_catalog.py")]),
        "fixtures_unchanged": all(matches_file(output / sample["source"], sample["sha256"])
                                  for sample in registration["samples"].values()),
        "target_build_unchanged": matches_file(output / "target_build.json",
            registration.get("target_build_sha256") or sha(BASELINE / "target_build.json")),
    }
    if "context_agent_backend" in registration:
        checks["context_backend_unchanged"] = backend_integrity(output, registration)
    return checks


def worker(output, index):
    registration = read(output / "registration.json")
    identity = registration["schedule"][index]
    if not all(integrity(output, registration).values()):
        raise RuntimeError("registered source identity changed")
    sys.path.insert(0, str(output / "frozen"))
    capability = dependency_preflight(output, registration, identity=identity)
    from harness_generation.artifacts import ArtifactStore
    from harness_generation.cli import main
    from harness_generation.records import write_json
    from harness_generation.semantic_discovery.provider_config import agent_configuration, load_environment_file
    from harness_generation.sfg_adapter import load_sfg_artifacts
    from sfg_builder.parser import CProjectParser, write_functions_json
    import harness_generation
    import project_catalog
    assert Path(harness_generation.__file__).is_relative_to(output / "frozen")
    assert Path(project_catalog.__file__).is_relative_to(output / "frozen")
    load_environment_file(ROOT / ".env")
    transport_registered = registration.get('agent_transport_policy') == 'public-agent-deadline-v1'
    config = agent_configuration("openai-compatible", **(
        {'timeout': registration['provider']['timeout']} if transport_registered else {}))
    if config.to_dict() != registration["provider"]:
        raise RuntimeError("registered provider settings changed")
    provider = ["--provider", "openai-compatible", "--model", config.model, "--thinking", config.thinking]
    agent_provider = provider + (["--agent-timeout", str(config.timeout)] if transport_registered else [])
    trial = Path(identity["trial_dir"])
    trial.mkdir(parents=True, exist_ok=False)
    artifacts = Path(identity["artifacts"])
    sample = registration["samples"][identity["case"]]
    if identity["phase"] == "json_parse":
        project = Path(registration["target_root"])
        globs = registration["source_globs"]
    else:
        project = trial / "project"
        project.mkdir()
        shutil.copyfile(output / sample["source"], project / "api.c")
        globs = ["api.c"]
    row = {**identity, "status": "running", "project": str(project),
           "production_fingerprint": registration["production_fingerprint"],
           "context_agent_backend": registration.get("context_agent_backend", {"name": "native"}),
           "started_utc": datetime.now(timezone.utc).isoformat(),
           "dataset_role": sample["dataset_role"], "fresh": True, "resume": False,
           "failed_retry": False, "stage_exits": {}, "stage_seconds": {}}
    if capability is not None:
        row["dependency_preflight"] = capability
    started = time.monotonic()
    write(trial / "trial.json", row)
    try:
        store = ArtifactStore(artifacts)
        parsed = CProjectParser(source_globs=globs).parse(project)
        write_functions_json(parsed, store.functions, project=project)
        for path, field in ((store.annotations, "annotations"), (store.flows, "flows")):
            write_json(path, {"schema_version": 1, field: []})
        write_json(store.sfg, {"schema_version": 1, "nodes": [], "edges": [], "functions": []})
        anchor, = [f["id"] for f in load_sfg_artifacts(artifacts).functions
                   if f["name"] == sample["anchor"] and f["file"] == sample["anchor_file"]]
        row.update(anchor=anchor, parsed_functions=len(parsed.functions), static_warnings=list(parsed.warnings))
        base = ["--artifacts", str(artifacts)]
        limits = budget_options(registration["validation_slice_budget"])
        candidate_recovery = budget_options(registration.get('agent_recovery_limits', {}).get('candidate', {}))
        upstream = [("candidates", []), ("candidate-validate", agent_provider + limits + candidate_recovery + ["--candidate", anchor]),
                    ("semantic-slice", agent_provider + limits + ["--candidate", anchor]),
                    ("minimal-ft", ["--candidate", anchor])]
        for command, options in upstream:
            print("[FRESH STAGE]", identity["trial_id"], command, flush=True)
            tick = time.monotonic()
            result = main([command, *base, *options])
            row["stage_exits"][command] = result
            row["stage_seconds"][command] = round(time.monotonic() - tick, 3)
            write(trial / "trial.json", row)
            if result:
                row["status"] = command + "_failed"
                return
        ft_path, = store.minimal_fts_directory.glob("ft_*/minimal_ft.json")
        ft_id = read(ft_path)["ft_id"]
        generation = provider + ["--ft", ft_id, "--language", "c++", "--build", "--runtime",
                                  "--project-root", str(project)]
        if 'max_code_repairs' in registration:
            generation += ['--max-code-repairs', str(registration['max_code_repairs'])]
        if identity["phase"] == "json_parse":
            generation += ["--header", "json.h", "--target-build", str(output / "target_build.json")]
        # Preserve the generation gate even when Context fails; it must make zero code calls.
        for command, options in [
            ("harness-context", agent_provider + budget_options(registration["context_budget"])
                + context_backend_options(output, registration)
                + ["--ft", ft_id, "--requirement-mode", "grouped"]),
            ("context-generate", generation),
        ]:
            print("[FRESH STAGE]", identity["trial_id"], command, flush=True)
            tick = time.monotonic()
            row["stage_exits"][command] = main([command, *base, *options])
            row["stage_seconds"][command] = round(time.monotonic() - tick, 3)
            write(trial / "trial.json", row)
        row["status"] = ("harness-context_failed" if row["stage_exits"]["harness-context"] else
                         "context-generate_failed" if row["stage_exits"]["context-generate"] else "passed")
    except BaseException as error:
        row["status"] = "runner_error"
        row["error_type"] = type(error).__name__
        traceback.print_exc()
    finally:
        row["finished_utc"] = datetime.now(timezone.utc).isoformat()
        row["elapsed_seconds"] = round(time.monotonic() - started, 3)
        row["integrity"] = integrity(output, registration)
        write(trial / "trial.json", row)


def register(output, json_repetitions, sample_repetitions, workers, *, freeze_current=False, cases=None, max_code_repairs=0, agent_timeout=60.0,
             agent_backend="native", dsh_profile=None):
    cases = selected_cases(cases)
    schedule = build_schedule(output, cases, json_repetitions, sample_repetitions)
    if workers not in (1, 2):
        raise ValueError("workers must be 1 or 2")
    if type(max_code_repairs) is not int or max_code_repairs not in (0, 1):
        raise ValueError('max code repairs must be 0 or 1')
    if max_code_repairs and not freeze_current:
        raise ValueError('code repair requires a newly registered current fingerprint')
    if isinstance(agent_timeout, bool) or agent_timeout not in (60.0, 120.0):
        raise ValueError('agent timeout must be 60 or 120 seconds')
    if agent_timeout != 60.0 and not freeze_current:
        raise ValueError('agent timeout change requires a newly registered current fingerprint')
    if agent_backend not in ("native", "deepseek-harness"):
        raise ValueError("Context agent backend must be native or deepseek-harness")
    if dsh_profile is not None and agent_backend != "deepseek-harness":
        raise ValueError("--dsh-profile requires --agent-backend deepseek-harness")
    if agent_backend == "deepseek-harness" and not freeze_current:
        raise ValueError("DeepSeek Harness requires a newly registered current fingerprint")
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "scripts"))
    from smoke_argument_graph import CASES
    from harness_generation.semantic_discovery.provider_config import agent_configuration, load_environment_file
    baseline = read(BASELINE / "manifest.json")
    current_hashes = production_file_hashes(ROOT)
    if not freeze_current and current_hashes != baseline["production_file_hashes"]:
        raise RuntimeError("current production differs from the report fingerprint")
    from harness_generation.harness_context.models import ContextBudget
    context_budget = (ContextBudget(**baseline['context_budget']).to_dict()
                      if freeze_current else baseline['context_budget'])
    # Complete configuration validation before creating a partial registration.
    load_environment_file(ROOT / ".env")
    model_config = agent_configuration("openai-compatible", **(
        {'timeout': agent_timeout} if freeze_current else {}))
    context_backend = backend_registration(model_config,
        budget=ContextBudget(**context_budget), agent_backend=agent_backend, profile_path=dsh_profile)
    output.mkdir(parents=True, exist_ok=False)
    frozen = output / "frozen"
    for key in current_hashes:
        dest = frozen / key
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / key, dest)
    shutil.copyfile(ROOT / "project_catalog.py", frozen / "project_catalog.py")
    shutil.copyfile(BASELINE / "target_build.json", output / "target_build.json")
    sources = output / "sources"
    sources.mkdir()
    samples = {}
    if "json_parse" in cases:
        samples["json_parse"] = {"anchor": "json_parse", "anchor_file": "json.c",
            "dataset_role": "known-project-development-regression", "coverage": CASE_COVERAGE["json_parse"],
            "source": "target_build.json", "sha256": sha(output / "target_build.json")}
    for name in [name for name in cases if name != "json_parse"]:
        path = sources / (name + ".c")
        if name == "memory_stream":
            original = ROOT / "benchmarks/blind/synthetic/memory_stream/source/api.c"
            shutil.copyfile(original, path)
            origin = str(original)
        else:
            path.write_text(CASES[name])
            origin = "scripts/smoke_argument_graph.py:CASES[" + name + "]"
        samples[name] = {"anchor": "sv_parse_stream" if name == "memory_stream" else "parse",
                         "anchor_file": "api.c", "source": str(path.relative_to(output)), "sha256": sha(path),
                         "origin": origin, "coverage": CASE_COVERAGE[name],
                         "dataset_role": "synthetic-development-regression"}
    # The real target is authenticated separately; its source is not copied into fixture sources.
    registration = {**baseline, "schema_version": 1, "created_utc": datetime.now(timezone.utc).isoformat(),
        "experiment_purpose": "fixed-fingerprint fresh pipeline stability, then established structural development examples",
        "frozen_root": str(frozen), "provider": model_config.to_dict(),
        "context_agent_backend": context_backend,
        "context_agent_backend_fingerprint": fingerprint(context_backend),
        "framework_root": str(ROOT),
        "framework_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "framework_branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip(),
        "production_file_hashes": current_hashes, "production_fingerprint": fingerprint(current_hashes),
        "target_build_sha256": sha(output / "target_build.json"),
        "production_inventory_policy": "all harness_generation/**/*.py, harness_generation/**/*.mjs, harness_generation/**/dsh_kernel.json, sfg_builder/**/*.py, pyproject.toml",
        "freeze_mode": "current" if freeze_current else "historical-report",
        "comparison_baseline_manifest": str(BASELINE / "manifest.json"),
        "comparison_baseline_fingerprint": baseline["production_fingerprint"],
        "baseline_cases": baseline.get("cases", []), "cases": cases,
        "protocol_role": "formal_development_repetition" if cases == list(CASE_COVERAGE)
            and json_repetitions >= 5 and sample_repetitions >= 3 else "targeted_development_smoke",
        "json_repetitions": json_repetitions, "sample_repetitions": sample_repetitions,
        "planned_trials": len(schedule), "workers": workers, "schedule": schedule, "samples": samples,
        "worker_timeout_seconds": 2400,
        "fresh_upstream_per_trial": True, "resume": False, "failed_retry": False,
        "agent_recovery_limits": ({
            'candidate': {'max_terminal_repairs': 1, 'max_semantic_recoveries': 1, 'max_provider_recoveries': 1, 'max_protocol_recoveries': 1},
            'slice': {'max_terminal_repairs': 1, 'max_provider_recoveries': 1, 'max_protocol_recoveries': 1},
            'context': {'max_semantic_recoveries': 1, 'max_provider_recoveries': 1, 'max_protocol_recoveries': 1},
        } if freeze_current else {}),
        "stopping_rules": ["stop on identity mutation", "retain all failed trials", "no retries or dropped failures"],
        "code_max_tokens": 8192, "agent_temperature": "provider default", "code_temperature": 0.2,
        "seed": "unspecified", "runtime_inputs": 6, "sanitizers": ["address", "undefined"],
        "candidate_recall_evaluation": False, "cross_project_generalization_evidence": False,
        "runner_sha256": sha(Path(__file__)), "ancillary_dependencies": {
            str(ROOT / "project_catalog.py"): sha(ROOT / "project_catalog.py"),
            str(ROOT / "scripts/smoke_argument_graph.py"): sha(ROOT / "scripts/smoke_argument_graph.py"),
            str(ROOT / "scripts/smoke_context_pipeline.py"): sha(ROOT / "scripts/smoke_context_pipeline.py"),
            str(ROOT / "scripts/smoke_harness_context.py"): sha(ROOT / "scripts/smoke_harness_context.py"),
        }}
    if freeze_current:
        # Bind all current knobs while preserving the report's original totals.
        # Older registrations remain historical records of their own schema.
        registration['context_budget'] = context_budget
        registration['max_code_repairs'] = max_code_repairs
        registration['agent_transport_policy'] = 'public-agent-deadline-v1'
        from harness_generation.semantic_discovery.loop import TERMINAL_REPAIR_POLICY_VERSION
        categories = {'candidate': ['terminal_schema_error', 'terminal_json_parse_error', 'candidate_unknown_evidence_reference', 'terminal_native_submission_missing'],
                      'slice': ['terminal_schema_error', 'terminal_json_parse_error', 'slice_role_choice_not_issued', 'terminal_native_submission_missing'],
                      'context': ['terminal_schema_error', 'terminal_native_submission_missing']}
        registration['agent_terminal_policies'] = {
            stage: {'terminal_repair_policy_version': TERMINAL_REPAIR_POLICY_VERSION,
                    'terminal_repair_allowed_categories': allowed,
                    'extra_terminal_repair_last_round_only': stage == 'slice'}
            for stage, allowed in categories.items()}
    if agent_backend == "deepseek-harness":
        # Copy only normalized allowlisted bridge limits, never arbitrary user JSON.
        write(output / "dsh_profile.json", context_backend["profile"])
        registration["dsh_profile"] = {"source": "dsh_profile.json",
            "sha256": sha(output / "dsh_profile.json"),
            "profile_sha256": context_backend["profile_sha256"]}
    write(output / "registration.json", registration)
    write(output / "manifest.json", registration)
    check = integrity(output, registration)
    write(output / "initial_integrity.json", check)
    if not all(check.values()):
        raise RuntimeError("initial frozen/target integrity failed")
    return registration


def supervise(output, registration):
    # Registration and --register-only remain SDK independent. Capability is
    # checked only when execution is requested, before any worker is created.
    dependency_preflight(output, registration)
    rows = []
    def execute(index):
        identity = registration["schedule"][index]
        if not all(integrity(output, registration).values()):
            raise RuntimeError("source mutation before trial")
        with (output / (identity["trial_id"] + ".log")).open("w") as log:
            try:
                process = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--worker", str(output),
                                          "--index", str(index)], cwd=output / "frozen", stdout=log,
                                         stderr=subprocess.STDOUT, timeout=registration.get('worker_timeout_seconds', 2400))
                code = process.returncode
            except subprocess.TimeoutExpired:
                code = "supervisor_timeout"
        path = Path(identity["trial_dir"]) / "trial.json"
        row = read(path) if path.is_file() else {**identity, "status": "worker_missing_trial",
            "production_fingerprint": registration["production_fingerprint"],
            "context_agent_backend": registration.get("context_agent_backend", {"name": "native"}),
            "fresh": True, "resume": False, "failed_retry": False,
            "integrity": integrity(output, registration), "stage_exits": {}, "stage_seconds": {}}
        row["worker_exit"] = code
        if code != 0:
            row["status"] = "supervisor_timeout" if code == "supervisor_timeout" else "worker_process_failed"
        capability_path = output / (identity["trial_id"] + "_dependency_preflight.json")
        if capability_path.is_file():
            capability = read(capability_path)
            row["dependency_preflight"] = capability
            if capability.get("static_capability_available") is False:
                row["status"] = "dependency_preflight_failed"
                row["error_category"] = capability.get("error_category")
        # Preflight/import failures happen before the worker creates its directory.
        # Persist them with the same registered identity instead of losing a trial.
        Path(identity["trial_dir"]).mkdir(parents=True, exist_ok=True)
        write(Path(identity["trial_dir"]) / "supervisor.json", row)
        return row
    for phase in ["json_parse", "structural"]:
        print("[PHASE]", phase, flush=True)
        indices = [i for i, trial in enumerate(registration["schedule"]) if trial["phase"] == phase]
        with ThreadPoolExecutor(max_workers=registration["workers"]) as pool:
            jobs = {pool.submit(execute, i): i for i in indices}
            for future in as_completed(jobs):
                row = future.result()
                rows.append(row)
                check = integrity(output, registration)
                write(output / "progress.json", {"completed_trials": len(rows), "trials": rows, "integrity": check})
                print("[RESULT]", row["trial_id"], row["status"], f"{len(rows)}/{len(registration['schedule'])}", flush=True)
                if not all(check.values()):
                    raise RuntimeError("source mutation after trial")
        write(output / (phase + "_phase_complete.json"), {"trials": [r for r in rows if r["phase"] == phase]})
    write(output / "completion_audit.json", {"completed_trials": len(rows), "planned_trials": len(registration["schedule"]),
          "completed_utc": datetime.now(timezone.utc).isoformat(), "integrity": integrity(output, registration)})


def argument_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--freeze-current", action="store_true",
                        help="Snapshot the complete current production inventory instead of requiring the historical fingerprint")
    parser.add_argument("--register-only", action="store_true",
                        help="Publish a reviewable frozen registration and return; no dependency checks, workers, SDK startup or provider calls")
    parser.add_argument("--cases", nargs="+", choices=list(CASE_COVERAGE),
                        help="Established cases to run; omitted selects all six")
    parser.add_argument("--json-repetitions", type=int, choices=range(1, 11), default=5)
    parser.add_argument("--sample-repetitions", type=int, choices=range(1, 6), default=3)
    parser.add_argument("--workers", type=int, choices=(1, 2), default=2)
    parser.add_argument('--max-code-repairs', type=int, choices=(0, 1), default=0,
                        help='Register one bounded code correction against the same frozen Plan; permits up to two code calls')
    parser.add_argument('--agent-timeout', type=float, choices=(60.0, 120.0), default=60.0,
                        help='Register transport timeout for agent requests; does not increase call budgets')
    parser.add_argument("--agent-backend", choices=("native", "deepseek-harness"), default="native",
                        help="Context investigation backend; DeepSeek Harness requires --freeze-current and keeps upstream/code stages native")
    parser.add_argument("--dsh-profile", type=Path,
                        help="Allowlisted JSON bridge limits frozen into the new DeepSeek Harness registration")
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--index", type=int)
    parser.add_argument("--run-registered", type=Path,
                        help="Execute an untouched existing registration after identity and static dependency preflight; rejects registration overrides")
    return parser


def cli(argv=None):
    parser = argument_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(arguments)
    if args.run_registered:
        supplied_flags = {argument.split("=", 1)[0] for argument in arguments if argument.startswith("--")}
        if supplied_flags - {"--run-registered"}:
            parser.error("--run-registered accepts no worker, registration or configuration overrides")
        output = args.run_registered.resolve()
        registration = read(output / "registration.json")
        if not all(integrity(output, registration).values()):
            parser.error("registered source identity changed; a new registration is required")
        if (any(Path(identity["trial_dir"]).exists() or (output / (identity["trial_id"] + ".log")).exists()
                for identity in registration["schedule"])
                or any((output / name).exists() for name in ("progress.json", "completion_audit.json"))):
            parser.error("registered trials have already started; a new fresh registration is required")
        # Absolute script invocation from another cwd need not have an editable
        # framework install. Resolve the pure preflight from authenticated code.
        sys.path.insert(0, str(output / "frozen"))
        try:
            supervise(output, registration)
        except CapabilityPreflightError as error:
            print(str(error), file=sys.stderr)
            raise SystemExit(2) from None
    elif args.worker:
        if args.register_only:
            parser.error("--register-only cannot be combined with --worker")
        if args.index is None or args.index < 0:
            parser.error("--worker requires a nonnegative --index")
        try:
            worker(args.worker.resolve(), args.index)
        except CapabilityPreflightError as error:
            print(str(error), file=sys.stderr)
            raise SystemExit(2) from None
    else:
        if not args.output:
            parser.error("--output is required")
        output = args.output.resolve()
        registration = register(output, args.json_repetitions, args.sample_repetitions, args.workers,
                                freeze_current=args.freeze_current, cases=args.cases, max_code_repairs=args.max_code_repairs,
                                agent_timeout=args.agent_timeout, agent_backend=args.agent_backend,
                                dsh_profile=args.dsh_profile)
        if args.register_only:
            write(output / "registration_review.json", {"schema_version": 1,
                "status": "registered_only", "production_fingerprint": registration["production_fingerprint"],
                "context_agent_backend_fingerprint": registration["context_agent_backend_fingerprint"],
                "planned_trials": registration["planned_trials"], "execution_started": False,
                "dependency_preflight": "not_requested", "runtime_started": False, "provider_requests": 0})
            print("Fresh registration published for review; execution and dependency preflight were not requested.")
            return
        try:
            supervise(output, registration)
        except CapabilityPreflightError as error:
            print(str(error), file=sys.stderr)
            raise SystemExit(2) from None


if __name__ == "__main__":
    cli()
