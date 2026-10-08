#!/usr/bin/env python3
"""Independent read-only audit of registered fresh development trial artifacts.

No production imports, environment credentials, provider requests, or trial mutations.
The only output is this audit's own JSON report.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
TOKEN_KEYS = ("prompt_tokens", "completion_tokens", "total_tokens")


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                    allow_nan=False, separators=(",", ":")).encode()).hexdigest()


def check_file(root, relative, expected):
    path = root / relative
    return path.is_file() and sha(path) == expected


def production_inventory(root):
    return {p.relative_to(root).as_posix()
            for pattern in ("harness_generation/**/*.py", "harness_generation/**/*.mjs",
                            "harness_generation/**/dsh_kernel.json", "sfg_builder/**/*.py")
            for p in root.glob(pattern) if p.is_file()} | {"pyproject.toml"}


def context_backend_checks(config, registration):
    """Absent historical descriptors mean native; a DSH claim needs exact identity."""
    expected = registration.get("context_agent_backend", {"name": "native"})
    observed = config.get("agent_backend", {"name": "native"}) if isinstance(config, dict) else None
    return {"registered_context_backend": observed == expected,
            "context_backend_name": isinstance(expected, dict)
                and expected.get("name") in {"native", "deepseek-harness"}}


def dependency_preflight_checks(path, registration, *, scope, trial_id=None, required=False):
    """Validate persisted static observations without probing installed packages."""
    checks = {}
    if not path.is_file():
        if required:
            checks["preflight:" + scope + ":observed"] = False
        return checks, None
    record = read(path)
    prefix = "preflight:" + scope + ":"
    backend = registration.get("context_agent_backend", {"name": "native"})
    checks[prefix + "dsh_backend"] = backend.get("name") == "deepseek-harness"
    checks[prefix + "production_identity"] = record.get("production_fingerprint") == registration.get("production_fingerprint")
    checks[prefix + "backend_identity"] = record.get("context_agent_backend_fingerprint") == registration.get("context_agent_backend_fingerprint")
    checks[prefix + "record_fingerprint"] = record.get("record_fingerprint") == digest(
        {key: value for key, value in record.items() if key != "record_fingerprint"})
    checks[prefix + "scope"] = record.get("scope") == scope
    if trial_id is not None:
        checks[prefix + "trial_identity"] = record.get("trial_id") == trial_id
    checks[prefix + "no_runtime_launch"] = record.get("runtime_started") is False
    checks[prefix + "no_optional_sdk_import"] = record.get("optional_sdk_imported") is False
    checks[prefix + "no_provider_requests"] = type(record.get("provider_requests")) is int and record["provider_requests"] == 0
    available = record.get("static_capability_available")
    checks[prefix + "static_status"] = (type(available) is bool
        and record.get("status") == ("static_ready" if available else "static_unavailable"))
    if available:
        checks[prefix + "carrier"] = record.get("runtime_carrier") == backend.get("runtime_carrier") == "bundled-exe"
        checks[prefix + "sdk_pin"] = record.get("sdk_version") == backend.get("sdk_version")
        checks[prefix + "runtime_pin"] = record.get("runtime_version") == backend.get("runtime_version")
    else:
        category = record.get("error_category")
        checks[prefix + "safe_failure_category"] = isinstance(category, str) and re.fullmatch(r"dsh_[a-z_]+", category) is not None
    return checks, record


def failed_preflight_execution_checks(capability, record, costs, *, stage_entered=False,
                                     paid_artifacts=False):
    """A valid failure receipt cannot coexist with subsequent pipeline work."""
    if not capability or capability.get("static_capability_available") is not False:
        return {}
    return {
        "preflight:worker:failed_no_success_claim": record.get("status") not in {"passed", "completed", "success"},
        "preflight:worker:failed_no_stage_entry": not stage_entered and not record.get("stage_exits"),
        "preflight:worker:failed_no_paid_artifacts": not paid_artifacts,
        "preflight:worker:failed_no_provider_observations": not (
            costs.get("observed_provider_request_attempts", 0)
            or costs.get("unknown_request_attempts", 0)
            or any(costs.get("observed_agent_model_calls", {}).values())
            or any(costs.get("upstream_trace_tool_calls", {}).values())),
    }


def frozen_backend_contract(root, profile, budget):
    """Independently derive literal identity and the complete frozen asset roster."""
    context = root / "harness_generation/harness_context"
    trees, bindings = {}, {}
    for name in ("dsh_backend.py", "dsh_config.py", "dsh_policy.py"):
        tree = ast.parse((context / name).read_text(), filename=str(context / name))
        trees[name], bindings[name] = tree, {}
        for statement in tree.body:
            if not isinstance(statement, ast.Assign):
                continue
            try:
                literal = ast.literal_eval(statement.value)
            except (ValueError, TypeError):
                continue
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    bindings[name][target.id] = literal
    config = bindings["dsh_config.py"]
    if not isinstance(profile, dict) or set(profile) != set(config["DEFAULT_DSH_PROFILE"]):
        raise ValueError("effective profile keys differ from frozen schema")
    normalized = dict(profile)
    for name, maximum in config["_INTEGER_LIMITS"].items():
        if type(normalized[name]) is not int or not 1 <= normalized[name] <= maximum:
            raise ValueError("effective profile integer limit is invalid")
    timeout = normalized["request_timeout_seconds"]
    if (type(timeout) not in (int, float)
            or not 0 < timeout <= config["_MAX_REQUEST_TIMEOUT_SECONDS"]):
        raise ValueError("effective profile timeout is invalid")
    normalized["request_timeout_seconds"] = float(timeout)
    scalars = {**bindings["dsh_backend.py"],
        **{key: config[key] for key in ("BACKEND_NAME", "PROFILE_VERSION", "BRIDGE_POLICY_VERSION")},
        "BOUNDED_POLICY_VERSION": bindings["dsh_policy.py"]["VERSION"]}
    dynamic = {"budget": budget, "profile": normalized, "profile_sha256": digest(normalized)}
    for field, constant in (("assets_sha256", "ASSETS"), ("native_policy_sha256", "NATIVE_POLICY_FILES")):
        roster = scalars[constant]
        if (not isinstance(roster, (list, tuple)) or not roster or not all(isinstance(item, str) for item in roster)
                or len(roster) != len(set(roster))):
            raise ValueError("frozen asset roster is invalid")
        dynamic[field] = {}
        for relative in roster:
            asset = (context / relative).resolve()
            asset.relative_to(root.resolve())
            dynamic[field][relative] = sha(asset)
    descriptor_nodes = []
    for node in ast.walk(trees["dsh_backend.py"]):
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Attribute) and target.attr == "_descriptor"
                and isinstance(target.value, ast.Name) and target.value.id == "self" for target in node.targets):
            descriptor_nodes.append(node.value)
    if len(descriptor_nodes) != 1 or not isinstance(descriptor_nodes[0], ast.Dict):
        raise ValueError("frozen backend descriptor definition is ambiguous")
    expected = {}
    for key_node, value_node in zip(descriptor_nodes[0].keys, descriptor_nodes[0].values):
        field = ast.literal_eval(key_node)
        if not isinstance(field, str) or field in expected:
            raise ValueError("frozen backend descriptor fields are invalid")
        expected[field] = (dynamic[field] if field in dynamic else
            scalars[value_node.id] if isinstance(value_node, ast.Name) else ast.literal_eval(value_node))
    if set(dynamic) - set(expected):
        raise ValueError("frozen backend descriptor lacks required fields")
    return expected


def backend_registration_checks(root, registration):
    """Authenticate bridge assets and effective profile without importing production."""
    backend = registration.get("context_agent_backend", {"name": "native"})
    checks = {"backend:registered_name": isinstance(backend, dict)
              and backend.get("name") in {"native", "deepseek-harness"}}
    if not checks["backend:registered_name"]:
        return checks
    if "context_agent_backend_fingerprint" in registration:
        checks["backend:descriptor_fingerprint"] = digest(backend) == registration["context_agent_backend_fingerprint"]
    if backend["name"] == "native":
        checks["backend:native_descriptor"] = backend == {"name": "native"} and not registration.get("dsh_profile")
        return checks
    checks["backend:descriptor_fingerprint_present"] = "context_agent_backend_fingerprint" in registration
    checks["backend:fresh_current_registration"] = registration.get("freeze_mode") == "current"
    checks["backend:context_budget"] = backend.get("budget") == registration.get("context_budget")
    profile = registration.get("dsh_profile", {})
    profile_path = root / "dsh_profile.json"
    checks["backend:profile_source"] = profile.get("source") == "dsh_profile.json"
    checks["backend:profile_file"] = check_file(root, "dsh_profile.json", profile.get("sha256"))
    effective = None
    try:
        effective = read(profile_path) if profile_path.is_file() else None
        checks["backend:effective_profile"] = effective == backend.get("profile") and isinstance(effective, dict)
        checks["backend:profile_fingerprint"] = (digest(effective) == backend.get("profile_sha256")
            == profile.get("profile_sha256"))
    except (OSError, ValueError, TypeError):
        checks["backend:effective_profile"] = False
        checks["backend:profile_fingerprint"] = False
    frozen = (root / "frozen").resolve()
    try:
        contract = frozen_backend_contract(frozen, effective, registration.get("context_budget"))
        checks["backend:frozen_descriptor_contract"] = backend == contract
        for field, value in contract.items():
            checks["backend:frozen_contract:" + field] = backend.get(field) == value
    except (OSError, ValueError, TypeError, KeyError, SyntaxError):
        checks["backend:frozen_descriptor_contract"] = False
    for key in ("assets_sha256", "native_policy_sha256"):
        assets = backend.get(key)
        checks["backend:" + key + ":present"] = isinstance(assets, dict) and bool(assets)
        if not isinstance(assets, dict):
            continue
        for name, expected in assets.items():
            prefix = "backend:" + key + ":" + str(name)
            try:
                relative = (frozen / "harness_generation/harness_context" / name).resolve().relative_to(frozen).as_posix()
                checks[prefix] = (registration["production_file_hashes"].get(relative) == expected
                    and check_file(frozen, relative, expected))
            except (ValueError, TypeError, OSError):
                checks[prefix] = False
    pyproject = frozen / "pyproject.toml"
    contents = pyproject.read_text() if pyproject.is_file() else ""
    for package, key in (("deepseek-harness-sdk", "sdk_version"),
                         ("deepseek-harness-runtime-bin", "runtime_version")):
        version = backend.get(key)
        checks["backend:pin:" + package] = (isinstance(version, str) and bool(version)
            and f'"{package}=={version}"' in contents)
    checks["backend:matching_sdk_runtime"] = backend.get("sdk_version") == backend.get("runtime_version")
    return checks


def backend_trace_checks(artifacts, registration):
    """Match the primary loop receipt to the registered Context executor."""
    expected = registration.get("context_agent_backend", {"name": "native"})
    if not isinstance(expected, dict):
        return {"backend:trace:registered_descriptor": False}
    checks = {}
    for path in sorted(artifacts.glob("harness_contexts/*/agent_runs/*/attempt_*/trace.json")):
        marker = path.with_name("metadata.json")
        metadata = read(marker) if marker.is_file() else {}
        if metadata.get("group_cost_owner") is False:
            continue
        prefix = "backend:trace:" + str(path.relative_to(artifacts)) + ":"
        checks[prefix + "metadata_present"] = marker.is_file()
        checks[prefix + "configuration_present"] = isinstance(metadata.get("configuration"), dict) and bool(metadata["configuration"])
        checks.update({prefix + key: value for key, value in
            context_backend_checks(metadata.get("configuration", {}), registration).items()})
        events = read(path).get("events", [])
        starts = [event for event in events if event.get("kind") == "dsh_backend_start"]
        if expected.get("name") == "deepseek-harness":
            # Preparation may end before the optional loop is ever entered.
            if metadata.get("model_calls", 0) or starts or any(
                    event.get("kind") in {"model_response", "model_error"} or
                    str(event.get("kind", "")).startswith("dsh_") for event in events):
                checks[prefix + "one_dsh_loop_receipt"] = len(starts) == 1
                checks[prefix + "registered_dsh_loop_receipt"] = len(starts) == 1 and starts[0].get("agent_backend") == expected
        else:
            checks[prefix + "native_has_no_dsh_loop"] = not starts
    return checks


def context_observation_checks(artifacts, record, *, finished=False, entered=False):
    """Distinguish an unentered Context from missing publications after entry."""
    statuses = {"passed", "harness-context_failed", "context-generate_failed"}
    exits = record.get("stage_exits", {})
    publications = sorted(artifacts.glob("harness_contexts/*/metadata.json"))
    traces = sorted(artifacts.glob("harness_contexts/*/agent_runs/*/attempt_*/trace.json"))
    primary = [path for path in traces if path.with_name("metadata.json").is_file()
        and read(path.with_name("metadata.json")).get("group_cost_owner") is not False]
    attempted = bool(entered or publications or traces or "harness-context" in exits
        or "context-generate" in exits or record.get("status") in statuses)
    terminal = bool(finished or "harness-context" in exits)
    checks = {}
    if attempted and terminal:
        checks["context:metadata_observed_after_entry"] = bool(publications)
        checks["context:published_bundle_observed_after_entry"] = bool(publications) and all(
            path.with_name("completeness.json").is_file()
            and path.with_name("harness_context.json").is_file() for path in publications)
        configurations = [read(path).get("configuration") for path in publications]
        checks["context:configuration_observed_after_entry"] = bool(configurations) and all(
            isinstance(value, dict) and bool(value) for value in configurations)
        metrics = [read(path).get("metrics", {}) for path in publications]
        checks["context:metrics_observed_after_entry"] = bool(metrics) and all(
            isinstance(value, dict) and type(value.get("model_calls")) is int and value["model_calls"] >= 0
            and type(value.get("tool_calls")) is int and value["tool_calls"] >= 0 for value in metrics)
        paid = any(read(path).get("metrics", {}).get("model_calls", 0) for path in publications)
        checks["context:primary_trace_observed_for_paid_calls"] = not paid or bool(primary)
    if not attempted:
        state = "not_started" if not record or record.get("status") == "not_started" else "skipped_upstream"
    elif not terminal:
        state = "in_progress"
    else:
        state = "observed" if all(checks.values()) else "missing_observations"
    return checks, {"state": state, "attempted": attempted,
        "context_publications": len(publications), "context_traces": len(traces),
        "primary_context_traces": len(primary), "dsh_loop_receipts": sum(
            event.get("kind") == "dsh_backend_start" for path in primary for event in read(path).get("events", []))}


def document_checks(path, metadata):
    checks = {}
    if "configuration" in metadata:
        checks["configuration_digest"] = digest(metadata["configuration"]) == metadata.get("configuration_fingerprint")
    for name, expected in metadata.get("document_digests", {}).items():
        document = path.parent / (name + ".json")
        checks["document:" + name] = document.is_file() and digest(read(document)) == expected
    for name, expected in metadata.get("file_digests", {}).items():
        checks["file:" + name] = check_file(path.parent, name, expected)
    return checks


def code_attempt_checks(path, metadata, repair_limit):
    """Validate a bounded correction chain independently from its cost counters."""
    directory = path.parent
    config = metadata.get('configuration', {})
    attempts = metadata.get('model_attempts', [])
    checks = {}
    valid_rows = isinstance(attempts, list) and all(isinstance(row, dict) for row in attempts)
    checks['code_attempt_rows'] = valid_rows
    if not valid_rows:
        return checks
    checks['code_attempt_sequence'] = [row.get('attempt') for row in attempts] == list(range(1, len(attempts) + 1))
    checks['code_attempt_bound'] = len(attempts) <= 1 + repair_limit
    checks['code_attempt_model_calls'] = metadata.get('model_calls') == sum(row.get('model_call') is True for row in attempts)
    checks['code_repair_count'] = metadata.get('code_repairs') == max(sum(row.get('model_call') is True for row in attempts) - 1, 0)
    checks['code_attempt_final_status'] = not attempts or attempts[-1].get('status') == metadata.get('status')
    checks['code_repair_trigger'] = all(row.get('status') in {'invalid_code', 'compile_failed'} for row in attempts[:-1])
    root_plan = directory / 'harness_plan.json'
    parent_plan = directory.parent / 'harness_plan.json'
    checks['code_attempt_frozen_plan'] = root_plan.is_file() and parent_plan.is_file() and read(root_plan) == read(parent_plan) \
        and digest(read(root_plan)) == config.get('plan_digest')
    expected_responses = set()
    for index, attempt in enumerate(attempts, 1):
        prefix = 'code_attempt:' + str(index) + ':'
        folder = directory / 'code_attempts' / f'attempt_{index:04d}'
        checks[prefix + 'entry'] = (folder / 'attempt.json').is_file() and read(folder / 'attempt.json') == attempt
        checks[prefix + 'plan_digest'] = attempt.get('plan_digest') == config.get('plan_digest')
        expected_response = 'response.json' if index == 1 else f'code_attempts/attempt_{index:04d}/response.json'
        response_path = attempt.get('response_path')
        checks[prefix + 'response_path'] = response_path in (None, expected_response)
        if response_path:
            expected_responses.add(expected_response)
        response = directory / expected_response
        actual_usage = read(response).get('usage') if response.is_file() else None
        usage_known = isinstance(actual_usage, dict) and all(type(actual_usage.get(key)) is int for key in TOKEN_KEYS)
        checks[prefix + 'usage_known'] = attempt.get('usage_known') is usage_known
        hashes = attempt.get('file_digests', {})
        safe_hashes = isinstance(hashes, dict) and all(isinstance(relative, str) and not Path(relative).is_absolute()
            and (directory / relative).resolve().is_relative_to(directory.resolve()) for relative in hashes)
        checks[prefix + 'hash_paths_safe'] = safe_hashes
        checks[prefix + 'hashes_match'] = safe_hashes and all(check_file(directory, relative, expected) for relative, expected in hashes.items())
        snapshot_files = {str(item.relative_to(directory)) for item in folder.rglob('*')
                          if item.is_file() and item.name != 'attempt.json'}
        if index == 1 and response_path:
            snapshot_files.add('response.json')
        checks[prefix + 'snapshot_inventory_exact'] = set(hashes) == snapshot_files
        if response.is_file():
            checks[prefix + 'response_hash_recorded'] = expected_response in hashes
    observed_responses = {str(p.relative_to(directory)) for p in [directory / 'response.json',
        *directory.glob('code_attempts/attempt_*/response.json')] if p.is_file()}
    checks['code_attempt_no_unregistered_response'] = observed_responses == expected_responses
    if metadata.get('status') == 'passed' and metadata.get('code_origin') == 'model_translation':
        final = read(directory / 'code_validation.json') if (directory / 'code_validation.json').is_file() else {}
        checks['accepted_code_validation'] = final.get('status') == 'valid'
        folder = directory / 'code_attempts' / f'attempt_{len(attempts):04d}'
        language = read(root_plan).get('language') if root_plan.is_file() else None
        harness = 'harness.cpp' if language == 'c++' else 'harness.c'
        for name in ('code_validation.json', harness):
            checks['accepted_snapshot:' + name] = (directory / name).is_file() and (folder / name).is_file() \
                and sha(directory / name) == sha(folder / name)
        if config.get('build'):
            for name in ('build/build.json', 'build/runtime.json'):
                checks['accepted_snapshot:' + name] = (directory / name).is_file() and (folder / name).is_file() \
                    and sha(directory / name) == sha(folder / name)
            expected_inputs = {str(item.relative_to(folder / 'build')): sha(item)
                               for item in (folder / 'build').glob('input_*.bin')}
            actual_inputs = {str(item.relative_to(directory / 'build')): sha(item)
                             for item in (directory / 'build').glob('input_*.bin')}
            checks['accepted_runtime_inputs_unchanged'] = actual_inputs == expected_inputs
    checks['code_attempt_authenticated_build_inputs'] = all(Path(name).is_file() and sha(Path(name)) == expected
        for name, expected in config.get('build_file_digests', {}).items())
    return checks


def cost_observations(artifacts):
    """Count primary traces, then deduplicate only identical provider response IDs.

    Context writes identical grouped traces for every requirement and also the
    latest attempt at the requirement root. Only attempt cost owners are primary.
    Missing failure usage stays unknown; it is never added as zero-cost work.
    """
    responses, errors, protocol = {}, [], []
    unknown_requests, local_budget_stops = [], []
    recoveries = Counter()
    recovery_events = Counter()
    recovery_traces = []
    stage_recoveries = {stage: Counter() for stage in ('candidate', 'slice', 'context', 'code')}
    collisions, no_id = [], []
    stage_calls = Counter()
    upstream_tools = Counter()
    patterns = [("candidate", "candidate_discovery/agent_runs/*/trace.json"),
                ("slice", "semantic_slices/*/trace.json"),
                ("context", "harness_contexts/*/agent_runs/*/attempt_*/trace.json")]
    for stage, pattern in patterns:
        for path in sorted(artifacts.glob(pattern)):
            marker = path.with_name("metadata.json")
            metadata = read(marker) if marker.is_file() else {}
            if stage == "context" and metadata.get("group_cost_owner") is False:
                continue
            trace_recoveries = Counter()
            for index, event in enumerate(read(path).get("events", [])):
                kind = event.get("kind")
                where = {"stage": stage, "trace": str(path.relative_to(artifacts)), "event_index": index}
                if kind == "model_response":
                    stage_calls[stage] += 1
                    observed = event.get("metadata", {})
                    response_id = observed.get("response_id")
                    observation = {**where, "response_id": response_id,
                                   "usage": observed.get("usage"), "served_model": observed.get("served_model")}
                    if not response_id:
                        no_id.append(observation)
                    elif response_id in responses:
                        if responses[response_id]["usage"] != observation["usage"] or responses[response_id]["served_model"] != observation["served_model"]:
                            collisions.append(response_id)
                    else:
                        responses[response_id] = observation
                elif kind == "model_error":
                    if event.get("error_category") == "budget_exhausted" or event.get("error") == "budget_exhausted":
                        local_budget_stops.append({**where, "category": "budget_exhausted"})
                    else:
                        stage_calls[stage] += 1
                        errors.append({**where, "category": event.get("error_category"),
                                       "response_status": event.get("http_status"),
                                       "usage": None, "attempts": 1})
                elif kind == "budget_stop":
                    local_budget_stops.append({**where, "category": "budget_exhausted",
                                               "reason": event.get("reason"),
                                               "provider_request": event.get("provider_request"),
                                               "model_call": event.get("model_call")})
                elif kind in {"provider_recovery", "semantic_recovery", "protocol_recovery"}:
                    trace_recoveries[kind] += 1
                    recovery_events[kind] += 1
                if (kind == "tool_call" and stage in {"candidate", "slice"}
                        and event.get("tool_executed") is not False
                        and not event.get("evidence_reuse")):
                    upstream_tools[stage] += 1
                if event.get("error_category"):
                    protocol.append({**where, "kind": kind, "category": event["error_category"]})
            accepted = {}
            for kind in ('provider_recovery', 'semantic_recovery', 'protocol_recovery'):
                persisted = metadata.get(kind.replace('recovery', 'recoveries'))
                count = persisted if type(persisted) is int else trace_recoveries[kind]
                accepted[kind] = count
                if count:
                    recoveries[kind] += count
                    stage_recoveries[stage][kind] += count
            recovery_traces.append({'stage': stage, 'trace': str(path.relative_to(artifacts)),
                                    'events': dict(trace_recoveries), 'accepted': accepted})
    code_responses = list(artifacts.glob("context_generations/**/response.json"))
    for path in sorted(code_responses):
        document = read(path)
        response_id = document.get("response_id")
        observation = {"stage": "code", "response": str(path.relative_to(artifacts)),
                       "response_id": response_id, "usage": document.get("usage"), "served_model": document.get("model")}
        if not response_id:
            no_id.append(observation)
        elif response_id in responses:
            collisions.append(response_id)
        else:
            responses[response_id] = observation
    for path in sorted(artifacts.glob("context_generations/**/metadata.json")):
        metadata = read(path)
        requested = metadata.get("model_calls", 0)
        stage_calls["code"] += requested
        attempts = metadata.get('model_attempts')
        if isinstance(attempts, list):
            missing = [attempt for attempt in attempts if attempt.get('model_call') is True
                       and not (path.parent / ('response.json' if attempt.get('attempt') == 1 else
                           f"code_attempts/attempt_{attempt.get('attempt', 0):04d}/response.json")).is_file()]
            observed = sum(p.is_file() for p in [path.with_name('response.json'),
                           *path.parent.glob('code_attempts/attempt_*/response.json')])
            residual = max(requested - observed - len(missing), 0)
            missing += [{'error': metadata.get('error'), 'attempts': residual}] if residual else []
        else:
            observed = sum(p.is_file() for p in [path.with_name('response.json'),
                           *path.parent.glob('code_attempts/attempt_*/response.json')])
            missing = [{'error': metadata.get('error'), 'attempts': max(requested-observed, 0)}]
        for attempt in missing:
            calls = attempt.get('attempts', 1)
            if not calls:
                continue
            error = attempt.get('error')
            http = re.search(r"(?:Error code:|HTTP(?: status)?|status_code[=:])\s*(4\d\d|5\d\d)", str(error), re.I)
            observation = {"stage": "code", "metadata": str(path.relative_to(artifacts)),
                           "category": "code_response_not_persisted", "response_status": None,
                           'attempt': attempt.get('attempt'), "usage": None, "attempts": calls}
            category = attempt.get('error_category')
            if http or category in {'timeout', 'provider_error'}:
                errors.append({**observation, 'category': 'http_' + http[1] if http else category,
                               **({'response_status': int(http[1])} if http else {})})
            else:
                unknown_requests.append(observation)
    known_tokens = {key: sum((record.get("usage") or {}).get(key, 0) for record in responses.values()) for key in TOKEN_KEYS}
    missing_usage = [record["response_id"] for record in responses.values()
                     if not isinstance(record.get("usage"), dict) or any(key not in record["usage"] for key in TOKEN_KEYS)]
    context_tokens = {key: sum((r.get("usage") or {}).get(key, 0) for r in responses.values() if r["stage"] == "context") for key in TOKEN_KEYS}
    return {"successful_responses": len(responses), "known_response_tokens": known_tokens,
            "responses": list(responses.values()), "failed_requests": errors,
            "failed_request_usage_unknown": sum(r['attempts'] for r in errors),
            "unknown_requests": unknown_requests,
            "unknown_request_attempts": sum(r['attempts'] for r in unknown_requests),
            "observed_provider_request_attempts": len(responses) + len(no_id) + sum(r['attempts'] for r in errors),
            "local_budget_stops": local_budget_stops,
            "local_budget_stop_counts": dict(Counter(r['stage'] for r in local_budget_stops)),
            "recovery_counts": dict(recoveries),
            "recovery_event_counts": dict(recovery_events), "recovery_trace_observations": recovery_traces,
            "stage_recovery_counts": {stage: dict(counts) for stage, counts in stage_recoveries.items()},
            "cost_is_lower_bound": bool(errors or unknown_requests or no_id or missing_usage),
            "protocol_events": protocol,
            "response_id_collisions": collisions, "responses_without_id": no_id,
            "responses_without_complete_usage": missing_usage,
            "observed_agent_model_calls": dict(stage_calls), "upstream_trace_tool_calls": dict(upstream_tools),
            "context_response_tokens": context_tokens, "code_response_files": len(code_responses)}



def agent_terminal_budget_checks(artifacts, registration):
    """Audit only explicitly registered terminal policies, without current defaults."""
    policies = registration.get('agent_terminal_policies')
    if not policies:
        return {}
    checks, context_requests, groups = {}, Counter(), {}
    patterns = [('candidate', 'candidate_discovery/agent_runs/*/trace.json', 'result.json'),
                ('slice', 'semantic_slices/*/trace.json', 'slice.json'),
                ('context', 'harness_contexts/*/agent_runs/*/attempt_*/trace.json', 'result.json')]
    terminal_names = {'candidate': {'submit_candidate_decision'}, 'slice': {'submit_semantic_slice'},
                      'context': {'submit_requirement_resolution', 'submit_requirement_resolutions'}}
    is_count = lambda value: type(value) is int and value >= 0
    for stage, pattern, result_name in patterns:
        if stage not in policies:
            continue
        policy = policies[stage]
        registered = registration['context_budget' if stage == 'context' else 'validation_slice_budget']
        rounds = registered['max_rounds_per_requirement' if stage == 'context' else 'max_rounds']
        extra_limit = (registered.get('max_terminal_repairs', 0) if stage == 'context' else
                       registration.get('agent_recovery_limits', {}).get(stage, {}).get('max_terminal_repairs', 0))
        checks['terminal:' + stage + ':registered_limits'] = is_count(rounds) and rounds > 0 \
            and type(extra_limit) is int and extra_limit in (0, 1)
        paths = sorted(artifacts.glob(pattern))
        if stage != 'context':
            checks['terminal:' + stage + ':one_fresh_trace'] = len(paths) <= 1
        for path in paths:
            prefix = 'terminal:' + stage + ':' + str(path.relative_to(artifacts)) + ':'
            marker = path.with_name('metadata.json')
            metadata, trace = (read(marker) if marker.is_file() else {}), read(path)
            checks[prefix + 'metadata_present'] = marker.is_file()
            config, events = metadata.get('configuration', {}), trace.get('events', [])
            v4 = policy.get('terminal_repair_policy_version') == 'terminal-only-resubmission-v4'
            def local_endpoint(event):
                return v4 and (event.get('kind') == 'budget_stop' or
                    (event.get('kind') == 'execution_error'
                     and event.get('error') == 'pretransport_model_failure')) \
                    and event.get('provider_request') is False and event.get('model_call') is False
            endpoints = [e for e in events if local_endpoint(e)]
            for index, event in enumerate(events):
                if v4 and (event.get('kind') == 'budget_stop' or
                    (event.get('kind') == 'execution_error' and event.get('error') == 'pretransport_model_failure')):
                    checks[prefix + f'local_stop:{index}:no_request'] = local_endpoint(event)
                    checks[prefix + f'local_stop:{index}:no_later_work'] = not any(
                        e.get('kind') in {'model_response', 'model_error', 'tool_call', 'decision_submission'}
                        for e in events[index + 1:])
            for key, expected in policy.items():
                checks[prefix + 'config:' + key] = config.get(key) == expected
            checks[prefix + 'configured_budget'] = config.get('budget') == registered
            requests = [e for e in events if e.get('kind') in {'model_response', 'model_error'}]
            actual = [e for e in requests if not (e.get('kind') == 'model_error' and
                      (e.get('error_category') == 'budget_exhausted' or e.get('error') == 'budget_exhausted'))]
            if stage == 'context' and metadata.get('group_requirement_ids'):
                group_key = (path.parents[3].name, tuple(metadata['group_requirement_ids']), digest(events))
                groups.setdefault(group_key, []).append((path, metadata))
            if stage == 'context' and metadata.get('group_cost_owner') is False:
                checks[prefix + 'replica_zero_calls'] = metadata.get('model_calls') == 0
                checks[prefix + 'replica_group_calls'] = metadata.get('group_model_calls') == len(actual)
                continue
            if stage == 'context':
                persisted_calls, persisted_rounds = metadata.get('model_calls'), metadata.get('rounds')
                context_requests[path.parents[3]] += len(actual)
                if 'group_model_calls' in metadata:
                    checks[prefix + 'group_calls_match'] = metadata['group_model_calls'] == len(actual)
            else:
                budget = read(path.with_name(result_name)).get('budget', {})
                persisted_calls, persisted_rounds = budget.get('model_calls'), budget.get('rounds')
                checks[prefix + 'tool_bound'] = is_count(budget.get('tool_calls')) \
                    and budget['tool_calls'] <= registered['max_tool_calls']
                checks[prefix + 'source_bound'] = is_count(budget.get('source_chars')) \
                    and budget['source_chars'] <= registered['max_source_chars']
            checks[prefix + 'requests_match_counter'] = is_count(persisted_calls) and persisted_calls == len(actual)
            checks[prefix + 'round_bound'] = is_count(persisted_rounds) and persisted_rounds <= rounds
            checks[prefix + 'registered_model_call_bound'] = is_count(persisted_calls) \
                and persisted_calls <= rounds + extra_limit
            ordinary = [e for e in requests if e.get('phase') != 'terminal_repair']
            ordinary_endpoints = [e for e in events if e in ordinary or
                                  (local_endpoint(e) and e.get('phase') != 'terminal_repair')]
            checks[prefix + 'ordinary_request_bound'] = len(ordinary) <= rounds
            checks[prefix + 'ordinary_round_sequence'] = [e.get('round') for e in ordinary_endpoints] \
                == list(range(1, len(ordinary_endpoints) + 1))
            checks[prefix + 'round_counter_matches_trace'] = persisted_rounds == len(ordinary_endpoints)
            indices = [e.get('model_call') if e.get('kind') == 'model_response' else
                       e.get('diagnostics', {}).get('attempt_number') for e in requests]
            checks[prefix + 'model_attempt_sequence'] = indices == list(range(1, len(requests) + 1))
            for number, request in enumerate(actual):
                diagnostic = (request.get('metadata', {}).get('request_diagnostics', {})
                              if request.get('kind') == 'model_response' else request.get('diagnostics', {}))
                checks[prefix + f'request:{number}:timeout'] = diagnostic.get('request_timeout_seconds') \
                    == registration['provider'].get('timeout', 60.0)
                checks[prefix + f'request:{number}:no_sdk_retries'] = diagnostic.get('sdk_max_retries') == 0
            extras = [(i, e) for i, e in enumerate(events) if e.get('kind') == 'extra_terminal_repair']
            # Pre-loop budget stops have no terminal operation to observe.
            if not requests and not extras and not endpoints and persisted_calls == 0:
                continue
            counter = metadata.get('extra_terminal_repair_attempts')
            checks[prefix + 'extra_counter'] = is_count(counter) and counter == len(extras) and counter <= extra_limit
            checks[prefix + 'trace_extra_counter'] = trace.get('extra_terminal_repair_attempts') == counter
            checks[prefix + 'calls_use_only_observed_extra'] = is_count(persisted_calls) and is_count(counter) \
                and persisted_calls <= rounds + counter
            if stage != 'context':
                checks[prefix + 'result_extra_counter'] = budget.get('terminal_repairs') == counter
            for key, expected in policy.items():
                checks[prefix + 'observed:' + key] = metadata.get(key) == expected and trace.get(key) == expected
            operations = metadata.get('terminal_correction_operations')
            safe_operations = isinstance(operations, list) and all(isinstance(o, dict) for o in operations)
            checks[prefix + 'correction_operations_recorded'] = safe_operations
            checks[prefix + 'correction_operations_match_trace'] = operations == trace.get('terminal_correction_operations')
            checks[prefix + 'correction_counter'] = safe_operations and metadata.get('terminal_correction_attempts') == len(operations) \
                and trace.get('terminal_correction_attempts') == len(operations)
            checks[prefix + 'correction_operation_sequence'] = safe_operations \
                and [o.get('operation') for o in operations] == list(range(1, len(operations) + 1))
            checks[prefix + 'extra_operations_match_events'] = safe_operations \
                and [o for o in operations if o.get('extra') is True] == [e.get('operation') for _, e in extras]
            phase_requests = [e for e in requests if e.get('phase') == 'terminal_repair']
            phase_stops = [e for e in endpoints if e.get('phase') == 'terminal_repair']
            checks[prefix + 'extra_requests_match_operations'] = len(phase_requests) + len(phase_stops) == len(extras)
            for index, (position, extra) in enumerate(extras, 1):
                extra_prefix = prefix + f'extra:{index}:'
                category, tail = extra.get('reason'), events[position + 1:]
                checks[extra_prefix + 'registered_category'] = category in policy['terminal_repair_allowed_categories']
                preceding_errors = [(i, e) for i, e in enumerate(events[:position]) if e.get('kind') == 'execution_error']
                trigger_position, trigger = preceding_errors[-1] if preceding_errors else (-1, {})
                preceding_requests = [(i, e) for i, e in enumerate(events[:position])
                                      if e.get('kind') in {'model_response', 'model_error'}]
                request_position, trigger_request = preceding_requests[-1] if preceding_requests else (-1, {})
                expected_error = ('terminal_validation_error' if category in
                    {'candidate_unknown_evidence_reference', 'slice_role_choice_not_issued'} else category)
                checks[extra_prefix + 'eligible_recorded_error'] = trigger.get('error_category') == expected_error \
                    and (expected_error != 'terminal_validation_error' or trigger.get('terminal_repair_category') == category) \
                    and (category != 'terminal_schema_error' or trigger.get('terminal_extra_repair_allowed') is True) \
                    and trigger_position > request_position and trigger_request.get('kind') == 'model_response' \
                    and trigger_request.get('round') == extra.get('round')
                if category == 'terminal_native_submission_missing':
                    assistants = [m for m in trace.get('messages', []) if m.get('role') == 'assistant']
                    later_response = any(e.get('kind') == 'model_response' for e in tail)
                    previous = assistants[-2 if later_response else -1] if len(assistants) >= (2 if later_response else 1) else {}
                    checks[extra_prefix + 'completed_zero_call_response'] = (
                        trigger_request.get('metadata', {}).get('finish_reason') in {'stop', 'tool_calls'}
                        and bool(previous) and not previous.get('tool_calls'))
                checks[extra_prefix + 'policy_version'] = extra.get('policy_version') == policy['terminal_repair_policy_version']
                checks[extra_prefix + 'shared_extra_limit'] = extra.get('shared_extra_attempt') == index \
                    and extra.get('max_extra_terminal_repairs') == extra_limit
                actual_round_limit = extra.get('ordinary_round_limit')
                checks[extra_prefix + 'round_limit'] = (is_count(actual_round_limit) and 0 < actual_round_limit <= rounds
                    if stage == 'context' else actual_round_limit == rounds)
                last_only = policy['extra_terminal_repair_last_round_only'] or category != 'terminal_schema_error'
                checks[extra_prefix + 'registered_last_round_policy'] = extra.get('extra_terminal_repair_last_round_only') \
                    is policy['extra_terminal_repair_last_round_only']
                checks[extra_prefix + 'last_round'] = not last_only or extra.get('round') == (
                    actual_round_limit if stage == 'context' else rounds)
                checks[extra_prefix + 'no_repository_execution'] = not any(e.get('kind') == 'tool_call' for e in tail)
                after_requests = [e for e in tail if e.get('kind') in {'model_response', 'model_error'}]
                after_stops = [e for e in tail if local_endpoint(e)]
                completion = after_requests + after_stops
                checks[extra_prefix + 'one_terminal_only_request'] = len(completion) == 1 \
                    and completion[0].get('phase') == 'terminal_repair' \
                    and completion[0].get('round') == extra.get('round')
                request = after_requests[0] if len(after_requests) == 1 else {}
                diagnostic = (request.get('metadata', {}).get('request_diagnostics', {})
                              if request.get('kind') == 'model_response' else request.get('diagnostics', {}))
                stopped_before_request = len(after_stops) == 1 and not after_requests
                checks[extra_prefix + 'only_terminal_schema_advertised'] = (
                    stopped_before_request or diagnostic.get('tool_count') == 1)
                operation = extra.get('operation') or {}
                next_call = request.get('model_call') if request.get('kind') == 'model_response' else diagnostic.get('attempt_number')
                checks[extra_prefix + 'operation_matches_request'] = operation.get('next_model_call') == next_call \
                    and operation.get('category') == category and operation.get('extra') is True \
                    and operation.get('terminal_only') is True and operation.get('ordinary_round') == extra.get('round')
                if stopped_before_request:
                    next_call = sum(e.get('kind') in {'model_response', 'model_error'} and not (
                        e.get('kind') == 'model_error' and (e.get('error_category') == 'budget_exhausted'
                        or e.get('error') == 'budget_exhausted')) for e in events[:position]) + 1
                    checks[extra_prefix + 'operation_matches_request'] = operation.get('next_model_call') == next_call \
                        and operation.get('category') == category and operation.get('extra') is True \
                        and operation.get('terminal_only') is True and operation.get('ordinary_round') == extra.get('round')
                submitted = [e for e in tail if e.get('kind') == 'decision_submission' and e.get('phase') == 'terminal_repair']
                rejected = any(e.get('kind') == 'repair_rejected' for e in tail)
                if request.get('kind') == 'model_response' and not rejected:
                    call_id = submitted[0].get('tool_call_id') if len(submitted) == 1 else None
                    messages = [m for m in trace.get('messages', []) if m.get('role') == 'assistant'
                        and any(c.get('id') == call_id for c in m.get('tool_calls', []))]
                    calls = messages[0].get('tool_calls', []) if len(messages) == 1 else []
                    checks[extra_prefix + 'sole_native_terminal_submission'] = len(submitted) == 1 and len(calls) == 1 \
                        and calls[0].get('function', {}).get('name') in terminal_names[stage]
                else:
                    # Failed transports and explicitly rejected replies still
                    # spend the one operation; no tool may execute afterward.
                    checks[extra_prefix + 'failed_or_rejected_no_submission'] = not submitted
    for key, records in groups.items():
        prefix = 'terminal:context:group:' + digest(key)[:16] + ':'
        checks[prefix + 'one_cost_owner'] = sum(m.get('group_cost_owner') is True for _, m in records) == 1
    for directory, requests in context_requests.items():
        prefix = 'terminal:context:' + directory.name + ':global:'
        metadata = read(directory / 'metadata.json')
        metrics, budget = metadata.get('metrics', {}), registration['context_budget']
        for observed, maximum in [('model_calls', 'max_total_model_calls'), ('tool_calls', 'max_tool_calls'),
                                  ('source_chars', 'max_source_chars')]:
            checks[prefix + observed + '_bound'] = is_count(metrics.get(observed)) and metrics[observed] <= budget[maximum]
        checks[prefix + 'primary_request_counter'] = metrics.get('model_calls') == requests
    return checks

def audit_trial(identity, registration):
    trial, artifacts = Path(identity["trial_dir"]), Path(identity["artifacts"])
    marker = trial / "supervisor.json"
    record = read(marker) if marker.is_file() else read(trial / "trial.json") if (trial / "trial.json").is_file() else {}
    done = marker.is_file()
    checks = {}
    preflight_checks, capability = dependency_preflight_checks(
        trial.parent / (identity["trial_id"] + "_dependency_preflight.json"), registration,
        scope="worker", trial_id=identity["trial_id"], required=bool(record)
            and registration.get("context_agent_backend", {}).get("name") == "deepseek-harness")
    checks.update(preflight_checks)
    log = trial.parent / (identity["trial_id"] + ".log")
    entered = log.is_file() and any(line == "[FRESH STAGE] " + identity["trial_id"] + " harness-context"
        for line in log.read_text(errors="replace").splitlines())
    observation_checks, context_observation = context_observation_checks(
        artifacts, record, finished=done, entered=entered)
    checks.update(observation_checks)
    sample = registration["samples"][identity["case"]]
    if record:
        checks["declared_identity"] = all(record.get(k) == identity[k] for k in identity)
        checks["fresh_no_resume_no_retry"] = record.get("fresh") is True and record.get("resume") is False and record.get("failed_retry") is False
        checks["declared_fingerprint"] = record.get("production_fingerprint") == registration["production_fingerprint"]
        checks["declared_context_backend"] = record.get("context_agent_backend", {"name": "native"}) == registration.get("context_agent_backend", {"name": "native"})
        if done:
            checks["worker_final_integrity"] = bool(record.get("integrity")) and all(record["integrity"].values())
    functions = artifacts / "functions.json"
    if functions.is_file():
        document = read(functions)
        project = (functions.parent / document["project"]).resolve()
        expected_project = Path(registration["target_root"]) if identity["phase"] == "json_parse" else trial / "project"
        checks["static_project_identity"] = project == expected_project
        checks["static_source_authentication"] = all(check_file(project, p, h) for p, h in document.get("source_hashes", {}).items())
        checks["exact_anchor"] = sum(f["name"] == sample["anchor"] and f["file"] == sample["anchor_file"] for f in document["functions"]) == 1
        if identity["phase"] != "json_parse":
            checks["fixture_copy_exact"] = check_file(project, "api.c", sample["sha256"])
    for stage, pattern, budget_key in [
        ("candidate", "candidate_discovery/agent_runs/*/metadata.json", "validation_slice_budget"),
        ("slice", "semantic_slices/*/metadata.json", "validation_slice_budget"),
        ("context", "harness_contexts/*/metadata.json", "context_budget"),
    ]:
        for path in sorted(artifacts.glob(pattern)):
            metadata = read(path)
            prefix = stage + ":" + path.parent.name + ":"
            checks.update({prefix + k: v for k, v in document_checks(path, metadata).items()})
            config = metadata.get("configuration", {})
            if not isinstance(config, dict):
                config = {}
            if stage == "context":
                checks.update({prefix + key: value for key, value in context_backend_checks(config, registration).items()})
            checks[prefix + "registered_budget"] = config.get("budget") == registration[budget_key]
            for key, value in registration.get('agent_recovery_limits', {}).get(stage, {}).items():
                checks[prefix + key + '_matches_registration'] = config.get(key) == value
            for key, value in registration.get('agent_terminal_policies', {}).get(stage, {}).items():
                checks[prefix + key + '_matches_registration'] = config.get(key) == value
            model = config.get("model", {})
            checks[prefix + "registered_provider"] = all(model.get(k) == registration["provider"].get(k) for k in ("provider", "base_url", "model", "thinking"))
            checks[prefix + "registered_request_timeout"] = model.get("timeout") == registration["provider"].get("timeout", 60.0)
            checks[prefix + "output_limit"] = model.get("max_tokens") == (8192 if stage == "context" else 4096)
    contexts = list(artifacts.glob("harness_contexts/*/completeness.json"))
    gate, context_metrics = None, None
    if contexts:
        checks["one_context"] = len(contexts) == 1
        bundle_present = all(contexts[0].with_name(name).is_file()
            for name in ("harness_context.json", "metadata.json"))
        checks["context_bundle_present"] = bundle_present
        if bundle_present:
            completeness = read(contexts[0])
            context = read(contexts[0].with_name("harness_context.json"))
            metadata = read(contexts[0].with_name("metadata.json"))
            context_metrics = metadata.get("metrics")
            gate = completeness.get("generation_allowed")
            checks["frozen_agrees_with_gate"] = context.get("frozen") == gate
            if gate:
                graph = completeness.get("semantic_obligation_graph", {})
                checks["admitted_context_no_hard_gaps"] = completeness.get("status") == "complete" and completeness.get("hard_missing") == []
                checks["admitted_roots_closed"] = set(graph.get("mandatory_roots", [])) <= set(graph.get("closed_roots", [])) and graph.get("frontier") == []
    plans = list(artifacts.glob("context_generations/*/*/harness_plan.json"))
    generations = list(artifacts.glob("context_generations/*/*/*/metadata.json"))
    all_code_metadata = list(artifacts.glob("context_generations/**/metadata.json"))
    checks["no_generation_history"] = len(generations) == len(all_code_metadata)
    checks["at_most_one_plan_and_translation"] = len(plans) <= 1 and len(generations) <= 1
    code_calls = sum(read(p).get("model_calls", 0) for p in generations)
    repair_limit = registration.get('max_code_repairs', 0)
    checks['registered_code_repair_limit'] = type(repair_limit) is int and repair_limit in (0, 1)
    checks["registered_code_call_bound"] = code_calls <= 1 + repair_limit
    for path in plans:
        plan = read(path)
        checks["plan_frozen_and_admitted"] = plan.get("frozen") is True and gate is True
        for name, expected in plan.get("input_digests", {}).items():
            source = (artifacts / "minimal_fts" / plan["ft_id"] / "minimal_ft.json") if name == "minimal_ft" else artifacts / "harness_contexts" / plan["ft_id"] / (name + ".json")
            actual = read(source)
            # The graph's own digest omits its graph_digest field.
            if name == "semantic_obligation_graph":
                actual = {k: v for k, v in actual.items() if k != "graph_digest"}
            checks["plan_input:" + name] = digest(actual) == expected
    for path in generations:
        metadata = read(path)
        checks.update({"generation:" + k: v for k, v in document_checks(path, metadata).items()})
        config = metadata.get("configuration", {})
        checks['generation_registered_code_repairs'] = config.get('max_code_repairs', 0) == repair_limit
        if 'model_attempts' in metadata:
            checks.update(code_attempt_checks(path, metadata, repair_limit))
        if 'max_code_repairs' in registration and metadata.get('model_calls', 0):
            checks['generation_attempt_chain_recorded'] = isinstance(metadata.get('model_attempts'), list)
        checks["translation_only_source"] = metadata.get("code_origin") == "model_translation" and config.get("existing_harness_digest") is None
        checks["generation_build_runtime_requested"] = config.get("build") is True and config.get("runtime") is True and config.get("plan_only") is False
        model = config.get("model", {})
        checks["generation_registered_provider"] = all(model.get(k) == registration["provider"].get(k) for k in ("provider", "base_url", "model", "thinking"))
        checks["generation_registered_output_temperature"] = model.get("max_tokens") == registration["code_max_tokens"] and model.get("temperature") == registration["code_temperature"]
        recipe = config.get("recipe", {})
        checks["build_exact_project_and_source"] = Path(recipe.get("project_root", "")) == Path(record.get("project", "")) and recipe.get("source_files") == [str(Path(record["project"]) / ("json.c" if identity["phase"] == "json_parse" else "api.c"))]
        build_path, runtime_path = path.parent / "build/build.json", path.parent / "build/runtime.json"
        if metadata.get("status") == "passed":
            build, runtime = read(build_path), read(runtime_path)
            checks["passed_generation_build_commands"] = build.get("success") is True and all(c.get("return_code") == 0 for c in build.get("commands", []))
            checks["passed_generation_six_sanitizer_cases"] = runtime.get("status") == "passed" and len(runtime.get("cases", [])) == 6 and all(c.get("success") is True for c in runtime["cases"])
    checks.update(agent_terminal_budget_checks(artifacts, registration))
    checks.update(backend_trace_checks(artifacts, registration))
    costs = cost_observations(artifacts)
    stage_entered = log.is_file() and any(line.startswith("[FRESH STAGE] " + identity["trial_id"] + " ")
        for line in log.read_text(errors="replace").splitlines())
    paid_artifacts = any(any(artifacts.glob(pattern)) for pattern in (
        "candidate_discovery/agent_runs/*/metadata.json", "candidate_discovery/agent_runs/*/trace.json",
        "semantic_slices/*/metadata.json", "semantic_slices/*/trace.json",
        "harness_contexts/*/metadata.json", "harness_contexts/*/agent_runs/*/attempt_*/trace.json",
        "context_generations/**/metadata.json", "context_generations/**/response.json"))
    checks.update(failed_preflight_execution_checks(capability, record, costs,
        stage_entered=stage_entered, paid_artifacts=paid_artifacts))
    checks['code_response_file_bound'] = costs['code_response_files'] <= 1 + repair_limit
    checks['code_responses_fit_declared_calls'] = costs['code_response_files'] <= code_calls
    checks["response_identity_nonconflicting"] = not costs["response_id_collisions"]
    checks['bounded_agent_recoveries'] = all(0 <= count <= 1 for trace in costs['recovery_trace_observations']
                                           for count in trace['accepted'].values())
    if gate is False:
        checks["blocked_gate_zero_code_calls"] = code_calls == 0 and costs["code_response_files"] == 0 and not plans
    if context_metrics:
        checks["context_tokens_match_primary_responses"] = context_metrics.get("tokens") == costs["context_response_tokens"]
        checks["context_model_calls_match_primary_events"] = context_metrics.get("model_calls") == costs["observed_agent_model_calls"].get("context", 0)
    return {"trial_id": identity["trial_id"], "case": identity["case"], "finished": done,
            "status": record.get("status", "not_started"), "checks": checks,
            "context_observation": context_observation,
            "pipeline_execution_observation": {"stage_entered": stage_entered,
                "stage_exit_recorded": bool(record.get("stage_exits")), "paid_artifacts": paid_artifacts},
            **({"dependency_preflight": capability} if capability is not None else {}),
            "audit_failures": [k for k, value in checks.items() if not value],
            "gate_allowed": gate, "context_metrics": context_metrics, "code_model_calls": code_calls, "costs": costs}


def audit(root):
    registration = read(root / "registration.json")
    schedule = registration["schedule"]
    expected = registration["production_file_hashes"]
    target = Path(registration["target_root"])
    target_files = {str(p.relative_to(target)): sha(p) for p in target.rglob("*") if p.is_file() and ".git" not in p.parts}
    checks = {
        "registered_trial_count": len(schedule) == registration["planned_trials"],
        "unique_trial_ids": len({r["trial_id"] for r in schedule}) == len(schedule),
        "unique_fresh_artifact_roots": len({r["artifacts"] for r in schedule}) == len(schedule),
        "trial_roots_belong_to_experiment": all(Path(r["trial_dir"]) == root / r["trial_id"]
            and Path(r["artifacts"]) == root / r["trial_id"] / "artifacts" for r in schedule),
        "declared_fingerprint_matches_manifest": digest(expected) == registration["production_fingerprint"],
        "current_production_exact": all(check_file(ROOT, k, v) for k, v in expected.items()),
        "frozen_production_exact": all(check_file(root / "frozen", k, v) for k, v in expected.items()),
        "target_exact": target_files == registration["target_file_hashes"],
        "target_head_exact": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=target, text=True).strip() == registration["target_head"],
        "target_clean": not subprocess.check_output(["git", "status", "--porcelain"], cwd=target, text=True).strip(),
        "registered_runner_exact": sha(ROOT / "scripts/repeat_fresh_stability.py") == registration["runner_sha256"],
        "ancillary_dependencies_exact": all(Path(p).is_file() and sha(p) == h for p, h in registration["ancillary_dependencies"].items()),
        "frozen_project_catalog_exact": check_file(root / "frozen", "project_catalog.py", registration["ancillary_dependencies"][str(ROOT / "project_catalog.py")]),
        "fixtures_exact": all(check_file(root, s["source"], s["sha256"]) for s in registration["samples"].values()),
    }
    checks.update(backend_registration_checks(root, registration))
    preflight_checks, capability = dependency_preflight_checks(root / "dependency_preflight.json", registration,
        scope="supervisor")
    checks.update(preflight_checks)
    if registration.get("production_inventory_policy"):
        checks["current_production_inventory_exact"] = production_inventory(ROOT) == set(expected)
        checks["frozen_production_inventory_exact"] = production_inventory(root / "frozen") == set(expected)
        checks["manifest_matches_registration"] = (root / "manifest.json").is_file() and read(root / "manifest.json") == registration
        checks["registered_cases_match_samples"] = set(registration["cases"]) == set(registration["samples"]) \
            and len(registration["cases"]) == len(registration["samples"])
    if registration.get("target_build_sha256"):
        checks["target_build_exact"] = check_file(root, "target_build.json", registration["target_build_sha256"])
    observed = Counter(r["case"] for r in schedule)
    checks["sample_repetition_counts_exact"] = all(observed[k] == (registration["json_repetitions"] if k == "json_parse" else registration["sample_repetitions"]) for k in registration["samples"])
    checks["json_phase_precedes_structural_phase"] = [r["phase"] for r in schedule] == sorted([r["phase"] for r in schedule])
    trials = [audit_trial(identity, registration) for identity in schedule]
    if capability and capability.get("static_capability_available") is False:
        for trial in trials:
            observation = trial["pipeline_execution_observation"]
            contradiction_checks = failed_preflight_execution_checks(capability,
                {"status": trial["status"], "stage_exits": observation["stage_exit_recorded"]}, trial["costs"],
                stage_entered=observation["stage_entered"], paid_artifacts=observation["paid_artifacts"])
            checks.update({key.replace("preflight:worker:", "preflight:supervisor:" + trial["trial_id"] + ":"): value
                for key, value in contradiction_checks.items()})
    response_trials = {}
    duplicate_responses = []
    for trial in trials:
        for response in trial["costs"]["responses"]:
            rid = response["response_id"]
            if rid in response_trials:
                duplicate_responses.append({"response_id": rid, "trials": [response_trials[rid], trial["trial_id"]]})
            response_trials[rid] = trial["trial_id"]
    checks["no_provider_response_reuse_across_trials"] = not duplicate_responses
    complete = all(t["finished"] for t in trials)
    failures = [k for k, v in checks.items() if not v] + [t["trial_id"] + ":" + k for t in trials for k in t["audit_failures"]]
    return {"schema_version": 1, "category": "independent_read_only_fresh_stability_audit",
            "auditor_sha256": sha(Path(__file__)), "registration_sha256": sha(root / "registration.json"),
            "audited_utc": datetime.now(timezone.utc).isoformat(), "experiment_root": str(root),
            "production_fingerprint": registration["production_fingerprint"], "planned_trials": len(schedule),
            "context_agent_backend": registration.get("context_agent_backend", {"name": "native"}),
            **({"dependency_preflight": capability} if capability is not None else {}),
            "finished_trials": sum(t["finished"] for t in trials), "complete": complete,
            "audit_passed": not failures, "checks": checks, "audit_failures": failures,
            "duplicate_responses_across_trials": duplicate_responses,
            "known_response_tokens": {k: sum(t["costs"]["known_response_tokens"][k] for t in trials) for k in TOKEN_KEYS},
            "successful_responses": sum(t["costs"]["successful_responses"] for t in trials),
            "failed_request_usage_unknown": sum(t["costs"]["failed_request_usage_unknown"] for t in trials),
            "unknown_request_attempts": sum(t["costs"]["unknown_request_attempts"] for t in trials),
            "local_budget_stops": sum(len(t["costs"]["local_budget_stops"]) for t in trials),
            "recovery_counts": dict(sum((Counter(t["costs"]["recovery_counts"]) for t in trials), Counter())),
            "cost_is_lower_bound": any(t["costs"]["cost_is_lower_bound"] or not t['finished']
                                      or t['status'] == 'worker_interrupted' for t in trials),
            "trials": trials}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    root = args.experiment_root.resolve()
    result = audit(root)
    output = args.output or root / "independent_audit.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: result[k] for k in ("planned_trials", "finished_trials", "complete", "audit_passed", "audit_failures", "known_response_tokens", "successful_responses")}, ensure_ascii=False))
    return int(not result["audit_passed"] or (args.require_complete and not result["complete"]))


if __name__ == "__main__":
    raise SystemExit(main())
