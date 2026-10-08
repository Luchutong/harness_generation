#!/usr/bin/env python3
"""Collect frozen fresh-run observations using only persisted artifacts.

No framework imports, model calls, retries, target writes, or environment secrets.
``collect_trial`` is read-only; the CLI writes derived metrics and event logs.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
from typing import Any

TOKEN_KEYS = ("prompt_tokens", "completion_tokens", "total_tokens")
STAGES = ("candidate-validate", "semantic-slice", "harness-context", "context-generate")
INTERRUPTED_TRIAL_STATUSES = {'worker_interrupted', 'supervisor_timeout'}
UNFINISHED_TRIAL_STATUSES = {'not_started', 'running', 'partial', 'worker_process_failed',
                             'worker_missing_trial'} | INTERRUPTED_TRIAL_STATUSES
PLAN_SIGNATURE_VERSION = "execution-semantics-v3"
ENTRY_STAGES = ('candidates', 'candidate-validate', 'semantic-slice', 'minimal-ft',
                'harness-context', 'context-generate')
OPAQUE_ID = re.compile(r"(?<![a-zA-Z0-9_])(?:hg_)?(?:resource|parameter|recipe|construction|call|invocation|callback|localvalue|fuzzinput|constant|state|subject|instance)_[0-9a-f]{16,64}")
PRIVATE_KEY = re.compile(r"^(?:api[_-]?key|authorization|access[_-]?token|refresh[_-]?token|password|secret|credential)$", re.I)


def canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def read(path: Path, warnings: list[str] | None = None) -> dict:
    if not path.is_file():
        return {}
    try:
        result = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        if warnings is not None:
            warnings.append(f"Unreadable artifact {path}: {type(error).__name__}")
        return {}
    return result if isinstance(result, dict) else {}


def safe(value: Any) -> Any:
    """Defense in depth for persisted provider diagnostics (already redacted upstream)."""
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if PRIVATE_KEY.match(k) else safe(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [safe(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [REDACTED]", value)
        value = re.sub(r"\bsk-[a-zA-Z0-9_-]{12,}", "[REDACTED]", value)
        value = re.sub(r"(?i)(api[_-]?key|authorization|access[_-]?token|password|secret)([\s\"']*[:=][\s\"']*)([^\s\"',}]+)", r"\1\2[REDACTED]", value)
    return value


def token_counts(value: dict) -> dict:
    value = value if isinstance(value, dict) else {}
    return {key: value.get(key, 0) if type(value.get(key, 0)) is int else 0 for key in TOKEN_KEYS}


def stage_for(path: Path, root: Path) -> str | None:
    first = path.relative_to(root).parts[0]
    return {"candidate_discovery": "candidate-validate", "semantic_slices": "semantic-slice",
            "harness_contexts": "harness-context", "context_generations": "context-generate"}.get(first)


def selected_traces(root: Path, warnings: list[str]) -> tuple[list[tuple[Path, dict]], dict]:
    """Prefer complete attempt histories to latest-root aliases and group replicas."""
    files = sorted(root.rglob("trace.json"))
    chosen = []
    excluded = Counter()
    for path in files:
        if stage_for(path, root) is None:
            continue
        if not path.parent.name.startswith("attempt_") and any(path.parent.glob("attempt_*/trace.json")):
            excluded["latest_root_alias"] += 1
            continue
        metadata = read(path.with_name("metadata.json"), warnings)
        if metadata.get("group_cost_owner") is False:
            excluded["replicated_context_group"] += 1
            continue
        chosen.append((path, metadata))
    return chosen, {"trace_files_found": len(files), "trace_files_selected": len(chosen),
                    "trace_files_excluded": dict(excluded)}


def first_json(root: Path, pattern: str, warnings: list[str]) -> tuple[Path | None, dict]:
    path = next(iter(sorted(root.glob(pattern))), None)
    return path, read(path, warnings) if path else {}


def stage_entries(trial_path: Path, trial: dict, warnings: list[str]) -> dict:
    """Read only exact, trial-bound supervisor stage markers from the worker log.

    The marker records entry before main() runs. It proves an attempt, while
    final stage publications alone prove termination, Gate evaluation and cost.
    Other trial IDs, partial lines and embedded text provide no such evidence.
    """
    trial_id = trial.get('trial_id')
    observed = {'artifact': None, 'sha256': None, 'stages': [], 'entry_counts': {}}
    if not isinstance(trial_id, str) or not re.fullmatch(r'[a-z_]+_r[0-9]{2}', trial_id) or trial_path.parent.name != trial_id:
        return observed
    path = trial_path.parent.parent / (trial_id + '.log')
    if not path.is_file():
        return observed
    try:
        content = path.read_bytes()
    except OSError as error:
        warnings.append(f'Unreadable worker stage log {path}: {type(error).__name__}')
        return observed
    marker = re.compile(r'\[FRESH STAGE\] ' + re.escape(trial_id) + r' (' + '|'.join(map(re.escape, ENTRY_STAGES)) + r')')
    stages = [match[1] for line in content.decode('utf-8', errors='replace').splitlines()
              if (match := marker.fullmatch(line))]
    return {'artifact': str(path), 'sha256': hashlib.sha256(content).hexdigest(),
            'stages': stages, 'entry_counts': dict(Counter(stages))}


def function_ids(rows: list) -> list[str]:
    return sorted({row if isinstance(row, str) else row.get("function_id", "") for row in rows
                   if isinstance(row, (str, dict))} - {""})


def semantic_plan(plan: dict) -> dict:
    """Execution projection: preserve call/argument order and resource aliasing.

    Evidence, proof digests, diagnostics, and random IDs cannot change this
    signature. IDs are replaced by API/parameter labels or ordered resource/call
    labels, so a different producer/consumer binding does change it. Diagnostic
    resource-identity observations and duplicated contracts are not execution.
    """
    labels: dict[str, str] = {}
    for section in ("call_sequence", "cleanup_sequence"):
        for index, call in enumerate(plan.get(section, [])):
            if call.get("invocation_id"):
                labels[call["invocation_id"]] = f"{section}:{index}:{call.get('function_id')}"
            for argument in call.get("arguments", []):
                label = f"parameter:{call.get('function_id')}:{argument.get('parameter')}"
                for key in ("canonical_parameter_id", "parameter_id"):
                    if argument.get(key):
                        labels[argument[key]] = label
    for recipe in plan.get("construction_recipes", []):
        label = f"parameter:{recipe.get('function_id')}:{recipe.get('parameter')}"
        if recipe.get("parameter_id"):
            labels[recipe["parameter_id"]] = label
        if recipe.get("recipe_id"):
            labels[recipe["recipe_id"]] = f"recipe:{recipe.get('function_id')}:{recipe.get('parameter')}:{recipe.get('kind')}"
        if recipe.get("storage_variable"):
            labels[recipe["storage_variable"]] = f"storage:{recipe.get('function_id')}:{recipe.get('parameter')}:{recipe.get('kind')}"
    # Resource traversal uses executable producer order, then semantic sorting.
    resources = {r.get("resource_id"): r for r in plan.get("resources", []) if r.get("resource_id")}
    order = []
    for call in plan.get("call_sequence", []):
        returned = call.get("return_resource")
        if returned in resources and returned not in order:
            order.append(returned)
        for out in call.get("out_resources", []):
            key = out.get("resource_id") if isinstance(out, dict) else out
            if key in resources and key not in order:
                order.append(key)
    for key in sorted(resources, key=lambda k: canonical({f: resources[k].get(f) for f in ("type", "bindings", "creation", "cleanup", "reuse")})):
        if key not in order:
            order.append(key)
    for index, key in enumerate(order):
        labels[key] = f"resource:{index}:{resources[key].get('type')}"
        labels["hg_" + key] = f"resource:{index}:{resources[key].get('type')}"
    for construction in plan.get("construction_sources", {}).get("sources", []):
        if construction.get("construction_id"):
            labels[construction["construction_id"]] = f"construction:{construction.get('function_id')}:{construction.get('parameter')}:{construction.get('kind')}:{construction.get('creator_api')}"
    ignored = {"evidence_ids", "fact_id", "proof_id", "proof_digest", "recipe_id", "parameter_id",
               "canonical_parameter_id", "invocation_id", "construction_id", "invocation_proof_id", "derived_by", "observed_pair_origins",
               "invocation_scope_proof", "observed_reuse", "transition_id"}
    unordered = {"core_apis", "required_support_apis", "resources", "construction_recipes", "dependencies",
                 "dependency_recipes", "headers", "type_declarations", "ordering_edges", "bindings"}
    def normalize(value: Any, key: str = "") -> Any:
        if isinstance(value, dict):
            return {k: normalize(v, k) for k, v in sorted(value.items())
                    if k not in ignored and not k.endswith("digest") and not k.endswith("_evidence_ids")}
        if isinstance(value, list):
            # The containing field may be an unordered collection, but each
            # nested pair (for example [before, after]) retains its direction.
            result = [normalize(v) for v in value]
            return sorted(result, key=canonical) if key in unordered else result
        if isinstance(value, str):
            if value in labels:
                return labels[value]
            for generated in (name for name in labels if name.startswith('hg_')):
                value = re.sub(r'(?<![a-zA-Z0-9_])' + re.escape(generated) + r'(?![a-zA-Z0-9_])',
                               lambda _: labels[generated], value)
            # Covers opaque names embedded in binding expressions as well.
            return OPAQUE_ID.sub(lambda m: labels.get(m[0], "opaque:" + m[0].split("_")[0]), value)
        return value
    fields = ("schema_version", "policy_version", "frozen", "language", "entrypoint", "headers", "type_declarations",
              "api_declarations", "core_apis", "required_support_apis", "call_sequence", "cleanup_sequence",
              "resources", "construction_recipes", "input_policy", "input_transforms", "callback_policy",
              "invocation_contract", "source_internal_invocations", "ordering_edges", "failure_policy")
    return normalize({key: plan[key] for key in fields if key in plan
                      and (key != 'source_internal_invocations' or plan[key])})


def binding_plan(normalized: dict) -> dict:
    """Concrete canonical recipes and producer/consumer links, without redundant annotations."""
    result = {k: normalized[k] for k in ("core_apis", "required_support_apis", "resources", "construction_recipes", "input_policy",
              "input_transforms", "invocation_contract", "ordering_edges", "failure_policy") if k in normalized}
    if "source_internal_invocations" in normalized:
        result["source_internal_invocations"] = normalized["source_internal_invocations"]
    for section in ("call_sequence", "cleanup_sequence"):
        result[section] = []
        for call in normalized.get(section, []):
            item = {k: call.get(k) for k in ("function_id", "role", "calls_per_input", "guard_nullable_resources",
                    "out_resources", "preconditions", "resource_instance", "return_resource")}
            item.update({k: call[k] for k in ("invocation_kind", "via_function_id", "parameter_forwarding",
                        "local_arguments", "calls_per_invocation", "multiplicity", "storage_lifetime") if k in call})
            item['invocation_kind'] = call.get('invocation_kind', 'direct')
            item["arguments"] = [{k: a.get(k) for k in ("parameter", "canonical_recipe", "binding_expression", "resource_id")}
                                 for a in call.get("arguments", [])]
            item["result_contract"] = ({k: call["result_contract"].get(k) for k in ("nullable", "owned", "success")}
                                       if call.get("result_contract") else None)
            result[section].append(item)
    return result


def runtime_success(document: dict) -> bool | None:
    if type(document.get("success")) is bool:
        return document["success"]
    if document.get("status") == "passed":
        cases = document.get("cases", [])
        return bool(cases) and all(c.get("success") is True for c in cases)
    if document.get("status"):
        return False
    return None


def collect_trial(root: Path) -> dict:
    """Return raw-artifact-derived metrics; never modify the trial or contact a provider."""
    root = Path(root).resolve()
    warnings: list[str] = []
    trial_path = root / "trial.json"
    if not trial_path.is_file() and any((root.parent / name).is_file()
                                      for name in ("trial.json", "supervisor.json")):
        trial_path = root.parent / "trial.json"
    trial = read(trial_path, warnings)
    supervisor = read(root.parent / "supervisor.json", warnings) if trial_path.parent == root.parent else {}
    if supervisor:
        # The supervisor knows a killed worker's outcome; the last native row
        # may still say running and is retained separately for inspection.
        trial = {**trial, "native_status": trial.get("status"), **supervisor}
    entries = stage_entries(trial_path, trial, warnings)
    entered = set(entries['stages'])
    stages = {stage: {"provider_responses": 0, "failed_requests": 0, "local_budget_stops": 0,
                      "provider_recoveries": 0, "semantic_recoveries": 0, "protocol_recoveries": 0,
                      "extra_terminal_repair_operations": 0, "extra_terminal_request_attempts": 0,
                      'code_repairs': 0,
                      "responses_without_complete_usage": 0,
                      "tokens": dict.fromkeys(TOKEN_KEYS, 0), "trace_tool_events": 0,
                      "trace_tool_executions": 0, "trace_evidence_reuses": 0,
                      "trace_framework_tool_events": 0, "unrecorded_codegen_calls": 0} for stage in STAGES}
    traces, trace_audit = selected_traces(root, warnings)
    provider_events = []
    agent_backend_events = []
    responses: dict[str, tuple[str, dict]] = {}
    context_attempts = []
    seen_tools = set()
    seen_events = set()
    selected_metadata: dict[str, list[dict]] = defaultdict(list)

    def add_event(stage: str, path: Path, index: int, event: dict, category: str, request_key: str | None = None):
        key = (stage, category, request_key or str(path.relative_to(root)), index if request_key is None else digest(event))
        if key in seen_events:
            return
        seen_events.add(key)
        provider_events.append({"stage": stage, "artifact": str(path.relative_to(root)),
                                "event_index": index, "category": category, "event": safe(event)})

    def add_response(stage: str, path: Path, index: int, metadata: dict):
        key = metadata.get("response_id") or metadata.get("request_diagnostics", {}).get("request_id") or f"{path.relative_to(root)}:{index}"
        if key in responses:
            return False
        responses[key] = (stage, metadata)
        stages[stage]["provider_responses"] += 1
        usage = metadata.get('usage')
        if not isinstance(usage, dict) or any(type(usage.get(token)) is not int for token in TOKEN_KEYS):
            stages[stage]['responses_without_complete_usage'] += 1
        for token, number in token_counts(metadata.get("usage", {})).items():
            stages[stage]["tokens"][token] += number
        add_event(stage, path, index, {"kind": "model_response", "metadata": metadata}, "provider_response", key)
        diagnostic = metadata.get("request_diagnostics") or {}
        if diagnostic.get("normalized_tool_history_count", 0) or diagnostic.get("normalized_tool_history"):
            add_event(stage, path, index, diagnostic, "history_normalization", key)
        return True

    for path, metadata in traces:
        stage = stage_for(path, root)
        selected_metadata[stage].append(metadata)
        events = read(path, warnings).get("events", [])
        if stage == 'harness-context':
            result = read(path.with_name('result.json'), warnings)
            view = metadata.get('semantic_obligation_view', metadata.get('semantic_obligations', {}))
            attempt_responses = {e.get('metadata', {}).get('response_id') or index: e.get('metadata', {})
                for index, e in enumerate(events) if e.get('kind') == 'model_response'}
            attempt_tokens = {key: sum(token_counts(e.get('usage', {}))[key] for e in attempt_responses.values())
                              for key in TOKEN_KEYS}
            context_attempts.append({'artifact': str(path.relative_to(root)),
                'agent_backend': safe(metadata.get('configuration', {}).get('agent_backend', {'name': 'native'})),
                'agent_backend_fingerprint': digest(metadata.get('configuration', {}).get('agent_backend', {'name': 'native'})),
                'dsh_loop_receipts': [safe(event.get('agent_backend')) for event in events
                    if event.get('kind') == 'dsh_backend_start'],
                'provider_request_events': sum(event.get('kind') in {'model_response', 'model_error'} for event in events),
                'requirement_id': metadata.get('requirement_id', result.get('requirement_id')),
                'group_requirement_ids': metadata.get('group_requirement_ids', []),
                'result_status': result.get('status'), 'open_questions': safe(result.get('open_questions', [])),
                'termination': metadata.get('termination'), 'execution_status': metadata.get('execution_status'),
                'model_calls': metadata.get('model_calls'), 'tool_calls': metadata.get('tool_calls'),
                'tokens': metadata.get('tokens', attempt_tokens), 'fact_predicates': sorted({f.get('predicate') for f in result.get('facts', []) if f.get('predicate')}),
                'schema_repair_attempted': metadata.get('schema_repair_attempted'),
                'schema_repair_success': metadata.get('schema_repair_success'),
                'extra_terminal_repair_attempts': metadata.get('extra_terminal_repair_attempts'),
                'extra_terminal_repair_success': metadata.get('extra_terminal_repair_success'),
                'terminal_correction_operations': safe(metadata.get('terminal_correction_operations', [])),
                'argument_graph_holes_at_attempt': safe(metadata.get('argument_graph_view', {}).get('holes', [])),
                'missing_proofs_at_attempt': safe(view.get('missing_evidence', [])),
                'blocked_proofs_at_attempt': safe(view.get('blocked', [])),
                'execution_errors': safe(metadata.get('execution_errors', []))})
        for index, event in enumerate(events):
            kind = event.get("kind")
            if stage == 'harness-context' and str(kind).startswith('dsh_'):
                # Runtime receipts diagnose execution; they are never provider
                # responses, proof tools, model calls or extra token usage.
                agent_backend_events.append({'artifact': str(path.relative_to(root)),
                    'event_index': index, 'kind': kind,
                    **({'agent_backend': safe(event['agent_backend']),
                        'agent_backend_fingerprint': digest(event['agent_backend'])}
                       if kind == 'dsh_backend_start' and 'agent_backend' in event else {}),
                    **({'session_event_type': event.get('event', {}).get('type')}
                       if kind == 'dsh_session_event' else {})})
            if kind == "model_response":
                # Persist only response metadata, never full messages/prompts.
                added = add_response(stage, path, index, event.get("metadata", {}))
                if added and event.get('phase') == 'terminal_repair':
                    stages[stage]['extra_terminal_request_attempts'] += 1
            elif kind == "model_error":
                budget = event.get("error_category") == "budget_exhausted" or event.get("error") == "budget_exhausted"
                category = "local_budget_stop" if budget else "failed_request"
                before = len(provider_events)
                add_event(stage, path, index, event, category)
                if len(provider_events) > before:
                    stages[stage]["local_budget_stops" if budget else "failed_requests"] += 1
                    if not budget and event.get('phase') == 'terminal_repair':
                        stages[stage]['extra_terminal_request_attempts'] += 1
                diagnostic = event.get("diagnostics", {})
                if diagnostic.get("normalized_tool_history_count", 0) or diagnostic.get("normalized_tool_history"):
                    add_event(stage, path, index, diagnostic, "history_normalization")
            elif kind == "budget_stop":
                # v4 records a pretransport guard without fabricating a failed
                # provider request. Retain it as a local budget observation.
                before = len(provider_events)
                add_event(stage, path, index, event, "local_budget_stop")
                if len(provider_events) > before:
                    stages[stage]["local_budget_stops"] += 1
            elif kind == "tool_call":
                # A framework seed has the same ID in distinct requirements;
                # execution identity for those events comes from event content.
                call_id = event.get("tool_call_id")
                key = (stage, call_id) if call_id and not call_id.startswith("framework_") else (stage, digest(event))
                if key in seen_tools:
                    continue
                seen_tools.add(key)
                stages[stage]["trace_tool_events"] += 1
                stages[stage]["trace_evidence_reuses"] += int(bool(event.get("evidence_reuse")))
                stages[stage]["trace_framework_tool_events"] += int(bool(event.get("framework_bootstrap") or event.get("round") == 0))
                stages[stage]["trace_tool_executions"] += int(
                    not event.get("evidence_reuse") and event.get("tool_executed") is not False)
            elif kind == 'extra_terminal_repair':
                before = len(provider_events)
                add_event(stage, path, index, event, 'extra_terminal_repair')
                if len(provider_events) > before:
                    stages[stage]['extra_terminal_repair_operations'] += 1
            elif kind in {"provider_recovery", "semantic_recovery", "protocol_recovery", "schema_error", "execution_error", "history_normalization", "tool_history_normalization"}:
                before = len(provider_events)
                add_event(stage, path, index, event, {"protocol_recovery": "protocol_recovery", "schema_error": "schema_error",
                          "provider_recovery": "provider_recovery", "semantic_recovery": "semantic_recovery",
                          "execution_error": "execution_error"}.get(kind, "history_normalization"))
                if len(provider_events) > before and kind in {"provider_recovery", "semantic_recovery", "protocol_recovery"}:
                    stages[stage][kind.replace("recovery", "recoveries")] += 1

        # Protocol recovery can record a final declined proposal after its
        # one ordinary correction was already spent. Preserve every event,
        # but use the persisted accepted counter for executed recoveries.
        for kind in ('provider_recovery', 'semantic_recovery', 'protocol_recovery'):
            key = kind.replace('recovery', 'recoveries')
            accepted = metadata.get(key)
            if type(accepted) is int:
                event_count = sum(e.get('kind') == kind for e in events)
                stages[stage][key] += accepted - event_count

    # Code translation uses response.json instead of agent traces.
    generations = []
    for path in sorted(root.glob("context_generations/*/*/*/metadata.json")):
        metadata = read(path, warnings)
        if not any(k in metadata for k in ("code_origin", "model_calls", "status")):
            continue
        selected_metadata["context-generate"].append(metadata)
        stages['context-generate']['code_repairs'] += metadata.get('code_repairs', 0)
        response_paths = [path.with_name('response.json'), *sorted(path.parent.glob('code_attempts/attempt_*/response.json'))]
        responses_observed = 0
        for response_path in response_paths:
            response = read(response_path, warnings)
            if not response:
                continue
            responses_observed += 1
            add_response("context-generate", response_path, 0,
                         {"response_id": response.get("response_id"), "served_model": response.get("model"),
                          "usage": response.get("usage"), "finish_reason": response.get("finish_reason"),
                          "request_diagnostics": response.get("request_diagnostics", response.get("metadata", {}).get("request_diagnostics", {}))})
        attempts = metadata.get('model_attempts')
        if isinstance(attempts, list):
            missing = [attempt for attempt in attempts if attempt.get('model_call') is True
                       and not read(path.parent / ('response.json' if attempt.get('attempt') == 1 else
                           'code_attempts/attempt_%04d/response.json' % attempt.get('attempt', 0)), warnings)]
            unaccounted = max(metadata.get('model_calls', 0) - responses_observed - len(missing), 0)
            missing += [{'error': metadata.get('error'), 'attempts': unaccounted}] if unaccounted else []
        else:
            missing = [{'error': metadata.get('error'), 'attempts': max(metadata.get('model_calls', 0) - responses_observed, 0)}]
        for attempt in missing:
            error = attempt.get("error")
            calls = attempt.get('attempts', 1)
            if not calls:
                continue
            # Old codegen transport stores an error string without response
            # diagnostics. Never invent a token count or provider response.
            explicit_http = re.search(r"(?:Error code:|HTTP(?: status)?|status_code[=:])\s*(4\d\d|5\d\d)", str(error), re.I)
            category = attempt.get('error_category')
            if explicit_http or category in {'timeout', 'provider_error'}:
                add_event("context-generate", path, 0, {"kind": "generation_error", "error": error,
                          'attempt': attempt.get('attempt'), 'error_category': category,
                          **({'http_status': int(explicit_http[1])} if explicit_http else {}),
                          "diagnostics_missing": True}, "failed_request", 'code_attempt:' + str(attempt.get('attempt', 'legacy')))
                stages["context-generate"]["failed_requests"] += calls
            else:
                stages["context-generate"]["unrecorded_codegen_calls"] += calls
                add_event("context-generate", path, 0, {"kind": "generation_error", "error": error,
                          'attempt': attempt.get('attempt'),
                          "unrecorded_calls": calls, "diagnostics_missing": True}, "unrecorded_codegen_call",
                          'code_attempt:' + str(attempt.get('attempt', 'legacy')))
        build = read(path.parent / "build/build.json", warnings)
        runtime = read(path.parent / "build/runtime.json", warnings)
        validation = read(path.with_name("code_validation.json"), warnings)
        generations.append({"artifact": str(path.relative_to(root)), "status": metadata.get("status"),
                            "code_origin": metadata.get("code_origin"), "model_calls": metadata.get("model_calls"),
                            'code_repairs': metadata.get('code_repairs', 0), 'model_attempts': safe(attempts or []),
                            "error": safe(metadata.get("error")), "code_validation": safe(validation),
                            "build_status": build.get("status"), "build_success": build.get("success"),
                            "build_return_codes": [c.get("return_code") for c in build.get("commands", [])],
                            "build_sanitizers": build.get("sanitizers", []),
                            "runtime_status": runtime.get("status"), "runtime_success": runtime_success(runtime),
                            "runtime_cases": len(runtime.get("cases", runtime.get("runs", []))),
                            "runtime_return_codes": [c.get("return_code") for c in runtime.get("cases", runtime.get("runs", []))],
                            "runtime_sanitizer_policy": runtime.get("sanitizer_policy"),
                            "runtime_details": safe(runtime)})

    _, catalog = first_json(root, "candidate_discovery/validated_candidates.json", warnings)
    validations = [c for c in catalog.get("candidates", []) if c.get("validation") or c.get("run_directory")]
    validation_rows = [{"function_id": c.get("function_id"), "status": c.get("status"),
                        "run_status": (c.get("validation") or {}).get("run_status"),
                        "budget": (c.get("validation") or {}).get("budget", {})} for c in validations]
    _, sliced = first_json(root, "semantic_slices/*/slice.json", warnings)
    _, sliced_meta = first_json(root, "semantic_slices/*/metadata.json", warnings)
    _, ft = first_json(root, "minimal_fts/*/minimal_ft.json", warnings)
    contexts = []
    for directory in sorted((root / "harness_contexts").glob("*")):
        if not directory.is_dir():
            continue
        metadata = read(directory / "metadata.json", warnings)
        completeness = read(directory / "completeness.json", warnings)
        graph = read(directory / "semantic_obligation_graph.json", warnings)
        closure = read(directory / "api_closure.json", warnings)
        context = read(directory / "harness_context.json", warnings)
        if not any((metadata, completeness, graph, context)):
            continue
        nodes = {n.get("obligation_id"): n for n in graph.get("nodes", [])}
        def node_details(ids):
            return [{"obligation_id": key, **{k: nodes.get(key, {}).get(k) for k in
                     ("kind", "predicate", "subject_function_id", "subject_parameter", "subject_field", "proof_status", "diagnostics", "blocking_obligations")}} for key in ids]
        hard = completeness.get("hard_missing")
        contexts.append({"artifact": str(directory.relative_to(root)), "ft_id": directory.name,
                         "metadata_observed": bool(metadata),
                         "configuration_observed": isinstance(metadata.get("configuration"), dict)
                            and bool(metadata["configuration"]),
                         "published_bundle_observed": bool(metadata and completeness and context),
                         "metrics_observed": isinstance(metadata.get("metrics"), dict)
                            and type(metadata["metrics"].get("model_calls")) is int
                            and type(metadata["metrics"].get("tool_calls")) is int,
                         "termination": metadata.get("termination"), "frozen": context.get("frozen"),
                         "generation_allowed": completeness.get("generation_allowed"),
                         "hard_gap_count": len(hard) if isinstance(hard, list) else None,
                         "hard_gaps": safe(hard), "hard_gap_codes": dict(Counter(h.get("code", "unspecified") for h in hard or [])),
                         "soft_unknowns": safe(completeness.get("soft_unknowns", [])),
                         "execution_failed_requirements": completeness.get("execution_failed_requirements", []),
                         "resource_scope_reconciliations": safe([{
                             "resource_id": r.get("resource_id"), "effective_reuse": r.get("reuse"),
                             "observed_reuse": r.get("observed_reuse"), "proof": r["invocation_scope_proof"]}
                             for r in context.get("resource_contract", {}).get("resources", [])
                             if r.get("invocation_scope_proof")]),
                         "source_callback_resource_reference_count": len(context.get("callback_resource_references", [])),
                         "source_callback_resource_references": safe([{key: proof.get(key) for key in
                             ("version", "proof_id", "function_id", "parameter", "producer_api", "cleanup_api", "resource_id")}
                             for proof in context.get("callback_resource_references", [])]),
                         "metrics": metadata.get("metrics", {}),
                         "semantic_roots": {"mandatory": graph.get("mandatory_roots", []), "closed": graph.get("closed_roots", []),
                                            "mandatory_count": len(graph.get("mandatory_roots", [])), "closed_count": len(graph.get("closed_roots", [])),
                                            "mandatory_details": node_details(graph.get("mandatory_roots", [])),
                                            "frontier": graph.get("frontier", []), "frontier_details": node_details(graph.get("frontier", [])),
                                            "node_count": len(nodes)},
                         "required_support_apis": function_ids(closure.get("required_support_apis", [])),
                         "optional_support_apis": function_ids(closure.get("optional_support_apis", [])),
                         "unresolved_api_dependencies": safe(closure.get("unresolved_api_dependencies", []))})

    plans = []
    for path in sorted(root.glob("context_generations/*/*/harness_plan.json")):
        plan = read(path, warnings)
        normalized = semantic_plan(plan)
        plans.append({"artifact": str(path.relative_to(root)), "plan_id": plan.get("plan_id"),
                      "frozen": plan.get("frozen"), "schema_version": plan.get("schema_version"),
                      "policy_version": plan.get("policy_version"), "core_apis": plan.get("core_apis", []),
                      "signature_version": PLAN_SIGNATURE_VERSION,
                      "required_support_apis": plan.get("required_support_apis", []),
                      "semantic_signature": digest(normalized), "semantic_projection": normalized,
                      "binding_signature": digest(binding_plan(normalized)), "binding_projection": binding_plan(normalized)})

    budgets = {"candidate-validate": [r["budget"] for r in validation_rows], "semantic-slice": [sliced.get("budget", {})],
               "harness-context": [c["metrics"] for c in contexts],
               "context-generate": [{"model_calls": m.get("model_calls", 0), "tool_calls": 0, "source_chars": 0}
                                    for m in selected_metadata["context-generate"]]}
    for stage, items in budgets.items():
        for key in ("model_calls", "tool_calls", "source_chars"):
            counters = [i[key] for i in items if type(i.get(key)) is int]
            stages[stage][key] = sum(counters) if counters else None
        if stages[stage]["model_calls"] is None:
            counters = [m["model_calls"] for m in selected_metadata[stage] if type(m.get("model_calls")) is int]
            stages[stage]["model_calls"] = sum(counters) if counters else stages[stage]["provider_responses"] + stages[stage]["failed_requests"]
        if stages[stage]["tool_calls"] is None and stages[stage]["trace_tool_events"]:
            stages[stage]["tool_calls"] = stages[stage]["trace_tool_executions"]
        stages[stage]["provider_request_attempts"] = stages[stage]["provider_responses"] + stages[stage]["failed_requests"]
        stages[stage]["exit_code"] = trial.get("stage_exits", {}).get(stage)
        stages[stage]["elapsed_seconds"] = trial.get("stage_seconds", {}).get(stage)
        configs = []
        if stage == "harness-context":
            configs = [read(root / c["artifact"] / "metadata.json", warnings).get("configuration", {}) for c in contexts]
            # Compare both publications and paid attempts. A root alias cannot
            # hide an attempt executed with a different backend or budget.
            configs += [m.get('configuration', {}) for m in selected_metadata[stage]]
        else:
            configs = [m.get("configuration", {}) for m in selected_metadata[stage]]
        stages[stage]["configurations"] = list({canonical({"budget": config.get("budget"),
                "max_terminal_repairs": config.get("max_terminal_repairs"),
                **({'agent_backend': config['agent_backend']} if 'agent_backend' in config else {}),
                **({'max_code_repairs': config['max_code_repairs']} if 'max_code_repairs' in config else {}),
                **{key: config[key] for key in ('max_protocol_recoveries', 'max_provider_recoveries',
                                               'max_semantic_recoveries', 'terminal_repair_policy_version',
                                               'terminal_repair_allowed_categories', 'extra_terminal_repair_last_round_only') if key in config},
                "model": {key: config.get("model", {}).get(key) for key in
                          ("provider", "model", "base_url", "thinking", "max_tokens", "timeout", "temperature")
                          if key in config.get("model", {})}}):
                {"budget": config.get("budget"), "max_terminal_repairs": config.get("max_terminal_repairs"),
                 **({'agent_backend': config['agent_backend']} if 'agent_backend' in config else {}),
                 **({'max_code_repairs': config['max_code_repairs']} if 'max_code_repairs' in config else {}),
                 **{key: config[key] for key in ('max_protocol_recoveries', 'max_provider_recoveries',
                                                'max_semantic_recoveries', 'terminal_repair_policy_version',
                                                'terminal_repair_allowed_categories', 'extra_terminal_repair_last_round_only') if key in config},
                 "model": {key: config.get("model", {}).get(key) for key in
                          ("provider", "model", "base_url", "thinking", "max_tokens", "timeout", "temperature")
                          if key in config.get("model", {})}} for config in configs if config}.values())

    total = {key: sum(s.get(key, 0) or 0 for s in stages.values()) for key in
             ("model_calls", "tool_calls", "source_chars", "provider_responses", "failed_requests", "local_budget_stops", "provider_request_attempts", "unrecorded_codegen_calls",
              "provider_recoveries", "semantic_recoveries", "protocol_recoveries", 'code_repairs',
              'extra_terminal_repair_operations', 'extra_terminal_request_attempts')}
    total['responses_without_complete_usage'] = sum(s['responses_without_complete_usage'] for s in stages.values())
    total['source_chars_unknown_stages'] = [stage for stage, values in stages.items()
                                          if values['source_chars'] is None and values['model_calls']]
    total["tokens"] = {key: sum(s["tokens"][key] for s in stages.values()) for key in TOKEN_KEYS}
    total["provider_event_counts"] = dict(Counter(e["category"] for e in provider_events))
    total["protocol_recovery_reasons"] = dict(Counter(e["event"].get("reason", "unspecified") for e in provider_events if e["category"] == "protocol_recovery"))
    total["provider_recovery_categories"] = dict(Counter(e["event"].get("error_category", "unspecified") for e in provider_events if e["category"] == "provider_recovery"))
    total["semantic_recovery_reasons"] = dict(Counter(e["event"].get("reason", "unspecified") for e in provider_events if e["category"] == "semantic_recovery"))
    total['extra_terminal_repair_reasons'] = dict(Counter(e['event'].get('reason', 'unspecified') for e in provider_events if e['category'] == 'extra_terminal_repair'))
    timings = []
    for event in provider_events:
        if event['category'] not in {'provider_response', 'failed_request'}:
            continue
        raw = event['event']
        diagnostic = (raw.get('metadata', {}).get('request_diagnostics', {})
                      if event['category'] == 'provider_response' else raw.get('diagnostics', {}))
        duration = diagnostic.get('request_elapsed_seconds')
        if type(duration) in (int, float) and math.isfinite(duration) and duration >= 0:
            timings.append({'stage': event['stage'], 'category': event['category'],
                            'elapsed_seconds': duration, 'timeout_seconds': diagnostic.get('request_timeout_seconds')})
    total['provider_request_timing'] = {
        'observed': len(timings), 'unknown_requests': total['provider_responses'] + total['failed_requests'] - len(timings),
        'elapsed_seconds': numeric_stats([t['elapsed_seconds'] for t in timings]),
        'responses_elapsed_seconds': numeric_stats([t['elapsed_seconds'] for t in timings if t['category'] == 'provider_response']),
        'failures_elapsed_seconds': numeric_stats([t['elapsed_seconds'] for t in timings if t['category'] == 'failed_request']),
        'configured_timeouts': sorted({t['timeout_seconds'] for t in timings if type(t['timeout_seconds']) in (int, float)})}
    total["failed_request_categories"] = dict(Counter(e["event"].get("error_category", "http_" + str(e["event"].get("http_status"))
                       if e["event"].get("http_status") else "unspecified") for e in provider_events if e["category"] == "failed_request"))
    total["served_models"] = sorted({m.get("served_model") for _, m in responses.values() if m.get("served_model")})
    context = contexts[0] if len(contexts) == 1 else {}
    build = trial.get("build", {})
    runtime = trial.get("runtime", {})
    if not build and generations:
        build = {"status": generations[-1]["build_status"], "success": generations[-1]["build_success"]}
    if not runtime and generations:
        runtime = {"status": generations[-1]["runtime_status"], "success": generations[-1]["runtime_success"]}
    recorded_tokens = trial.get("response_tokens")
    reconciliation = {"recorded_response_tokens": recorded_tokens, "collected_response_tokens": total["tokens"],
                      "tokens_match_recorded": token_counts(recorded_tokens) == total["tokens"] if recorded_tokens else None,
                      "recorded_provider_responses": trial.get("successful_provider_responses"),
                      "provider_responses_match_recorded": trial.get("successful_provider_responses") == total["provider_responses"]
                          if "successful_provider_responses" in trial else None}
    if reconciliation["tokens_match_recorded"] is False or reconciliation["provider_responses_match_recorded"] is False:
        warnings.append("Collected response totals disagree with trial.json; inspect reconciliation before reporting cost.")
    fallback_status = "partial" if root.is_dir() else "not_started"
    partial = trial.get("status", fallback_status) in {"partial", "not_started", "running", "supervisor_timeout", "worker_process_failed", "worker_missing_trial", "worker_interrupted", "runner_error"}
    # A Context interrupted after issuing source/model calls has reached that
    # stage even though its final completeness publication does not exist.
    # Keep stage attempts and final Gate observations as separate denominators.
    exits = trial.get('stage_exits', {})
    stopped = trial.get('status') in INTERRUPTED_TRIAL_STATUSES
    context_gate_evaluated = bool(contexts) and all(type(c.get('generation_allowed')) is bool for c in contexts)
    context_complete = context_gate_evaluated and all(c['generation_allowed'] and c['hard_gap_count'] == 0 for c in contexts)
    has_dsh_receipt = any(attempt['dsh_loop_receipts'] for attempt in context_attempts)
    has_native_attempt = any(attempt['provider_request_events'] and attempt['agent_backend'].get('name') == 'native'
        and not attempt['dsh_loop_receipts'] for attempt in context_attempts)
    context_backend_execution = ('mixed_backend_observations' if has_dsh_receipt and has_native_attempt
        else 'observed_dsh' if has_dsh_receipt
        else 'observed_native' if has_native_attempt
        else 'not_entered' if context_gate_evaluated and all(item['metrics_observed'] for item in contexts)
            and stages['harness-context']['model_calls'] == 0
        else 'unknown' if contexts or context_attempts or 'harness-context' in exits or 'harness-context' in entered
        else 'not_started' if trial.get('status', fallback_status) == 'not_started' else 'skipped_upstream')
    generation_entered = 'context-generate' in exits or 'context-generate' in entered or bool(generations or plans) or any(root.glob('context_generations/*/blocked.json'))
    plan_attempted = bool(plans) or bool(context_complete and generation_entered)
    plan_terminal = bool(plans) or bool(context_complete and any(root.glob('context_generations/*/blocked.json')))
    build_terminal = bool(build.get('status') or type(build.get('success')) is bool)
    build_attempted = build_terminal or any(root.glob('context_generations/*/*/*/build/smoke_driver.c'))
    runtime_terminal = runtime.get('status') != 'skipped' and bool(
        runtime.get('cases') or runtime.get('status') in {'passed', 'failed'} or type(runtime.get('success')) is bool)
    runtime_attempted = runtime_terminal or any(
        root.glob('context_generations/*/*/*/build/input_*.bin'))
    observation_inputs = {
        'validation': (bool(validation_rows or selected_metadata['candidate-validate'] or 'candidate-validate' in exits or 'candidate-validate' in entered),
                       bool(validation_rows), 'candidate-validate' in exits),
        'slice': (bool(sliced or selected_metadata['semantic-slice'] or 'semantic-slice' in exits or 'semantic-slice' in entered),
                  bool(sliced), 'semantic-slice' in exits),
        'context': (bool(contexts or context_attempts or selected_metadata['harness-context'] or 'harness-context' in exits or 'harness-context' in entered),
                    context_gate_evaluated, 'harness-context' in exits),
        'plan': (plan_attempted, plan_terminal, plan_terminal),
        'build': (build_attempted, build_terminal, build_terminal),
        'runtime': (runtime_attempted, runtime_terminal, runtime_terminal),
    }
    stage_observations = {name: {'attempted': attempted, 'terminal_observed': terminal,
                                'completed': completed or terminal,
                                'interrupted': bool(attempted and not (completed or terminal) and stopped)}
                          for name, (attempted, terminal, completed) in observation_inputs.items()}
    stage_observations['context']['complete_gate_evaluated'] = context_gate_evaluated
    for name, stage in [('validation', 'candidate-validate'), ('slice', 'semantic-slice'),
                        ('context', 'harness-context')]:
        stages[stage].update(stage_observations[name])
    total["cost_is_lower_bound"] = partial or bool(total["failed_requests"] or total["unrecorded_codegen_calls"]
                                                  or total['responses_without_complete_usage'])
    return {"schema_version": 1, "artifact_root": str(root), "case": trial.get("case", root.name),
            "anchor": trial.get("anchor", ft.get("anchor_function_id", sliced.get("anchor_function_id"))),
            "dataset_role": trial.get("dataset_role"), "status": trial.get("status", fallback_status),
            "trial_id": trial.get("trial_id"), "phase": trial.get("phase"), "repetition": trial.get("repetition"),
            "production_fingerprint": trial.get("production_fingerprint"), "fresh": trial.get("fresh"),
            "context_agent_backend": safe(trial.get("context_agent_backend", {"name": "native"})),
            "context_backend_execution_state": context_backend_execution,
            **({"dependency_preflight": safe(trial["dependency_preflight"])}
                if isinstance(trial.get("dependency_preflight"), dict) else {}),
            "resume": trial.get("resume"), "failed_retry": trial.get("failed_retry"),
            "worker_exit": supervisor.get("worker_exit"), "native_status": trial.get("native_status"),
            "integrity": trial.get("integrity"), "observations_are_partial": partial,
            "stage_exits": trial.get("stage_exits", {}), "stage_entry_log": entries, "elapsed_seconds": trial.get("elapsed_seconds"),
            "started_utc": trial.get("started_utc"), "finished_utc": trial.get("finished_utc"),
            "validation": validation_rows, "validation_status": validation_rows[0]["status"] if len(validation_rows) == 1 else None,
            "slice_status": sliced.get("run_status", "not_observed"), "slice_core": function_ids(sliced.get("core_functions", [])),
            "slice_support": function_ids(sliced.get("support_functions", [])),
            "slice_unresolved": safe(sliced.get("unresolved_frontier", [])), "slice_unresolved_count": len(sliced.get("unresolved_frontier", [])),
            "slice_metadata": {k: sliced_meta.get(k) for k in ("termination", "canonical_is_fallback", "validation_errors", "protocol_recoveries", "schema_repair_attempted", "schema_repair_success", 'extra_terminal_repair_attempts', 'extra_terminal_repair_success', 'terminal_correction_operations')},
            "ft_status": ft.get("build_status", "not_observed"), "ft_core": function_ids(ft.get("core_functions", [])),
            "contexts": contexts, "context_attempts": context_attempts, "context_status": context.get("termination", "not_observed"),
            "context_complete": context_complete,
            "hard_gap_count": sum(c["hard_gap_count"] for c in contexts) if contexts and all(c["hard_gap_count"] is not None for c in contexts) else None,
            "hard_gap_codes": dict(sum((Counter(c["hard_gap_codes"]) for c in contexts), Counter())),
            "required_support_apis": sorted({api for c in contexts for api in c["required_support_apis"]}),
            "plans": plans, "plan_frozen": bool(plans) and all(p["frozen"] for p in plans),
            "plan_semantic_signatures": sorted({p["semantic_signature"] for p in plans}),
            "plan_binding_signatures": sorted({p["binding_signature"] for p in plans}),
            "generations": generations, "generation_status": generations[-1]["status"] if generations else "not_observed",
            "generation_blocks": safe(trial.get("generation_blocks", [])),
            "build_status": build.get("status", "not_observed"), "compile_success": build.get("success", trial.get("compile_success")),
            "runtime_status": runtime.get("status", "not_observed"), "runtime_success": runtime_success(runtime) if runtime else trial.get("runtime_success"),
            "stages": stages, "stage_observations": stage_observations, "totals": total, "provider_events": provider_events, "trace_deduplication": trace_audit,
            "agent_backend_events": agent_backend_events,
            "agent_backend_event_counts": dict(Counter(event['kind'] for event in agent_backend_events)),
            "reconciliation": reconciliation, "warnings": warnings,
            "accounting_notes": ["Model calls are persisted stage budget counters; actual provider request attempts exclude local budget stops.",
                "Tokens count unique successful response IDs; failed requests can consume unreported tokens.",
                "Context tool/source counters use aggregate persisted metrics; trace event counts also include cached framework evidence.",
                "Latest trace aliases and non-owner Context group replicas are excluded; unique response IDs deduplicate residual copies.",
                "Missing observations remain unknown; a stage that never ran has no demonstrated success."]}


def registration_rows(registration: dict, experiment_root: Path) -> list[dict]:
    rows = registration.get("trial_dirs") or registration.get("schedule") or registration.get("trials") or []
    result = []
    for index, raw in enumerate(rows):
        row = dict(raw) if isinstance(raw, dict) else {"artifacts": raw}
        path = next((row[k] for k in ("artifacts", "artifact_root", "trial_dir", "directory") if row.get(k)), None)
        if path is None:
            raise ValueError(f"Registration row {index} has no artifact path")
        path = Path(path)
        if not path.is_absolute():
            path = experiment_root / path
        row["artifacts"] = str(path.resolve())
        result.append(row)
    return result


def numeric_stats(values: list[int | float]) -> dict:
    if not values:
        return {"observed": 0}
    return {"observed": len(values), "min": min(values), "median": statistics.median(values), "max": max(values), "total": sum(values)}


def cohort_summary(rows: list[dict]) -> dict:
    counts = lambda key: dict(Counter(str(r.get(key)) for r in rows))
    signatures = Counter(tuple(r.get("plan_semantic_signatures", [])) for r in rows if r.get("plans"))
    bindings = Counter(tuple(r.get("plan_binding_signatures", [])) for r in rows if r.get("plans"))
    cores = Counter(tuple(r.get("ft_core", [])) for r in rows if r.get("ft_status") != "not_observed")
    end_to_end = sum(bool(r.get("validation_status") == "accepted" and r.get("slice_status") in {"completed", "completed_with_unresolved"}
                     and r.get("context_complete") and r.get("plan_frozen") and r.get("compile_success") and r.get("runtime_success")) for r in rows)
    conditionals = {"validation": lambda r: r.get("validation_status") == "accepted",
                    "slice": lambda r: r.get("slice_status") in {"completed", "completed_with_unresolved"},
                    "context": lambda r: r.get("context_complete"),
                    "plan": lambda r: r.get("plan_frozen"),
                    "build": lambda r: r.get("compile_success"),
                    "runtime": lambda r: r.get("runtime_success")}
    return {"trials": len(rows), "completed_trials": sum(r["status"] not in UNFINISHED_TRIAL_STATUSES for r in rows),
            "started_trials": sum(r['status'] != 'not_started' for r in rows),
            "not_started_trials": sum(r['status'] == 'not_started' for r in rows),
            "interrupted_trials": sum(r['status'] in INTERRUPTED_TRIAL_STATUSES for r in rows),
            "in_progress_trials": sum(r['status'] in {'running', 'partial'} for r in rows),
            "unfinished_worker_failures": sum(r['status'] in {'worker_process_failed', 'worker_missing_trial'} for r in rows),
            "status_counts": counts("status"), "end_to_end_successes": end_to_end,
            "all_end_to_end_passed": bool(rows) and end_to_end == len(rows),
            "slice_status_counts": counts("slice_status"), "context_status_counts": counts("context_status"),
            "context_backend_execution_states": counts("context_backend_execution_state"),
            "generation_status_counts": counts("generation_status"), "build_status_counts": counts("build_status"),
            "runtime_status_counts": counts("runtime_status"), "hard_gaps": numeric_stats([r["hard_gap_count"] for r in rows if r["hard_gap_count"] is not None]),
            "ft_core_variants": [{"core": list(k), "trials": v} for k, v in cores.items()],
            "plan_semantic_variants": [{"signatures": list(k), "trials": v} for k, v in signatures.items()],
            "plan_binding_variants": [{"signatures": list(k), "trials": v} for k, v in bindings.items()],
            "conditional_stage_success": {name: {
                    "reached": sum(r['stage_observations'][name]['attempted'] for r in rows),
                    "terminal_observed": sum(r['stage_observations'][name]['terminal_observed'] for r in rows),
                    "completed": sum(r['stage_observations'][name]['completed'] for r in rows),
                    "interrupted": sum(r['stage_observations'][name]['interrupted'] for r in rows),
                    **({'complete_gate_evaluated': sum(r['stage_observations']['context']['complete_gate_evaluated'] for r in rows)}
                       if name == 'context' else {}),
                    "passed": sum(bool(passed(r)) for r in rows)} for name, passed in conditionals.items()},
            "provider_event_counts": dict(sum((Counter(r["totals"]["provider_event_counts"]) for r in rows), Counter())),
            "agent_backend_event_counts": dict(sum((Counter(r.get("agent_backend_event_counts", {})) for r in rows), Counter())),
            "cost_is_lower_bound": any(r['totals']['cost_is_lower_bound'] for r in rows),
            "responses_without_complete_usage": sum(r['totals']['responses_without_complete_usage'] for r in rows),
            "unrecorded_codegen_calls": sum(r['totals']['unrecorded_codegen_calls'] for r in rows),
            "protocol_recovery_reasons": dict(sum((Counter(r["totals"]["protocol_recovery_reasons"]) for r in rows), Counter())),
            "provider_recovery_categories": dict(sum((Counter(r["totals"]["provider_recovery_categories"]) for r in rows), Counter())),
            "semantic_recovery_reasons": dict(sum((Counter(r["totals"]["semantic_recovery_reasons"]) for r in rows), Counter())),
            'extra_terminal_repair_reasons': dict(sum((Counter(r['totals']['extra_terminal_repair_reasons']) for r in rows), Counter())),
            "hard_gap_codes": dict(sum((Counter(r["hard_gap_codes"]) for r in rows), Counter())),
            "stage_costs": {stage: {"calls": {key: numeric_stats([r["stages"][stage][key] for r in rows if type(r["stages"][stage].get(key)) is int])
                                              for key in ("model_calls", "tool_calls", "source_chars", "provider_responses", "failed_requests", "local_budget_stops", "provider_recoveries", "semantic_recoveries", "protocol_recoveries", 'extra_terminal_repair_operations', 'extra_terminal_request_attempts')},
                                   "tokens": {key: numeric_stats([r["stages"][stage]["tokens"][key] for r in rows]) for key in TOKEN_KEYS}}
                            for stage in STAGES},
            "totals": {key: numeric_stats([r["totals"][key] for r in rows]) for key in
                       ("model_calls", "tool_calls", "source_chars", "provider_responses", "failed_requests", "local_budget_stops", "provider_recoveries", "semantic_recoveries", "protocol_recoveries", 'code_repairs', 'extra_terminal_repair_operations', 'extra_terminal_request_attempts')},
            "tokens": {key: numeric_stats([r["totals"]["tokens"][key] for r in rows]) for key in TOKEN_KEYS}}


def render_report(metrics: dict) -> str:
    backend = metrics.get('context_agent_backend', {'name': 'native'})
    lines = ["# Frozen fresh-run stability observations", "", f"Fingerprint: `{metrics.get('fingerprint', 'unrecorded')}`.", "",
             f"Registered Context backend: `{backend.get('name', 'unrecorded')}`; descriptor fingerprint: `{metrics.get('context_agent_backend_fingerprint', digest(backend))}`.", "",
             "These are known-development repeats. They measure this frozen implementation and target set; they do not establish blind generalization or Candidate recall.", "",
             "| Cohort / case | Trials | End-to-end passed | FT CORE variants | Plan semantic / binding variants | Hard gap range |", "| --- | ---: | ---: | ---: | ---: | --- |"]
    for key, summary in metrics["cohorts"].items():
        gaps = summary["hard_gaps"]
        span = f"{gaps['min']}–{gaps['max']}" if gaps["observed"] else "unknown"
        lines.append(f"| {key} | {summary['trials']} | {summary['end_to_end_successes']} | {len(summary['ft_core_variants'])} | {len(summary['plan_semantic_variants'])} / {len(summary['plan_binding_variants'])} | {span} |")
    lines.extend(["", "| Trial | Backend execution | Slice | Context | Hard gaps | Plan | Build / runtime | Model / tool calls | Tokens | Failed requests / local stops |", "| --- | --- | --- | --- | ---: | --- | --- | ---: | ---: | ---: |"])
    for row in metrics["trials"]:
        t = row["totals"]
        name = row.get("trial_id", Path(row["artifact_root"]).parent.name)
        lines.append(f"| {name} | {row.get('context_backend_execution_state', 'unknown')} | {row['slice_status']} | {row['context_status']} | {row['hard_gap_count']} | {row['plan_frozen']} | {row['build_status']} / {row['runtime_status']} | {t['model_calls']} / {t['tool_calls']} | {t['tokens']['total_tokens']} | {t['failed_requests']} / {t['local_budget_stops']} |")
    lines.extend(["", "Model calls are persisted budget counters. Actual provider attempts exclude local budget exhaustion; failed requests may have unreported usage. Tokens sum unique successful response IDs. Context tool calls and source characters use aggregate metadata because framework evidence reuse is also present in replicated traces.", "",
                  "Plan semantic signatures retain declared call contracts as well as execution recipes. Binding signatures compare concrete canonical recipes, producer/consumer links, call order, and cleanup. Both ignore opaque IDs, proof evidence, and digests. Different redundant call annotations can change the semantic signature while bindings remain equal. A stable blocked result is a repeatable gap, not a successful harness.", ""])
    for key, summary in metrics["cohorts"].items():
        conditional = "; ".join(f"{stage} {observed['passed']}/{observed['reached']} attempted"
                    + (f" ({observed['complete_gate_evaluated']} Gate evaluations)" if stage == 'context' else '')
                    + (f" ({observed['interrupted']} interrupted)" if observed['interrupted'] else '')
                    for stage, observed in summary["conditional_stage_success"].items())
        lines.append(f"- `{key}` stage success among reached trials: {conditional}. Provider recovery categories: `{canonical(summary['provider_recovery_categories'])}`. Protocol recovery reasons: `{canonical(summary['protocol_recovery_reasons'])}`. Semantic recovery reasons: `{canonical(summary['semantic_recovery_reasons'])}`. Extra terminal correction operations: `{canonical(summary['extra_terminal_repair_reasons'])}`; request attempts are recorded separately from local budget stops.")
    lines.append("")
    for row in metrics["trials"]:
        if row["hard_gap_codes"] or row["totals"]["failed_requests"] or row["warnings"] or row["slice_metadata"].get("validation_errors"):
            lines.append(f"- `{row.get('trial_id', row['artifact_root'])}`: hard gaps {canonical(row['hard_gap_codes'])}; actual failed requests {row['totals']['failed_requests']}; warnings {canonical(row['warnings'])}.")
            if row["slice_metadata"].get("validation_errors"):
                lines.append(f"  Slice terminal validation: `{canonical(safe(row['slice_metadata']['validation_errors']))}`.")
    return "\n".join(lines) + "\n"


def configuration_audit(row: dict, registration: dict) -> dict:
    expected_provider = registration.get("provider", registration.get("model", {}))
    checks = []
    for stage, stage_row in row["stages"].items():
        expected_budget = registration.get("context_budget") if stage == "harness-context" else (
            registration.get("validation_slice_budget") if stage in {"candidate-validate", "semantic-slice"} else None)
        for config in stage_row["configurations"]:
            matches = {}
            if stage == "harness-context":
                expected_backend = registration.get("context_agent_backend", {"name": "native"})
                observed_backend = config.get("agent_backend", {"name": "native"})
                matches["agent_backend_matches_registration"] = observed_backend == expected_backend
                if "context_agent_backend_fingerprint" in registration:
                    matches["agent_backend_fingerprint_matches_registration"] = digest(observed_backend) == registration["context_agent_backend_fingerprint"]
            recovery_stage = {'candidate-validate': 'candidate', 'semantic-slice': 'slice',
                              'harness-context': 'context'}.get(stage)
            for key, value in registration.get('agent_recovery_limits', {}).get(recovery_stage, {}).items():
                matches[key + '_matches_registration'] = config.get(key) == value
            for key, value in registration.get('agent_terminal_policies', {}).get(recovery_stage, {}).items():
                matches[key + '_matches_registration'] = config.get(key) == value
            if expected_budget is not None:
                matches["budget_matches_registration"] = config.get("budget") == expected_budget
            model = config.get("model", {})
            for key in ("provider", "model", "base_url", "thinking"):
                if key in expected_provider:
                    matches[key + "_matches_registration"] = model.get(key) == expected_provider[key]
            if stage == "context-generate":
                matches['max_code_repairs_matches_registration'] = config.get('max_code_repairs', 0) == registration.get('max_code_repairs', 0)
                matches["max_tokens_matches_registration"] = model.get("max_tokens") == registration.get("code_max_tokens", 8192)
                matches["temperature_matches_registration"] = model.get("temperature") == registration.get("code_temperature", 0.2)
                matches["timeout_matches_default"] = model.get("timeout") == 120.0
            elif expected_provider:
                expected_tokens = 8192 if stage == "harness-context" else expected_provider.get("max_tokens", 4096)
                matches["max_tokens_matches_registration"] = model.get("max_tokens") == expected_tokens
                matches["timeout_matches_registration"] = model.get("timeout") == expected_provider.get("timeout", 60.0)
            checks.append({"stage": stage, "checks": matches, "all_match": all(matches.values()) if matches else None})
    declared_backend_match = (row.get("context_agent_backend") == registration.get("context_agent_backend", {"name": "native"})
        if "context_agent_backend" in row and row.get("status") != "not_started" else None)
    observation_checks = {}
    context_observation = row.get('stage_observations', {}).get('context', {})
    context_entered = (context_observation.get('attempted') or 'harness-context' in row.get('stage_exits', {})
        or 'context-generate' in row.get('stage_exits', {}) or row.get('status') in
            {'passed', 'harness-context_failed', 'context-generate_failed'})
    context_finished = (context_observation.get('completed') or 'harness-context' in row.get('stage_exits', {})
        or bool(row.get('finished_utc')) or row.get('status') in
            {'passed', 'harness-context_failed', 'context-generate_failed', 'worker_interrupted', 'supervisor_timeout'})
    if context_entered and context_finished:
        context_configs = row.get('stages', {}).get('harness-context', {}).get('configurations', [])
        observation_checks['context_configuration_observed'] = bool(context_configs)
        observation_checks['context_publication_observed'] = bool(row.get('contexts'))
        observation_checks['context_metadata_observed'] = bool(row.get('contexts')) and all(
            item.get('metadata_observed') for item in row['contexts'])
        observation_checks['context_root_configuration_observed'] = bool(row.get('contexts')) and all(
            item.get('configuration_observed') for item in row['contexts'])
        observation_checks['context_published_bundle_observed'] = bool(row.get('contexts')) and all(
            item.get('published_bundle_observed') for item in row['contexts'])
        observation_checks['context_metrics_observed'] = bool(row.get('contexts')) and all(
            item.get('metrics_observed') for item in row['contexts'])
        paid_calls = row.get('stages', {}).get('harness-context', {}).get('model_calls')
        observation_checks['context_primary_attempt_observed_for_paid_calls'] = not paid_calls or bool(row.get('context_attempts'))
    if registration.get('context_agent_backend', {}).get('name') == 'deepseek-harness':
        expected = registration['context_agent_backend']
        for index, attempt in enumerate(row.get('context_attempts', [])):
            if attempt.get('model_calls') or attempt.get('provider_request_events') or attempt.get('dsh_loop_receipts'):
                receipts = attempt.get('dsh_loop_receipts', [])
                observation_checks[f'context_attempt_{index}_dsh_receipt'] = len(receipts) == 1 and receipts[0] == expected
    complete_match = (all(c['all_match'] for c in checks) if checks else None)
    context_checks = [check for check in checks if check['stage'] == 'harness-context']
    context_match = all(check['all_match'] for check in context_checks) if context_checks else None
    if declared_backend_match is False or not all(observation_checks.values()):
        complete_match = False
        if context_entered or context_checks:
            context_match = False
    return {"observed_configurations": len(checks),
            "all_observed_match": complete_match,
            "context_backend_observed_configurations": len(context_checks),
            "context_backend_matches_registration": context_match,
            "declared_backend_matches_registration": declared_backend_match,
            "observation_checks": observation_checks, "checks": checks}


def collect_experiment(experiment_root: Path, write_outputs: bool = True) -> dict:
    experiment_root = Path(experiment_root).resolve()
    registration = read(experiment_root / "registration.json")
    if not registration:
        raise ValueError("Missing or unreadable registration.json")
    rows = []
    for schedule in registration_rows(registration, experiment_root):
        row = collect_trial(Path(schedule["artifacts"]))
        for key in ("trial_id", "case", "repetition", "cohort", "phase", "patterns", "structure"):
            if key in schedule:
                row[key] = schedule[key]
        rows.append(row)
        row["configuration_audit"] = configuration_audit(row, registration)
        if write_outputs:
            output = Path(row["artifact_root"]) / "provider_events.json"
            if output.parent.is_dir():
                output.write_text(json.dumps({"schema_version": 1, "counts": row["totals"]["provider_event_counts"],
                                              "events": row["provider_events"]}, ensure_ascii=False, indent=2) + "\n")
    groups = defaultdict(list)
    for row in rows:
        groups[f"{row.get('cohort', row.get('phase')) or 'registered'} / {row['case']}"].append(row)
    fingerprint = registration.get("fingerprint", registration.get("production_fingerprint", registration.get("framework_fingerprint")))
    observed_audits = [row['configuration_audit'] for row in rows
        if row['configuration_audit']['all_observed_match'] is not None]
    context_audits = [row['configuration_audit']['context_backend_matches_registration'] for row in rows
        if row['configuration_audit']['context_backend_matches_registration'] is not None]
    metrics = {"schema_version": 1, "plan_signature_version": PLAN_SIGNATURE_VERSION, "experiment_root": str(experiment_root), "fingerprint": fingerprint,
               **({"dependency_preflight": safe(read(experiment_root / "dependency_preflight.json"))}
                  if (experiment_root / "dependency_preflight.json").is_file() else {}),
               **({"registration_review": read(experiment_root / "registration_review.json")}
                  if (experiment_root / "registration_review.json").is_file() else {}),
               "context_agent_backend": registration.get("context_agent_backend", {"name": "native"}),
               "context_agent_backend_fingerprint": registration.get("context_agent_backend_fingerprint",
                    digest(registration.get("context_agent_backend", {"name": "native"}))),
               "registered_trials": len(rows), "cohorts": {key: cohort_summary(group) for key, group in sorted(groups.items())},
               "configuration_audit": {"observed_trials": sum(r["configuration_audit"]["observed_configurations"] > 0 for r in rows),
                    "all_observed_match": all(item['all_observed_match'] for item in observed_audits) if observed_audits else None,
                    "context_backend_all_observed_match": all(context_audits) if context_audits else None,
                    "mismatched_trials": [r.get("trial_id") for r in rows if r["configuration_audit"]["all_observed_match"] is False]},
               "trials": rows}
    if write_outputs:
        (experiment_root / "metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2) + "\n")
        (experiment_root / "cohort_report.md").write_text(render_report(metrics))
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-root", type=Path, required=True)
    args = parser.parse_args()
    metrics = collect_experiment(args.experiment_root)
    print(json.dumps({"experiment_root": str(args.experiment_root), "registered_trials": metrics["registered_trials"],
                      "cohorts": metrics["cohorts"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
