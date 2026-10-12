"""Shared execution quality; finite measurements never grant semantic authority.

Only a process-local receipt captured around a live independent observer may
claim input sensitivity. Saved quality labels and fixed smoke counts supply no
such receipt. Historical results can receive a separate current projection.
"""
from copy import deepcopy
import hashlib
from pathlib import Path

from ..effectiveness.validation import POLICY as EFFECTIVENESS_POLICY, evaluate_effectiveness
from ..semantic_discovery.models import digest

QUALITY_POLICY = "orchestration-harness-quality-v1"
_LIVE_TOKEN = object()


def execution_identity(outcome):
    build = outcome.get("build", {})
    code = outcome.get("code")
    return {"plan_digest": outcome.get("plan_digest", build.get("plan_digest")),
            "strategy_digest": outcome.get("strategy_digest", build.get("strategy_digest")),
            "recipe_digest": build.get("recipe_digest"),
            "target_input_digests": deepcopy(build.get("target_input_digests", {})),
            "harness_sha256": hashlib.sha256(code.encode()).hexdigest() if isinstance(code, str) else None}


def _bool(value):
    return value if type(value) is bool else None


def _runtime_stable(runtime):
    cases = runtime.get("cases", [])
    if (runtime.get("status") in {"failed", "unavailable", "timed_out"}
            or runtime.get("success") is False
            or any(case.get("success") is False or case.get("timed_out") for case in cases)):
        return False
    if cases and all(case.get("success") is True and not case.get("timed_out") for case in cases):
        return True
    if runtime.get("status") == "passed" or runtime.get("success") is True:
        return True
    return None


class _LiveObservation:
    def __init__(self, token, binding, evidence, error=None, current_binding=None, live_fuzzer_execution=None):
        if token is not _LIVE_TOKEN:
            raise ValueError("live quality receipt is not deserializable")
        self._binding, self._evidence, self._error = deepcopy(binding), deepcopy(evidence), error
        self._token = token
        self._current_binding = current_binding
        self._live_fuzzer_execution = deepcopy(live_fuzzer_execution)

    def to_dict(self):
        """Persist measurements for audit; this dictionary grants no live authority."""
        return {"binding": deepcopy(self._binding), "effectiveness": deepcopy(self._evidence),
                "error": self._error, "quality_policy_version": QUALITY_POLICY,
                "live_fuzzer_execution": deepcopy(self._live_fuzzer_execution),
                "generation_authority": False}


def _current_observation(outcome, binding, evidence, current_binding=None):
    identity = execution_identity(outcome)
    required = ("plan_digest", "strategy_digest", "recipe_digest", "harness_sha256")
    if any(not identity.get(key) for key in required) or binding != identity:
        raise ValueError("quality_observation_execution_identity_mismatch")
    if current_binding is not None and current_binding() != binding:
        raise ValueError("quality_observation_current_execution_changed")
    if evidence.get("policy_version") != EFFECTIVENESS_POLICY:
        raise ValueError("quality_observation_policy_unknown")
    if evidence.get("harness_sha256") != identity["harness_sha256"]:
        raise ValueError("quality_observation_harness_mismatch")
    hashes = evidence.get("source_file_hashes", {})
    dependencies = evidence.get("build_dependency_hashes", {})
    if not hashes or not dependencies or evidence.get("source_identity_unchanged") is not True:
        raise ValueError("quality_observation_source_identity_unknown")
    for path, expected in [*hashes.items(), *dependencies.items(), *identity["target_input_digests"].items()]:
        if hashlib.sha256(Path(path).read_bytes()).hexdigest() != expected:
            raise ValueError("quality_observation_source_changed")
    harness = Path(evidence["harness_path"])
    if hashlib.sha256(harness.read_bytes()).hexdigest() != identity["harness_sha256"]:
        raise ValueError("quality_observation_harness_changed")
    contract = evidence.get("contract", {})
    if contract.get("source_file") not in hashes:
        raise ValueError("quality_observation_target_source_unbound")
    # Recompute finite evidence; the observer's saved fuzz_effective label is
    # never the criterion, and API/entry/smoke counts cannot imply sensitivity.
    runtime_stable = _bool(evidence.get("runtime_stable"))
    live_fuzzer = evidence.get("live_fuzzer_execution")
    if isinstance(live_fuzzer, dict) and (live_fuzzer.get("exit_code") != 0 or live_fuzzer.get("timed_out")):
        runtime_stable = False
    return evaluate_effectiveness(evidence.get("probes", []), contract,
        buildable=_bool(evidence.get("buildable")), runtime_stable=runtime_stable)


def capture_live_quality(outcome, observer, *, binding, current_binding=None, live_fuzzer_execution=None):
    """Capture a freshly executed observer bound to the exact current execution.

    ``binding`` comes from the live caller's plan/strategy/recipe and current
    code identity, before observation. It must never come from a saved quality
    label. The caller chooses the finite input corpus and owns observer cost.
    This helper performs no compilation, execution or provider work itself.
    """
    evidence = {}
    try:
        identity = execution_identity(outcome)
        if (binding != identity or any(not identity.get(key) for key in
                ("plan_digest", "strategy_digest", "recipe_digest", "harness_sha256"))):
            raise ValueError("quality_observation_execution_identity_mismatch")
        if current_binding is not None and current_binding() != binding:
            raise ValueError("quality_observation_current_execution_changed")
        evidence = observer()
        if live_fuzzer_execution is not None:
            evidence = {**evidence, "live_fuzzer_execution": deepcopy(live_fuzzer_execution)}
        _current_observation(outcome, binding, evidence, current_binding)
        return _LiveObservation(_LIVE_TOKEN, binding, evidence, current_binding=current_binding,
                                live_fuzzer_execution=live_fuzzer_execution)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        return _LiveObservation(_LIVE_TOKEN, binding, evidence, str(error), current_binding, live_fuzzer_execution)


def assess_harness_quality(outcome, *, live_observation=None):
    """Derive nullable build/runtime/effectiveness axes without changing permission."""
    category = ("candidate" if outcome.get("mode") == "generate" or outcome.get("statistics_category") == "candidate"
                else "experimental" if outcome.get("experimental") is True else "verified")
    result = {"schema_version": 1, "policy_version": QUALITY_POLICY,
        "statistics_category": category, "execution_identity": execution_identity(outcome),
        "buildable": _bool(outcome.get("build", {}).get("success")),
        "runtime_stable": _runtime_stable(outcome.get("runtime", outcome.get("replay", {}))),
        "runtime_evidence_scope": "recorded_execution_only",
        "fuzz_effective": None, "instrumented_probe_buildable": None,
        "target_call_count": None, "valid_state_call_count": None,
        "target_body_coverage": {"status": "unknown"},
        "input_sensitive_coverage": {"status": "unknown"},
        "reason": "isolated_effectiveness_evidence_not_recorded",
        "effectiveness_policy_version": None, "finite_evidence_only": True,
        "semantic_correctness_certified": False, "generation_authority": False}
    if type(live_observation) is not _LiveObservation or live_observation._token is not _LIVE_TOKEN:
        return result
    live_fuzzer = live_observation._live_fuzzer_execution
    if isinstance(live_fuzzer, dict) and (live_fuzzer.get("exit_code") != 0 or live_fuzzer.get("timed_out")):
        try:
            identity = execution_identity(outcome)
            if (all(identity.get(key) for key in ("plan_digest", "strategy_digest", "recipe_digest", "harness_sha256"))
                    and live_observation._binding == identity
                    and (live_observation._current_binding is None
                         or live_observation._current_binding() == identity)):
                # A bound live failure remains a failure even when independent
                # coverage probes are unavailable, invalid or throw an error.
                result["runtime_stable"] = False
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            result["reason"] = str(error)
            return result
    if live_observation._error:
        result["reason"] = live_observation._error
        return result
    try:
        observed = _current_observation(outcome, live_observation._binding, live_observation._evidence,
                                        live_observation._current_binding)
        result.update({key: deepcopy(observed[key]) for key in
            ("fuzz_effective", "target_call_count", "valid_state_call_count",
             "target_body_coverage", "input_sensitive_coverage", "reason")})
        result["instrumented_probe_buildable"] = _bool(observed.get("buildable"))
        result["effectiveness_policy_version"] = EFFECTIVENESS_POLICY
        result["observation_digest"] = digest(live_observation.to_dict())
        if observed.get("runtime_stable") is False:
            result["runtime_stable"] = False
        if result["fuzz_effective"] is True and not (result["buildable"] is True
                and result["runtime_stable"] is True and observed.get("buildable") is True):
            result.update(fuzz_effective=None, reason="quality_execution_or_probe_not_successful")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        result["reason"] = str(error)
    return result


def summarize_harness_quality(rows):
    result = {"observations": len(rows)}
    for metric in ("buildable", "runtime_stable", "fuzz_effective"):
        result[metric] = {label: sum(row.get(metric) is value for row in rows)
                         for label, value in (("true", True), ("false", False), ("unknown", None))}
    result["effective_successes"] = result["fuzz_effective"]["true"]
    return result


def with_current_quality(result, *, live_observations=(), preserve_historical_status=False):
    """Classify new results, or separately project immutable historical results."""
    current, rows = deepcopy(result), []
    for category in ("verified", "experimental"):
        for number, outcome in enumerate(result.get(category + "_harnesses", [])):
            matches = [receipt for receipt in live_observations if type(receipt) is _LiveObservation
                       and receipt._binding == execution_identity(outcome)]
            row = assess_harness_quality({**outcome, "experimental": category == "experimental"},
                                        live_observation=matches[0] if len(matches) == 1 else None)
            row["harness_index"] = number
            rows.append(row)
    status = result.get("status")
    if result.get("verified_harnesses"):
        status = "verified_success"
    elif result.get("experimental_harnesses"):
        status = "experimental_success" if any(row["statistics_category"] == "experimental"
            and row["fuzz_effective"] is True for row in rows) else "experimental_build_runtime_only"
    projection = {"status": status, "quality_policy_version": QUALITY_POLICY, "harness_quality": rows,
                  "quality_summary": {category: summarize_harness_quality(
                      [row for row in rows if row["statistics_category"] == category])
                      for category in ("verified", "experimental")}}
    if preserve_historical_status:
        current["current_quality"] = projection
    else:
        current.update(projection)
    return current
