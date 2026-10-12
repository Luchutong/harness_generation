"""Execution failure, proof unknown and pending actions cannot start feedback."""
from copy import deepcopy

import pytest

from harness_generation.orchestration.checkpoint import Checkpoint
from harness_generation.orchestration.single_generation import SingleGenerationController
from harness_generation.semantic_discovery.models import digest


class Services:
    def __init__(self, *, allowed=True, build=True, runtime=True, broken=None):
        self.allowed, self.build, self.runtime, self.broken = allowed, build, runtime, broken
        self.calls = []

    def verify_identity(self):
        self.calls.append("identity")

    def plan(self, feedback):
        assert feedback is None
        self.calls.append("plan")
        return {"candidates": [{"strategy": {"strategy_id": "first"}}, {"strategy": {"strategy_id": "other"}}]}

    def evaluate_single(self, candidate, *, mode):
        self.calls.append("evaluate:" + candidate["strategy"]["strategy_id"])
        if self.broken == "preflight":
            raise ValueError("source drift")
        return {"execution_preflight": {"allowed": self.allowed,
                   "unknown_contracts": [{"kind": "cleanup_internal_effect_unverified", "status": "unknown"}]},
                "completeness": {"generation_allowed": False},
                "diagnoses": []}

    def generate_single(self, candidate, evaluation, *, mode):
        self.calls.append("generate:" + candidate["strategy"]["strategy_id"])
        if self.broken == "generate":
            raise OSError("write failed")
        return {"mode": mode, "plan_valid": True, "code_generated": True, "execution_allowed": True,
                "generation_allowed": False, "semantic_verified": False,
                "build_success": self.build, "runtime_passed": self.build and self.runtime,
                "build": {"success": self.build}, "runtime": {"status": "passed" if self.build and self.runtime else
                    "failed" if self.build else "skipped"}, "code": "fixture", "repairable": True}

    def verify_single_result(self, result, checkpoint, *, mode):
        self.calls.append("resume_auth")
        assert result == checkpoint.result() and result["mode"] == mode

    def verify_single_candidate(self, candidate, *, mode):
        self.calls.append("candidate_auth")
        assert candidate["strategy"]["strategy_id"] == "first"

    def verify_single_planning(self, response, *, mode):
        self.calls.append("planning_auth")
        assert response["candidates"][0]["strategy"]["strategy_id"] == "first"

    def verify_single_evaluation(self, candidate, evaluation, *, mode):
        self.calls.append("evaluation_auth")
        assert evaluation["execution_preflight"]["allowed"] is self.allowed

    def verify_single_outcome(self, candidate, evaluation, outcome, *, mode):
        self.calls.append("outcome_auth")
        assert outcome["code"] == "fixture"
        assert outcome["build"]["success"] is self.build
        assert outcome["runtime_passed"] is (self.build and self.runtime)

    def repair(self, *args, **kwargs):
        raise AssertionError("generation-first must not invoke recovery")


@pytest.mark.parametrize("build,runtime,status", [(True, True, "runtime_passed"),
    (False, False, "build_failed"), (True, False, "runtime_failed")])
def test_single_attempt_stops_after_success_or_build_runtime_failure(tmp_path, build, runtime, status):
    services = Services(build=build, runtime=runtime)
    checkpoint = Checkpoint(tmp_path, {"mode": "generate"})
    result = SingleGenerationController(services, checkpoint).run()
    assert result["status"] == status
    assert services.calls == ["identity", "plan", "evaluate:first", "generate:first"]
    assert result["feedback_iteration"] == 0 and result["automatic_regeneration_allowed"] is False
    assert result["semantic_verified"] is result["generation_allowed"] is False
    assert result["quality"]["statistics_category"] == "candidate"
    assert result["fuzz_effective"] is None
    assert result["execution_preflight"]["unknown_contracts"][0]["status"] == "unknown"
    assert result["verified_harnesses"] == result["experimental_harnesses"] == []
    snapshot = {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()}
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {"mode": "generate"}, resume=True)).run()
    assert resumed == result and services.calls[-2:] == ["identity", "resume_auth"]
    assert snapshot == {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.is_file()}


def test_known_preflight_violation_stops_before_generation(tmp_path):
    services = Services(allowed=False)
    result = SingleGenerationController(services, Checkpoint(tmp_path, {})).run()
    assert result["status"] == "preflight_rejected" and not result["code_generated"]
    assert services.calls == ["identity", "plan", "evaluate:first"]


@pytest.mark.parametrize("mode", ["verify", "recover"])
def test_removed_modes_cannot_start_a_generation_controller(tmp_path, mode):
    services = Services()
    with pytest.raises(ValueError):
        SingleGenerationController(services, Checkpoint(tmp_path, {}), mode=mode)
    assert services.calls == []


@pytest.mark.parametrize("phase", ["preflight", "generate"])
def test_service_error_cannot_start_another_planner_or_generation(tmp_path, phase):
    services = Services(broken=phase)
    checkpoint = Checkpoint(tmp_path, {})
    result = SingleGenerationController(services, checkpoint).run()
    assert result["success"] is False
    assert services.calls.count("plan") == 1
    assert services.calls.count("generate:first") <= 1
    assert not checkpoint.pending_actions()
    assert result["feedback_iteration"] == 0


def test_pending_external_action_is_not_silently_repeated(tmp_path):
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    checkpoint.append("action_started", {"action_id": "uncertain", "action": "single_strategy_planning", "request": {}})
    result = SingleGenerationController(services, checkpoint).run()
    assert services.calls == ["identity"]
    assert result["requires_explicit_action_reconciliation"] and not result["automatic_action_replay_allowed"]
    assert result["pending_action_ids"] == ["uncertain"]


def test_result_hash_mutation_is_rejected_without_new_execution(tmp_path):
    import json
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    SingleGenerationController(services, checkpoint).run()
    marker = json.loads((tmp_path / "result.json").read_text())
    marker["result"]["semantic_verified"] = True
    (tmp_path / "result.json").write_text(json.dumps(marker))
    before = list(services.calls)
    result = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    assert result["status"] == "rejected"
    assert services.calls == before + ["identity"]


@pytest.mark.parametrize("action", ["single_strategy_planning", "evaluation", "single_generate_and_execute"])
def test_durable_action_before_interruption_is_authenticated_and_never_repeated(tmp_path, action):
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    actual_action = "execution_preflight" if action == "evaluation" else action
    original = checkpoint.append
    failed = False
    def interrupt_after_publish(kind, payload):
        nonlocal failed
        event = original(kind, payload)
        if kind == "action_finished" and payload["action"] == actual_action and not failed:
            failed = True
            raise OSError("injected after durable action_finished")
        return event
    checkpoint.append = interrupt_after_publish
    first = SingleGenerationController(services, checkpoint).run()
    assert first["status"] == "persistence_failed"
    assert first["action_response_durable"] and not checkpoint.pending_actions()
    assert not (tmp_path / "result.json").exists()
    expected_actions = {"plan": services.calls.count("plan"), "evaluate:first": services.calls.count("evaluate:first"),
                        "generate:first": services.calls.count("generate:first")}
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    assert resumed["status"] == "runtime_passed"
    assert services.calls.count("plan") == services.calls.count("evaluate:first") == services.calls.count("generate:first") == 1
    assert "planning_auth" in services.calls
    if expected_actions["evaluate:first"]:
        assert "evaluation_auth" in services.calls
    if expected_actions["generate:first"]:
        assert "outcome_auth" in services.calls
    assert not resumed["automatic_regeneration_allowed"]


@pytest.mark.parametrize("after_publish", [False, True])
def test_completion_before_result_marker_restores_without_reexecution(tmp_path, after_publish):
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    original = checkpoint.append
    def fail_completion(kind, payload):
        if kind == "single_generation_completed":
            if after_publish:
                original(kind, payload)
            raise OSError("injected completion persistence failure")
        return original(kind, payload)
    checkpoint.append = fail_completion
    result = SingleGenerationController(services, checkpoint).run()
    assert result["status"] == "persistence_failed"
    assert not (tmp_path / "result.json").exists()
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    assert resumed["status"] == "runtime_passed"
    assert services.calls.count("plan") == services.calls.count("evaluate:first") == services.calls.count("generate:first") == 1
    actual = Checkpoint(tmp_path, {}, resume=True)
    assert sum(event["kind"] == "single_generation_completed" for event in actual.events) == 1


def test_result_marker_write_failure_restores_only_summary(tmp_path):
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    def fail_result(result):
        raise OSError("injected result write failure")
    checkpoint.finish = fail_result
    first = SingleGenerationController(services, checkpoint).run()
    assert first["status"] == "persistence_failed"
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    assert resumed["status"] == "runtime_passed"
    assert services.calls.count("plan") == services.calls.count("evaluate:first") == services.calls.count("generate:first") == 1


def test_external_candidate_selection_survives_missing_result_without_planning(tmp_path):
    services = Services()
    candidate = {"strategy": {"strategy_id": "first"}}
    checkpoint = Checkpoint(tmp_path, {})
    checkpoint.finish = lambda result: (_ for _ in ()).throw(OSError("result missing"))
    SingleGenerationController(services, checkpoint).run([candidate])
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    assert resumed["status"] == "runtime_passed"
    assert "plan" not in services.calls
    assert services.calls.count("evaluate:first") == services.calls.count("generate:first") == 1
    assert "candidate_auth" in services.calls


@pytest.mark.parametrize("method", ["verify_single_candidate", "verify_single_planning", "verify_single_evaluation", "verify_single_outcome"])
def test_missing_independent_authentication_refuses_completed_actions(tmp_path, method):
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    checkpoint.finish = lambda result: (_ for _ in ()).throw(OSError("result missing"))
    SingleGenerationController(services, checkpoint).run()
    setattr(services, method, None)
    before = list(services.calls)
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    assert resumed["status"] == "rejected"
    assert services.calls.count("plan") == services.calls.count("evaluate:first") == services.calls.count("generate:first") == 1
    assert services.calls[len(before):][0] == "identity"


def test_refused_completed_outcome_does_not_run_again(tmp_path):
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    checkpoint.finish = lambda result: (_ for _ in ()).throw(OSError("result missing"))
    SingleGenerationController(services, checkpoint).run()
    services.verify_single_outcome = lambda *args, **kwargs: False
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    assert resumed["status"] == "rejected"
    assert services.calls.count("generate:first") == 1


def test_different_candidate_cannot_start_second_execution(tmp_path):
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    checkpoint.finish = lambda result: (_ for _ in ()).throw(OSError("result missing"))
    SingleGenerationController(services, checkpoint).run()
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run(
        [{"strategy": {"strategy_id": "other"}}])
    assert resumed["status"] == "rejected"
    assert services.calls.count("plan") == services.calls.count("evaluate:first") == services.calls.count("generate:first") == 1


def rewrite_chain(directory, mutate):
    """Coherent hashes are deliberately insufficient for factual authority."""
    import json
    header = json.loads((directory / "checkpoint.json").read_text())
    previous = header["checkpoint_digest"]
    for path in sorted(directory.glob("event_*.json")):
        event = json.loads(path.read_text())
        mutate(event)
        event["previous_digest"] = previous
        event["event_digest"] = digest({key: value for key, value in event.items() if key != "event_digest"})
        previous = event["event_digest"]
        path.write_text(json.dumps(event))
    return previous


@pytest.mark.parametrize("change", ["response_digest", "request", "action_id", "evaluation", "outcome"])
def test_coherently_rehashed_completed_action_still_requires_identity_and_facts(tmp_path, change):
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    checkpoint.finish = lambda result: (_ for _ in ()).throw(OSError("result missing"))
    SingleGenerationController(services, checkpoint).run()
    def mutate(event):
        row = event["payload"]
        if event["kind"] == "action_started" and row["action"] == "single_generate_and_execute":
            if change == "request":
                row["request"]["candidate_digest"] = "0" * 64
            if change == "action_id":
                row["action_id"] = "action_fake"
        if event["kind"] == "action_finished":
            if change == "response_digest" and row["action"] == "single_generate_and_execute":
                row["response_digest"] = "0" * 64
            if change == "evaluation" and row["action"] == "execution_preflight":
                row["response"]["execution_preflight"]["allowed"] = False
                row["response_digest"] = digest(row["response"])
            if change == "outcome" and row["action"] == "single_generate_and_execute":
                row["response"]["code"] = "forged"
                row["response_digest"] = digest(row["response"])
    rewrite_chain(tmp_path, mutate)
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    if change == "action_id":
        assert resumed["requires_explicit_action_reconciliation"] and resumed["pending_action_ids"] == ["action_fake"]
    else:
        assert resumed["status"] == "rejected"
    assert services.calls.count("plan") == services.calls.count("evaluate:first") == services.calls.count("generate:first") == 1


@pytest.mark.parametrize("field,value", [("quality", {"fuzz_effective": True}), ("semantic_verified", True),
                                        ("code_generated", False), ("status", "formal_success"),
                                        ("cost", {"model_calls": 0})])
def test_rehashed_saved_result_axes_are_recomputed_not_trusted(tmp_path, field, value):
    import json
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    SingleGenerationController(services, checkpoint).run()
    marker = json.loads((tmp_path / "result.json").read_text())
    marker["result"][field] = value
    marker["result_digest"] = digest(marker["result"])
    (tmp_path / "result.json").write_text(json.dumps(marker))
    before = list(services.calls)
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    assert resumed["status"] == "rejected"
    assert services.calls == before + ["identity", "resume_auth"]


def test_completed_action_accounting_is_recorded_once_after_restore(tmp_path):
    services = Services()
    original = services.generate_single
    def accounted(*args, **kwargs):
        result = original(*args, **kwargs)
        result["accounting"] = [{"stage_id": "observed_build", "metadata": {"model_calls": 0, "tool_calls": 4}}]
        return result
    services.generate_single = accounted
    checkpoint = Checkpoint(tmp_path, {})
    original_record = checkpoint.append
    failed = False
    def stop_after_action(kind, payload):
        nonlocal failed
        event = original_record(kind, payload)
        if kind == "action_finished" and payload["action"] == "single_generate_and_execute" and not failed:
            failed = True
            raise OSError("before separate stage accounting")
        return event
    checkpoint.append = stop_after_action
    SingleGenerationController(services, checkpoint).run()
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    assert resumed["cost"]["tool_calls"] == 4
    actual = Checkpoint(tmp_path, {}, resume=True)
    assert sum(event["kind"] == "stage_accounting" for event in actual.events) == 1
    assert services.calls.count("generate:first") == 1


def test_served_execution_without_durable_response_remains_pending(tmp_path):
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    original = checkpoint.append
    def fail_before_response(kind, payload):
        if kind == "action_finished" and payload["action"] == "single_generate_and_execute":
            raise OSError("execution returned but response publication failed")
        return original(kind, payload)
    checkpoint.append = fail_before_response
    first = SingleGenerationController(services, checkpoint).run()
    assert first["pending_action_ids"] and not first["action_response_durable"]
    before = list(services.calls)
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    assert resumed["requires_explicit_action_reconciliation"]
    assert services.calls == before + ["identity"]
    assert services.calls.count("generate:first") == 1


def test_result_marker_published_before_error_is_preserved_and_authenticated(tmp_path):
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    original = checkpoint.finish
    def fail_after_result(result):
        original(result)
        raise OSError("result published before final persistence error")
    checkpoint.finish = fail_after_result
    first = SingleGenerationController(services, checkpoint).run()
    assert first["status"] == "persistence_failed"
    raw = (tmp_path / "result.json").read_bytes()
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    assert resumed["status"] == "runtime_passed" and (tmp_path / "result.json").read_bytes() == raw
    assert services.calls.count("generate:first") == 1


def test_completed_generate_checkpoint_cannot_be_resumed_in_verify_mode(tmp_path):
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    checkpoint.finish = lambda result: (_ for _ in ()).throw(OSError("result missing"))
    SingleGenerationController(services, checkpoint).run()
    before = list(services.calls)
    with pytest.raises(ValueError):
        SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True), mode="verify")
    assert services.calls == before


def test_pending_action_cannot_hide_under_coherently_rehashed_saved_result(tmp_path):
    import json
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    SingleGenerationController(services, checkpoint).run()
    checkpoint.append("action_started", {"action_id": "uncertain", "action": "single_generate_and_execute", "request": {}})
    marker = json.loads((tmp_path / "result.json").read_text())
    marker["final_event_digest"] = checkpoint.previous_digest
    (tmp_path / "result.json").write_text(json.dumps(marker))
    before = list(services.calls)
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    assert resumed["requires_explicit_action_reconciliation"] and resumed["pending_action_ids"] == ["uncertain"]
    assert services.calls == before + ["identity"]


@pytest.mark.parametrize("saved_label", [0, "verified", {"verified": True}, {"valid": False}])
def test_authenticator_status_labels_cannot_replace_trusted_authentication(tmp_path, saved_label):
    services = Services()
    checkpoint = Checkpoint(tmp_path, {})
    checkpoint.finish = lambda result: (_ for _ in ()).throw(OSError("result missing"))
    SingleGenerationController(services, checkpoint).run()
    services.verify_single_outcome = lambda *args, **kwargs: saved_label
    resumed = SingleGenerationController(services, Checkpoint(tmp_path, {}, resume=True)).run()
    assert resumed["status"] == "rejected"
    assert services.calls.count("generate:first") == 1
