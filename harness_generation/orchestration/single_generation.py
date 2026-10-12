"""One plan and one execution; observations never trigger another generation.

The shared checkpoint boundary records requests/cost and prevents replaying an
uncertain external action. Completed actions are independently authenticated
and reused after interruption. Authentication can rerun Clang analysis; it
does not repeat provider planning, harness compilation, or target execution.
Observations never start a feedback or regeneration loop.
"""
from copy import deepcopy

from ..semantic_discovery.models import digest
from .execution_controller import ActionController, ControllerFailure
from .quality import assess_harness_quality

VERSION = "single-harness-generation-v1"
_ACTIONS = frozenset({"single_strategy_planning", "execution_preflight",
                      "single_generate_and_execute"})


class SingleGenerationController(ActionController):
    def __init__(self, services, checkpoint, budget=None, *, mode="generate"):
        if mode != "generate":
            raise ValueError("single generation mode must be generate")
        super().__init__(services, checkpoint, budget)
        self.mode = mode

    def _failure_result(self, failure):
        return {**super()._failure_result(failure), "mode": self.mode,
                "controller_policy": VERSION, "feedback_iteration": 0,
                "automatic_regeneration_allowed": False, "semantic_verified": False}

    def _project_result(self, status, *, candidate=None, evaluation=None, outcome=None, diagnoses=()):
        outcome = outcome or {"mode": self.mode}
        quality = assess_harness_quality(outcome)
        formal = False
        return {"schema_version": 1, "policy_version": VERSION, "mode": self.mode,
            "status": status, "success": quality["buildable"] is True and quality["runtime_stable"] is True,
            "plan_valid": outcome.get("plan_valid") is True,
            "code_generated": outcome.get("code_generated") is True,
            "build_success": quality["buildable"], "runtime_passed": quality["runtime_stable"],
            "fuzz_effective": quality["fuzz_effective"], "semantic_verified": formal,
            "generation_allowed": formal, "execution_allowed": outcome.get("execution_allowed") is True,
            "feedback_iteration": 0, "automatic_regeneration_allowed": False,
            "candidate": deepcopy(candidate), "evaluation": deepcopy(evaluation), "outcome": deepcopy(outcome),
            "execution_preflight": deepcopy((evaluation or {}).get("execution_preflight")),
            "diagnoses": deepcopy(list(diagnoses)), "quality": quality,
            "verified_harnesses": [deepcopy(outcome)] if formal and outcome.get("runtime_passed") is True else [],
            "candidate_harnesses": [deepcopy(outcome)] if not formal and outcome.get("code_generated") is True else [],
            "experimental_harnesses": [], "cost": self.ledger.totals()}

    def _finish(self, status, *, candidate=None, evaluation=None, outcome=None, diagnoses=()):
        result = self._project_result(status, candidate=candidate, evaluation=evaluation,
                                      outcome=outcome, diagnoses=diagnoses)
        completion = {"mode": self.mode, "status": status, "candidate_digest": digest(candidate),
                      "outcome_digest": digest(result["outcome"])}
        existing = [event["payload"] for event in self.checkpoint.events if event["kind"] == "single_generation_completed"]
        if existing and (len(existing) != 1 or existing[0] != completion):
            raise ControllerFailure("single_completion_identity", ValueError("saved completion does not match authenticated actions"),
                                    authentication=True)
        if not existing:
            self.checkpoint.append("single_generation_completed", completion)
        self.checkpoint.finish(result)
        return result

    def _completed_response(self, action, payload):
        """Validate action linkage, before independently authenticating facts.

        A chain/digest alone supplies integrity, not source or execution trust.
        A recorded action for different inputs cannot be ignored and retried.
        """
        starts, finishes, number = [], [], 0
        for event in self.checkpoint.events:
            row = event["payload"]
            if event["kind"] == "action_started":
                if row.get("action") == action:
                    expected = "action_" + digest({"number": number, "action": action, "payload": row.get("request")})[:24]
                    if row.get("action_id") != expected or row.get("request") != payload:
                        raise ValueError("saved single action request or ID differs")
                    starts.append(row)
                number += 1
            elif event["kind"] == "action_finished" and row.get("action") == action:
                finishes.append(row)
        if not starts and not finishes:
            return None
        if len(starts) != 1 or len(finishes) != 1:
            raise ValueError("single action is not uniquely completed")
        if finishes[0].get("action_id") != starts[0]["action_id"]:
            raise ValueError("saved action response has no matching request")
        response = finishes[0].get("response")
        if not isinstance(response, dict) or finishes[0].get("response_digest") != digest(response):
            raise ValueError("saved single action response digest differs")
        return deepcopy(response)

    def _verify_reused(self, method, *args):
        verifier = getattr(self.services, method, None)
        if not callable(verifier):
            raise ValueError("completed single action requires independent " + method)
        authenticated = verifier(*args, mode=self.mode)
        if authenticated is not None and authenticated is not True:
            raise ValueError("completed single action independent authentication rejected")

    def _call(self, action, payload, function, *, cached_validator=None):
        if action not in _ACTIONS:
            raise ValueError("single generation cannot dispatch a recovery action")
        if self.checkpoint.pending_actions():
            raise ControllerFailure("pending_action_reconciliation",
                RuntimeError("unfinished action requires explicit reconciliation"), action=action)
        saved = self._authenticate("completed_single_action_identity", lambda: self._completed_response(action, payload))
        if saved is not None:
            if cached_validator is None:
                raise ControllerFailure("completed_single_action_authentication",
                    ValueError("completed action lacks independent authentication"), authentication=True)
            self._authenticate("completed_single_action_authentication", lambda: cached_validator(saved))
            self.reused_responses.add(id(saved))
            return saved
        return super()._call(action, payload, function)

    def _selected_candidate(self):
        events = [event["payload"] for event in self.checkpoint.events if event["kind"] == "single_candidate_selected"]
        if not events:
            return None
        if len(events) != 1:
            raise ValueError("single candidate selection is not unique")
        row = events[0]
        if row.get("mode") != self.mode or row.get("candidate_digest") != digest(row.get("candidate")):
            raise ValueError("single candidate selection identity differs")
        self._verify_reused("verify_single_candidate", row["candidate"])
        return deepcopy(row["candidate"])

    def _verify_history(self):
        evaluation = "execution_preflight"
        phases = [event["payload"].get("action") for event in self.checkpoint.events if event["kind"] == "action_started"]
        ordered = ["single_strategy_planning", evaluation, "single_generate_and_execute"]
        if phases not in [ordered[:count] for count in range(4)] + [ordered[1:][:count] for count in range(3)]:
            raise ValueError("single action history changes mode, repeats a phase, or violates execution order")

    def _allowed(self, evaluation):
        return evaluation.get("execution_preflight", {}).get("allowed") is True

    @staticmethod
    def _outcome_status(outcome):
        quality = assess_harness_quality(outcome)
        return ("runtime_passed" if quality["buildable"] is True and quality["runtime_stable"] is True else
                "runtime_failed" if quality["buildable"] is True else
                "build_failed" if outcome.get("code_generated") is True else
                outcome.get("status", "generation_failed"))

    def _verify_result_projection(self, saved):
        """Recompute axes and bind the result to the exact durable responses."""
        candidate, evaluation, outcome = saved.get("candidate"), saved.get("evaluation"), saved.get("outcome")
        planned = self._completed_response("single_strategy_planning", {"mode": self.mode})
        if candidate is None:
            status = "planning_failed"
            if planned is not None and planned.get("candidates"):
                raise ValueError("planning failure discarded a durable candidate")
            diagnoses = planned.get("diagnoses", []) if planned is not None else [{"code": "single_candidate_missing"}]
        else:
            selected = [event["payload"] for event in self.checkpoint.events if event["kind"] == "single_candidate_selected"]
            if selected and (len(selected) != 1 or selected[0].get("candidate") != candidate
                    or selected[0].get("candidate_digest") != digest(candidate) or selected[0].get("mode") != self.mode):
                raise ValueError("saved result candidate differs from selected candidate")
            if planned is not None and (not planned.get("candidates") or planned["candidates"][0] != candidate):
                raise ValueError("saved result candidate differs from first planned candidate")
            action = "execution_preflight"
            previous = self._completed_response(action, {"candidate_digest": digest(candidate), "mode": self.mode})
            if previous is None or previous != evaluation:
                raise ValueError("saved result evaluation has no exact durable response")
            if self._allowed(evaluation):
                previous = self._completed_response("single_generate_and_execute", {"candidate_digest": digest(candidate),
                    "evaluation_digest": digest(evaluation), "mode": self.mode})
                if previous is None or previous != outcome:
                    raise ValueError("saved result outcome has no exact durable response")
                status = self._outcome_status(outcome)
                diagnoses = outcome.get("diagnoses", [])
            else:
                if outcome != {"mode": self.mode}:
                    raise ValueError("rejected preflight cannot have an execution outcome")
                status = "preflight_rejected"
                diagnoses = evaluation.get("diagnoses", [])
        expected = self._project_result(status, candidate=candidate, evaluation=evaluation, outcome=outcome,
                                        diagnoses=diagnoses)
        if saved != expected:
            raise ValueError("saved single result axes or cost differ from independent projection")
        completed = [event["payload"] for event in self.checkpoint.events if event["kind"] == "single_generation_completed"]
        if completed != [{"mode": self.mode, "status": status, "candidate_digest": digest(candidate),
                           "outcome_digest": digest(outcome)}]:
            raise ValueError("saved single result has no exact terminal completion")

    def _run(self, candidates=None):
        self._authenticate("initial_identity", self.services.verify_identity)
        try:
            for event in list(self.checkpoint.events):
                if event["kind"] == "action_finished":
                    for row in event["payload"]["response"].get("accounting", []):
                        self.ledger.record(row["stage_id"], row["metadata"])
        except Exception as error:
            raise ControllerFailure("reconcile_accounting", error) from error
        saved = self._authenticate("saved_result_identity", self.checkpoint.result)
        if self.checkpoint.pending_actions():
            raise ControllerFailure("pending_action_reconciliation",
                RuntimeError("unfinished action requires explicit reconciliation"))
        self._authenticate("single_action_history", self._verify_history)
        if saved is not None:
            self._authenticate("saved_result_authentication",
                lambda: self.services.verify_single_result(saved, self.checkpoint, mode=self.mode))
            self._authenticate("saved_result_projection", lambda: self._verify_result_projection(saved))
            # Independent authentication can rerun analysis. No provider,
            # harness build/runtime, result rewrite or new generation occurs.
            return saved
        selected = self._authenticate("saved_candidate_authentication", self._selected_candidate)
        planning_exists = any(event["kind"] == "action_started" and event["payload"].get("action") == "single_strategy_planning"
                              for event in self.checkpoint.events)
        if candidates is None and selected is None and not planning_exists and any(
                event["kind"] == "action_started" and event["payload"].get("action") in
                {"execution_preflight", "single_generate_and_execute"}
                for event in self.checkpoint.events):
            raise ControllerFailure("single_candidate_identity", ValueError("completed actions require their original candidate input"),
                                    authentication=True)
        if planning_exists or candidates is None and selected is None:
            planned = self._call("single_strategy_planning", {"mode": self.mode},
                lambda: self.services.plan(None),
                cached_validator=lambda response: self._verify_reused("verify_single_planning", response))
            previous = planned.get("candidates", [])
            if candidates is not None and (not previous or not isinstance(candidates, list) or not candidates
                    or previous[0] != candidates[0]):
                raise ControllerFailure("single_candidate_identity", ValueError("provided input differs from durable first planned candidate"),
                                        authentication=True)
            candidates = previous
            if not candidates:
                return self._finish("planning_failed", diagnoses=planned.get("diagnoses", []))
        elif candidates is None:
            candidates = [selected]
        if not isinstance(candidates, list) or not candidates:
            return self._finish("planning_failed", diagnoses=[{"code": "single_candidate_missing"}])
        # The planner receives max_candidates=1. Saved input may contain more:
        # select its first ranked candidate once, never search after failure.
        candidate = deepcopy(candidates[0])
        if selected is not None and selected != candidate:
            raise ControllerFailure("single_candidate_identity", ValueError("resume selected a different candidate"), authentication=True)
        if selected is None:
            self.checkpoint.append("single_candidate_selected", {"mode": self.mode,
                "candidate": candidate, "candidate_digest": digest(candidate)})
        action = "execution_preflight"
        evaluation = self._call(action, {"candidate_digest": digest(candidate), "mode": self.mode},
            lambda: self.services.evaluate_single(candidate, mode=self.mode),
            cached_validator=lambda response: self._verify_reused("verify_single_evaluation", candidate, response))
        allowed = self._allowed(evaluation)
        if not allowed:
            return self._finish("preflight_rejected",
                candidate=candidate, evaluation=evaluation, diagnoses=evaluation.get("diagnoses", []))
        outcome = self._call("single_generate_and_execute", {"candidate_digest": digest(candidate),
            "evaluation_digest": digest(evaluation), "mode": self.mode},
            lambda: self.services.generate_single(candidate, evaluation, mode=self.mode),
            cached_validator=lambda response: self._verify_reused("verify_single_outcome", candidate, evaluation, response))
        status = self._outcome_status(outcome)
        return self._finish(status, candidate=candidate, evaluation=evaluation, outcome=outcome,
                            diagnoses=outcome.get("diagnoses", []))
