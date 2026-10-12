"""Durable single-execution action boundaries, accounting and authentication.

These shared boundaries preserve the checkpoint policy of v0.5. They do not
schedule source repair, semantic proof recovery, replanning or code repair.
"""
from copy import deepcopy
from ..semantic_discovery.models import digest
from .models import ControllerBudget, VERSION
from .checkpoint import Checkpoint
from .trial_ledger import TrialLedger

FAILURE_FEEDBACK_VERSION = "controller-boundary-feedback-v1"


class ControllerFailure(RuntimeError):
    """A failed boundary carries its recovery policy, not a success response."""
    def __init__(self, phase, error, *, action=None, action_id=None, authentication=False, observed_response=None):
        super().__init__(str(error))
        self.phase, self.error = phase, error
        self.action, self.action_id = action, action_id
        self.authentication = authentication
        self.observed_response = observed_response


class ActionController:
    def __init__(self, services, checkpoint, budget=None):
        self.services, self.checkpoint = services, checkpoint
        self.budget = budget or ControllerBudget()
        self.ledger = None
        self.initialization_error = None
        try:
            self.ledger = TrialLedger(checkpoint)
        except Exception as error:
            self.initialization_error = error
        self.reused_responses = set()

    @staticmethod
    def _authenticate(phase, function):
        try:
            return function()
        except Exception as error:
            raise ControllerFailure(phase, error, authentication=True) from error

    def _failure_result(self, failure):
        """Describe the durable boundary without committing a fake completion."""
        checkpoint_verified, checkpoint_error = True, None
        if isinstance(failure.error, OSError):
            # Publishing may have succeeded immediately before fsync reported
            # failure. Read the real chain before describing its durable state.
            try:
                actual = Checkpoint(self.checkpoint.directory, self.checkpoint.header["identity"], resume=True)
                self.checkpoint.events, self.checkpoint.previous_digest = actual.events, actual.previous_digest
            except Exception as error:
                checkpoint_verified = False
                checkpoint_error = {"error": type(error).__name__, "detail": str(error)}
        pending = self.checkpoint.pending_actions()
        finished = {event["payload"]["action_id"] for event in self.checkpoint.events
                    if event["kind"] == "action_finished"}
        try:
            cost = TrialLedger(self.checkpoint, include_completed=True).totals() if self.ledger is not None else None
            cost_error = None
        except Exception as error:
            cost, cost_error = None, {"error": type(error).__name__, "detail": str(error)}
        persistence = isinstance(failure.error, OSError) and not failure.authentication and failure.phase in {
            "start_action", "publish_action", "record_accounting", "reconcile_accounting", "controller_run"}
        diagnosis = {"root_cause": "checkpoint_persistence_failed" if persistence else
            "source_or_saved_state_authentication_failed" if failure.authentication else "controller_boundary_failed",
            "code": "controller_" + failure.phase + "_failed", "phase": failure.phase,
            "error": type(failure.error).__name__, "detail": str(failure.error),
            "action": failure.action, "action_id": failure.action_id,
            "recovery_allowed": False, "requires_explicit_action_reconciliation": bool(pending) or
                not checkpoint_verified or failure.phase in {"collect_accounting", "validate_response", "record_accounting",
                    "reconcile_accounting", "publish_action"}}
        result = {"schema_version": 1, "policy_version": VERSION,
            "failure_feedback_policy": FAILURE_FEEDBACK_VERSION,
            "status": "persistence_failed" if persistence else "rejected" if failure.authentication else "controller_failed",
            "generation_allowed": False, "success": False, "diagnoses": [diagnosis],
            "pending_action_ids": pending, "action_response_durable": failure.action_id in finished,
            "requires_explicit_action_reconciliation": diagnosis["requires_explicit_action_reconciliation"],
            "automatic_action_replay_allowed": False, "accounting_complete": False, "cost": cost}
        result["cost_scope"] = "confirmed_stage_rows_and_durable_action_responses"
        result["unrecorded_accounting_possible"] = bool(pending) or failure.phase in {"collect_accounting", "validate_response"}
        if cost is not None and result["unrecorded_accounting_possible"]:
            cost["usage_complete"] = cost["provider_requests_complete"] = False
            cost["ledger_digest"] = digest({key: value for key, value in cost.items() if key != "ledger_digest"})
        result["checkpoint_state_verified"] = checkpoint_verified
        if checkpoint_error is not None:
            result["checkpoint_state_error"] = checkpoint_error
        observation = None
        if failure.observed_response is not None:
            try:
                digest(failure.observed_response)
                observation = deepcopy(failure.observed_response)
                result["observed_response"] = observation
                result["observed_response_authority"] = "none"
            except (TypeError, ValueError):
                result["observed_response_serializable"] = False
        if cost_error is not None:
            result["cost_error"] = cost_error
        # Never invalidate or replace a previously written result marker. An
        # unauthenticated saved success remains preserved for investigation.
        if not (self.checkpoint.directory / "result.json").exists():
            try:
                self.checkpoint.append("controller_failure", {"diagnosis": diagnosis,
                    "pending_action_ids": pending, "action_response_durable": result["action_response_durable"],
                    "observed_response": observation, "observed_response_authority": "none"})
                result["failure_persisted"] = True
            except Exception as error:
                result["failure_persisted"] = False
                result["failure_persistence_error"] = {"error": type(error).__name__, "detail": str(error)}
        else:
            result["failure_persisted"] = False
        return result

    def _call(self, action, payload, function, *, cached_validator=None):
        if self.initialization_error is not None:
            raise ControllerFailure("ledger_initialization", self.initialization_error, authentication=True)
        if self.checkpoint.pending_actions():
            raise ControllerFailure("pending_action_reconciliation",
                RuntimeError("unfinished action requires explicit reconciliation"), action=action)
        number = sum(event["kind"] == "action_started" for event in self.checkpoint.events)
        if number >= self.budget.max_trials:
            return {"error": "controller_trial_budget_exhausted"}
        action_id = "action_" + digest({"number": number, "action": action, "payload": payload})[:24]
        try:
            self.checkpoint.append("action_started", {"action_id": action_id, "action": action, "request": payload})
        except Exception as error:
            raise ControllerFailure("start_action", error, action=action, action_id=action_id) from error
        try:
            response = function()
        except Exception as error:
            response = {"error": type(error).__name__, "detail": str(error), "generation_allowed": False,
                "diagnoses": [{"root_cause": "controller_action_failed", "code": "service_exception",
                    "action": action, "error": type(error).__name__, "detail": str(error), "recovery_allowed": False}]}
        if not isinstance(response, dict):
            raise ControllerFailure("validate_response", TypeError("service response must be an object"),
                                    action=action, action_id=action_id, observed_response=response)
        response = deepcopy(response)
        try:
            if hasattr(self.services, "collect_pending_accounting"):
                collected = self.services.collect_pending_accounting()
                if not isinstance(collected, list):
                    raise ValueError("pending accounting must be a list")
                response.setdefault("accounting", []).extend(collected)
        except Exception as error:
            raise ControllerFailure("collect_accounting", error, action=action, action_id=action_id,
                                    observed_response=response) from error
        try:
            accounting = response.get("accounting", [])
            if not isinstance(accounting, list):
                raise ValueError("response accounting must be a list")
            seen = {}
            for row in accounting:
                normalized = self.ledger.validate(row["stage_id"], row["metadata"])
                if row["stage_id"] in seen and seen[row["stage_id"]] != normalized:
                    raise ValueError("action accounting contains conflicting stage IDs")
                seen[row["stage_id"]] = normalized
            response_digest = digest(response)
        except Exception as error:
            raise ControllerFailure("validate_response", error, action=action, action_id=action_id,
                                    observed_response=response) from error
        try:
            self.checkpoint.append("action_finished", {"action_id": action_id, "action": action,
                "response_digest": response_digest, "response": response})
        except Exception as error:
            raise ControllerFailure("publish_action", error, action=action, action_id=action_id,
                                    observed_response=response) from error
        try:
            for row in accounting:
                self.ledger.record(row["stage_id"], row["metadata"])
        except Exception as error:
            raise ControllerFailure("record_accounting", error, action=action, action_id=action_id,
                                    observed_response=response) from error
        return response

    def run(self, candidates=None):
        try:
            if self.initialization_error is not None:
                raise ControllerFailure("ledger_initialization", self.initialization_error, authentication=True)
            return self._run(candidates)
        except ControllerFailure as failure:
            return self._failure_result(failure)
        except Exception as error:
            return self._failure_result(ControllerFailure("controller_run", error))
