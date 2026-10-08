"""Bounded Context policy driven by DSH, without a nested native loop.

DSH owns scheduling of registered calls. This policy owns the framework's
authoritative conversation, budgets, dynamic terminal and strict validator.
An internal SDK feedback call can observe ``action`` without issuing evidence,
charging a tool or making a model request.
"""
from __future__ import annotations

import json

from ..semantic_discovery.loop import BoundedAgentLoop, LoopOutcome, TERMINAL_REPAIR_POLICY_VERSION
from ..semantic_discovery.models import canonical
from ..semantic_discovery.tools import ToolBudgetExceeded


VERSION = "dsh-bounded-context-policy-v3"


class DSHContextPolicy:
    def __init__(self, *, model, budget, terminal, validator, messages, tools,
                 initial_tool_calls=0, initial_events=(), **policy_options):
        # Construction validates the registered limits, but its run method is
        # never called. Only its existing request/terminal primitives are used.
        self.helper = BoundedAgentLoop(model, budget, terminal, validator, **policy_options)
        self.tools, self.budget = tools, budget
        self.outcome = LoopOutcome(messages=list(messages), tool_calls=initial_tool_calls,
            events=list(initial_events),
            terminal_repair_allowed_categories=list(self.helper.terminal_repair_categories),
            extra_terminal_repair_last_round_only=self.helper.extra_terminal_repair_last_round_only)
        self.seen_calls = {event["tool_call_id"] for event in initial_events if "tool_call_id" in event}
        self.pending_calls = []
        self.done = False
        self.action = "continue"
        self._prepared = False
        self._schemas = []
        self._recovering = False
        self._extra_pending = False
        self._extra_active = False
        self._extra_category = None
        self._final_only = False
        self._response = None
        self._prepared_round = None

    @property
    def terminal_name(self):
        return self.helper.terminal_name

    def surface(self):
        """Observe the roster without reserving a turn or appending guidance."""
        if self.done:
            return []
        final_only = self._final_only if self._prepared else (self._extra_pending or self._recovering
            or self.helper.reserve_terminal_round and self.outcome.rounds + 1 >= self.budget.max_rounds)
        return ([self.helper.terminal_schema] if final_only else
            self.tools.schemas + [self.helper.terminal_schema])

    def prepare(self):
        """Refresh this turn's exact schema roster, without a provider call."""
        if self.done:
            return []
        if self.pending_calls:
            raise ValueError("previous model calls must execute before the next model turn")
        if self._prepared:
            return self._schemas
        self._extra_active, self._extra_pending = self._extra_pending, False
        if not self._extra_active:
            if self.outcome.rounds >= self.budget.max_rounds:
                self.outcome.exhausted, self.outcome.termination = True, "max_rounds"
                self._stop()
                return []
            self._prepared_round = self.outcome.rounds + 1
            if self.helper.terminal_schema_factory:
                refreshed = self.helper.terminal_schema_factory()
                if refreshed["function"]["name"] != self.terminal_name:
                    raise ValueError("terminal identity cannot change during investigation")
                self.helper.terminal_schema = refreshed
        if self._extra_active:
            self._prepared_round = self.outcome.rounds
        number = self._prepared_round
        self._final_only = (self._extra_active or self._recovering or
            self.helper.reserve_terminal_round and number == self.budget.max_rounds)
        if (not self._extra_active and self.helper.terminal_guidance_factory and
                (self._final_only or number == self.budget.max_rounds - 1)):
            self.outcome.messages.append({"role": "user", "content": canonical({
                "terminal_guidance": self.helper.terminal_guidance_factory(),
                "remaining_ordinary_rounds": self.budget.max_rounds - number + 1,
                "next_action": "submit_only_terminal_now" if self._final_only else
                    ("finish_only_necessary_source_reads_or_submit; next_round_is_terminal_only"
                     if self.helper.reserve_terminal_round else
                     "finish_only_necessary_source_reads_or_submit; submit_before_remaining_rounds_expire")})})
        if self._final_only and not self._extra_active:
            self.outcome.messages.append({"role": "user", "content":
                "Terminal-only budgeted round: submit the terminal tool now using issued evidence, without prose or deliberation. Preserve unknown contracts as unresolved. Correct all reported validation errors. No further repository investigation is available."})
        self._schemas = ([self.helper.terminal_schema] if self._final_only else
            self.tools.schemas + [self.helper.terminal_schema])
        self._prepared = True
        return self._schemas

    def complete(self):
        """Issue one guarded request; None means observe action via feedback."""
        schemas = self.prepare()
        if self.done:
            return None
        self.outcome.rounds = self._prepared_round
        self._prepared = False
        phase = "terminal_repair" if self._extra_active else "terminal_budget" if self._final_only else "exploration"
        response = self.helper._complete(self.outcome, schemas, phase)
        if response is None:
            failure = self.outcome.events[-1] if self.outcome.events else {}
            if (not self._final_only and self.outcome.rounds < self.budget.max_rounds
                    and self.outcome.provider_recoveries < self.helper.max_provider_recoveries
                    and failure.get("kind") == "model_error"
                    and failure.get("error_category") in {"timeout", "http_429", "http_5xx"}):
                self.outcome.provider_recoveries += 1
                self.outcome.events.append({"round": self.outcome.rounds, "kind": "provider_recovery",
                    "error_category": failure["error_category"], "failed_model_call": self.outcome.model_calls,
                    "remaining_rounds": self.budget.max_rounds - self.outcome.rounds,
                    "within_existing_budget": True})
                self.outcome.messages.append({"role": "user", "content": canonical({
                    "provider_recovery": failure["error_category"],
                    "remaining_ordinary_rounds": self.budget.max_rounds - self.outcome.rounds,
                    "instruction": "The request failed before a response. Continue this same investigation in the next existing budgeted round using already issued evidence; no new evidence was issued by the failed request."})})
                self.action = "continue"
            else:
                self._stop()
            return None
        self._response = response
        calls = response.tool_calls
        truncated = response.metadata.get("finish_reason") == "length"
        if self._extra_active:
            if (truncated or len(calls) != 1 or calls[0].name != self.terminal_name
                    or not self.helper._valid_call(calls[0], self.seen_calls, 64000)):
                self.outcome.termination = "invalid_output"
                self.outcome.events.append({"round": self.outcome.rounds, "kind": "repair_rejected",
                    "error": "repair_requires_only_terminal_submission", "error_category": "terminal_repair_error"})
                self._discard(calls, "repair_requires_only_terminal_submission")
                self._stop()
                return None
        elif not calls and not truncated and self.outcome.rounds == self.budget.max_rounds and (
                response.metadata.get("finish_reason") in {"stop", "tool_calls"}
                and "terminal_native_submission_missing" in self.helper.terminal_repair_categories):
            self.outcome.termination = "invalid_output"
            feedback = {"error": "native_terminal_not_submitted",
                "instruction": "Submit the registered native terminal tool explicitly; prior prose was not accepted."}
            self.outcome.events.append({"round": self.outcome.rounds, "kind": "execution_error",
                "error_category": "terminal_native_submission_missing", **feedback})
            if not self._schedule_extra("terminal_native_submission_missing", feedback):
                self._stop()
            return None
        elif truncated or not calls:
            self._protocol_failure(response, truncated)
            return None
        submissions = [call for call in calls if call.name == self.terminal_name]
        if submissions:
            if len(calls) != 1 or not self.helper._valid_call(submissions[0], self.seen_calls, 64000):
                self.helper._terminal(response, submissions, self.tools, self.outcome, self.seen_calls, allow_extra=False)
                self._discard(calls, "mixed_or_invalid_terminal_not_executed")
                self._stop()
                return None
            try:
                json.loads(submissions[0].arguments)
            except (TypeError, ValueError):
                # DSH preserves malformed arguments as a string. Handle the
                # original envelope here, so it receives native JSON feedback
                # instead of being rejected by SDK argument correlation.
                first = len(self.outcome.events)
                self.helper._terminal(response, submissions, self.tools, self.outcome,
                    self.seen_calls, allow_extra=False)
                if not self._extra_active:
                    for event in self.outcome.events[first:]:
                        if event.get("kind") == "decision_submission":
                            event.pop("phase", None)
                feedback = json.loads(self.outcome.messages[-1]["content"])
                if self._extra_active or not self._recover_terminal(feedback):
                    self._stop()
                return None
        elif self._final_only:
            self.outcome.exhausted, self.outcome.termination = True, "terminal_round_without_submission"
            self._discard(calls, "terminal_only_round")
            self._stop()
            return None
        elif response.content:
            try:
                mixed = json.loads(response.content)
            except (TypeError, ValueError):
                mixed = None
            if isinstance(mixed, dict) and any(key in mixed for key in ("verdict", "classification")):
                self._discard(calls, "mixed_text_decision_not_executed")
                self._stop()
                return None
        repository_names = {schema["function"]["name"] for schema in self.tools.schemas}
        if not submissions and any(not isinstance(call.name, str) or call.name not in repository_names
                                   for call in calls):
            # Reject the whole batch before the SDK sees a name for which it
            # has no executor. Its original IDs receive native feedback and
            # ordinary investigation can continue inside the existing budget.
            self._unknown_repository_batch(calls, repository_names)
            return None
        self.pending_calls = list(calls)
        self.action = "execute"
        return response

    def execute_named(self, name, arguments, tool_call_id=None):
        """Bind an SDK invocation to the next authenticated native call."""
        if self.done:
            return {"error": "investigation_stopped"}, True
        if not self.pending_calls:
            return self._invalid_sdk_call("sdk_call_without_native_submission")
        call = self.pending_calls[0]
        try:
            expected = json.loads(call.arguments)
            same_arguments = canonical(expected) == canonical(arguments)
        except (TypeError, ValueError):
            # Official 0.1.5rc1 parseArguments retains malformed strings and
            # maps the empty string to {}. The original native tool still
            # receives None and its usual schema error, with actual accounting.
            same_arguments = (arguments == call.arguments if call.arguments else arguments == {})
        if call.name != name or not same_arguments or tool_call_id is not None and call.id != tool_call_id:
            return self._invalid_sdk_call("sdk_call_differs_from_native_submission")
        return self.execute(call)

    def execute(self, call):
        """Execute one exact call once; return its JSON result and stop flag."""
        if self.done:
            return {"error": "investigation_stopped"}, True
        if not self.pending_calls or call != self.pending_calls[0]:
            return self._invalid_sdk_call("sdk_call_differs_from_native_submission")
        self.pending_calls.pop(0)
        if call.name == self.terminal_name:
            first = len(self.outcome.events)
            before_messages = len(self.outcome.messages)
            self.helper._terminal(self._response, [call], self.tools, self.outcome, self.seen_calls, allow_extra=False)
            # _terminal uses allow_extra=False for native extra operations; an
            # ordinary SDK turn must retain ordinary event provenance.
            if not self._extra_active:
                for event in self.outcome.events[first:]:
                    if event.get("kind") == "decision_submission":
                        event.pop("phase", None)
            output = {"decision_status": "validated" if self.outcome.decision is not None else "invalid"}
            for message in reversed(self.outcome.messages[before_messages:]):
                if message.get("role") == "tool" and message.get("tool_call_id") == call.id:
                    output = json.loads(message["content"])
                    break
            if self._extra_active:
                self.outcome.extra_terminal_repair_success = self.outcome.decision is not None
                self.outcome.schema_repair_success = (self._extra_category == "terminal_schema_error"
                    and self.outcome.extra_terminal_repair_success)
                self._stop()
            elif self.outcome.decision is not None:
                self._stop()
            elif not self._recover_terminal(output):
                self._stop()
            return output, self.done
        if self.outcome.tool_calls >= self.budget.max_tool_calls:
            self.outcome.exhausted, self.outcome.termination = True, "max_tool_calls"
            self._stop()
            return {"error": "budget_exhausted", "evidence_ids": []}, True
        self.outcome.tool_calls += 1
        if not self.helper._valid_call(call, self.seen_calls, 8192):
            return self._invalid_sdk_call("tool_call_parse_error")
        self.seen_calls.add(call.id)
        try:
            arguments = json.loads(call.arguments)
        except (TypeError, ValueError):
            arguments = None
            self.outcome.events.append({"kind": "execution_error", "error_category": "tool_call_parse_error"})
        tool_executed = True
        try:
            output = self.tools.execute(call.name, arguments)
        except ToolBudgetExceeded as error:
            self.outcome.exhausted, self.outcome.termination = True, error.args[0]
            output = {"error": "budget_exhausted", "evidence_ids": []}
            tool_executed = getattr(error, "tool_executed", True)
            self._stop()
        self.outcome.events.append({"round": self.outcome.rounds, "kind": "tool_call", "tool_call_id": call.id,
            "tool": call.name, "arguments": arguments, "result_evidence_ids": output["evidence_ids"],
            "tool_executed": tool_executed, "error": output.get("error"),
            "query_truncated": output.get("query_truncated", False)})
        self.outcome.messages.append({"role": "tool", "tool_call_id": call.id, "content": canonical(output)})
        if not self.pending_calls and not self.done:
            if self.outcome.rounds == self.budget.max_rounds:
                self.outcome.exhausted, self.outcome.termination = True, "max_rounds"
                self._stop()
            else:
                self.action = "continue"
        return output, self.done

    def _unknown_repository_batch(self, calls, repository_names):
        """Reject a valid unknown-name batch without issuing source evidence."""
        valid = all(self.helper._valid_call(call, self.seen_calls, 8192)
                    and bool(call.name) and len(call.name) <= 512 for call in calls)
        valid = valid and len({call.id for call in calls}) == len(calls)
        if valid:
            from ..minimal_ft.persistence import _bad_constant, _unique_object
            try:
                for call in calls:
                    # Validate the original envelope; do not repair its bytes
                    # or execute parsed values from this rejected batch.
                    canonical(json.loads(call.arguments, object_pairs_hook=_unique_object,
                                         parse_constant=_bad_constant))
            except (TypeError, ValueError, RecursionError):
                valid = False
        self.outcome.termination = "invalid_output"
        if not valid:
            self.outcome.events.append({"round": self.outcome.rounds, "kind": "execution_error",
                "error_category": "tool_call_parse_error", "provider_request": False,
                "model_call": False, "tool_executed": False})
            self._discard(calls, "invalid_response_not_executed")
            self._stop()
            return
        for call in calls:
            self.seen_calls.add(call.id)
            output = {"data_class": "framework_protocol_feedback",
                "error": ("unknown_repository_tool" if call.name not in repository_names
                          else "repository_batch_not_executed"),
                "error_category": "unknown_repository_tool", "evidence_ids": [],
                "tool_executed": False,
                "instruction": "No call in this batch executed. Use only the registered repository tools; rejected tool names and arguments are not source evidence."}
            self.outcome.events.append({"round": self.outcome.rounds, "kind": "execution_error",
                "tool_call_id": call.id, "error_category": "unknown_repository_tool",
                "error": output["error"], "provider_request": False,
                "model_call": False, "tool_executed": False})
            self.outcome.messages.append({"role": "tool", "tool_call_id": call.id,
                "content": canonical(output)})
        if (self.outcome.rounds >= self.budget.max_rounds or
                self.outcome.protocol_recoveries >= self.helper.max_protocol_recoveries):
            self._stop()
            return
        self.outcome.protocol_recoveries += 1
        operation = self.helper._correction_operation(self.outcome, "unknown_repository_tool", extra=False)
        # This protocol correction allows repository investigation; the same
        # audit's terminal-only flag remains true for native terminal repairs.
        operation["terminal_only"] = False
        self.outcome.events.append({"round": self.outcome.rounds, "kind": "protocol_recovery",
            "reason": "unknown_repository_tool",
            "remaining_rounds": self.budget.max_rounds - self.outcome.rounds,
            "within_existing_budget": True, "operation": operation})
        self.outcome.messages.append({"role": "user", "content": canonical({
            "protocol_feedback": "unknown_repository_tool",
            "registered_repository_tools": sorted(repository_names),
            "remaining_ordinary_rounds": self.budget.max_rounds - self.outcome.rounds,
            "instruction": "The complete previous batch was rejected without tool execution or new evidence. Correct the tool selection explicitly and continue this investigation using registered tools or submit the terminal. Rejected names and arguments are not facts. Budgets are unchanged and the reserved terminal-only round still applies."})})
        self.action = "continue"

    def _protocol_failure(self, response, truncated):
        calls = response.tool_calls
        valid_ids = all(isinstance(call.id, str) and call.id and len(call.id) <= 512
            and call.id not in self.seen_calls for call in calls)
        valid_ids = valid_ids and len({call.id for call in calls}) == len(calls)
        if not self.helper.max_protocol_recoveries or not valid_ids:
            self.outcome.termination = "invalid_output"
            self._discard(calls, "invalid_response_not_executed")
            self._stop()
            return
        self._discard(calls, "truncated_response_not_executed")
        self.outcome.events.append({"round": self.outcome.rounds, "kind": "protocol_recovery",
            "reason": "output_truncated" if truncated else "native_terminal_not_submitted",
            "remaining_rounds": self.budget.max_rounds - self.outcome.rounds})
        if (self.outcome.rounds == self.budget.max_rounds
                or self.outcome.protocol_recoveries >= self.helper.max_protocol_recoveries):
            self.outcome.termination = "invalid_output"
            self._stop()
            return
        self.outcome.protocol_recoveries += 1
        self.helper._correction_operation(self.outcome, "output_protocol", extra=False)
        self.outcome.messages.append({"role": "user", "content":
            "The previous response was not accepted. Submit the native terminal tool as the sole call, without prose. Use only already issued choices/evidence; preserve unproved items as unresolved."})
        self._recovering, self.action = True, "continue"

    def _recover_terminal(self, feedback):
        failure = self.outcome.events[-1] if self.outcome.events else {}
        category = failure.get("error_category")
        extra_category = ("terminal_schema_error" if category == "terminal_schema_error"
            and failure.get("terminal_extra_repair_allowed", True) else
            failure.get("terminal_repair_category") if category == "terminal_validation_error" else
            "terminal_json_parse_error" if category == "terminal_json_parse_error" else None)
        if extra_category and self._schedule_extra(extra_category, feedback):
            return True
        if self.outcome.rounds >= self.budget.max_rounds:
            return False
        if category in {"terminal_json_parse_error", "terminal_schema_error"}:
            if self.outcome.protocol_recoveries >= self.helper.max_protocol_recoveries:
                return False
            self.outcome.protocol_recoveries += 1
            reason = "malformed_terminal_json" if category == "terminal_json_parse_error" else "terminal_schema_error"
            self.outcome.events.append({"round": self.outcome.rounds, "kind": "protocol_recovery",
                "reason": reason, "remaining_rounds": self.budget.max_rounds - self.outcome.rounds,
                "within_existing_budget": True})
        elif category == "terminal_validation_error":
            if self.outcome.semantic_recoveries >= self.helper.max_semantic_recoveries:
                return False
            self.outcome.semantic_recoveries += 1
            self.outcome.events.append({"round": self.outcome.rounds, "kind": "semantic_recovery",
                "reason": "terminal_validation_error", "remaining_rounds": self.budget.max_rounds - self.outcome.rounds,
                "within_existing_budget": True})
        else:
            return False
        self.helper._correction_operation(self.outcome, failure.get("terminal_repair_category", category), extra=False)
        self.outcome.messages.append({"role": "user", "content":
            "The native terminal was not accepted. Correct all reported validation errors and submit one complete sole native terminal call with already issued choices and evidence. Preserve unproved claims as unresolved. No repository tools are available for this correction."})
        self._recovering, self.action = True, "continue"
        return True

    def _schedule_extra(self, category, feedback):
        helper, outcome = self.helper, self.outcome
        if (category not in helper.terminal_repair_categories
                or outcome.extra_terminal_repair_attempts >= helper.max_terminal_repairs
                or ((helper.extra_terminal_repair_last_round_only or category != "terminal_schema_error")
                    and outcome.rounds < self.budget.max_rounds)):
            return False
        outcome.extra_terminal_repair_attempts += 1
        outcome.schema_repair_attempted = category == "terminal_schema_error"
        operation = helper._correction_operation(outcome, category, extra=True)
        outcome.events.append({"round": outcome.rounds, "phase": "terminal_repair", "kind": "extra_terminal_repair",
            "reason": category, "shared_extra_attempt": outcome.extra_terminal_repair_attempts,
            "policy_version": TERMINAL_REPAIR_POLICY_VERSION, "max_extra_terminal_repairs": helper.max_terminal_repairs,
            "extra_terminal_repair_last_round_only": helper.extra_terminal_repair_last_round_only,
            "ordinary_round_limit": self.budget.max_rounds, "operation": operation})
        legacy_schema_extra = category == "terminal_schema_error" and not helper.extra_terminal_repair_last_round_only
        if not legacy_schema_extra:
            if helper.terminal_guidance_factory:
                outcome.messages.append({"role": "user", "content": canonical({
                    "terminal_guidance": helper.terminal_guidance_factory(),
                    "remaining_ordinary_rounds": max(0, self.budget.max_rounds - outcome.rounds),
                    "extra_terminal_repair_remaining": 0})})
            outcome.messages.append({"role": "user", "content": canonical({
                "terminal_only_resubmission": category, "policy_version": TERMINAL_REPAIR_POLICY_VERSION,
                "strict_validation_feedback": feedback,
                "instruction": "One explicit complete native terminal call only. Use only already issued choices/evidence; copy exact identifiers, choose every role/verdict yourself, and provide every required field. Preserve unproved claims as unresolved with short concrete missing-proof questions. No repository tools, new source, prose, automatic byte/ID/role/field repair, or changes to budgets."})})
        self._extra_pending, self._extra_category, self.action = True, category, "continue"
        return True

    def _discard(self, calls, reason):
        for call in calls:
            if (isinstance(call.id, str) and call.id and len(call.id) <= 512
                    and call.id not in self.seen_calls):
                self.seen_calls.add(call.id)
                self.outcome.messages.append({"role": "tool", "tool_call_id": call.id,
                    "content": canonical({"error": reason})})

    def _invalid_sdk_call(self, reason):
        self.outcome.termination = "invalid_output"
        self.outcome.events.append({"round": self.outcome.rounds, "kind": "execution_error",
            "error_category": reason, "provider_request": False, "tool_executed": False})
        self._stop()
        return {"error": reason}, True

    def _stop(self):
        self.done, self.action = True, "stop"
        self.pending_calls = []

    def abort(self, reason):
        """Record an SDK/bridge stop without reclassifying prior provider calls."""
        self.outcome.decision = None
        self.outcome.submission_revoked = True
        self.outcome.submission_revocation_reason = reason
        self.outcome.termination = "invalid_output"
        self.outcome.events.append({"round": self.outcome.rounds, "kind": "execution_error",
            "error_category": reason, "provider_request": False, "tool_executed": False})
        self._stop()
