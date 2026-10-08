"""Shared bounded tool loop: task validators own all semantic decisions."""
from __future__ import annotations

from dataclasses import dataclass, field
import json

from .models import AgentModelResponse, DecisionSchemaError, TerminalSelectionError, canonical
from .tools import ToolBudgetExceeded
from .request_diagnostics import classify_error, request_observation

TERMINAL_REPAIR_POLICY_VERSION = 'terminal-only-resubmission-v4'
EXTRA_TERMINAL_REPAIR_CATEGORIES = frozenset({
    'terminal_schema_error', 'terminal_json_parse_error',
    'slice_role_choice_not_issued', 'candidate_unknown_evidence_reference',
    'terminal_native_submission_missing'})


@dataclass
class LoopOutcome:
    decision: dict | None = None
    termination: str = "invalid_output"
    rounds: int = 0
    tool_calls: int = 0
    model_calls: int = 0
    exhausted: bool = False
    messages: list = field(default_factory=list)
    events: list = field(default_factory=list)
    terminal_submission_attempts: int = 0
    schema_repair_attempted: bool = False
    schema_repair_success: bool = False
    initial_schema_errors: list = field(default_factory=list)
    protocol_recoveries: int = 0
    provider_recoveries: int = 0
    semantic_recoveries: int = 0
    extra_terminal_repair_attempts: int = 0
    extra_terminal_repair_success: bool = False
    terminal_correction_attempts: int = 0
    terminal_correction_operations: list = field(default_factory=list)
    terminal_repair_policy_version: str = TERMINAL_REPAIR_POLICY_VERSION
    terminal_repair_allowed_categories: list = field(default_factory=list)
    extra_terminal_repair_last_round_only: bool = False
    # Optional executor revocation is separate from historical native repairs.
    # Leave repair_audit's existing native wire shape unchanged.
    submission_revoked: bool = False
    submission_revocation_reason: str | None = None

    def repair_audit(self):
        return {name: getattr(self, name) for name in (
            "terminal_submission_attempts", "schema_repair_attempted", "schema_repair_success", "initial_schema_errors", "protocol_recoveries", "provider_recoveries", "semantic_recoveries", "extra_terminal_repair_attempts", "extra_terminal_repair_success", "terminal_correction_attempts", "terminal_correction_operations", "terminal_repair_policy_version", "terminal_repair_allowed_categories", "extra_terminal_repair_last_round_only")}


class BoundedAgentLoop:
    def __init__(self, model, budget, terminal_schema, validator, *, max_terminal_repairs=0,
                 allow_text_terminal=False, reserve_terminal_round=False, stage=None, terminal_schema_factory=None,
                 max_protocol_recoveries=0, terminal_guidance_factory=None, max_provider_recoveries=0,
                 max_semantic_recoveries=0,
                 terminal_repair_categories=("terminal_schema_error",),
                 extra_terminal_repair_last_round_only=False):
        if type(max_terminal_repairs) is not int or max_terminal_repairs not in {0, 1}:
            raise ValueError("max_terminal_repairs must be 0 or 1")
        self.model, self.budget, self.terminal_schema = model, budget, terminal_schema
        self.validator = validator
        self.terminal_name = terminal_schema["function"]["name"]
        self.max_terminal_repairs, self.allow_text_terminal = max_terminal_repairs, allow_text_terminal
        self.reserve_terminal_round = reserve_terminal_round
        self.stage = stage or terminal_schema["function"]["name"]
        self.terminal_schema_factory = terminal_schema_factory
        self.terminal_guidance_factory = terminal_guidance_factory
        if type(max_protocol_recoveries) is not int or max_protocol_recoveries not in {0, 1}:
            raise ValueError("max_protocol_recoveries must be 0 or 1")
        self.max_protocol_recoveries = max_protocol_recoveries
        if type(max_provider_recoveries) is not int or max_provider_recoveries not in {0, 1}:
            raise ValueError("max_provider_recoveries must be 0 or 1")
        self.max_provider_recoveries = max_provider_recoveries
        if type(max_semantic_recoveries) is not int or max_semantic_recoveries not in {0, 1}:
            raise ValueError("max_semantic_recoveries must be 0 or 1")
        self.max_semantic_recoveries = max_semantic_recoveries
        if (not isinstance(terminal_repair_categories, (tuple, list))
                or any(not isinstance(c, str) or c not in EXTRA_TERMINAL_REPAIR_CATEGORIES
                       for c in terminal_repair_categories)
                or len(set(terminal_repair_categories)) != len(terminal_repair_categories)):
            raise ValueError('terminal_repair_categories must be a unique registered allowlist')
        self.terminal_repair_categories = tuple(terminal_repair_categories)
        if type(extra_terminal_repair_last_round_only) is not bool:
            raise ValueError('extra_terminal_repair_last_round_only must be boolean')
        self.extra_terminal_repair_last_round_only = extra_terminal_repair_last_round_only

    def run(self, messages, tools, *, initial_tool_calls=0, initial_events=()):
        outcome = LoopOutcome(messages=list(messages), tool_calls=initial_tool_calls,
                              events=list(initial_events),
                              terminal_repair_allowed_categories=list(self.terminal_repair_categories),
                              extra_terminal_repair_last_round_only=self.extra_terminal_repair_last_round_only)
        seen_calls = {event["tool_call_id"] for event in initial_events if "tool_call_id" in event}
        recovering = False
        for number in range(1, self.budget.max_rounds + 1):
            outcome.rounds = number
            if self.terminal_schema_factory:
                refreshed = self.terminal_schema_factory()
                if refreshed["function"]["name"] != self.terminal_name:
                    raise ValueError("terminal identity cannot change during investigation")
                self.terminal_schema = refreshed
            final_only = recovering or self.reserve_terminal_round and number == self.budget.max_rounds
            if self.terminal_guidance_factory and (final_only or number == self.budget.max_rounds - 1):
                outcome.messages.append({"role": "user", "content": canonical({
                    "terminal_guidance": self.terminal_guidance_factory(),
                    "remaining_ordinary_rounds": self.budget.max_rounds - number + 1,
                    "next_action": "submit_only_terminal_now" if final_only else
                        ("finish_only_necessary_source_reads_or_submit; next_round_is_terminal_only"
                         if self.reserve_terminal_round else
                         "finish_only_necessary_source_reads_or_submit; submit_before_remaining_rounds_expire")})})
            if final_only:
                outcome.messages.append({"role": "user", "content": "Terminal-only budgeted round: submit the terminal tool now using issued evidence, without prose or deliberation. Preserve unknown contracts as unresolved. Correct all reported validation errors. No further repository investigation is available."})
            response = self._complete(outcome, [self.terminal_schema] if final_only else tools.schemas + [self.terminal_schema], "terminal_budget" if final_only else "exploration")
            if response is None:
                failure = outcome.events[-1] if outcome.events else {}
                if (not final_only and number < self.budget.max_rounds
                        and outcome.provider_recoveries < self.max_provider_recoveries
                        and failure.get("kind") == "model_error"
                        and failure.get("error_category") in {"timeout", "http_429", "http_5xx"}):
                    outcome.provider_recoveries += 1
                    outcome.events.append({"round": number, "kind": "provider_recovery",
                        "error_category": failure["error_category"],
                        "failed_model_call": outcome.model_calls,
                        "remaining_rounds": self.budget.max_rounds - number,
                        "within_existing_budget": True})
                    outcome.messages.append({"role": "user", "content": canonical({
                        "provider_recovery": failure["error_category"],
                        "remaining_ordinary_rounds": self.budget.max_rounds - number,
                        "instruction": "The request failed before a response. Continue this same investigation in the next existing budgeted round using already issued evidence; no new evidence was issued by the failed request."})})
                    continue
                break
            truncated = response.metadata.get("finish_reason") == "length"
            no_submission = not response.tool_calls and not self.allow_text_terminal
            if (no_submission and not truncated and number == self.budget.max_rounds
                    and response.metadata.get('finish_reason') in {'stop', 'tool_calls'}
                    and 'terminal_native_submission_missing' in self.terminal_repair_categories):
                # Completed zero-call prose never becomes a decision. The
                # shared registered extra permits one explicit native answer.
                outcome.termination = 'invalid_output'
                feedback = {'error': 'native_terminal_not_submitted',
                            'instruction': 'Submit the registered native terminal tool explicitly; prior prose was not accepted.'}
                outcome.events.append({'round': number, 'kind': 'execution_error',
                    'error_category': 'terminal_native_submission_missing', **feedback})
                self._extra_terminal_repair('terminal_native_submission_missing', feedback, tools, outcome, seen_calls)
                break
            if (truncated or no_submission) and self.max_protocol_recoveries:
                # Never execute/accept a partial response. Recovery consumes a
                # remaining ordinary round; it cannot increase the call budget.
                valid_ids = all(isinstance(c.id, str) and c.id and len(c.id) <= 512
                    and c.id not in seen_calls for c in response.tool_calls)
                if valid_ids:
                    valid_ids = len({c.id for c in response.tool_calls}) == len(response.tool_calls)
                if not valid_ids:
                    outcome.termination = "invalid_output"
                    break
                for call in response.tool_calls:
                    seen_calls.add(call.id)
                    outcome.messages.append({"role": "tool", "tool_call_id": call.id,
                        "content": canonical({"error": "truncated_response_not_executed"})})
                outcome.events.append({"round": number, "kind": "protocol_recovery",
                    "reason": "output_truncated" if truncated else "native_terminal_not_submitted",
                    "remaining_rounds": self.budget.max_rounds - number})
                if (number == self.budget.max_rounds or
                        outcome.protocol_recoveries >= self.max_protocol_recoveries):
                    outcome.termination = "invalid_output"
                    break
                outcome.protocol_recoveries += 1
                self._correction_operation(outcome, 'output_protocol', extra=False)
                outcome.messages.append({"role": "user", "content":
                    "The previous response was not accepted. Submit the native terminal tool as the sole call, "
                    "without prose. Use only already issued choices/evidence; preserve unproved items as unresolved."})
                recovering = True
                continue
            submissions = [c for c in response.tool_calls if c.name == self.terminal_name]
            if submissions or not response.tool_calls:
                if not submissions and not self.allow_text_terminal:
                    outcome.termination = "invalid_output"
                    break
                self._terminal(response, submissions, tools, outcome, seen_calls)
                failure = outcome.events[-1] if outcome.events else {}
                if (outcome.decision is None and outcome.termination == 'invalid_output'
                        and submissions and not outcome.extra_terminal_repair_attempts
                        and failure.get('error_category') == 'terminal_json_parse_error'
                        and number < self.budget.max_rounds
                        and outcome.protocol_recoveries < self.max_protocol_recoveries):
                    # JSON syntax belongs to the native terminal envelope.
                    # Never repair its bytes, infer fields or accept a prefix.
                    # One new explicit submission spends the existing protocol
                    # allowance and a remaining ordinary terminal-only round.
                    outcome.protocol_recoveries += 1
                    self._correction_operation(outcome, failure['error_category'], extra=False)
                    outcome.events.append({'round': number, 'kind': 'protocol_recovery',
                        'reason': 'malformed_terminal_json',
                        'remaining_rounds': self.budget.max_rounds - number,
                        'within_existing_budget': True})
                    outcome.messages.append({'role': 'user', 'content':
                        'The native terminal arguments were malformed JSON and were not accepted. '
                        'Submit one new complete terminal call as the sole call, using only already issued choices/evidence. '
                        'Keep the payload compact; one selected choice per subject, short explicit missing-proof questions. '
                        'No prose, invented fields, inferred claims, automatic prefix completion or repository tools.'})
                    recovering = True
                    continue
                if (outcome.decision is None and outcome.termination == 'invalid_output'
                        and submissions and not outcome.extra_terminal_repair_attempts
                        and failure.get('error_category') == 'terminal_validation_error'
                        and number < self.budget.max_rounds
                        and outcome.semantic_recoveries < self.max_semantic_recoveries):
                    # A new explicit submission must pass the same strict
                    # validator. Never carry invalid rows forward as decisions.
                    outcome.semantic_recoveries += 1
                    self._correction_operation(outcome, failure.get('terminal_repair_category', 'terminal_validation_error'), extra=False)
                    outcome.events.append({'round': number, 'kind': 'semantic_recovery',
                        'reason': 'terminal_validation_error',
                        'remaining_rounds': self.budget.max_rounds - number,
                        'within_existing_budget': True})
                    outcome.messages.append({'role': 'user', 'content':
                        'The terminal submission failed strict validation and was not accepted. '
                        'Correct every reported validation error and submit the complete native terminal tool as the sole call. '
                        'Use only already issued choices/evidence. Preserve unproved claims as unresolved; do not invent proof. '
                        'No repository tools are available for this correction.'})
                    recovering = True
                    continue
                if (outcome.termination == 'invalid_output' and not outcome.extra_terminal_repair_attempts
                        and outcome.initial_schema_errors
                        and submissions and failure.get('schema_errors')
                        and self.max_protocol_recoveries and number < self.budget.max_rounds
                        and outcome.protocol_recoveries < self.max_protocol_recoveries):
                    # Shape repair uses one remaining ordinary round. Evidence
                    # and semantic failures do not qualify; no extra call or
                    # source/tool budget is created for the repair.
                    outcome.protocol_recoveries += 1
                    self._correction_operation(outcome, failure['error_category'], extra=False)
                    outcome.events.append({'round': number, 'kind': 'protocol_recovery',
                        'reason': 'terminal_schema_error', 'remaining_rounds': self.budget.max_rounds - number})
                    outcome.messages.append({'role': 'user', 'content':
                        'Correct only the reported terminal schema errors and resubmit the native terminal tool. '
                        'Keep unproved roles unresolved and supply their missing-proof questions. No repository tools are available.'})
                    recovering = True
                    continue
                break
            if final_only:
                outcome.exhausted, outcome.termination = True, "terminal_round_without_submission"
                break
            if response.content:
                try:
                    mixed = json.loads(response.content)
                except (TypeError, ValueError):
                    mixed = None
                if isinstance(mixed, dict) and any(k in mixed for k in ("verdict", "classification")):
                    break
            stopped = False
            for call in response.tool_calls:
                if outcome.tool_calls >= self.budget.max_tool_calls:
                    outcome.exhausted, outcome.termination, stopped = True, "max_tool_calls", True
                    break
                outcome.tool_calls += 1
                if not self._valid_call(call, seen_calls, 8192):
                    outcome.events.append({"kind": "execution_error", "error_category": "tool_call_parse_error"})
                    outcome.termination, stopped = "invalid_output", True
                    break
                seen_calls.add(call.id)
                try:
                    arguments = json.loads(call.arguments)
                except (TypeError, ValueError):
                    arguments = None
                    outcome.events.append({"kind": "execution_error", "error_category": "tool_call_parse_error"})
                tool_executed = True
                try:
                    output = tools.execute(call.name, arguments)
                except ToolBudgetExceeded as error:
                    outcome.exhausted, outcome.termination, stopped = True, error.args[0], True
                    output = {"error": "budget_exhausted", "evidence_ids": []}
                    tool_executed = getattr(error, "tool_executed", True)
                outcome.events.append({"round": number, "kind": "tool_call", "tool_call_id": call.id,
                    "tool": call.name, "arguments": arguments, "result_evidence_ids": output["evidence_ids"],
                    "tool_executed": tool_executed,
                    "error": output.get("error"), "query_truncated": output.get("query_truncated", False)})
                outcome.messages.append({"role": "tool", "tool_call_id": call.id, "content": canonical(output)})
                if stopped:
                    break
            if stopped:
                break
            if number == self.budget.max_rounds:
                outcome.exhausted, outcome.termination = True, "max_rounds"
        return outcome

    def _complete(self, outcome, schemas, phase):
        outcome.model_calls += 1
        try:
            response = self.model.complete(outcome.messages, json.loads(canonical(schemas)))
        except Exception as error:
            category = classify_error(error)
            if getattr(error, "model_call", None) is False:
                # Explicit pretransport failures issue no provider request,
                # including failures inside the extra terminal repair.
                outcome.model_calls -= 1
                if category == "budget_exhausted":
                    outcome.exhausted = True
                    outcome.termination = getattr(error, "budget_stop_reason", "budget_exhausted")
                    outcome.events.append({"round": outcome.rounds, "phase": phase,
                        "kind": "budget_stop", "reason": outcome.termination,
                        "provider_request": False, "model_call": False})
                else:
                    outcome.termination = "invalid_output"
                    outcome.events.append({"round": outcome.rounds, "phase": phase,
                        "kind": "execution_error", "error": "pretransport_model_failure",
                        "error_category": category, "provider_request": False, "model_call": False})
                return None
            outcome.termination = "budget_exhausted" if category == "budget_exhausted" else "provider_error"
            status = getattr(error, "http_status", None)
            diagnostic = dict(getattr(error, "diagnostics", {}))
            model = getattr(self.model, "model", None)
            if not isinstance(model, str):
                model = getattr(model, "model", "unspecified")
            diagnostic = {**request_observation(model, outcome.messages, schemas), **diagnostic,
                "stage": self.stage, "phase": phase, "attempt_number": outcome.model_calls,
                "error_category": category}
            outcome.events.append({"round": outcome.rounds, "phase": phase, "kind": "model_error",
                                   "error": outcome.termination, "error_category": category, "diagnostics": diagnostic,
                                   **({"repair_error_category": "terminal_repair_error"} if phase == "terminal_repair" else {}),
                                   **({"http_status": status} if type(status) is int and 100 <= status <= 599 else {})})
            return None
        if not isinstance(response, AgentModelResponse):
            outcome.termination = "invalid_output"
            outcome.events.append({"kind": "execution_error", "error_category": "invalid_response"})
            return None
        outcome.messages.append(response.assistant_message())
        metadata = {key: response.metadata[key] for key in
                    ("usage", "response_id", "finish_reason", "served_model", "request_diagnostics") if key in response.metadata}
        outcome.events.append({"round": outcome.rounds, "phase": phase, "model_call": outcome.model_calls,
                               "kind": "model_response", "metadata": metadata})
        return response

    @staticmethod
    def _validation_feedback(error):
        output = {"error": "terminal_validation_failed", "detail": str(error)[:1024]}
        if callable(getattr(error, "to_dict", None)):
            diagnostic = error.to_dict()
            if isinstance(diagnostic, dict):
                output["validation_diagnostics"] = diagnostic
        return output

    @staticmethod
    def _valid_call(call, seen, limit):
        return (isinstance(call.id, str) and bool(call.id) and len(call.id) <= 512 and call.id not in seen
                and isinstance(call.name, str) and isinstance(call.arguments, str) and len(call.arguments) <= limit)

    def _terminal(self, response, submissions, tools, outcome, seen, *, allow_extra=True):
        call = submissions[0] if submissions else None
        if call and (response.metadata.get('finish_reason') == 'length'
                     or len(response.tool_calls) != 1 or not self._valid_call(call, seen, 64000)):
            outcome.termination = "invalid_output"
            outcome.events.append({"kind": "execution_error", "error_category": "tool_call_parse_error"})
            return
        if call:
            seen.add(call.id)
        outcome.terminal_submission_attempts += 1
        event = {"round": outcome.rounds, "kind": "decision_submission",
                 **({"phase": "terminal_repair"} if not allow_extra else {})}
        if call:
            event["tool_call_id"] = call.id
            outcome.events.append(event)
        if call:
            try:
                json.loads(call.arguments)
            except json.JSONDecodeError as error:
                # Parse only the sole authenticated native tool envelope here.
                # A JSONDecodeError raised inside a validator for an already
                # well-formed payload is still a semantic validation failure.
                output = {'error': 'malformed_terminal_json', 'detail': error.msg,
                    'json_location': {'line': error.lineno, 'column': error.colno, 'position': error.pos},
                    'arguments_chars': len(call.arguments),
                    'instruction': 'Resubmit complete JSON explicitly; the framework does not complete the prefix.'}
                outcome.events.append({'round': outcome.rounds, 'kind': 'execution_error',
                    'error_category': 'terminal_json_parse_error', **output})
                outcome.messages.append({'role': 'tool', 'tool_call_id': call.id, 'content': canonical(output)})
                outcome.termination = 'invalid_output'
                if allow_extra:
                    self._extra_terminal_repair('terminal_json_parse_error', output, tools, outcome, seen)
                return
        schema_error = None
        schema_extra_allowed = True
        validation_error = None
        selection_category = None
        try:
            outcome.decision = self.validator(call.arguments if call else response.content)
            outcome.termination = "final_decision"
        except DecisionSchemaError as error:
            schema_error = error.to_dict()
            schema_extra_allowed = getattr(error, 'terminal_extra_repair_allowed', True) is True
            current_errors = schema_error.get("errors", [schema_error])
            if not outcome.initial_schema_errors:
                outcome.initial_schema_errors = current_errors
            outcome.events.append({"kind": "execution_error", "error_category": "terminal_schema_error",
                                   "schema_errors": current_errors,
                                   "terminal_extra_repair_allowed": schema_extra_allowed})
            outcome.termination = "invalid_output"
        except (ValueError, TypeError) as error:
            validation_error = self._validation_feedback(error)
            selection_category = getattr(error, "terminal_repair_category", None) if isinstance(error, TerminalSelectionError) else None
            if selection_category in self.terminal_repair_categories:
                validation_error["terminal_repair_category"] = selection_category
            outcome.events.append({"kind": "execution_error", "error_category": "terminal_validation_error",
                                   **validation_error})
            outcome.termination = "invalid_output"
        if call:
            output = schema_error or validation_error or {"decision_status": "validated" if outcome.decision else "invalid"}
            outcome.messages.append({"role": "tool", "tool_call_id": call.id, "content": canonical(output)})
        if allow_extra and call and ((schema_error and schema_extra_allowed) or selection_category in self.terminal_repair_categories):
            category = 'terminal_schema_error' if schema_error else selection_category
            self._extra_terminal_repair(category, schema_error or validation_error, tools, outcome, seen)

    @staticmethod
    def _correction_operation(outcome, category, *, extra):
        outcome.terminal_correction_attempts += 1
        operation = {'operation': outcome.terminal_correction_attempts,
            'category': category, 'extra': extra,
            'next_model_call': outcome.model_calls + 1,
            'ordinary_round': outcome.rounds if extra else outcome.rounds + 1,
            'terminal_only': True}
        outcome.terminal_correction_operations.append(operation)
        return operation

    def _extra_terminal_repair(self, category, feedback, tools, outcome, seen):
        # The legacy schema allowance remains one shared extra operation. Newly
        # registered parse/selection categories qualify only at the last
        # ordinary round, after all ordinary budget has been used.
        if (category not in self.terminal_repair_categories
                or outcome.extra_terminal_repair_attempts >= self.max_terminal_repairs
                or ((self.extra_terminal_repair_last_round_only or category != 'terminal_schema_error')
                    and outcome.rounds < self.budget.max_rounds)):
            return
        outcome.extra_terminal_repair_attempts += 1
        outcome.schema_repair_attempted = category == 'terminal_schema_error'
        operation = self._correction_operation(outcome, category, extra=True)
        outcome.events.append({'round': outcome.rounds, 'phase': 'terminal_repair',
            'kind': 'extra_terminal_repair', 'reason': category,
            'shared_extra_attempt': outcome.extra_terminal_repair_attempts,
            'policy_version': TERMINAL_REPAIR_POLICY_VERSION,
            'max_extra_terminal_repairs': self.max_terminal_repairs,
            'extra_terminal_repair_last_round_only': self.extra_terminal_repair_last_round_only,
            'ordinary_round_limit': self.budget.max_rounds, 'operation': operation})
        legacy_schema_extra = category == 'terminal_schema_error' and not self.extra_terminal_repair_last_round_only
        if self.terminal_guidance_factory and not legacy_schema_extra:
            outcome.messages.append({'role': 'user', 'content': canonical({
                'terminal_guidance': self.terminal_guidance_factory(),
                'remaining_ordinary_rounds': 0 if outcome.rounds == self.budget.max_rounds else self.budget.max_rounds-outcome.rounds,
                'extra_terminal_repair_remaining': 0})})
        if not legacy_schema_extra:
            outcome.messages.append({'role': 'user', 'content': canonical({
                'terminal_only_resubmission': category,
                'policy_version': TERMINAL_REPAIR_POLICY_VERSION,
                'strict_validation_feedback': feedback,
                'instruction': 'One explicit complete native terminal call only. Use only already issued choices/evidence; '
                    'copy exact identifiers, choose every role/verdict yourself, and provide every required field. '
                    'Preserve unproved claims as unresolved with short concrete missing-proof questions. '
                    'No repository tools, new source, prose, automatic byte/ID/role/field repair, or changes to budgets.'})})
        repair = self._complete(outcome, [self.terminal_schema], 'terminal_repair')
        if repair is None:
            return
        calls = repair.tool_calls
        if (repair.metadata.get('finish_reason') == 'length' or len(calls) != 1
                or calls[0].name != self.terminal_name or not self._valid_call(calls[0], seen, 64000)):
            outcome.termination = 'invalid_output'
            outcome.events.append({'round': outcome.rounds, 'kind': 'repair_rejected',
                'error': 'repair_requires_only_terminal_submission',
                'error_category': 'terminal_repair_error'})
            return
        self._terminal(repair, calls, tools, outcome, seen, allow_extra=False)
        outcome.extra_terminal_repair_success = outcome.decision is not None
        outcome.schema_repair_success = category == 'terminal_schema_error' and outcome.extra_terminal_repair_success
