"""Shared bounded tool loop: task validators own all semantic decisions."""
from __future__ import annotations

from dataclasses import dataclass, field
import json

from .models import AgentModelResponse, DecisionSchemaError, canonical
from .tools import ToolBudgetExceeded


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

    def repair_audit(self):
        return {name: getattr(self, name) for name in (
            "terminal_submission_attempts", "schema_repair_attempted", "schema_repair_success", "initial_schema_errors")}


class BoundedAgentLoop:
    def __init__(self, model, budget, terminal_schema, validator, *, max_terminal_repairs=0,
                 allow_text_terminal=False):
        if type(max_terminal_repairs) is not int or max_terminal_repairs not in {0, 1}:
            raise ValueError("max_terminal_repairs must be 0 or 1")
        self.model, self.budget, self.terminal_schema = model, budget, terminal_schema
        self.validator = validator
        self.terminal_name = terminal_schema["function"]["name"]
        self.max_terminal_repairs, self.allow_text_terminal = max_terminal_repairs, allow_text_terminal

    def run(self, messages, tools, *, initial_tool_calls=0, initial_events=()):
        outcome = LoopOutcome(messages=list(messages), tool_calls=initial_tool_calls,
                              events=list(initial_events))
        seen_calls = {event["tool_call_id"] for event in initial_events if "tool_call_id" in event}
        for number in range(1, self.budget.max_rounds + 1):
            outcome.rounds = number
            response = self._complete(outcome, tools.schemas + [self.terminal_schema], "exploration")
            if response is None:
                break
            submissions = [c for c in response.tool_calls if c.name == self.terminal_name]
            if submissions or not response.tool_calls:
                if not submissions and not self.allow_text_terminal:
                    outcome.termination = "invalid_output"
                    break
                self._terminal(response, submissions, tools, outcome, seen_calls)
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
                    outcome.termination, stopped = "invalid_output", True
                    break
                seen_calls.add(call.id)
                try:
                    arguments = json.loads(call.arguments)
                except (TypeError, ValueError):
                    arguments = None
                try:
                    output = tools.execute(call.name, arguments)
                except ToolBudgetExceeded as error:
                    outcome.exhausted, outcome.termination, stopped = True, error.args[0], True
                    output = {"error": "budget_exhausted", "evidence_ids": []}
                outcome.events.append({"round": number, "kind": "tool_call", "tool_call_id": call.id,
                    "tool": call.name, "arguments": arguments, "result_evidence_ids": output["evidence_ids"],
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
        except Exception:
            outcome.termination = "provider_error"
            outcome.events.append({"round": outcome.rounds, "phase": phase, "kind": "model_error",
                                   "error": "provider_error"})
            return None
        if not isinstance(response, AgentModelResponse):
            outcome.termination = "invalid_output"
            return None
        outcome.messages.append(response.assistant_message())
        metadata = {key: response.metadata[key] for key in
                    ("usage", "response_id", "finish_reason", "served_model") if key in response.metadata}
        outcome.events.append({"round": outcome.rounds, "phase": phase, "model_call": outcome.model_calls,
                               "kind": "model_response", "metadata": metadata})
        return response

    @staticmethod
    def _valid_call(call, seen, limit):
        return (isinstance(call.id, str) and bool(call.id) and len(call.id) <= 512 and call.id not in seen
                and isinstance(call.name, str) and isinstance(call.arguments, str) and len(call.arguments) <= limit)

    def _terminal(self, response, submissions, tools, outcome, seen):
        call = submissions[0] if submissions else None
        if call and (len(response.tool_calls) != 1 or not self._valid_call(call, seen, 64000)):
            outcome.termination = "invalid_output"
            return
        if call:
            seen.add(call.id)
        outcome.terminal_submission_attempts += 1
        event = {"round": outcome.rounds, "kind": "decision_submission"}
        if call:
            event["tool_call_id"] = call.id
            outcome.events.append(event)
        schema_error = None
        try:
            outcome.decision = self.validator(call.arguments if call else response.content)
            outcome.termination = "final_decision"
        except DecisionSchemaError as error:
            schema_error = error.to_dict()
            outcome.initial_schema_errors = [schema_error]
            outcome.termination = "invalid_output"
        except (ValueError, TypeError):
            outcome.termination = "invalid_output"
        if call:
            output = schema_error or {"decision_status": "validated" if outcome.decision else "invalid"}
            outcome.messages.append({"role": "tool", "tool_call_id": call.id, "content": canonical(output)})
        if schema_error and call and self.max_terminal_repairs:
            outcome.schema_repair_attempted = True
            outcome.events.append({"round": outcome.rounds, "phase": "terminal_repair", "kind": "schema_error",
                                   **schema_error})
            # A separate single model call: repository tools are not advertised,
            # executed or charged. The already gathered evidence is immutable.
            repair = self._complete(outcome, [self.terminal_schema], "terminal_repair")
            if repair is None:
                return
            calls = repair.tool_calls
            if (len(calls) != 1 or calls[0].name != self.terminal_name
                    or not self._valid_call(calls[0], seen, 64000)):
                outcome.termination = "invalid_output"
                outcome.events.append({"round": outcome.rounds, "kind": "repair_rejected",
                                       "error": "repair_requires_only_terminal_submission"})
                return
            call = calls[0]
            outcome.terminal_submission_attempts += 1
            outcome.events.append({"round": outcome.rounds, "phase": "terminal_repair",
                                   "kind": "decision_submission", "tool_call_id": call.id})
            try:
                outcome.decision = self.validator(call.arguments)
                outcome.termination, outcome.schema_repair_success = "final_decision", True
                output = {"decision_status": "validated"}
            except DecisionSchemaError as error:
                outcome.decision, outcome.termination = None, "invalid_output"
                output = error.to_dict()
            except (ValueError, TypeError):
                outcome.decision, outcome.termination = None, "invalid_output"
                output = {"decision_status": "invalid"}
            outcome.messages.append({"role": "tool", "tool_call_id": call.id, "content": canonical(output)})
