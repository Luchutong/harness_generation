#!/usr/bin/env python3
"""Controlled bad terminal replay followed by exactly one REAL DeepSeek repair.

The first two responses are deliberately recorded stimuli, not live model output.
Repository evidence is gathered normally; only the repair response uses the API.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evaluate_candidate_validation_real import credential_environment
from harness_generation.artifacts import ArtifactStore
from harness_generation.semantic_discovery import (AgentModelResponse, AgentToolCall, CandidateValidationAgent,
    DeepSeekAgentModel, DeepSeekConfig, RepositoryTools, ValidationBudget)
from harness_generation.semantic_discovery.models import canonical
from harness_generation.semantic_discovery.persistence import run_configuration, save_run
from harness_generation.semantic_discovery.tools import RepositoryIndex
from harness_generation.sfg_adapter import load_sfg_artifacts


class ControlledErrorThenLiveRepair:
    provider = "deepseek"

    def __init__(self, live, anchor, feed):
        self.live, self.anchor, self.feed = live, anchor, feed
        self.config, self.model, self.calls = live.config, live.model, 0

    def complete(self, messages, tools):
        self.calls += 1
        if self.calls == 1:
            return AgentModelResponse(tool_calls=tuple(AgentToolCall(f"recorded_source_{i}", "get_function",
                canonical({"function": fid})) for i, fid in enumerate((self.anchor, self.feed))))
        if self.calls == 2:
            ids = [r["evidence_id"] for m in messages if m["role"] == "tool"
                   for r in json.loads(m["content"]).get("evidence", [])]
            return AgentModelResponse(tool_calls=(AgentToolCall("recorded_invalid_submission", "submit_candidate_decision",
                canonical({"verdict": "accepted", "input_mode": "context_feed", "reason_codes": ["context_feed"],
                           "evidence_ids": ids, "discovered_symbols": [], "open_questions": []})),))
        assert self.calls == 3 and [t["function"]["name"] for t in tools] == ["submit_candidate_decision"]
        return self.live.complete(messages, tools)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True, help="A parser-only hub Phase 1 snapshot containing parse/feed")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--credentials", type=Path, default=ROOT / ".env")
    args = parser.parse_args()
    source_store = ArtifactStore(args.artifacts)
    catalog = source_store.load_candidate_catalog()
    artifacts = load_sfg_artifacts(source_store.root)
    catalog.validate_against(artifacts)
    index = RepositoryIndex(artifacts, catalog, functions_path=source_store.functions)
    candidate = next(c for c in catalog.candidates if c.function == "parse")
    feed = next(c for c in catalog.candidates if c.function == "feed")
    environment = credential_environment(args.credentials)
    live = DeepSeekAgentModel(DeepSeekConfig.from_environment(environ=environment, thinking="disabled"), environ=environment)
    model = ControlledErrorThenLiveRepair(live, candidate.function_id, feed.function_id)
    budget = ValidationBudget(max_rounds=2, max_tool_calls=2)
    run = CandidateValidationAgent(model, budget).validate(candidate, RepositoryTools(artifacts, catalog, budget, index=index))
    run.metadata["experiment"] = "recorded_bad_submission_then_live_terminal_repair"
    run.metadata["live_model_calls"] = 1
    save_run(ArtifactStore(args.output), run, run_configuration(catalog, budget, model))
    print(canonical({"verdict": run.result["verdict"], "run_status": run.result["run_status"],
                     "budget": run.result["budget"], **run.trace.get("initial_schema_errors", [{}])[0],
                     **{key: run.metadata[key] for key in ("terminal_submission_attempts", "schema_repair_attempted", "schema_repair_success")}}))
    return 0 if run.metadata["schema_repair_success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
