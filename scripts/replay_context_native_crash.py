#!/usr/bin/env python3
"""Replay saved native Context responses locally; never opens a provider client.

Use --code-root to select an archived implementation. Inputs stay read-only.
Exhausting saved responses is a diagnostic boundary, not model/Gate success.
"""
import argparse
import faulthandler
import gc
import json
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--code-root", type=Path)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--sdk-transport", action="store_true",
                        help="Parse saved envelopes through real OpenAI/httpx/pydantic using an offline transport")
    args = parser.parse_args()
    faulthandler.enable(all_threads=True)
    sys.path.insert(0, str((args.code_root or Path(__file__).resolve().parents[1]).resolve()))
    from harness_generation.minimal_ft.models import ProjectSnapshot
    from harness_generation.sfg_adapter import load_sfg_artifacts
    from harness_generation.harness_context.models import MiningState, ContextBudget
    from harness_generation.harness_context.loop import HarnessContextMiningLoop
    from harness_generation.harness_context.tools import HarnessContextTools
    from harness_generation.entry_candidates import CandidateCatalog
    from harness_generation.semantic_discovery.tools import RepositoryIndex
    from harness_generation.semantic_discovery.models import AgentModelResponse, AgentToolCall
    root = args.input.resolve()
    snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(root))
    ft = json.loads(next(root.glob("minimal_fts/*/minimal_ft.json")).read_text())
    responses = []
    for path in sorted(root.glob("harness_contexts/*/agent_runs/*/attempt_*/metadata.json"),
                       key=lambda p: p.stat().st_mtime_ns):
        metadata = json.loads(path.read_text())
        if not metadata.get("group_cost_owner", True):
            continue
        trace = json.loads((path.parent / "trace.json").read_text())
        messages = [m for m in trace["messages"] if m["role"] == "assistant" and not any(
            c["id"].startswith("framework_") for c in m.get("tool_calls", []))]
        events = [e for e in trace["events"] if e.get("kind") == "model_response"]
        assert len(messages) == len(events), path
        for message, event in zip(messages, events):
            calls = tuple(AgentToolCall(c["id"], c["function"]["name"], c["function"]["arguments"])
                          for c in message.get("tool_calls", []))
            responses.append(AgentModelResponse(message.get("content"), calls,
                message.get("reasoning_content"), event.get("metadata", {})))

    class ReplayBoundary(Exception):
        pass

    class ReplayModel:
        provider, model = "offline-saved-native", "offline-saved-native"
        def __init__(self):
            self.cursor = 0
            if args.sdk_transport:
                import httpx
                from openai import OpenAI
                from harness_generation.semantic_discovery.provider_config import CompatibleAgentModel
                from harness_generation.semantic_discovery.deepseek_client import DeepSeekConfig
                def respond(request):
                    response = responses[self.cursor]
                    self.cursor += 1
                    message = response.assistant_message()
                    metadata = response.metadata
                    return httpx.Response(200, json={'id': metadata.get('response_id', 'offline'),
                        'object': 'chat.completion', 'created': 0,
                        'model': metadata.get('served_model', 'offline'),
                        'choices': [{'index': 0, 'message': message,
                            'finish_reason': metadata.get('finish_reason', 'tool_calls')}],
                        'usage': metadata.get('usage', {})})
                client = OpenAI(api_key='offline-replay', base_url='http://offline.invalid/v1',
                    max_retries=0, http_client=httpx.Client(transport=httpx.MockTransport(respond)))
                self.adapter = CompatibleAgentModel(DeepSeekConfig(model='offline', max_tokens=8192),
                    client=client, environ={})
        def complete(self, messages, tools):
            print("REPLAY_RESPONSE", self.cursor + 1, flush=True)
            if self.cursor == len(responses):
                raise ReplayBoundary()
            if args.sdk_transport:
                return self.adapter.complete(messages, tools)
            response = responses[self.cursor]
            self.cursor += 1
            return response

    print("SAVED_RESPONSES", len(responses), "EXTERNAL_MODEL_CALLS", 0, flush=True)
    for repetition in range(args.repeat):
        print("REPETITION", repetition + 1, flush=True)
        state = MiningState(ContextBudget())
        model = ReplayModel()
        catalog = CandidateCatalog((), snapshot.source_fingerprint)
        index = RepositoryIndex(snapshot.artifacts, catalog, functions_path=root / "functions.json")
        tools = HarnessContextTools(snapshot, catalog, ft, state, index=index)
        def progress(requirement, result, reused, current):
            print("REPLAY_REQUIREMENT", requirement["subject_function_id"], requirement["kind"],
                  result["status"], current.model_calls, flush=True)
        run = HarnessContextMiningLoop(model, state, group_requirements=True).run(
            ft, snapshot, tools, on_requirement=progress)
        print("REPLAY_END", model.cursor, run.completeness["status"], run.metadata["termination"], flush=True)
        gc.collect()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
