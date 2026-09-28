#!/usr/bin/env python3
"""Explicit real DeepSeek smoke, never a fallback to a fake semantic model."""
import argparse
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from harness_generation.artifacts import ArtifactStore
from harness_generation.semantic_discovery.cli import main
from harness_generation.semantic_discovery.models import candidate_id


def smoke(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--candidate", required=True, help="Recorded function ID or candidate ID")
    parser.add_argument("--model")
    args = parser.parse_args(argv)
    if not os.environ.get("DEEPSEEK_API_KEY", "").strip():
        print("Real DeepSeek smoke NOT RUN: DEEPSEEK_API_KEY is not configured.", file=sys.stderr)
        return 2
    store = ArtifactStore(args.artifacts)
    catalog = store.load_candidate_catalog()
    if catalog is None:
        print("Run candidate discovery first.", file=sys.stderr)
        return 2
    matches = [c for c in catalog.candidates if args.candidate in {c.function_id, candidate_id(c.function_id)}]
    if len(matches) != 1:
        print("Candidate ID is not recorded.", file=sys.stderr)
        return 2
    command = ["--artifacts", str(args.artifacts), "--provider", "deepseek",
               "--candidate", args.candidate, "--max-candidates", "1",
               "--max-rounds", "6", "--max-tool-calls", "12"]
    if args.model:
        command += ["--model", args.model]
    if main(command) != 0:
        return 1
    directory = store.candidate_agent_run(candidate_id(matches[0].function_id))
    trace = json.loads((directory / "trace.json").read_text())
    result = json.loads((directory / "result.json").read_text())
    metadata = json.loads((directory / "metadata.json").read_text())
    if (not any(e["kind"] == "tool_call" and e["result_evidence_ids"] for e in trace["events"])
            or metadata["termination"] != "final_decision"
            or result["model"]["provider"] != "deepseek"):
        print("Real smoke failed: expected source tool roundtrip and a valid final JSON decision.", file=sys.stderr)
        return 1
    print(f"Real DeepSeek smoke passed: tool roundtrip, structured verdict={result['verdict']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(smoke())
