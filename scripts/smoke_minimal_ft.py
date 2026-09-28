#!/usr/bin/env python3
"""Build and resume four existing real Semantic Slices without model/source I/O."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path
import sys
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness_generation.artifacts import ArtifactStore
from harness_generation.minimal_ft import MinimalFTValidator, ProjectSnapshot
from harness_generation.minimal_ft.cli import main as minimal_ft_cli
from harness_generation.minimal_ft.persistence import load_legacy_inputs, load_slice_input
from harness_generation.records import write_json
from harness_generation.semantic_discovery import DeepSeekAgentModel, FakeAgentModel
from harness_generation.semantic_discovery.tools import RepositoryIndex
from harness_generation.sfg_adapter import load_sfg_artifacts
from sfg_builder.parser import CProjectParser

CASES = (("json_parser", "json_phase1"), ("direct_parser", "direct_phase1"),
         ("shared_context_hub", "hub_phase1"), ("wrapper_fixture", "fixture_phase1"))


def input_checksums(root):
    result = {}
    for path in sorted(root.rglob("*.json")):
        relative = path.relative_to(root)
        if relative.parts[0] == "minimal_fts":
            continue
        checksum = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                checksum.update(chunk)
        result[str(relative)] = checksum.hexdigest()
    return result


def forbidden(*args, **kwargs):
    raise AssertionError("Minimal FT smoke attempted a model call or repository rescan")


def evaluate(case, root):
    store = ArtifactStore(root)
    before = input_checksums(root)
    arguments = ["--artifacts", str(root)]
    output = StringIO()
    with redirect_stdout(output):
        build_exit = minimal_ft_cli(arguments)
    catalog = json.loads(store.minimal_ft_catalog.read_text(encoding="utf-8"))
    assert len(catalog["fts"]) == 1, (case, catalog)
    entry = catalog["fts"][0]
    directory = store.minimal_ft_run(entry["ft_id"])
    output_paths = [directory / "minimal_ft.json", directory / "metadata.json"]
    saved = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in output_paths}
    with redirect_stdout(output):
        resume_exit = minimal_ft_cli(arguments + ["--resume"])
    resume_preserved = all(saved[path] == (path.read_bytes(), path.stat().st_mtime_ns) for path in output_paths)
    document = json.loads(output_paths[0].read_text(encoding="utf-8"))
    metadata = json.loads(output_paths[1].read_text(encoding="utf-8"))
    snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(root))
    legacy, _ = load_legacy_inputs(store, {entry["anchor_function_id"]})
    source = load_slice_input(store, entry["candidate_id"], legacy=legacy[entry["anchor_function_id"]])
    errors = MinimalFTValidator().validate(document, source, snapshot)
    core = {row["function_id"] for row in document["core_functions"]}
    support = {row["function_id"] for row in document["support_candidates"]}
    row = {"case": case, "artifacts": str(root), "ft_id": entry["ft_id"],
           "candidate_id": entry["candidate_id"], "build_status": document["build_status"],
           "core_functions": [item["function"] for item in document["core_functions"]],
           "support_candidates": [{"function": item["function"], "support_kind": item["support_kind"]}
                                  for item in document["support_candidates"]],
           "excluded_functions": document["excluded_functions"],
           "unresolved_dependencies": document["unresolved_dependencies"],
           "relations": len(document["relations"]),
           "relation_strengths": {strength: sum(item["strength"] == strength for item in document["relations"])
                                  for strength in ("strong", "weak")},
           "source_slice": document["source_slice"],
           "build_exit": build_exit, "resume_exit": resume_exit, "resume_preserved": resume_preserved,
           "validator_errors": errors, "inputs_unchanged": before == input_checksums(root),
           "exact_core_projection": core == set(source.document["core_functions"]),
           "exact_support_projection": support == set(source.document["support_functions"]),
           "llm_calls": metadata["llm_calls"], "repository_rescans": metadata["repository_rescans"]}
    row["passed"] = (build_exit == resume_exit == 0 and not errors and resume_preserved
                     and row["inputs_unchanged"] and row["exact_core_projection"] and row["exact_support_projection"]
                     and row["llm_calls"] == row["repository_rescans"] == 0)
    print(f"[SMOKE] {case}: {row['build_status']} core={len(core)} support={len(support)} "
          f"unresolved={len(row['unresolved_dependencies'])} relations={row['relations']} passed={row['passed']}", flush=True)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slices", type=Path, default=ROOT / "artifacts/semantic_slice_real_20260928_03")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/minimal_ft_smoke_20260928_01/summary.json")
    args = parser.parse_args()
    with ExitStack() as stack:
        for owner, name in ((DeepSeekAgentModel, "__init__"), (DeepSeekAgentModel, "complete"),
                            (FakeAgentModel, "complete"), (CProjectParser, "parse"),
                            (RepositoryIndex, "build_syntax_index")):
            stack.enter_context(patch.object(owner, name, forbidden))
        rows = [evaluate(case, args.slices / directory) for case, directory in CASES]
    summary = {"schema_version": 1, "artifact_kind": "minimal_ft_smoke", "cases": rows,
               "passed": all(row["passed"] for row in rows), "llm_calls": 0, "repository_rescans": 0,
               "model_and_source_scan_guards": True}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, summary, sort_keys=True, allow_nan=False)
    print(f"[SMOKE] wrote={args.output}")
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
