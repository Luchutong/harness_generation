#!/usr/bin/env python3
"""Real Plan → code/compile/replay isolated from Context mining quality.

Frozen input fixtures use explicit offline contracts from the regression suite.
Only the translation stage is a real model test; this is not a full-model chain.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from test_context_generation import ready
from test_context_semantics import registered_ready, owned_consumer_ready
from harness_generation.context_generation.persistence import load_frozen_inputs
from harness_generation.context_generation import HarnessPlanBuilder
from harness_generation.context_generation.cli import main
from harness_generation.records import write_json
from harness_generation.semantic_discovery.provider_config import load_environment_file, agent_configuration


def smoke(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    parser.add_argument("--case", action="append", choices=("direct", "context", "owned", "borrowed", "callback", "nul", "registered_callback", "owned_consumer"))
    args = parser.parse_args(argv)
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    load_environment_file(args.env_file)
    cfg = agent_configuration("openai-compatible")
    rows = []
    for name in (args.case or ("direct", "context", "owned", "borrowed", "callback", "nul")):
        directory = args.output / name
        directory.mkdir()
        if name in {"registered_callback", "owned_consumer"}:
            prepared, context_run, _ = {"registered_callback": registered_ready, "owned_consumer": owned_consumer_ready}[name](directory)
            store = prepared[0][0]
            frozen = load_frozen_inputs(store, prepared[1]["ft_id"])
            plan = HarnessPlanBuilder().build(*frozen[:5])
        else:
            store, _, plan = ready(directory, name)
        upstream = {p: p.read_bytes() for p in store.root.rglob("*.json")}
        command = ["--artifacts", str(store.root), "--provider", "openai-compatible", "--model", cfg.model,
                   "--thinking", cfg.thinking, "--build", "--runtime"]
        print(f"[REAL TRANSLATION] starting {name}", flush=True)
        result = main(command)
        marker = next((store.root / "context_generations").glob("*/*/*/metadata.json"), None)
        metadata = json.loads(marker.read_text()) if marker else {"status": "blocked", "model_calls": 0}
        row = {"case": name, "category": "plan_translation_only", "frozen_input_preparation": "explicit_offline_fixture_contracts",
            "real_context_model": False, "real_code_model": True, "exit": result,
            "status": metadata["status"], "model_calls": metadata["model_calls"],
            "upstream_unchanged": all(p.read_bytes() == data for p, data in upstream.items()),
            "artifact_directory": str(marker.parent) if marker else str(store.root)}
        if marker:
            run = marker.parent
            for field, filename in (("response", "response.json"), ("code_validation", "code_validation.json"),
                                    ("build", "build/build.json"), ("runtime", "build/runtime.json")):
                if (run / filename).is_file():
                    row[field] = json.loads((run / filename).read_text())
            row.get("response", {}).pop("content", None)
            if result == 0:
                saved = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in run.rglob("*") if p.is_file()}
                row["resume_exit"] = main(command + ["--resume"])
                row["resume_unchanged"] = all(saved[p] == (p.read_bytes(), p.stat().st_mtime_ns) for p in saved)
        row["audit_passed"] = (row["upstream_unchanged"] and row.get("response", {}).get("provider") == "openai-compatible"
            and row.get("response", {}).get("usage", {}).get("total_tokens", 0) > 0)
        rows.append(row)
        write_json(args.output / "summary.json", {"schema_version": 1, "provider": cfg.to_dict(), "cases": rows,
            "mock_fallback": False, "real_model_stages": ["plan_translation"],
            "passed_cases": sum(row["status"] == "passed" for row in rows)}, sort_keys=True, allow_nan=False)
        print(f"[REAL TRANSLATION] {name}: {row['status']} audit={row['audit_passed']}", flush=True)
    return int(any(row["status"] != "passed" or not row["audit_passed"] for row in rows))


if __name__ == "__main__":
    raise SystemExit(smoke())
