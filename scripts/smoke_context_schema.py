#!/usr/bin/env python3
"""Explicit paired provider token accounting. Not a semantic pipeline test."""
import argparse
from dataclasses import replace
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness_generation.harness_context.models import obj, arr, resolution_schema
from harness_generation.harness_context.requirements import requirement
from harness_generation.harness_context.terminal import terminal_schema
from harness_generation.semantic_discovery.models import canonical
from harness_generation.semantic_discovery.provider_config import agent_configuration, native_agent_model, load_environment_file
from harness_generation.semantic_discovery.tools import _schema
from harness_generation.records import write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env")
    args = parser.parse_args()
    load_environment_file(args.env_file)
    cfg = replace(agent_configuration("openai-compatible"), max_tokens=32)
    model = native_agent_model(cfg)
    groups = {"direct": ("input_binding", "argument_construction", "buffer_length", "ownership", "return_semantics"),
        "shared": ("input_binding", "argument_construction", "lifecycle", "ownership", "return_semantics", "state", "call_order"),
        "callback": ("input_binding", "argument_construction", "buffer_length", "lifecycle", "ownership", "return_semantics", "state", "callback")}
    rows = []
    for name, kinds in groups.items():
        reqs = [requirement("ft_schema_measurement", "api.c:1:parse", kind) for kind in kinds]
        old = obj({"resolutions": arr({"anyOf": [resolution_schema(r["kind"], requirement=r) for r in reqs]}, len(reqs))})
        row = {"group": name, "category": "schema_accounting_only", "measurements": {}}
        for version, schema in (("v2_anyof", old), ("v3_bound_slots", terminal_schema(reqs))):
            tool = _schema("submit_requirement_resolutions", "Submit typed resolutions.", schema["properties"], schema["required"])
            response = model.complete([{"role": "user", "content": "This is schema token accounting only. Do not call any tool. Reply OK."}], [tool])
            row["measurements"][version] = {"schema_chars": len(canonical(tool)), **response.metadata}
            print(name, version, response.metadata.get("usage"), flush=True)
        rows.append(row)
        write_json(args.output, {"category": "schema_accounting_only", "provider": cfg.to_dict(), "cases": rows,
            "semantic_evaluation": False, "model_calls": 2 * len(rows)}, sort_keys=True, allow_nan=False)


if __name__ == "__main__":
    main()
