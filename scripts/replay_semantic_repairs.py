#!/usr/bin/env python3
"""Offline replay of archived proposals; no provider/model/tool requests.

This evaluates retirement on existing terminal facts, not fresh-model completion
or compile/runtime success. Source artifacts are read only; output is separate.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def read(path):
    return json.loads(path.read_text())


def write(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    native = args.native_root.resolve()
    if args.output.resolve().is_relative_to(native):
        parser.error("output must be outside the immutable native input tree")
    from harness_generation.sfg_adapter import load_sfg_artifacts
    from harness_generation.minimal_ft import ProjectSnapshot
    from harness_generation.harness_context.models import ContextBudget, MiningState
    from harness_generation.harness_context.api_closure import build_api_closure
    from harness_generation.harness_context.evidence import build_context
    from harness_generation.harness_context.completeness import HarnessContextCompletenessValidator
    from harness_generation.harness_context.repair_proofs import RepairProofEvaluator
    from harness_generation.harness_context.repairs import merge_resolution, VERSION
    from harness_generation.context_generation import HarnessPlanBuilder
    from harness_generation.semantic_discovery.models import digest
    trials = []
    for trial in sorted(native.glob("*_revision_*/trial.json")):
        phase1 = trial.parent / "fixture/phase1"
        directory = next((phase1 / "harness_contexts").iterdir())
        paths = [directory / name for name in ("requirements.json", "resolutions.json", "evidence.json", "metadata.json", "completeness.json")]
        hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        ft = read(phase1 / "minimal_fts" / directory.name / "minimal_ft.json")
        ft_before = digest(ft)
        snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(phase1))
        rows = read(directory / "requirements.json")["requirements"]
        resolutions = read(directory / "resolutions.json")["resolutions"]
        metadata = read(directory / "metadata.json")
        state = MiningState(ContextBudget(**metadata["configuration"]["budget"]))
        state.evidence = {r["evidence_id"]: r for r in read(directory / "evidence.json")["records"]}
        state.discoveries = metadata["discoveries"]
        evidence_before = digest(state.evidence)
        facts = [f for r in resolutions.values() for f in r["facts"]]
        validator = HarnessContextCompletenessValidator()
        def projection():
            closure = build_api_closure(ft, rows, resolutions, snapshot, state)
            context = build_context(ft, rows, facts, snapshot, state.evidence)
            context["dependencies"] = deepcopy(closure["unresolved_api_dependencies"])
            report = validator.validate(context, closure, ft, snapshot, rows, resolutions, state)
            return context, closure, report
        before_context, _, before = projection()
        evaluator = RepairProofEvaluator(ft, snapshot, state)
        evaluator.remember(before_context, before["semantic_obligation_graph"])
        history = []
        for _ in range(len(resolutions)):
            changed = False
            for row in rows:
                rid = row["requirement_id"]
                if rid not in resolutions:
                    continue
                evaluator.configure(facts, rows, resolutions)
                result, audit = merge_resolution(None, resolutions[rid], row, proof_evaluator=evaluator)
                if not audit["withdrawals"]:
                    continue
                resolutions[rid] = result
                row["status"] = result["status"]
                row["evidence_ids"] = sorted({e for f in result["facts"] for e in f["evidence_ids"]})
                facts = [f for f in facts if f["requirement_id"] != rid] + result["facts"]
                history += audit["withdrawals"]
                changed = True
            if not changed:
                break
        context, closure, after = projection()
        plan = None
        if after["generation_allowed"]:
            context["frozen"] = True
            plan = HarnessPlanBuilder().build(ft, context, closure, snapshot, after)
        immutable = all(hashlib.sha256(Path(p).read_bytes()).hexdigest() == expected for p, expected in hashes.items())
        assert immutable and digest(ft) == ft_before and digest(state.evidence) == evidence_before
        row = {"trial": trial.parent.name, "archived_status": read(directory / "completeness.json")["status"],
            "before_status": before["status"], "after_status": after["status"], "generation_allowed": after["generation_allowed"],
            "retired_proposals": len(history), "plan_built": plan is not None, "immutable_inputs": immutable,
            "input_sha256": hashes, "model_calls": 0, "tool_calls": 0,
            "remaining_codes": sorted({d["code"] for d in after["hard_missing"] + after["validation_errors"]})}
        trials.append(row)
        destination = args.output / trial.parent.name
        for name, document in (("harness_context", context), ("api_closure", closure),
                ("completeness", after), ("subject_repair_history", {"withdrawals": history})):
            write(destination / (name + ".json"), document)
        if plan is not None:
            write(destination / "harness_plan.json", plan)
    summary = {"repair_version": VERSION, "experiment_kind": "archived-proposal-offline-replay",
        "fresh_native_trials": 0, "model_calls": 0, "tool_calls": 0, "trials": trials}
    write(args.output / "summary.json", summary)
    print(json.dumps({"trials": len(trials), "generation_allowed": sum(r["generation_allowed"] for r in trials),
        "repaired": sum(r["before_status"] != "complete" and r["after_status"] == "complete" for r in trials)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
