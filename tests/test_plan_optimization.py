import json
from pathlib import Path
import shutil

import pytest

from harness_generation.cli import main as cli_main
from harness_generation.llm import MockLLM
from harness_generation.plan_optimization import (
    PlanOptimizationConfig, run_plan_optimization,
)
from harness_generation.target_build import TargetBuildConfig
from harness_generation.triplet import load_triplets_json
from tests.test_generation_cli import (
    GenerationCLITests, HARNESS_CODE, NO_FUZZ_VALIDATION,
    SIMPLE_PROJECT, SOURCE_ARTIFACTS, harness_plan,
)
from tests.toolchain_probe import LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON


@pytest.mark.skipif(not LIBFUZZER_AVAILABLE, reason=LIBFUZZER_SKIP_REASON)
def test_measured_plan_refinement_uses_stage4_and_retains_best_candidate(tmp_path):
    artifacts = tmp_path / "parent"
    artifacts.mkdir()
    for name in ("functions.json", "triplets.json"):
        shutil.copyfile(SOURCE_ARTIFACTS / name, artifacts / name)
    triplet = load_triplets_json(artifacts / "triplets.json")[0]
    fixture = GenerationCLITests()
    fixture.artifacts = artifacts
    fixture.triplet = triplet
    assert cli_main([
        "generate", "--artifacts", str(artifacts), "--ft", triplet.id,
        "--project-root", str(SIMPLE_PROJECT),
    ], llm=MockLLM(fixture.responses()), validation_config=NO_FUZZ_VALIDATION) == 0

    score_by_candidate = {"r000_c000": 10.0, "r001_c000": 20.0,
                          "r001_c001": 5.0}

    def measure(harness, target, root, ft_id, seed, budget, corpus):
        percent = score_by_candidate[root.name]
        return {
            "status": "passed", "scope": "target_code", "runs": budget,
            "seed": seed, "recipe_identity": target.to_recipe().identity,
            "target_only": {"totals": {"branches": {
                "count": 100, "covered": int(percent), "percent": percent,
            }}},
        }

    output = tmp_path / "optimization"
    result = run_plan_optimization(PlanOptimizationConfig(
        artifacts=artifacts, output=output, ft_id=triplet.id,
        target_build=TargetBuildConfig.for_simple_project(SIMPLE_PROJECT),
        rounds=1, children_per_round=2, runs=8,
        seeds=(1, 2), holdout_seeds=(3,),
    ), MockLLM([
        harness_plan(triplet.id), HARNESS_CODE,
        harness_plan(triplet.id), HARNESS_CODE,
    ]), measure=measure)

    assert result.status == "completed"
    assert result.selected_candidate == "r001_c000"
    assert (output / "candidates" / "r001_c000" / "plan_feedback.json").is_file()
    assert (output / "candidates" / "r001_c000" / "holdout_evaluation.json").is_file()
    document = json.loads((output / "plan_optimization.json").read_text())
    assert document["selected_candidate"] == "r001_c000"
