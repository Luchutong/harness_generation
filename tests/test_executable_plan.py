"""Independent generation candidate admission and small real compiler checks."""
from copy import deepcopy
import json
import shutil

import pytest

from harness_generation.context_generation.executable_plan import (ExecutablePlanVerifier,
    UnsupportedTranslationError, require_executable_plan)
from harness_generation.context_generation.strategy_generation import deterministic_translate, execute_strategy_plan
from harness_generation.context_generation.strategy_validation import validate_strategy_code
from harness_generation.semantic_discovery.models import digest
from harness_generation.target_build import TargetBuildConfig
from v05_fixtures import (block_legacy_proof_imports, executable_fixture as prepared,
                         build_executable_plan as build)

pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="trusted Clang is required")


def refresh(plan):
    plan["plan_id"] = "executable_plan_" + digest({key: value for key, value in plan.items()
                                                 if key not in {"plan_id", "plan_digest"}})[:24]
    plan["plan_digest"] = digest({key: value for key, value in plan.items() if key != "plan_digest"})


def test_executable_candidate_replays_without_full_proof_or_code_model(tmp_path, monkeypatch):
    inputs, strategy, _ = prepared(tmp_path)
    block_legacy_proof_imports(monkeypatch)
    before = deepcopy(strategy)
    plan = build(inputs, strategy)
    assert strategy == before and plan == build(inputs, strategy)
    assert plan["artifact_kind"] == "executable_plan"
    assert plan["frozen"] and plan["immutable"] and plan["execution_allowed"]
    assert plan["statistics_category"] == "candidate"
    assert not any(plan[key] for key in ("semantic_verified", "generation_allowed", "formal_success_statistics_allowed",
                                       "experimental_execution_allowed"))
    assert plan["unknown_contracts"]
    assert require_executable_plan(plan) is plan
    validator = ExecutablePlanVerifier(**inputs)
    assert validator(plan)
    code = deterministic_translate(plan)
    assert validate_strategy_code(code, plan)["valid"]
    assert "destroy(hg_v_obj)" in code and "create((const unsigned char *)data, size)" in code
    assert not validate_strategy_code(code.replace("destroy(hg_v_obj)", "destroy(NULL)"), plan)["valid"]
    (tmp_path / "plan_acceptance.json").write_text(json.dumps({"plan": plan, "code": code, "verdict": validator.verify(plan),
        "model_calls": 0, "provider_requests": 0, "full_semantic_gate_calls": 0}, indent=2))


@pytest.mark.parametrize("field,value", [("generation_allowed", True), ("semantic_verified", True),
    ("formal_success_statistics_allowed", True), ("experimental_execution_allowed", True)])
def test_executable_flags_cannot_claim_other_authority(tmp_path, field, value):
    inputs, strategy, _ = prepared(tmp_path)
    changed = build(inputs, strategy)
    changed[field] = value
    refresh(changed)
    with pytest.raises(ValueError, match="authority"):
        require_executable_plan(changed)


def test_rehashed_declaration_and_resource_tampering_fail_independent_verifier(tmp_path):
    inputs, strategy, _ = prepared(tmp_path)
    plan = build(inputs, strategy)
    changed = deepcopy(plan)
    changed["api_declarations"][0]["signature"] = "int forged(void)"
    refresh(changed)
    # The self-contained serializer checks integrity; live admission proves provenance.
    assert not ExecutablePlanVerifier(**inputs)(changed)
    changed = deepcopy(plan)
    changed["executable_resources"][0]["origin"]["call_step_id"] = "parse_call"
    refresh(changed)
    assert not ExecutablePlanVerifier(**inputs)(changed)


def test_replay_binds_original_authorization_and_evidence(tmp_path):
    inputs, strategy, _ = prepared(tmp_path)
    plan = build(inputs, strategy)
    scope = {**inputs, "authorized_ids": {inputs["ft"]["anchor_function_id"]}}
    assert not ExecutablePlanVerifier(**scope)(plan)
    forged = deepcopy(inputs["evidence"])
    next(iter(forged.values()))["content"] = "unissued evidence text"
    assert not ExecutablePlanVerifier(**{**inputs, "evidence": forged})(plan)
    different_ft = {**inputs["ft"], "support_candidates": []}
    assert not ExecutablePlanVerifier(**{**inputs, "ft": different_ft})(plan)


def test_execution_requires_independent_inputs_and_current_recipe(tmp_path):
    inputs, strategy, project = prepared(tmp_path)
    plan = build(inputs, strategy)
    recipe = TargetBuildConfig(project, (project / "api.c",), (project / "api.h",), timeout=10)
    with pytest.raises(ValueError, match="independent source/scope/evidence/build"):
        execute_strategy_plan(plan, deterministic_translate(plan), tmp_path / "missing", recipe)
    wrong = TargetBuildConfig(project, (project / "api.c",), compiler_flags=("-std=c11", "-DOTHER=1"), timeout=10)
    with pytest.raises(ValueError, match="build_recipe_compile_flags_mismatch"):
        execute_strategy_plan(plan, deterministic_translate(plan), tmp_path / "wrong", wrong, **inputs)
    assert not (tmp_path / "wrong" / "harness.c").exists()


def test_live_source_change_invalidates_serialized_candidate(tmp_path):
    inputs, strategy, project = prepared(tmp_path)
    plan = build(inputs, strategy)
    source = project / "api.c"
    source.write_text(source.read_text() + "\n/* current source changed */\n")
    assert not ExecutablePlanVerifier(**inputs)(plan)


def test_transitive_header_change_during_execution_invalidates_candidate(tmp_path, monkeypatch):
    inputs, strategy, project = prepared(tmp_path)
    plan = build(inputs, strategy)
    recipe = TargetBuildConfig(project, (project / "api.c",), timeout=10)
    def changed(*args, **kwargs):
        header = project / "api.h"
        header.write_text(header.read_text() + "\n/* transitive input changed */\n")
        return {"success": True}, {"status": "passed"}
    monkeypatch.setattr("harness_generation.context_generation.strategy_generation.build_and_run", changed)
    with pytest.raises(ValueError, match="source_dependency_changed|source_snapshot_changed"):
        execute_strategy_plan(plan, deterministic_translate(plan), tmp_path / "execution", recipe, **inputs)


def test_unsupported_translation_is_explicit_and_no_code_model_fallback(tmp_path, monkeypatch):
    inputs, strategy, _ = prepared(tmp_path)
    def unsupported(*args, **kwargs):
        raise ValueError("unsupported constructed source type")
    monkeypatch.setattr("harness_generation.context_generation.strategy_generation._resource_ctype", unsupported)
    with pytest.raises(UnsupportedTranslationError, match="unsupported_translation") as caught:
        build(inputs, strategy)
    assert caught.value.code == "unsupported_translation"


def test_real_compiler_and_smoke_preserve_candidate_statistics(tmp_path, monkeypatch):
    inputs, strategy, project = prepared(tmp_path)
    block_legacy_proof_imports(monkeypatch)
    plan = build(inputs, strategy)
    recipe = TargetBuildConfig(project, (project / "api.c",), (project / "api.h",), timeout=10)
    build_report, runtime = execute_strategy_plan(plan, deterministic_translate(plan), tmp_path / "execution", recipe, **inputs)
    assert build_report["success"], build_report
    assert runtime["status"] == "passed" and len(runtime["cases"]) == 6
    for report in (build_report, runtime):
        assert report["statistics_category"] == "candidate" and report["artifact_kind"] == "executable_plan"
        assert report["execution_allowed"]
        assert not report["generation_allowed"] and not report["semantic_verified"]
        assert not report["formal_success_statistics_allowed"]
    assert not runtime["fuzz_executed"]
