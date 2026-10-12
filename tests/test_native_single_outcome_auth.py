"""Outer Native outcome authentication, using real Clang plans and no execution.

Candidate/evaluation replay is isolated here. These checks cover binding of the
already authenticated inputs to saved observations; they do not stand in for
harness build/runtime acceptance.
"""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import hashlib
import shutil

import pytest

from harness_generation.context_generation.executable_plan import (
    ExecutablePlanBuilder, ExecutablePlanVerifier, UnsupportedTranslationError,
)
from harness_generation.context_generation.build import SMOKE_INPUTS
from harness_generation.context_generation.strategy_generation import deterministic_translate
from harness_generation.context_generation.strategy_validation import validate_strategy_code
from harness_generation.compiler_validation import CommandResult
from harness_generation.harness_strategy.normalization import normalize_strategy, proposal_projection
from harness_generation.orchestration.generation_services import NativeGenerationServices
from harness_generation.orchestration.quality import assess_harness_quality
from harness_generation.records import write_json
from harness_generation.runtime_validation import RuntimeValidationResult
from harness_generation.semantic_discovery.models import digest
from harness_generation.target_build import TargetBuildConfig
from v05_fixtures import build_executable_plan as build, executable_fixture as prepared

pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="trusted Clang is required")


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    inputs, strategy, project = prepared(tmp_path_factory.mktemp("native_auth_source"))
    plan = build(inputs, strategy)
    return inputs, strategy, project, plan


def services_for(sample, tmp_path, monkeypatch):
    inputs, strategy, project, plan = sample
    service = NativeGenerationServices.__new__(NativeGenerationServices)
    service.analysis = inputs["build_analysis"]
    service.directory = tmp_path / "single_generation"
    service.directory.mkdir()
    service.language, service.headers = "c", ["api.h"]
    service.lightweight_context, service.svf_provider = None, None
    service.recipe = TargetBuildConfig(project, (project / "api.c",), (project / "api.h",),
        compiler_flags=("-std=c11",), timeout=10)
    # Only the outer binding is under test; source/preflight themselves are
    # exercised by the real ExecutablePlanVerifier below.
    service._inputs = lambda candidate: (None, inputs["ft"], None, inputs["snapshot"],
                                         SimpleNamespace(project_root=project))
    service.verify_single_evaluation = lambda *args, **kwargs: None
    candidate = {"strategy": deepcopy(strategy), "evidence": deepcopy(inputs["evidence"]),
                 "authorized_function_ids": sorted(inputs["authorized_ids"])}
    evaluation = {"execution_preflight": deepcopy(plan["execution_preflight"]),
                  "generation_allowed": False, "semantic_verified": False, "diagnoses": []}
    execute_calls = []

    def unavailable(*args, **kwargs):
        execute_calls.append((args, kwargs))
        raise ValueError("isolated native executor is unavailable")

    monkeypatch.setattr("harness_generation.orchestration.generation_services.execute_strategy_plan", unavailable)
    return service, candidate, evaluation, execute_calls


def generated_failure(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, calls = services_for(sample, tmp_path, monkeypatch)
    outcome = service.generate_single(candidate, evaluation, mode="generate")
    assert outcome["plan_valid"] is True and outcome["code_generated"] is True
    assert outcome["status"] == "execution_failed" and len(calls) == 1
    assert outcome["build_success"] is outcome["runtime_passed"] is None
    return service, candidate, evaluation, outcome, calls


def save_outcome(outcome):
    write_json(Path(outcome["directory"]) / "execution_report.json", outcome, sort_keys=True, allow_nan=False)


def replace_saved_plan(sample, outcome, plan):
    """Rehash/rewrite all the plan's own labels; the selected input stays fixed."""
    inputs = sample[0]
    directory = Path(outcome["directory"])
    validator = ExecutablePlanVerifier(**inputs)
    assert validator(plan) is True  # independently legal in this same source scope
    code = deterministic_translate(plan, plan_validator=validator)
    validation = validate_strategy_code(code, plan, plan_validator=validator)
    assert validation["valid"] is True
    write_json(directory / "plan.json", plan, sort_keys=True, allow_nan=False)
    (directory / ("harness.cpp" if plan["language"] == "c++" else "harness.c")).write_text(code)
    write_json(directory / "code_validation.json", validation, sort_keys=True)
    outcome.update({key: plan[key] for key in ("plan_id", "plan_digest", "strategy_id", "strategy_digest")})
    outcome.update(code=code, code_sha256=hashlib.sha256(code.encode()).hexdigest(), code_validation=validation)
    outcome["quality"] = assess_harness_quality(outcome)
    save_outcome(outcome)


def test_completed_native_failure_authenticates_without_repeating_execution(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    assert service.verify_single_outcome(candidate, evaluation, outcome, mode="generate") is None
    assert len(calls) == 1


def test_another_legal_strategy_in_same_scope_cannot_replace_selected_candidate(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    inputs, strategy, _, _ = sample
    proposal = proposal_projection(strategy)
    proposal["open_questions"] = ["A distinct recorded strategy proposal."]
    other_strategy = normalize_strategy(proposal, inputs["ft"], inputs["snapshot"])
    assert other_strategy["strategy_digest"] != strategy["strategy_digest"]
    replace_saved_plan(sample, outcome, build(inputs, other_strategy))
    with pytest.raises(ValueError, match="selected candidate"):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert len(calls) == 1


@pytest.mark.parametrize("configuration", [{"language": "c++"}, {"max_input_bytes": 1024}])
def test_another_legal_translation_configuration_cannot_replace_selected_request(
        sample, tmp_path, monkeypatch, configuration):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    inputs, strategy, _, _ = sample
    other = ExecutablePlanBuilder().build(**inputs, strategy=strategy, headers=("api.h",), **configuration)
    replace_saved_plan(sample, outcome, other)
    with pytest.raises(ValueError, match="selected candidate"):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert len(calls) == 1


@pytest.mark.parametrize("field,value", [("plan_id", "executable_plan_forged"),
    ("strategy_id", "strategy_forged"), ("strategy_digest", "0" * 64)])
def test_rehashed_outcome_identity_cannot_diverge_from_its_plan(sample, tmp_path, monkeypatch, field, value):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    outcome[field] = value
    save_outcome(outcome)
    with pytest.raises(ValueError, match="selected candidate"):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert len(calls) == 1


def test_plan_invalid_label_cannot_bypass_outcome_authentication(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    outcome.update(plan_valid=False, build={"success": True}, runtime={"status": "passed"},
                   build_success=True, runtime_passed=True, success=True)
    outcome["quality"] = assess_harness_quality(outcome)
    save_outcome(outcome)
    with pytest.raises(ValueError, match="preparation failure"):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert len(calls) == 1


def test_no_generated_code_cannot_claim_compilation_or_runtime_success(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    directory = Path(outcome["directory"])
    outcome.update(code_generated=False, build={"success": True}, runtime={"status": "passed"},
                   build_success=True, runtime_passed=True, success=True)
    for name in ("build", "runtime"):
        write_json(directory / (name + ".json"), outcome[name])
    outcome["quality"] = assess_harness_quality(outcome)
    save_outcome(outcome)
    with pytest.raises(ValueError):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert len(calls) == 1


def test_untranslated_code_cannot_use_a_runtime_passed_status_without_observations(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    (Path(outcome["directory"]) / "harness.c").unlink()
    outcome.update(code_generated=False, status="runtime_passed")
    assert "build" not in outcome and "runtime" not in outcome
    outcome["quality"] = assess_harness_quality(outcome)
    save_outcome(outcome)
    with pytest.raises(ValueError, match="untranslated candidate cannot claim execution success"):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert len(calls) == 1


def persist_observations(outcome):
    directory = Path(outcome["directory"])
    for name in ("build", "runtime"):
        write_json(directory / (name + ".json"), outcome[name], sort_keys=True)
    for number, case in enumerate(outcome["runtime"]["cases"]):
        write_json(directory / f"runtime_{number}.json",
                   {key: value for key, value in case.items() if key != "size"}, sort_keys=True)
    save_outcome(outcome)


def isolated_observations(service, sample, outcome, *, runtime_status="skipped", build_success=False):
    """Match saved native shapes with explicit, inert test-only process artifacts.

    Source/recipe hashes describe the real fixture. Every command/result below
    is synthetic and the inert executable is never started.
    """
    identity = {key: sample[3][key] for key in ("artifact_kind", "plan_id", "plan_digest",
        "strategy_id", "strategy_digest", "statistics_category", "generation_allowed",
        "execution_allowed", "semantic_verified", "formal_success_statistics_allowed")}
    directory = Path(outcome["directory"])
    inert_executable = directory / "isolated_smoke_harness"
    inert_executable.write_bytes(b"INERT TEST ARTIFACT: NO COMPILER OR TARGET PROCESS WAS STARTED\n")
    command = CommandResult(command=("isolated_compiler_stub", "-o", str(inert_executable)),
        status="completed", return_code=0 if build_success else 1, stdout="", stderr="").to_dict()
    source_hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in (*service.recipe.source_files, *service.recipe.header_files)}
    cases = []
    if runtime_status != "skipped":
        for number, data in enumerate(SMOKE_INPUTS):
            input_path = directory / f"input_{number}.bin"
            input_path.write_bytes(data)
            record = RuntimeValidationResult(status="passed", reason=None, stdout="", stderr="",
                return_code=0, command=(str(inert_executable), str(input_path)), timed_out=False,
                timeout_seconds=10, metadata={"schema_version": 1, "stage": "runtime",
                    "validator": "runtime", "executable": str(inert_executable),
                    "working_directory": str(directory), "isolated_test_stub": True}).to_dict()
            cases.append({"size": len(data), **record})
    outcome.update(build={**identity, "status": "passed" if build_success else "failed",
        "success": build_success, "commands": [command], "recipe": service.recipe.to_dict(),
        "recipe_digest": digest(service.recipe.to_dict()), "target_input_digests": source_hashes,
        "executable": str(inert_executable) if build_success else None,
        "isolated_test_stub": True},
        runtime={**identity, "status": runtime_status, "cases": cases, "fuzz_executed": False,
                 "isolated_test_stub": True},
        build_success=build_success, runtime_passed=runtime_status == "passed",
        success=build_success and runtime_status == "passed")
    outcome["quality"] = assess_harness_quality(outcome)
    persist_observations(outcome)


def test_failed_build_with_skipped_runtime_authenticates_without_retry(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    isolated_observations(service, sample, outcome)
    assert service.verify_single_outcome(candidate, evaluation, outcome, mode="generate") is None
    assert len(calls) == 1


def test_failed_build_cannot_have_a_passed_runtime(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    isolated_observations(service, sample, outcome, runtime_status="passed")
    with pytest.raises(ValueError, match="successful build"):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert len(calls) == 1


@pytest.mark.parametrize("field,value", [("artifact_kind", "verified_strategy_plan"),
    ("plan_digest", "0" * 64), ("strategy_digest", "0" * 64),
    ("generation_allowed", True), ("formal_success_statistics_allowed", True)])
def test_another_plan_or_proof_flag_cannot_be_copied_into_observations(
        sample, tmp_path, monkeypatch, field, value):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    isolated_observations(service, sample, outcome)
    outcome["build"][field] = value
    write_json(Path(outcome["directory"]) / "build.json", outcome["build"], sort_keys=True)
    save_outcome(outcome)
    with pytest.raises(ValueError, match="different plan"):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert len(calls) == 1


def test_saved_success_shapes_authenticate_without_starting_any_process(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    isolated_observations(service, sample, outcome, build_success=True, runtime_status="passed")
    assert service.verify_single_outcome(candidate, evaluation, outcome, mode="generate") is None
    assert len(calls) == 1


@pytest.mark.parametrize("field,value", [("return_code", 1), ("status", "unavailable")])
def test_failed_compiler_record_cannot_be_relabelled_as_build_success(sample, tmp_path, monkeypatch, field, value):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    isolated_observations(service, sample, outcome, build_success=True, runtime_status="passed")
    outcome["build"]["commands"][0][field] = value
    persist_observations(outcome)
    with pytest.raises(ValueError, match="compiler observations"):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert len(calls) == 1


@pytest.mark.parametrize("field,value", [("success", False), ("return_code", 1),
    ("status", "failed"), ("timed_out", True), ("reason", "process failure")])
def test_failed_process_record_cannot_be_relabelled_as_runtime_success(sample, tmp_path, monkeypatch, field, value):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    isolated_observations(service, sample, outcome, build_success=True, runtime_status="passed")
    outcome["runtime"]["cases"][0][field] = value
    # Save the same contradictory per-process record as well: hashes and an
    # internally copied observation cannot replace execution-result facts.
    persist_observations(outcome)
    with pytest.raises(ValueError):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert len(calls) == 1


@pytest.mark.parametrize("field", ["recipe_digest", "target_input_digests"])
def test_other_recipe_or_target_hash_cannot_replace_saved_build_identity(sample, tmp_path, monkeypatch, field):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    isolated_observations(service, sample, outcome, build_success=True, runtime_status="passed")
    outcome["build"][field] = "0" * 64 if field == "recipe_digest" else {}
    persist_observations(outcome)
    with pytest.raises(ValueError, match="source or recipe identity"):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert len(calls) == 1


def test_runtime_process_file_cannot_diverge_from_its_case(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, outcome, calls = generated_failure(sample, tmp_path, monkeypatch)
    isolated_observations(service, sample, outcome, build_success=True, runtime_status="passed")
    changed = {key: value for key, value in outcome["runtime"]["cases"][0].items() if key != "size"}
    changed["stdout"] = "a different process observation"
    write_json(Path(outcome["directory"]) / "runtime_0.json", changed)
    with pytest.raises(ValueError, match="process observation changed"):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert len(calls) == 1


def unsupported_builder(*args, **kwargs):
    raise UnsupportedTranslationError("unsupported_translation: isolated unsupported representation")


def preparation_failure(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, calls = services_for(sample, tmp_path, monkeypatch)
    monkeypatch.setattr(ExecutablePlanBuilder, "build", unsupported_builder)
    outcome = service.generate_single(candidate, evaluation, mode="generate")
    assert outcome["status"] == "unsupported_translation" and outcome["plan_valid"] is False
    assert outcome["code_generated"] is False and not calls
    return service, candidate, evaluation, outcome, calls


def test_fixed_unsupported_preparation_failure_is_durable_and_replays_without_execution(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, outcome, calls = preparation_failure(sample, tmp_path, monkeypatch)
    directory = Path(outcome["directory"])
    assert (directory / "execution_request.json").is_file()
    assert (directory / "recipe.json").is_file()
    assert (directory / "execution_report.json").is_file()
    assert not (directory / "plan.json").exists()
    assert service.verify_single_outcome(candidate, evaluation, outcome, mode="generate") is None
    assert not calls


def test_changed_preparation_failure_cannot_reuse_original_receipt(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, outcome, calls = preparation_failure(sample, tmp_path, monkeypatch)

    def changed(*args, **kwargs):
        raise UnsupportedTranslationError("unsupported_translation: changed representation")

    monkeypatch.setattr(ExecutablePlanBuilder, "build", changed)
    with pytest.raises(ValueError, match="preparation failure"):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert not calls


def test_fixed_failure_receipt_cannot_be_relabelled_as_runtime_success(sample, tmp_path, monkeypatch):
    service, candidate, evaluation, outcome, calls = preparation_failure(sample, tmp_path, monkeypatch)
    outcome.update(build_success=True, runtime_passed=True, success=True,
                   build={"success": True}, runtime={"status": "passed"})
    outcome["quality"] = assess_harness_quality(outcome)
    save_outcome(outcome)
    with pytest.raises(ValueError, match="preparation failure"):
        service.verify_single_outcome(candidate, evaluation, outcome, mode="generate")
    assert not calls
