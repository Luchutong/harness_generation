"""Actual target-to-runtime CLI with scoped source evidence and offline planner."""
import json
from pathlib import Path
import shutil

import pytest

from harness_generation import cli as public_cli
from harness_generation.orchestration import cli
from harness_generation.semantic_discovery.models import AgentModelResponse, AgentToolCall, FakeAgentModel, canonical
from harness_generation.target_build import TargetBuildConfig
from v05_fixtures import block_legacy_proof_imports, compile_fixture as prepared
from v05_fixtures import LIGHTWEIGHT_SOURCE as SOURCE, LIGHTWEIGHT_HEADER as HEADER

pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="real Clang required")


def proposal(ids, eids, anchor):
    producer = "parse" if anchor == "parse" else "create"
    fid = ids[producer]
    steps = [{"kind": "call", "step_id": "create_call", "function_id": fid,
        "arguments": {"data": {"kind": "fuzz_bytes"}, "size": {"kind": "fuzz_size"}} if anchor == "parse" else {},
        "evidence_ids": eids[fid], "hypothesis_ids": [], "guard_ids": []},
        {"kind": "capture", "step_id": "capture", "value_id": "obj", "call_step_id": "create_call",
         "source": "return", "parameter": "", "evidence_ids": eids[fid], "hypothesis_ids": []},
        {"kind": "guard", "step_id": "nonnull", "condition": {"kind": "nonnull", "value_id": "obj"},
         "evidence_ids": eids[fid], "hypothesis_ids": []}]
    if anchor == "use":
        steps.append({"kind": "call", "step_id": "consume", "function_id": ids[anchor],
            "arguments": {"object": {"kind": "value", "value_id": "obj"},
                "data": {"kind": "fuzz_bytes"}, "size": {"kind": "fuzz_size"}},
            "evidence_ids": eids[ids[anchor]], "hypothesis_ids": [], "guard_ids": ["nonnull"]})
    steps.append({"kind": "cleanup", "step_id": "cleanup", "function_id": ids["destroy"],
        "arguments": {"object": {"kind": "value", "value_id": "obj"}}, "resource_value_id": "obj",
        "evidence_ids": eids[ids["destroy"]], "hypothesis_ids": [], "guard_ids": ["nonnull"]})
    return {"steps": steps, "hypotheses": [], "open_questions": []}


@pytest.mark.parametrize("anchor", ["parse", "use"])
def test_target_cli_generates_builds_runs_and_resumes_without_slice_or_code_model(tmp_path, monkeypatch, anchor):
    project, artifacts, commands, snapshot, analysis, ids = prepared(tmp_path, source=SOURCE, header=HEADER)
    recipe = tmp_path / "target_build.json"
    recipe.write_text(json.dumps(TargetBuildConfig(project, (project / "api.c",),
        (project / "api.h",), compiler=shutil.which("clang"),
        compiler_flags=("-std=c11", "-DENABLED=0"), timeout=10).to_recipe().to_dict()))
    requested = ("parse", "destroy") if anchor == "parse" else ("create", "use", "destroy")

    def terminal(messages, schemas):
        outputs = [json.loads(row["content"]) for row in messages if row["role"] == "tool"]
        eids = {row["evidence"][0]["function_id"]: row["evidence_ids"] for row in outputs if row.get("evidence")}
        return AgentModelResponse(tool_calls=(AgentToolCall("submit", "submit_harness_strategies",
            canonical({"strategies": [proposal(ids, eids, anchor)]})),))

    model = FakeAgentModel([AgentModelResponse(tool_calls=tuple(AgentToolCall(name, "get_function",
        canonical({"function": ids[name]})) for name in requested)), terminal])

    def forbidden(*args, **kwargs):
        raise AssertionError("default target generation must bypass Candidate/Slice/FT/full semantic proof")

    monkeypatch.setattr(cli, "load_minimal_ft", forbidden)
    block_legacy_proof_imports(monkeypatch)
    arguments = ["--artifacts", str(artifacts), "--target", ids[anchor], "--target-build", str(recipe),
                 "--headers", "api.h", "--max-input-bytes", "1024"]
    assert cli.main(arguments, model=model) == 0
    result_path, = artifacts.glob("orchestration/target_*/generate_run_*/result.json")
    result = json.loads(result_path.read_text())["result"]
    assert result["mode"] == "generate" and result["status"] == "runtime_passed"
    assert all(result[key] is True for key in ("plan_valid", "code_generated", "build_success", "runtime_passed"))
    assert result["fuzz_effective"] is None and result["semantic_verified"] is False
    assert result["generation_allowed"] is False and not result["verified_harnesses"]
    assert len(result["candidate_harnesses"]) == 1 and result["feedback_iteration"] == 0
    candidate = result["candidate"]
    assert candidate["context_type"] == "lightweight_api_context" and candidate["ft_id"].startswith("lac_")
    assert set(candidate["authorized_function_ids"]) == set(candidate["authorization"]["allowed_function_ids"])
    plan = json.loads((Path(result["outcome"]["directory"]) / "plan.json").read_text())
    assert plan["input_policy"]["max_bytes"] == 1024
    assert plan["authorization_basis"]["artifact_kind"] == "lightweight_api_context_reference"
    assert len(result["outcome"]["runtime"]["cases"]) == 6
    assert len(model.calls) == 2
    assert result["cost"]["provider_requests"] == 0
    for name in ("candidate_discovery", "semantic_slices", "minimal_fts", "harness_strategies", "strategy_contexts"):
        assert not (artifacts / name).exists(), name
    stored = {path: path.read_bytes() for path in result_path.parent.rglob("*") if path.is_file()}
    assert cli.main([*arguments, "--resume-run", result_path.parent.name], model=FakeAgentModel([])) == 0
    assert stored == {path: path.read_bytes() for path in result_path.parent.rglob("*") if path.is_file()}


@pytest.mark.parametrize("mode", ["verify", "recover"])
def test_removed_public_modes_are_rejected_before_execution(tmp_path, mode):
    model = FakeAgentModel([])
    with pytest.raises(SystemExit) as caught:
        cli.main(["--mode", mode, "--artifacts", str(tmp_path), "--target", "api.c:1:parse",
            "--target-build", str(tmp_path / "missing.json")], model=model)
    assert caught.value.code == 2
    assert model.calls == []
    assert not list(tmp_path.iterdir())


def test_public_entrypoints_and_generate_mode_are_explicit(capsys):
    assert set(public_cli.COMMANDS) == {"parse", "harness-run"}
    with pytest.raises(SystemExit) as caught:
        public_cli.main(["harness-run", "--help"])
    assert caught.value.code == 0
    assert "--mode {generate}" in capsys.readouterr().out


@pytest.mark.parametrize("command", ["discover", "slice", "minimal-ft", "harness-context",
    "harness-strategy", "strategy-context", "generate", "verify", "recover"])
def test_removed_public_entrypoints_are_argparse_errors(command):
    with pytest.raises(SystemExit) as caught:
        public_cli.main([command])
    assert caught.value.code == 2
