"""Small real-Clang API contexts; no effect proof, provider or fresh run."""
from dataclasses import replace
import json
import shutil

import pytest

from harness_generation.artifacts import ArtifactStore
from harness_generation.harness_strategy.models import StrategyBudget
from harness_generation.harness_strategy.normalization import normalize_strategy
from harness_generation.harness_strategy.planner import StrategyPlanner
from harness_generation.harness_strategy.tools import StrategyTools
from harness_generation.harness_strategy.validation import StrategyValidator
from harness_generation.lightweight_context import ContextBudget, LightweightAPIContext, LightweightContextStore, build_context
from harness_generation.lightweight_context.persistence import load_strategy_inputs, save_strategy_run, strategy_run_configuration
from harness_generation.semantic_discovery.models import AgentModelResponse, AgentToolCall, FakeAgentModel, canonical, digest
from harness_generation.source_analysis import BuildAnalysisError
from v05_fixtures import lightweight_sample as sample, context_for, proposal_for

pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="real Clang frontend required")


def issued_tools(context):
    budget = StrategyBudget()
    tools = context.make_strategy_tools(budget)
    ids = {}
    for fid in sorted(context.scope.function_ids):
        result = tools.execute("get_function", {"function": fid})
        assert not result.get("error")
        ids[fid] = result["evidence_ids"]
    return budget, tools, ids


def test_confirmed_parser_uses_independent_scope_without_slice(sample, tmp_path):
    context = context_for(sample)
    ids = sample[5]
    assert context.scope.function_ids == {ids[name] for name in ("parse", "create", "use", "destroy")}
    assert context.context_id.startswith("lac_parse_")
    document = context.document
    assert document["artifact_kind"] == "lightweight_api_context"
    assert document["authorization_kind"] == "live_clang_api_scope"
    assert not document["semantic_verified"] and not document["generation_allowed"]
    assert not {"candidate_id", "slice_status", "build_status"} & document.keys()
    assert document["cost"]["model_calls"] == document["cost"]["semantic_verifier_calls"] == 0
    assert context.strategy_input["context_type"] == "lightweight_api_context"
    store = LightweightContextStore(tmp_path)
    directory = store.save(context)
    loaded = store.load(context.context_id, sample[3], sample[4], sample[6])
    assert loaded.document == document and loaded.metadata == context.metadata
    assert directory.parent.name == "lightweight_api_contexts"
    assert not any((tmp_path / name).exists() for name in ("minimal_fts", "semantic_slices", "candidate_discovery"))
    with pytest.raises(ValueError, match="invalid minimal FT ID"):
        ArtifactStore(tmp_path).minimal_ft_run(context.context_id)


@pytest.mark.parametrize("anchor,use_create", [("parse", False), ("use", True)])
def test_parser_and_create_use_cleanup_are_structurally_valid(sample, anchor, use_create):
    context = context_for(sample, anchor)
    budget, tools, eids = issued_tools(context)
    proposal = proposal_for(sample, context, eids, use_create=use_create)
    strategy = normalize_strategy(proposal, context.strategy_input, context.snapshot, budget)
    result = StrategyValidator(context.strategy_input, context.snapshot, tools.evidence,
        tools.authorized_ids, budget=budget).validate(strategy)
    assert result["valid"], result["errors"]
    assert result["generation_allowed"] is False
    assert any(row["ownership"] == "unknown" for row in strategy["resources"])
    assert not any(row.get("source_proven") for row in result["pending_semantic_checks"])


def test_exact_anchor_callable_and_receipt_are_required(sample):
    context = context_for(sample)
    with pytest.raises(ValueError, match="exact indexed"):
        build_context(sample[3], sample[4], sample[6], "parse")
    with pytest.raises(ValueError, match="not Clang-confirmed"):
        build_context(sample[3], sample[4], sample[6], sample[5]["hidden"])
    with pytest.raises(ValueError, match="live context receipt"):
        StrategyTools(sample[3], sample[6].catalog, context.strategy_input, StrategyBudget(),
            index=sample[6], build_analysis=sample[4])
    with pytest.raises(ValueError, match="live construction"):
        LightweightAPIContext(context.document, sample[3], sample[4], sample[6], ContextBudget())
    altered = context.document
    altered["allowed_api_scope"].clear()
    assert context.scope.function_ids


def test_queries_never_authorize_hidden_or_unrelated_api_and_ranges_are_bounded(sample):
    context = context_for(sample)
    tools = context.make_strategy_tools(StrategyBudget())
    before = set(tools.authorized_ids)
    output = tools.execute("find_callees", {"function": sample[5]["parse"]})
    assert not output.get("error") and set(tools.authorized_ids) == before
    for name in ("hidden", "unrelated"):
        assert tools.execute("get_function", {"function": sample[5][name]})["error"] == "outside_strategy_scope"
    function = context.snapshot.functions[sample[5]["parse"]]
    output = tools.execute("read_source_range", {"file": function["file"], "line_start": 1,
        "line_end": function["end_line"] + 5})
    assert output["error"] == "outside_lightweight_source_scope"
    assert not tools.discovered and set(tools.authorized_ids) == before


def test_coherently_rehashed_scope_forgery_is_rejected_by_live_rebuild(sample, tmp_path):
    context = context_for(sample)
    store = LightweightContextStore(tmp_path)
    directory = store.save(context)
    document = context.document
    document["allowed_api_scope"].append({"function_id": sample[5]["unrelated"],
        "candidate_roles": ["cleanup"], "clang_function": sample[4].verify_function(sample[5]["unrelated"]),
        "semantic_contract_verified": True})
    metadata = context.metadata
    metadata["context_digest"] = digest(document)
    metadata["authorization"]["context_digest"] = digest(document)
    metadata["authorization"]["allowed_function_ids"].append(sample[5]["unrelated"])
    (directory / "context.json").write_text(json.dumps(document))
    (directory / "metadata.json").write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="did not reproduce"):
        store.load(context.context_id, sample[3], sample[4], sample[6])


def test_source_and_build_recipe_changes_invalidate_live_and_saved_context(sample, tmp_path):
    context = context_for(sample)
    store = LightweightContextStore(tmp_path)
    store.save(context)
    commands = sample[2]
    original = commands.read_bytes()
    try:
        commands.write_bytes(original.replace(b"-DENABLED=0", b"-DENABLED=1"))
        with pytest.raises(BuildAnalysisError, match="compile_database_changed"):
            context.make_strategy_tools(StrategyBudget())
        with pytest.raises(BuildAnalysisError, match="compile_database_changed"):
            store.load(context.context_id, sample[3], sample[4], sample[6])
    finally:
        commands.write_bytes(original)
    source = sample[0] / "api.c"
    original = source.read_bytes()
    try:
        source.write_bytes(original.replace(b"object->value = data[0]", b"object->value = data[0] + 1"))
        with pytest.raises(BuildAnalysisError, match="source_dependency_changed"):
            context.validate()
    finally:
        source.write_bytes(original)


def test_budgeted_scope_and_source_are_explicit_without_false_semantics(sample):
    budget = replace(ContextBudget(), max_allowed_functions=1, max_scanned_functions=1)
    context = context_for(sample, budget=budget)
    assert context.scope.function_ids == {sample[5]["parse"]}
    assert context.document["discovery"]["scan_truncated"]
    assert context.document["source_evidence"]["queries"]
    assert all(not row["semantic_contract_verified"] for row in context.document["allowed_api_scope"])


def test_strategy_run_is_saved_and_replayed_under_independent_context(sample, tmp_path):
    context = context_for(sample)
    budget = StrategyBudget()
    calls = tuple(AgentToolCall(name, "get_function", canonical({"function": sample[5][name]}))
        for name in ("parse", "destroy"))

    def terminal(messages, schemas):
        outputs = [json.loads(row["content"]) for row in messages if row["role"] == "tool"]
        eids = {response["evidence"][0]["function_id"]: response["evidence_ids"] for response in outputs}
        return AgentModelResponse(tool_calls=(AgentToolCall("submit", "submit_harness_strategies",
            canonical({"strategies": [proposal_for(sample, context, eids)]})),))

    model = FakeAgentModel([AgentModelResponse(tool_calls=calls), terminal])
    run = StrategyPlanner(model, budget).plan(context.strategy_input, context.snapshot, context.make_strategy_tools(budget))
    assert run.result["status"] == "proposed"
    store = LightweightContextStore(tmp_path)
    configuration = strategy_run_configuration(context, budget, model, build_analysis_directory=sample[1])
    run_id = save_strategy_run(store, context, run, configuration)
    inputs = load_strategy_inputs(store, context, run_id)
    assert inputs["strategy"]["strategy_id"] == run.result["selected_strategy_id"]
    assert inputs["replay"]["model_calls"] == inputs["replay"]["provider_requests"] == 0
    assert len(model.calls) == 2
    assert inputs["directory"].parent.parent.name == "lightweight_strategy_runs"
    assert "minimal_ft_digest" not in configuration and not (tmp_path / "minimal_fts").exists()
    evidence = json.loads((inputs["directory"] / "evidence.json").read_text())
    evidence["authorized_function_ids"].append(sample[5]["unrelated"])
    (inputs["directory"] / "evidence.json").write_text(json.dumps(evidence))
    marker = json.loads((inputs["directory"] / "metadata.json").read_text())
    marker["document_digests"]["evidence"] = digest(evidence)
    (inputs["directory"] / "metadata.json").write_text(json.dumps(marker))
    with pytest.raises(ValueError, match="expanded callable scope"):
        load_strategy_inputs(store, context, run_id)
