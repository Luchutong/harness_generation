"""Generation source authentication with saved offline strategy transcripts.

The FT-shaped fixture is an explicit shared-component input. These checks do
not exercise or certify the complete Minimal FT loader or upstream pipeline.
No provider, compiler or runtime process is started.
"""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from harness_generation.harness_strategy import persistence
from harness_generation.orchestration.generation_base import (
    authenticate_candidate_evidence, load_strategy_inputs,
)
from harness_generation.semantic_discovery.models import digest
from v05_fixtures import planner_fixture, run_planner_fixture


@pytest.fixture
def saved_strategy(tmp_path):
    fixture = planner_fixture(tmp_path)
    store, ft, metadata, snapshot, _, _ = fixture
    run, model, configuration = run_planner_fixture(fixture)
    assert run.result["status"] == "proposed"
    assert configuration["agent"]["provider"] == "fake"
    run_id = persistence.save_run(store, ft["ft_id"], run, configuration)
    selected = next(row["strategy"] for row in run.result["candidates"]
                    if row["strategy"]["strategy_id"] == run.result["selected_strategy_id"])
    evidence = {"schema_version": 1,
                "records": sorted(deepcopy(run.evidence["records"]), key=lambda row: row["evidence_id"]),
                "authorized_function_ids": sorted(run.evidence["authorized_function_ids"])}
    candidate = {"artifacts": str(store.root), "ft_id": ft["ft_id"], "ft_digest": digest(ft),
                 "strategy": deepcopy(selected), "strategy_run": run_id,
                 "effect_runs": [], "query_runs": [], "evidence": evidence,
                 "authorized_function_ids": list(evidence["authorized_function_ids"])}
    return SimpleNamespace(store=store, ft=ft, metadata=metadata, snapshot=snapshot,
                           run=run, model=model, run_id=run_id, candidate=candidate,
                           directory=persistence.run_directory(store, ft["ft_id"], run_id))


def authenticate(saved, candidate):
    return authenticate_candidate_evidence(candidate, saved.store, saved.ft,
                                           saved.metadata, saved.snapshot)


def test_saved_offline_strategy_returns_exact_live_evidence_and_scope(saved_strategy, monkeypatch):
    saved = saved_strategy
    planner_calls = len(saved.model.calls)
    files = {path: path.read_bytes() for path in saved.directory.iterdir()}
    replay_calls = []
    complete = persistence.TranscriptModel.complete

    def observe_replay(model, messages, tools):
        replay_calls.append(model)
        return complete(model, messages, tools)

    monkeypatch.setattr(persistence.TranscriptModel, "complete", observe_replay)
    replay = persistence.replay_run(saved.store, saved.ft, saved.metadata, saved.snapshot, saved.run_id)
    strategy, upstream = load_strategy_inputs(saved.store, saved.ft, saved.metadata,
                                              saved.snapshot, saved.run_id)
    before = deepcopy(saved.candidate)
    authenticated = authenticate(saved, saved.candidate)
    assert strategy == saved.candidate["strategy"]
    assert upstream == saved.run.evidence
    assert authenticated == saved.candidate["evidence"]
    assert authenticated["authorized_function_ids"] == [saved.ft["anchor_function_id"]]
    assert authenticated["records"] == sorted(saved.run.evidence["records"], key=lambda row: row["evidence_id"])
    assert saved.candidate == before
    assert replay["status"] == "reproduced"
    assert replay["model_calls"] == replay["provider_requests"] == 0
    assert replay_calls and len(saved.model.calls) == planner_calls
    assert files == {path: path.read_bytes() for path in saved.directory.iterdir()}


@pytest.mark.parametrize("mutation", ["evidence", "scope", "strategy", "ft_digest"])
def test_candidate_cannot_replace_saved_evidence_scope_or_strategy(saved_strategy, mutation):
    saved = saved_strategy
    candidate = deepcopy(saved.candidate)
    if mutation == "evidence":
        candidate["evidence"]["records"][0]["source_sha256"] = "0" * 64
    elif mutation == "scope":
        # Matching candidate labels cannot widen the transcript's live scope.
        candidate["authorized_function_ids"].append("api.c:99:unissued")
        candidate["evidence"]["authorized_function_ids"].append("api.c:99:unissued")
    elif mutation == "strategy":
        candidate["strategy"]["open_questions"].append("Unissued strategy edit")
        candidate["strategy"]["strategy_digest"] = digest({key: value for key, value
            in candidate["strategy"].items() if key != "strategy_digest"})
    else:
        candidate["ft_digest"] = "0" * 64
    with pytest.raises(ValueError, match="identity changed|evidence or API scope changed"):
        authenticate(saved, candidate)


@pytest.mark.parametrize("field", ["effect_runs", "query_runs"])
def test_generation_refuses_recovery_evidence_extensions(saved_strategy, field):
    candidate = deepcopy(saved_strategy.candidate)
    candidate[field] = ["unissued_recovery_run"]
    with pytest.raises(ValueError, match="cannot extend.*evidence through recovery"):
        authenticate(saved_strategy, candidate)


@pytest.mark.parametrize("mutation,document_name", [
    ("evidence", "evidence"), ("scope", "evidence"), ("strategy", "strategies"),
])
def test_rehashed_saved_document_cannot_bypass_transcript_replay(saved_strategy, mutation, document_name):
    saved = saved_strategy
    path = saved.directory / (document_name + ".json")
    document = json.loads(path.read_text())
    if mutation == "evidence":
        document["records"][0]["content"] += "\n/* forged source evidence */"
    elif mutation == "scope":
        document["authorized_function_ids"].append("api.c:99:unissued")
    else:
        document["candidates"][0]["strategy"]["open_questions"].append("Unissued strategy edit")
    path.write_text(json.dumps(document))
    marker_path = saved.directory / "metadata.json"
    marker = json.loads(marker_path.read_text())
    marker["document_digests"][document_name] = digest(document)
    marker_path.write_text(json.dumps(marker))
    with pytest.raises(ValueError, match="transcript did not reproduce"):
        load_strategy_inputs(saved.store, saved.ft, saved.metadata, saved.snapshot, saved.run_id)


@pytest.mark.parametrize("entrypoint", ["load", "authenticate"])
def test_current_source_drift_refuses_saved_strategy_authentication(saved_strategy, entrypoint):
    saved = saved_strategy
    source = saved.store.root.parent / "project" / "api.c"
    source.write_text(source.read_text() + "\nint changed_source(void) { return 1; }\n")
    with pytest.raises(ValueError, match="source"):
        if entrypoint == "load":
            load_strategy_inputs(saved.store, saved.ft, saved.metadata, saved.snapshot, saved.run_id)
        else:
            authenticate(saved, saved.candidate)
