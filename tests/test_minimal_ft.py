"""Artifact-only deterministic projection and cache/integrity regressions."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import random
import shutil

import pytest

from harness_generation.artifacts import ArtifactStore
from harness_generation.minimal_ft import MinimalFTBuilder, MinimalFTValidator, ProjectSnapshot, stable_ft_id
from harness_generation.minimal_ft.cli import main
from harness_generation.minimal_ft.models import POLICY_VERSION, canonical_slice
from harness_generation.minimal_ft.persistence import (build_configuration, load_compatible_build,
    load_legacy_inputs, load_slice_input, save_build)
from harness_generation.records import write_json
from harness_generation.semantic_discovery.models import canonical, candidate_id, digest
from harness_generation.semantic_slicing.persistence import run_configuration as slice_config, save_run as save_slice
from harness_generation.sfg_adapter import load_sfg_artifacts
from test_semantic_slicing import DIRECT, HUB, fixture, queries, run as slice_run, terminal, tool


def prepare(tmp_path, *, source=HUB, anchor="parse", roles=None, relations=False, extras=None, discover_callers=False):
    sample = fixture(tmp_path, source, anchor, relations=relations)
    store, artifacts, catalog, candidate, _, ids = sample
    roles = roles or {anchor: ("core", "accepted_anchor")}
    mapping = {ids[name]: value for name, value in roles.items()}
    responses = []
    if discover_callers:
        responses.append(queries(tool("find_callers", "discover_callers", function=ids[anchor]),
            tool("find_callees", "discover_callees", function=ids[anchor])))
    if source == DIRECT and anchor == "wrapper" and "parse" in roles:
        responses.append(queries(tool("find_callees", "discover_delegate", function=ids["wrapper"])))
    responses.append(queries(*(tool("get_function", f"body_{name}", function=ids[name]) for name in roles)))
    def mutate(document):
        for row in document["classification"]:
            if extras and row["function_id"] in {ids[name] for name in extras}:
                name = next(name for name in extras if ids[name] == row["function_id"])
                row["reason_codes"].extend(extras[name])
    responses.append(terminal(mapping, mutate=mutate))
    run, model, tools = slice_run(sample, responses)
    assert run.result["run_status"] in {"completed", "completed_with_unresolved"}
    save_slice(store, run, slice_config(catalog, tools.frontier, tools.budget, model, 32))
    return store, candidate_id(candidate.function_id), ids


def inputs(sample, *, comparison=False):
    store, cid, _ = sample
    snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(store.root))
    anchor = snapshot.anchor_for_candidate(cid)
    legacy, manifest = load_legacy_inputs(store, {anchor}, enabled=comparison)
    source = load_slice_input(store, cid, legacy=legacy[anchor])
    return source, snapshot, build_configuration(source, snapshot, manifest, compare_legacy=comparison)


def build(sample, *, comparison=False):
    source, snapshot, _ = inputs(sample, comparison=comparison)
    return MinimalFTBuilder().build(source, snapshot, compare_legacy=comparison)


def rewrite_slice(sample, transform, *, update_digest=True):
    store, cid, _ = sample
    directory = store.semantic_slice_run(cid)
    document = json.loads((directory / "slice.json").read_text())
    transform(document)
    write_json(directory / "slice.json", document)
    if update_digest:
        metadata = json.loads((directory / "metadata.json").read_text())
        metadata["document_digests"]["slice"] = digest(canonical_slice(document))
        write_json(directory / "metadata.json", metadata)


def codes(result):
    return {error["code"] for error in result.minimal_ft["validation_errors"]}


def test_single_direct_parser_is_a_one_function_ft(tmp_path):
    sample = prepare(tmp_path, source=DIRECT)
    result = build(sample)
    doc = result.minimal_ft
    assert result.valid and doc["build_status"] == "completed"
    assert [(r["function"], r["role"]) for r in doc["core_functions"]] == [("parse", "anchor")]
    assert doc["support_candidates"] == [] and doc["unresolved_dependencies"] == []


def test_multi_stage_core_projects_exactly_and_maps_roles(tmp_path):
    source = HUB + "\nint process(Context *ctx,size_t extent) { ctx->size=extent; return extent?ctx->data[0]:0; }\n"
    roles = {"parse": ("core", "accepted_anchor"), "feed": ("core", "external_input_injection"),
             "process": ("core", "core_processing")}
    sample = prepare(tmp_path, source=source, roles=roles)
    doc = build(sample).minimal_ft
    assert {r["function_id"] for r in doc["core_functions"]} == {sample[-1][name] for name in roles}
    assert {r["function"]: r["role"] for r in doc["core_functions"]} == {"parse": "anchor", "feed": "input", "process": "processing"}


def test_lifecycle_support_remains_candidate_not_core_or_mandatory(tmp_path):
    roles = {"parse": ("core", "accepted_anchor"), "create": ("support", "resource_creation"),
             "destroy": ("support", "resource_cleanup")}
    sample = prepare(tmp_path, roles=roles, relations=True)
    result = build(sample)
    assert {r["function"] for r in result.minimal_ft["core_functions"]} == {"parse"}
    assert {r["function"]: r["support_kind"] for r in result.minimal_ft["support_candidates"]} == {"create": "creation", "destroy": "cleanup"}
    assert all("mandatory" not in row for row in result.minimal_ft["support_candidates"])
    assert result.metadata["support_is_api_closure"] is False


def test_optional_logger_excluded_despite_shared_context(tmp_path):
    roles = {"parse": ("core", "accepted_anchor"), "set_logger": ("exclude", "diagnostic_only")}
    sample = prepare(tmp_path, roles=roles)
    doc = build(sample).minimal_ft
    logger = sample[-1]["set_logger"]
    assert [r["function"] for r in doc["core_functions"]] == ["parse"]
    assert doc["excluded_functions"] == [logger]
    assert all(logger not in {r["source_function_id"], r["target_function_id"]} for r in doc["relations"])


def test_unresolved_ids_and_original_questions_are_fully_retained(tmp_path):
    roles = {"parse": ("core", "accepted_anchor"), "stats": ("unresolved", "insufficient_evidence")}
    sample = prepare(tmp_path, roles=roles)
    source, _, _ = inputs(sample)
    doc = build(sample).minimal_ft
    deps = {r["function_id"]: r for r in doc["unresolved_dependencies"]}
    assert set(source.document["unresolved_frontier"]) <= set(deps)
    assert deps[sample[-1]["stats"]]["questions"] == ["Need more source evidence."]
    assert doc["build_status"] == "completed_with_unresolved"


@pytest.mark.parametrize("mutation,code", [
    (lambda d: d["core_functions"].append(d["core_functions"][0]), "duplicate_function_id"),
    (lambda d: d["classification"].append(deepcopy(d["classification"][0])), "duplicate_function_id"),
    (lambda d: d.update(core_functions=[]), "empty_core"),
    (lambda d: d.pop("anchor_function_id"), "invalid_slice_schema"),
    (lambda d: d.update(anchor_function_id="api.c:999:missing"), "anchor_identity_unknown"),
    (lambda d: d.update(core_functions=["parse"]), "function_identity_unknown"),
    (lambda d: d["classification"][0].update(function="different_source_symbol"), "source_identity_mismatch"),
    (lambda d: d["classification"][0].update(role="important"), "invalid_role_enum"),
    (lambda d: d["classification"][0].update(reason_codes=["please_mark_core"]), "invalid_reason_enum"),
    (lambda d: d["classification"][0].update(evidence_ids=["ev_foreign_run"]), "unissued_slice_evidence"),
    (lambda d: d.update(support_functions=list(d["core_functions"])), "overlapping_slice_roles"),
    (lambda d: d.update(run_status="invalid"), "unsupported_or_incomplete_slice"),
])
def test_invalid_slice_invariants_are_never_repaired(tmp_path, mutation, code):
    sample = prepare(tmp_path, source=DIRECT)
    rewrite_slice(sample, mutation)
    result = build(sample)
    assert result.minimal_ft["build_status"] == "invalid"
    assert code in codes(result)
    assert result.minimal_ft["core_functions"] == []
    assert result.metadata["llm_calls"] == 0


def test_stale_slice_digest_invalidates_cached_ft(tmp_path):
    sample = prepare(tmp_path, source=DIRECT)
    source, snapshot, config = inputs(sample)
    result = MinimalFTBuilder().build(source, snapshot)
    save_build(sample[0], result, config)
    assert load_compatible_build(sample[0], result.minimal_ft["ft_id"], config, source, snapshot)
    rewrite_slice(sample, lambda d: d["classification"][0]["reason_codes"].append("input_consumption"), update_digest=False)
    changed, _, changed_config = inputs(sample)
    assert load_compatible_build(sample[0], result.minimal_ft["ft_id"], changed_config, changed, snapshot) is None
    assert "slice_document_digest_mismatch" in codes(build(sample))




def test_permutation_determinism_including_slice_digest_and_canonical_json(tmp_path):
    roles = {"parse": ("core", "accepted_anchor"), "feed": ("core", "external_input_injection"),
             "create": ("support", "resource_creation"), "destroy": ("support", "resource_cleanup"),
             "stats": ("exclude", "statistics_only"), "set_logger": ("exclude", "diagnostic_only")}
    sample = prepare(tmp_path, roles=roles, extras={"feed": ["core_state_dependency"]})
    original = build(sample).minimal_ft
    rng = random.Random(1701)
    def permute(document):
        for key in ("classification", "core_functions", "support_functions", "excluded_functions", "unresolved_frontier"):
            rng.shuffle(document[key])
        for row in document["classification"]:
            for key in ("reason_codes", "evidence_ids", "open_questions"):
                rng.shuffle(row[key])
    for _ in range(8):
        rewrite_slice(sample, permute, update_digest=False)
        changed = build(sample).minimal_ft
        assert changed["ft_id"] == original["ft_id"]
        assert canonical(changed) == canonical(original)


def test_support_changes_do_not_change_ft_identity(tmp_path):
    sample = prepare(tmp_path)
    initial = build(sample).minimal_ft["ft_id"]
    _, _, ids = sample
    anchor = ids["parse"]
    assert initial == stable_ft_id(anchor, [anchor], anchor_name="parse")
    assert stable_ft_id(anchor, [anchor, ids["feed"]], anchor_name="parse") != initial
    # Two complete audited slices with the same anchor/core, different support.
    second_path = tmp_path / "second"
    second_path.mkdir()
    second = prepare(second_path, roles={"parse": ("core", "accepted_anchor"), "create": ("support", "resource_creation")})
    assert build(second).minimal_ft["ft_id"] == initial
    assert build(second).minimal_ft["support_candidates"] != build(sample).minimal_ft["support_candidates"]


def test_artifact_root_and_project_path_do_not_affect_identity_or_canonical_ft(tmp_path):
    sample = prepare(tmp_path, source=DIRECT)
    original = build(sample).minimal_ft
    copied = tmp_path / "different_root"
    shutil.copytree(sample[0].root, copied)
    document = json.loads((copied / "functions.json").read_text())
    document["project"] = "/an/unavailable/project/root"
    write_json(copied / "functions.json", document)
    moved = build((ArtifactStore(copied), sample[1], sample[2])).minimal_ft
    assert canonical(moved) == canonical(original)


def test_ambiguous_support_kind_retains_candidate_and_unknown(tmp_path):
    sample = prepare(tmp_path, roles={"parse": ("core", "accepted_anchor"), "create": ("support", "resource_creation")},
                     extras={"create": ["required_initialization"]})
    doc = build(sample).minimal_ft
    assert doc["support_candidates"][0]["support_kind"] == "unknown"
    assert doc["unresolved_dependencies"][0]["function_id"] == sample[-1]["create"]
    assert any("support_kind_unresolved" in r["questions"] for r in doc["unresolved_dependencies"])


def test_syntactic_call_keeps_weak_strength_and_exact_evidence_provenance(tmp_path):
    sample = prepare(tmp_path, source=DIRECT, anchor="wrapper", roles={
        "wrapper": ("core", "accepted_anchor"), "parse": ("core", "core_processing")})
    result = build(sample)
    calls = [r for r in result.minimal_ft["relations"] if r["kind"] == "calls"]
    assert len(calls) == 1
    assert (calls[0]["source_function_id"], calls[0]["target_function_id"]) == (sample[-1]["wrapper"], sample[-1]["parse"])
    assert calls[0]["strength"] == "weak" and calls[0]["evidence_ids"]
    assert calls[0]["provenance"]["symbol_resolution"] == "name_only_not_a_proven_call_edge"


def test_existing_ownership_and_usage_preserve_strong_fact_provenance(tmp_path):
    sample = prepare(tmp_path, relations=True, roles={"parse": ("core", "accepted_anchor"),
        "feed": ("core", "external_input_injection"), "create": ("support", "resource_creation"), "destroy": ("support", "resource_cleanup")})
    doc = build(sample).minimal_ft
    sources = {r["provenance"]["artifact"] for r in doc["relations"] if r["strength"] == "strong"}
    assert {"ownership.json", "usage_patterns.json"} <= sources
    assert all(r["strength"] == "weak" for r in doc["relations"] if r["kind"] == "structural")






def test_builder_validator_rejects_invented_projection_and_lost_unknown(tmp_path):
    sample = prepare(tmp_path)
    source, snapshot, _ = inputs(sample)
    doc = build(sample).minimal_ft
    assert MinimalFTValidator().validate(doc, source, snapshot) == []
    changed = deepcopy(doc)
    changed["unresolved_dependencies"] = []
    assert "unresolved_disappeared" in {e["code"] for e in MinimalFTValidator().validate(changed, source, snapshot)}
    changed = deepcopy(doc)
    changed["ft_id"] = "ft_invented"
    assert "ft_identity_mismatch" in {e["code"] for e in MinimalFTValidator().validate(changed, source, snapshot)}
    changed = deepcopy(doc)
    changed["core_functions"][0]["role"] = "actually_important"
    assert "invalid_projection_role_enum" in {e["code"] for e in MinimalFTValidator().validate(changed, source, snapshot)}


def test_validator_rejects_dropped_builder_unknown_even_with_matching_output_digest(tmp_path):
    sample = prepare(tmp_path, roles={"parse": ("core", "accepted_anchor"),
        "create": ("support", "resource_creation")}, extras={"create": ["required_initialization"]})
    source, snapshot, configuration = inputs(sample)
    result = build(sample)
    save_build(sample[0], result, configuration)
    directory = sample[0].minimal_ft_run(result.minimal_ft["ft_id"])
    changed = deepcopy(result.minimal_ft)
    changed["unresolved_dependencies"] = [d for d in changed["unresolved_dependencies"]
        if d["function_id"] != sample[-1]["create"]]
    errors = MinimalFTValidator().validate(changed, source, snapshot)
    assert "dependencies_changed_projection" in {error["code"] for error in errors}
    metadata = json.loads((directory / "metadata.json").read_text())
    metadata["minimal_ft_digest"] = digest(changed)
    write_json(directory / "minimal_ft.json", changed)
    write_json(directory / "metadata.json", metadata)
    assert load_compatible_build(sample[0], changed["ft_id"], configuration, source, snapshot) is None


def test_validator_rejects_fabricated_strong_relation_with_valid_identity(tmp_path):
    sample = prepare(tmp_path, roles={"parse": ("core", "accepted_anchor"),
        "feed": ("core", "external_input_injection")})
    source, snapshot, _ = inputs(sample)
    changed = deepcopy(build(sample).minimal_ft)
    from harness_generation.minimal_ft.relations import relation_id
    relation = {"source_function_id": sample[-1]["feed"], "target_function_id": sample[-1]["parse"],
        "kind": "feeds", "strength": "strong", "provenance": {"artifact": "ownership.json"}, "evidence_ids": []}
    relation["relation_id"] = relation_id(relation)
    changed["relations"].append(relation)
    errors = MinimalFTValidator().validate(changed, source, snapshot)
    assert "relations_changed_persisted_facts" in {error["code"] for error in errors}


def test_cli_candidate_selection_preserves_other_compatible_catalog_entries(tmp_path, capsys):
    first = prepare(tmp_path, source=DIRECT)
    second_path = tmp_path / "second"
    second_path.mkdir()
    second = prepare(second_path, source=DIRECT, anchor="wrapper", roles={
        "wrapper": ("core", "accepted_anchor"), "parse": ("core", "input_consumption")})
    store = first[0]
    shutil.copytree(second[0].semantic_slice_run(second[1]), store.semantic_slice_run(second[1]))
    catalog = json.loads(store.validated_candidates.read_text())
    other = json.loads(second[0].validated_candidates.read_text())
    catalog["candidates"] = [r for r in catalog["candidates"] if r["candidate_id"] != second[1]]
    catalog["candidates"].extend(r for r in other["candidates"] if r["candidate_id"] == second[1])
    write_json(store.validated_candidates, catalog)
    assert main(["--artifacts", str(store.root)]) == 0
    entries = json.loads(store.minimal_ft_catalog.read_text())["fts"]
    assert {r["candidate_id"] for r in entries} == {first[1], second[1]}
    paths = [store.minimal_ft_run(r["ft_id"]) / "minimal_ft.json" for r in entries]
    before = {path: path.stat().st_mtime_ns for path in paths}
    assert main(["--artifacts", str(store.root), "--candidate", first[-1]["parse"], "--resume"]) == 0
    assert json.loads(store.minimal_ft_catalog.read_text())["fts"] == entries
    assert before == {path: path.stat().st_mtime_ns for path in paths}
    assert "processed=0 resumed=1 invalid=0" in capsys.readouterr().out


def test_cli_resume_no_llm_no_source_scan_and_inputs_unchanged(tmp_path, monkeypatch, capsys):
    sample = prepare(tmp_path, source=DIRECT)
    store, cid, ids = sample
    from harness_generation.semantic_discovery import DeepSeekAgentModel, FakeAgentModel
    from harness_generation.semantic_discovery.tools import RepositoryIndex
    from sfg_builder.parser import CProjectParser
    def forbidden(*args, **kwargs):
        raise AssertionError("model or repository scanner called by Minimal FT Builder")
    monkeypatch.setattr(DeepSeekAgentModel, "__init__", forbidden)
    monkeypatch.setattr(DeepSeekAgentModel, "complete", forbidden)
    monkeypatch.setattr(FakeAgentModel, "complete", forbidden)
    monkeypatch.setattr(RepositoryIndex, "build_syntax_index", forbidden)
    monkeypatch.setattr(CProjectParser, "parse", forbidden)
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    shutil.rmtree(tmp_path / "project")
    before = {path: path.read_bytes() for path in store.root.rglob("*.json")}
    args = ["--artifacts", str(store.root), "--candidate", ids["parse"]]
    assert main(args) == 0
    catalog = json.loads(store.minimal_ft_catalog.read_text())
    directory = store.minimal_ft_run(catalog["fts"][0]["ft_id"])
    files = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in directory.iterdir()}
    assert main(["--artifacts", str(store.root), "--candidate", cid, "--resume"]) == 0
    assert "processed=0 resumed=1" in capsys.readouterr().out
    assert all((p.read_bytes(), p.stat().st_mtime_ns) == old for p, old in files.items())
    assert all(path.read_bytes() == old for path, old in before.items())


def test_resume_invalidates_phase1_function_snapshot_change(tmp_path):
    sample = prepare(tmp_path, source=DIRECT)
    assert main(["--artifacts", str(sample[0].root)]) == 0
    path = sample[0].functions
    document = json.loads(path.read_text())
    document["functions"][0]["body"] += "\n/* changed snapshot */"
    write_json(path, document)
    assert main(["--artifacts", str(sample[0].root), "--resume"]) == 1
    assert json.loads(sample[0].minimal_ft_catalog.read_text())["fts"][0]["status"] == "invalid"


def test_resume_rejects_output_tampering_and_recovers_missing_commit_marker(tmp_path):
    sample = prepare(tmp_path, source=DIRECT)
    source, snapshot, config = inputs(sample)
    result = build(sample)
    save_build(sample[0], result, config)
    directory = sample[0].minimal_ft_run(result.minimal_ft["ft_id"])
    path = directory / "minimal_ft.json"
    document = json.loads(path.read_text())
    document["source_slice"]["digest"] = "0" * 64
    write_json(path, document)
    assert load_compatible_build(sample[0], result.minimal_ft["ft_id"], config, source, snapshot) is None
    assert main(["--artifacts", str(sample[0].root), "--resume"]) == 0
    (directory / "metadata.json").unlink()
    assert main(["--artifacts", str(sample[0].root), "--resume"]) == 0
    assert load_compatible_build(sample[0], result.minimal_ft["ft_id"], config, source, snapshot)


@pytest.mark.parametrize("key,value", [("policy_version", "future-policy"), ("builder_schema_version", 2), ("functions_fingerprint", "stale")])
def test_resume_fingerprint_checks_all_versioned_inputs(tmp_path, key, value):
    sample = prepare(tmp_path, source=DIRECT)
    source, snapshot, config = inputs(sample)
    result = build(sample)
    save_build(sample[0], result, config)
    assert load_compatible_build(sample[0], result.minimal_ft["ft_id"], {**config, key: value}, source, snapshot) is None








def test_no_legacy_comparison_and_explicit_candidate_errors(tmp_path):
    sample = prepare(tmp_path, source=DIRECT)
    doc = build(sample, comparison=False).minimal_ft
    assert "legacy_comparison" not in doc
    assert main(["--artifacts", str(sample[0].root), "--candidate", "parse"]) == 1
    assert main(["--artifacts", str(sample[0].root), "--candidate", sample[-1]["unrelated"]]) == 1
