"""Behavioral regression tests for discovery/construction separation."""
from dataclasses import replace
import json
from pathlib import Path

import pytest

from harness_generation import (ArtifactStore, CandidateCatalog, CandidateSignal,
                                FunctionTripletExtractor, MockLLM,
                                discover_candidates, discover_candidates_legacy)
from harness_generation.cli import main
from harness_generation.ft_relations import StructuralSelection
from harness_generation.ft_selection import build_selection_manifest
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.triplet import TRIPLET_SCHEMA_VERSION, load_triplets_json
from sfg_builder.mock import MockSemanticAnalyzer
from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline


API_SOURCE = """typedef struct Context { int value; } Context;
int feed(Context *ctx, const char *data, unsigned long len) {
    ctx->value += len ? data[0] : 0;
    return ctx->value;
}
void context_reset(Context *ctx) { ctx->value = 0; }
int inspect(Context *ctx) { return ctx->value; }
int parse_wrapped(Context *ctx) { return ctx->value; }
int feed_unusual(Context *ctx, const void *src, unsigned long cb) {
    return ctx->value + (cb ? ((const unsigned char *)src)[0] : 0);
}
int path_bytes(Context *ctx, const char *path, unsigned long len) {
    return ctx->value + (len ? path[0] : 0);
}
int scalar(void) { return 7; }
int declaration_only(void);
"""


def phase1(tmp_path, source=API_SOURCE, paper_minimal=False):
    project = tmp_path / "project"
    project.mkdir()
    (project / "api.c").write_text(source)
    output = tmp_path / "artifacts"
    SFGPipeline(MockSemanticAnalyzer(), ignored_directories=DEFAULT_IGNORES,
                paper_minimal=paper_minimal).run(project, output)
    return ArtifactStore(output), load_sfg_artifacts(output)


@pytest.fixture
def sample(tmp_path):
    return phase1(tmp_path)


def candidate_named(catalog, name):
    return next(c for c in catalog.candidates if c.function == name)


def test_discovery_retains_all_functions_despite_legacy_filters(sample):
    _, artifacts = sample
    catalog = discover_candidates(artifacts)
    assert len(catalog.candidates) == len(artifacts.functions) == 8
    assert {c.function for c in catalog.selected} == {
        "feed", "context_reset", "inspect", "parse_wrapped", "feed_unusual", "path_bytes", "scalar"}
    for name in ("feed_unusual", "parse_wrapped", "path_bytes", "scalar"):
        candidate = candidate_named(catalog, name)
        assert candidate.status == "unresolved"
        assert not candidate.metadata["legacy_isf_annotation"]
    unusual = candidate_named(catalog, "feed_unusual")
    assert {s.kind for s in unusual.signals} >= {
        "pointer_parameter", "length_like_parameter", "buffer_length_relation_candidate"}
    assert any(s.evidence["relation_proven"] is False
               for s in unusual.signals if s.kind == "buffer_length_relation_candidate")
    declaration = candidate_named(catalog, "declaration_only")
    assert catalog.deferred_reasons[declaration.function_id] == "declaration_only"


def test_paper_minimal_cannot_erase_entry_hypotheses(tmp_path):
    _, artifacts = phase1(tmp_path, "int parse(const char *data, unsigned long len) { return len ? data[0] : 0; }",
                          paper_minimal=True)
    assert not artifacts.annotations
    broad = discover_candidates(artifacts)
    legacy = discover_candidates_legacy(artifacts)
    assert [c.function for c in broad.selected] == ["parse"]
    assert len(legacy.candidates) == 1 and not legacy.selected
    assert legacy.deferred_reasons[broad.selected[0].function_id] == "not_selected_by_legacy_isf_policy"


def test_budget_defers_hypotheses_without_deleting_them(sample):
    _, artifacts = sample
    catalog = discover_candidates(artifacts, max_candidates=1)
    assert len(catalog.candidates) == 8
    assert [c.function for c in catalog.selected] == ["feed"]
    assert sum(r == "candidate_budget" for r in catalog.deferred_reasons.values()) == 6
    assert len(discover_candidates(artifacts, max_candidates=0).deferred_reasons) == 8


def test_catalog_is_deterministic_and_contains_no_raw_model_output(sample):
    store, artifacts = sample
    original_static = (store.root / "candidates.json").read_bytes()
    catalog = discover_candidates(artifacts)
    reordered = replace(artifacts, functions=tuple(reversed(artifacts.functions)),
                        annotations=tuple(reversed(artifacts.annotations)))
    assert discover_candidates(reordered).to_dict() == catalog.to_dict()
    store.write_candidate_catalog(catalog)
    initial = store.entry_candidates.read_bytes()
    loaded = store.load_candidate_catalog()
    assert loaded.to_dict() == catalog.to_dict()
    store.write_candidate_catalog(loaded)
    assert store.entry_candidates.read_bytes() == initial
    assert (store.root / "candidates.json").read_bytes() == original_static
    assert not store.triplets.exists()
    assert not any(key in initial.decode() for key in ('"prompt"', '"response"', '"reason": "path-like name"'))


def test_stale_catalog_is_rejected(sample):
    _, artifacts = sample
    catalog = discover_candidates(artifacts)
    changed = tuple({**f, "body": str(f.get("body", "")) + " /* changed */"}
                    if f["name"] == "feed" else f for f in artifacts.functions)
    with pytest.raises(ValueError, match="does not match current Phase 1"):
        FunctionTripletExtractor().extract(replace(artifacts, functions=changed), candidates=catalog)


def test_forged_candidate_identity_is_rejected(sample):
    _, artifacts = sample
    catalog = discover_candidates(artifacts)
    candidate = candidate_named(catalog, "feed")
    forged = replace(candidate, signature="void forged(void)")
    with pytest.raises(ValueError, match="identity"):
        FunctionTripletExtractor().extract_for_anchor(artifacts, forged)
    with pytest.raises(ValueError, match="identity"):
        replace(catalog, candidates=tuple(forged if c == candidate else c for c in catalog.candidates)).validate_against(artifacts)


@pytest.mark.parametrize("score", [float("nan"), float("inf"), True, -0.1, 1.1])
def test_signals_reject_invalid_scores(score):
    with pytest.raises(ValueError, match="score"):
        CandidateSignal("pointer_parameter", score)


def test_catalog_requires_explicit_reason_for_every_deferred_candidate(sample):
    _, artifacts = sample
    catalog = discover_candidates(artifacts)
    document = catalog.to_dict()
    document["selection"]["deferred"] = []
    with pytest.raises(ValueError, match="deferred reason"):
        CandidateCatalog.from_dict(document)
    with pytest.raises(ValueError, match="unique"):
        catalog.select_anchors([catalog.selected_function_ids[0]] * 2)
    with pytest.raises(ValueError, match="unknown"):
        catalog.select_anchors(["unknown"])


def test_legacy_wrapper_and_catalog_produce_identical_fts(sample):
    _, artifacts = sample
    catalog = discover_candidates_legacy(artifacts)
    assert [c.function for c in catalog.selected] == ["feed"]
    assert len(catalog.candidates) == 8
    implicit = FunctionTripletExtractor().extract(artifacts)
    explicit = FunctionTripletExtractor().extract(artifacts, candidates=catalog)
    assert [t.to_dict() for t in implicit] == [t.to_dict() for t in explicit]
    assert {f.function for f in implicit[0].functions} == {
        "feed", "context_reset", "inspect", "parse_wrapped", "feed_unusual", "path_bytes"}


def test_explicit_non_isf_anchor_is_constructed_without_changing_annotations(sample):
    _, artifacts = sample
    before = json.dumps(list(artifacts.annotations), sort_keys=True)
    candidate = candidate_named(discover_candidates(artifacts), "parse_wrapped")
    triplet, = FunctionTripletExtractor().extract_for_anchor(artifacts, candidate)
    assert triplet.isf.function_id == candidate.function_id
    assert "ISF" in triplet.isf.roles
    assert triplet.metadata["anchor_candidate"]["status"] == "unresolved"
    assert triplet.metadata["anchor_candidate"]["existing_isf_annotation"] is False
    assert json.dumps(list(artifacts.annotations), sort_keys=True) == before
    ranking = build_selection_manifest([triplet], artifacts.annotations)["ranking"][0]
    assert "missing_positive_byte_stream_evidence" in ranking["exclusion_reasons"]


def test_anchor_without_any_annotation_or_flow_is_retained(sample):
    _, artifacts = sample
    candidate = candidate_named(discover_candidates(artifacts), "scalar")
    assert candidate.function_id not in artifacts.annotations_by_id
    triplet, = FunctionTripletExtractor().extract_for_anchor(artifacts, candidate.function_id)
    assert [f.function for f in triplet.functions] == ["scalar"]
    assert triplet.isf.function == "scalar"


def test_oversized_ft_has_frontier_and_retained_candidate(sample):
    _, artifacts = sample
    catalog = discover_candidates_legacy(artifacts)
    extractor = FunctionTripletExtractor()
    assert not extractor.extract(artifacts, candidates=catalog, max_functions_per_ft=2)
    diagnostic, = extractor.exclusions
    assert diagnostic["function_count"] == 6 and diagnostic["candidate_retained"] is True
    assert set(diagnostic["frontier"]["function_ids"]) >= {catalog.selected_function_ids[0]}
    assert len(diagnostic["frontier"]["relation_evidence"]["weak_only_function_ids"]) == 5
    updated = catalog.with_construction_results([], extractor.exclusions)
    assert len(updated.candidates) == 8
    assert updated.selected[0].status == "unresolved"
    assert updated.selected[0].metadata["construction"]["status"] == "oversized"
    assert updated.selected[0].metadata["construction"]["diagnostics"][0]["frontier"] == diagnostic["frontier"]
    assert CandidateCatalog.from_dict(updated.to_dict()).to_dict() == updated.to_dict()


def test_structural_propagation_is_weak_evidence(sample):
    _, artifacts = sample
    triplet, = FunctionTripletExtractor().extract(artifacts)
    relations = triplet.metadata["relation_evidence"]
    assert relations["structural_policy"] == "legacy_structural_closure"
    assert relations["shared_type_is_semantic_evidence"] is False
    assert not relations["strong"]
    inspect_id = next(f["id"] for f in artifacts.functions if f["name"] == "inspect")
    assert inspect_id in relations["weak_only_function_ids"]


def test_lifecycle_closure_and_usage_variants_keep_strong_evidence(tmp_path):
    source = """typedef struct Hidden *Handle;
Handle handle_create(void) { return (Handle)malloc(8); }
int handle_feed(Handle h, const char *data, unsigned long len) { return h && (len ? data[0] : 0); }
void handle_free(Handle h) { free(h); }
int example(const char *data, unsigned long len) {
    Handle h=handle_create(); int r=handle_feed(h,data,len); handle_free(h); return r;
}
"""
    _, artifacts = phase1(tmp_path, source)
    candidate = candidate_named(discover_candidates(artifacts), "handle_feed")
    triplet, = FunctionTripletExtractor().extract_for_anchor(artifacts, candidate)
    assert {f.function for f in triplet.functions} == {"handle_create", "handle_feed", "handle_free"}
    relations = triplet.metadata["relation_evidence"]
    assert "explicit_usage_pattern" in {r["kind"] for r in relations["strong"]}
    assert len(relations["strong_function_ids"]) == 3
    assert not relations["weak_only_function_ids"]
    assert len(triplet.ownership_relations) == 1
    # Paper-minimal skips usage variants but still preserves the legacy
    # return-value ownership closure.
    minimal, = FunctionTripletExtractor().extract_for_anchor(artifacts, candidate, paper_minimal=True)
    assert minimal.metadata["usage_pattern"] is None
    assert {f.function for f in minimal.functions} == {"handle_create", "handle_feed", "handle_free"}


def test_future_relation_policy_can_replace_type_expansion(sample):
    _, artifacts = sample

    class AnchorOnlyPolicy:
        name = "test_anchor_only"

        def select(self, graph, *, anchor_edges, **kwargs):
            inputs = frozenset(e.source for e in anchor_edges)
            outputs = frozenset(e.target for e in anchor_edges)
            return StructuralSelection(inputs, outputs, inputs | outputs, anchor_edges)

    triplet, = FunctionTripletExtractor(AnchorOnlyPolicy()).extract(artifacts)
    assert [f.function for f in triplet.functions] == ["feed"]
    assert triplet.metadata["relation_evidence"]["structural_policy"] == "test_anchor_only"


def test_exclusions_reset_between_anchor_calls(sample):
    _, artifacts = sample
    catalog = discover_candidates(artifacts)
    extractor = FunctionTripletExtractor()
    assert not extractor.extract_for_anchor(artifacts, candidate_named(catalog, "feed"), max_functions_per_ft=1)
    assert extractor.exclusions
    assert extractor.extract_for_anchor(artifacts, candidate_named(catalog, "scalar"), max_functions_per_ft=1)
    assert not extractor.exclusions


def test_two_cli_stages_and_existing_downstream_consumers(sample):
    store, artifacts = sample
    original = (store.root / "candidates.json").read_bytes()
    assert main(["candidates", "--artifacts", str(store.root), "--policy", "legacy"]) == 0
    assert not store.triplets.exists()
    assert main(["triplets", "--artifacts", str(store.root), "--individual"]) == 0
    catalog = store.load_candidate_catalog()
    assert catalog.selected[0].metadata["construction"]["status"] == "constructed"
    assert (store.root / "candidates.json").read_bytes() == original
    assert json.loads(store.triplets.read_text())["schema_version"] == TRIPLET_SCHEMA_VERSION
    triplet, = load_triplets_json(store.triplets)
    assert store.for_triplet(triplet.id).triplet.exists()
    assert main(["triplets", "rank", "--artifacts", str(store.root), "--max-ft", "1"]) == 0
    selection = json.loads(store.ft_selection.read_text())
    assert selection["selection"][0]["triplet_id"] == triplet.id
    # Exercise unchanged generation_cli + Stage 1 with deterministic docs.
    responses = []
    for ref in triplet.functions:
        record = artifacts.functions_by_id[ref.function_id]
        arguments = ["&ctx" if p["base_type"] == "Context" else
                     '"x"' if p["is_pointer"] else "1" for p in record["parameters"]]
        responses.append(json.dumps({
            "function": ref.function, "signature": record["signature"],
            "functionality": "Fixture API", "application_scenario": "FT compatibility check",
            "example_code": f"Context ctx = {{0}}; {ref.function}({', '.join(arguments)});",
            "parameter_notes": [],
            "return_semantics": "See fixture source", "resource_lifecycle_notes": [], "notes": [],
        }))
    assert main(["generate-all", "--artifacts", str(store.root), "--selection", str(store.ft_selection),
                 "--until-stage", "1"], llm=MockLLM(responses)) == 0
    layout = store.for_triplet(triplet.id)
    documents = json.loads(layout.stage1_docs.read_text())["documents"]
    assert {d["function_id"] for d in documents} == {f.function_id for f in triplet.functions}
    state = json.loads(layout.pipeline_state.read_text())
    assert any(event["event"] == "stage_validated" and event["status"] == "passed"
               and event["stage"] == "STAGE_1_DOCS" for event in state["history"])


def test_cli_legacy_fallback_preserves_hypotheses(sample):
    store, _ = sample
    assert not store.entry_candidates.exists()
    assert main(["triplets", "--artifacts", str(store.root)]) == 0
    catalog = store.load_candidate_catalog()
    assert catalog.policy == "legacy" and len(catalog.candidates) == 8
    assert [t.isf.function for t in load_triplets_json(store.triplets)] == ["feed"]


def test_cli_records_oversized_candidate_then_allows_explicit_retry(sample):
    store, _ = sample
    assert main(["candidates", "--artifacts", str(store.root), "--policy", "legacy"]) == 0
    catalog = store.load_candidate_catalog()
    assert main(["triplets", "--artifacts", str(store.root), "--max-functions-per-ft", "2"]) == 0
    assert not load_triplets_json(store.triplets)
    assert store.load_candidate_catalog().selected[0].metadata["construction"]["status"] == "oversized"
    scalar = candidate_named(catalog, "scalar")
    assert main(["triplets", "--artifacts", str(store.root), "--anchor-id", scalar.function_id]) == 0
    assert [t.isf.function for t in load_triplets_json(store.triplets)] == ["scalar"]
    final = store.load_candidate_catalog()
    assert len(final.candidates) == 8
    assert candidate_named(final, "feed").metadata["construction"]["status"] == "oversized"
    assert final.deferred_reasons[candidate_named(final, "feed").function_id] == "not_requested"


def test_cli_refuses_malformed_catalog_instead_of_falling_back(sample, capsys):
    store, _ = sample
    store.candidate_discovery_directory.mkdir()
    store.entry_candidates.write_text('{"schema_version": 99}')
    assert main(["triplets", "--artifacts", str(store.root)]) == 1
    assert "unsupported entry candidate catalog" in capsys.readouterr().err
    assert not store.triplets.exists()
    assert main(["triplets", "--artifacts", str(store.root), "--candidates", str(store.root / "absent.json")]) == 1
    assert not store.triplets.exists()


def test_empty_selection_validates_limits(sample):
    _, artifacts = sample
    catalog = discover_candidates(artifacts, max_candidates=0)
    assert FunctionTripletExtractor().extract(artifacts, candidates=catalog) == ()
    with pytest.raises(ValueError, match="positive"):
        FunctionTripletExtractor().extract(artifacts, candidates=catalog, max_functions_per_ft=0)
