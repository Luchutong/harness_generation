"""Exact bounded API selection and live replay; no model or harness execution."""
from dataclasses import replace
import json
import shutil

import pytest

from harness_generation.entry_candidates import CandidateCatalog
from harness_generation.lightweight_context import ContextBudget, LightweightContextStore, build_context
from harness_generation.lightweight_context.models import VERSION
from harness_generation.semantic_discovery.models import digest
from harness_generation.semantic_discovery.tools import RepositoryIndex
from v05_fixtures import compile_fixture as prepared
from v05_fixtures import lightweight_sample as sample

pytestmark = pytest.mark.skipif(shutil.which("clang") is None, reason="small real Clang fixture required")


def selected(sample, names, *, budget=None):
    return build_context(sample[3], sample[4], sample[6], sample[5]["parse"],
        budget=budget, support_function_ids=[sample[5][name] for name in names])


def test_explicit_related_ids_are_exact_and_survive_live_store_replay(sample, tmp_path):
    context = selected(sample, ["destroy", "create"])
    expected = {sample[5][name] for name in ("parse", "destroy", "create")}
    assert context.scope.function_ids == expected
    assert sample[5]["use"] not in expected
    assert context.document["policy_version"] == VERSION == "lightweight-api-context-v2"
    assert context.document["scope_selection_policy"] == "explicit_related_api_ids"
    assert context.document["requested_support_function_ids"] == sorted(expected - {sample[5]["parse"]})
    assert not context.document["discovery"]["repository_scan_performed"]
    assert context.document["discovery"]["scanned_functions"] == 2
    assert context.document["cost"]["model_calls"] == context.document["cost"]["provider_requests"] == 0
    assert selected(sample, ["create", "destroy"]).document == context.document
    store = LightweightContextStore(tmp_path)
    store.save(context)
    replayed = store.load(context.context_id, sample[3], sample[4], sample[6])
    assert replayed.document == context.document
    assert replayed.scope.receipt == context.scope.receipt
    assert replayed.strategy_input["requested_support_function_ids"] == context.document["requested_support_function_ids"]
    assert replayed.strategy_input["artifact_kind"] == "lightweight_api_context_reference"
    assert all(row["semantic_contract_verified"] is False for row in replayed.document["allowed_api_scope"])
    assert replayed.metadata["semantic_verified"] is replayed.metadata["generation_allowed"] is False
    assert not any((tmp_path / name).exists() for name in ("minimal_fts", "semantic_slices", "candidate_discovery"))


@pytest.mark.parametrize("names,message", [
    (["destroy", "destroy"], "duplicate"),
    (["parse"], "must not repeat the anchor"),
    (["hidden"], "not Clang-confirmed callable"),
    (["unrelated"], "no canonical resource type association"),
])
def test_explicit_selection_rejects_duplicate_anchor_noncallable_and_unrelated(sample, names, message):
    with pytest.raises(ValueError, match=message):
        selected(sample, names)


@pytest.mark.parametrize("ids", ["destroy", ["destroy"], [None], {"destroy"}])
def test_explicit_selection_requires_exact_indexed_ids(sample, ids):
    with pytest.raises(ValueError, match="exact indexed function IDs"):
        build_context(sample[3], sample[4], sample[6], sample[5]["parse"], support_function_ids=ids)


def test_explicit_scope_budget_is_enforced_before_admission(sample):
    budget = replace(ContextBudget(), max_allowed_functions=2)
    with pytest.raises(ValueError, match="exceed scope budget"):
        selected(sample, ["create", "destroy"], budget=budget)
    context = selected(sample, ["destroy"], budget=budget)
    assert context.scope.function_ids == {sample[5]["parse"], sample[5]["destroy"]}


@pytest.fixture(scope="module")
def crowded(tmp_path_factory):
    root = tmp_path_factory.mktemp("lightweight_crowded_scope")
    header = """#include <stdlib.h>
typedef struct Object { int value; } Object;
Object *parse(const unsigned char *data, size_t size, unsigned int *counts);
Object *create(int a, int b, int c, int d, int e);
void destroy(Object *object);
void reset_bytes(unsigned char *data);
void reset_counts(unsigned int *counts);
"""
    source = """#include "api.h"
Object *parse(const unsigned char *data, size_t size, unsigned int *counts) {
    (void)data; (void)size; (void)counts; return NULL;
}
Object *create(int a, int b, int c, int d, int e) {
    Object *object = calloc(1, sizeof(Object));
    if (object) object->value = a + b + c + d + e;
    return object;
}
void destroy(Object *object) { free(object); }
void reset_bytes(unsigned char *data) { data[0] = 0; }
void reset_counts(unsigned int *counts) { counts[0] = 0; }
"""
    # All setter candidates have fewer parameters than create. A global
    # arity-only ordering would consume the bounded scope before create.
    for number in range(12):
        header += f"void setter_{number:02d}(Object *object);\n"
        source += f"void setter_{number:02d}(Object *object) {{ object->value = {number}; }}\n"
    _, artifacts, _, snapshot, analysis, ids = prepared(root, source=source, header=header)
    index = RepositoryIndex(snapshot.artifacts, CandidateCatalog((), snapshot.source_fingerprint),
        functions_path=artifacts / "functions.json")
    return snapshot, analysis, ids, index


def test_default_bounded_selection_reserves_create_and_cleanup_opportunities(crowded):
    snapshot, analysis, ids, index = crowded
    context = build_context(snapshot, analysis, index, ids["parse"],
        budget=replace(ContextBudget(), max_allowed_functions=3))
    assert context.scope.function_ids == {ids["parse"], ids["create"], ids["destroy"]}
    assert context.document["scope_selection_policy"] == "bounded_role_balanced_discovery"
    assert context.document["requested_support_function_ids"] == []
    assert context.document["discovery"]["repository_scan_performed"]
    assert context.document["discovery"]["scope_truncated"]
    rows = {row["function_id"]: row for row in context.document["allowed_api_scope"]}
    assert "construction_candidate" in rows[ids["create"]]["candidate_roles"]
    assert "cleanup_name_hint" in rows[ids["destroy"]]["candidate_roles"]
    assert all(row["semantic_contract_verified"] is False for row in rows.values())
    assert rows[ids["destroy"]]["candidate_role_authority"] == "type_or_name_hint_only"


@pytest.mark.parametrize("name", ["reset_bytes", "reset_counts"])
def test_shared_primitive_pointer_does_not_grant_resource_support_authority(crowded, name):
    snapshot, analysis, ids, index = crowded
    with pytest.raises(ValueError, match="no canonical resource type association"):
        build_context(snapshot, analysis, index, ids["parse"], support_function_ids=[ids[name]])


def test_saved_scope_selection_cannot_be_rehashed_into_a_different_live_receipt(sample, tmp_path):
    context = selected(sample, ["create", "destroy"])
    store = LightweightContextStore(tmp_path)
    directory = store.save(context)
    document = context.document
    # Replace the selection and authorization coherently, but preserve the
    # old Context ID. The live builder derives a different content identity.
    document["requested_support_function_ids"] = [sample[5]["destroy"]]
    document["allowed_api_scope"] = [row for row in document["allowed_api_scope"]
        if row["function_id"] != sample[5]["create"]]
    metadata = context.metadata
    metadata["context_digest"] = digest(document)
    metadata["authorization"]["context_digest"] = digest(document)
    metadata["authorization"]["allowed_function_ids"] = sorted({sample[5]["parse"], sample[5]["destroy"]})
    metadata["authorization"]["requested_support_function_ids"] = document["requested_support_function_ids"]
    (directory / "context.json").write_text(json.dumps(document))
    (directory / "metadata.json").write_text(json.dumps(metadata))
    with pytest.raises(ValueError, match="did not reproduce"):
        store.load(context.context_id, sample[3], sample[4], sample[6])


def test_old_scope_policy_is_rejected_without_silent_migration(sample, tmp_path):
    context = selected(sample, ["destroy"])
    store = LightweightContextStore(tmp_path)
    directory = store.save(context)
    document = context.document
    document["policy_version"] = "lightweight-api-context-v1"
    (directory / "context.json").write_text(json.dumps(document))
    with pytest.raises(ValueError, match="policy mismatch"):
        store.load(context.context_id, sample[3], sample[4], sample[6])
