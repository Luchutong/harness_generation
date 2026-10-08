"""Witness provenance tests authored while execution is paused.

These construct small artifact documents; they do not invoke a provider or a
Context fixture. No import, fixture or test was run while writing this file.
"""
from copy import deepcopy
import hashlib
import json

import pytest

from harness_generation.artifacts import ArtifactStore
from harness_generation.harness_context.persistence import context_directory
from harness_generation.harness_context.transaction_support import (
    save_source_support, validate_source_support,
)
from harness_generation.records import write_json
from harness_generation.semantic_discovery.agent import ValidationRun
from harness_generation.semantic_discovery.models import digest
from harness_generation.semantic_discovery.persistence import save_run_documents


FT = "ft_support_" + "0" * 24
SNAPSHOT = "source-support-fixture"
DOCS = ("result", "trace", "evidence", "metadata")


class OwnedIndex:
    def __init__(self, root):
        self.root = root

    def owned_path(self, relative):
        path = self.root / relative
        if not path.resolve().is_relative_to(self.root.resolve()):
            raise ValueError("source path escapes")
        return path


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def environment(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    sources = tmp_path / "sources"
    sources.mkdir()
    content = "int parse(const unsigned char *data, unsigned long size){return size?data[0]:0;}\n"
    (sources / "api.c").write_text(content, encoding="utf-8")
    directory = context_directory(store, FT)
    destination = directory / "revision_transactions" / ("context_revision_" + "a" * 24)
    destination.mkdir(parents=True)
    record = {"tool": "get_function", "arguments": {"function": "api.c:1:parse"},
        "function_id": "api.c:1:parse", "requirement_id": "req_creator", "source": "api.c",
        "source_sha256": hashlib.sha256(content.encode()).hexdigest(), "content": content,
        "truncated": False, "origin": "phase1_snapshot"}
    record["evidence_id"] = "ev_" + digest({"snapshot": SNAPSHOT, "record": record})[:32]
    return store, directory, destination, record, OwnedIndex(sources)


def archive(directory, record, *, rid="req_creator", number=1):
    path = directory / "agent_runs" / rid / f"attempt_{number:04d}"
    run = ValidationRun({"requirement_id": rid, "status": "unresolved", "facts": [],
        "discovered_api_dependencies": [], "open_questions": ["artifact-only support carrier"]},
        {"schema_version": 1, "events": [{"kind": "tool_call", "tool_call_id": "actual_source",
            "tool": record["tool"], "arguments": deepcopy(record["arguments"]),
            "result_evidence_ids": [record["evidence_id"]], "round": 1}], "messages": []},
        {"schema_version": 1, "records": [deepcopy(record)]},
        {"schema_version": 1, "requirement_id": rid, "model_calls": 1, "tool_calls": 1,
            "source_chars": len(record["content"]), "tokens": {"total_tokens": 17},
            "live_sources": {"api.c": record["source_sha256"]}, "result_origin": "native_submission"})
    save_run_documents(path, run, {"source_fingerprint": SNAPSHOT, "policy": "artifact-fixture"})
    metadata = read(path / "metadata.json")
    return path, {"path": path.relative_to(directory).as_posix(),
        "metadata_digest": digest(metadata), "result_digest": digest(run.result)}


def support_rows(destination):
    return read(destination / "source-support.json")["witnesses"]


def rewrite_support(destination, summary, mutate):
    document = read(destination / "source-support.json")
    mutate(document)
    write_json(destination / "source-support.json", document, sort_keys=True, allow_nan=False)
    return {**summary, "digest": digest(document)}


def test_current_native_carrier_is_preferred_and_original_documents_and_cost_stay_unchanged(tmp_path):
    store, directory, destination, record, index = environment(tmp_path)
    old_path, _ = archive(directory, record)
    current_path, current = archive(directory, record, rid="req_current")
    before = {path: {name: (path / (name + ".json")).read_bytes() for name in DOCS}
        for path in (old_path, current_path)}
    witness = {record["evidence_id"]: record}
    copied = deepcopy(witness)
    summary = save_source_support(store, FT, destination, witness, {"req_current": current})
    assert summary["witness_digest"] == digest(witness)
    assert support_rows(destination)[record["evidence_id"]]["origin"]["path"] == current["path"]
    assert validate_source_support(store, FT, destination, summary, index)
    assert witness == copied
    assert {path: {name: (path / (name + ".json")).read_bytes() for name in DOCS}
        for path in (old_path, current_path)} == before


def test_record_requirement_history_precedes_other_history_and_never_depends_on_latest(tmp_path):
    store, directory, destination, record, index = environment(tmp_path)
    _, hint = archive(directory, record)
    archive(directory, record, rid="req_aaa")
    latest = directory / "agent_runs" / "req_creator"
    (latest / "metadata.json").write_text("{}", encoding="utf-8")
    summary = save_source_support(store, FT, destination, {record["evidence_id"]: record}, {})
    assert support_rows(destination)[record["evidence_id"]]["origin"]["path"] == hint["path"]
    assert validate_source_support(store, FT, destination, summary, index)


def test_other_requirement_carrier_within_same_ft_is_used_when_issuer_hint_has_no_history(tmp_path):
    store, directory, destination, record, index = environment(tmp_path)
    _, fallback = archive(directory, record, rid="req_sibling")
    summary = save_source_support(store, FT, destination, {record["evidence_id"]: record}, {})
    assert support_rows(destination)[record["evidence_id"]]["origin"]["path"] == fallback["path"]
    assert validate_source_support(store, FT, destination, summary, index)


def test_unarchived_global_record_is_not_an_issued_artifact_origin(tmp_path):
    store, _, destination, record, _ = environment(tmp_path)
    with pytest.raises(ValueError, match="source_support_origin_not_found"):
        save_source_support(store, FT, destination, {record["evidence_id"]: record}, {})
    assert not (destination / "source-support.json").exists()


@pytest.mark.parametrize("damage", ["issued_set", "metadata", "record_id"])
def test_invalid_origins_cannot_be_published_as_support(tmp_path, damage):
    store, directory, destination, record, _ = environment(tmp_path)
    path, reference = archive(directory, record)
    if damage == "issued_set":
        trace = read(path / "trace.json")
        trace["events"] = []
        write_json(path / "trace.json", trace)
        metadata = read(path / "metadata.json")
        metadata["document_digests"]["trace"] = digest(trace)
        write_json(path / "metadata.json", metadata)
        reference["metadata_digest"] = digest(metadata)
    elif damage == "metadata":
        metadata = read(path / "metadata.json")
        metadata["tool_calls"] += 1
        write_json(path / "metadata.json", metadata)
    else:
        record = {**record, "evidence_id": "ev_" + "f" * 32}
    with pytest.raises(ValueError, match="source_support_origin_not_found"):
        save_source_support(store, FT, destination, {record["evidence_id"]: record}, {"req_creator": reference})
    assert not (destination / "source-support.json").exists()


@pytest.mark.parametrize("damage", ["support", "origin_trace", "origin_metadata", "source"])
def test_support_origin_and_live_source_tampering_are_rejected(tmp_path, damage):
    store, directory, destination, record, index = environment(tmp_path)
    path, reference = archive(directory, record)
    summary = save_source_support(store, FT, destination, {record["evidence_id"]: record}, {"req_creator": reference})
    assert validate_source_support(store, FT, destination, summary, index)
    if damage == "support":
        document = read(destination / "source-support.json")
        document["witnesses"][record["evidence_id"]]["record"]["content"] = "forged"
        write_json(destination / "source-support.json", document)
    elif damage == "origin_trace":
        trace = read(path / "trace.json")
        trace["events"] = []
        write_json(path / "trace.json", trace)
    elif damage == "origin_metadata":
        metadata = read(path / "metadata.json")
        metadata["tokens"]["total_tokens"] += 1
        write_json(path / "metadata.json", metadata)
    else:
        (index.root / "api.c").write_text("changed live source", encoding="utf-8")
    assert not validate_source_support(store, FT, destination, summary, index)


@pytest.mark.parametrize("relative", ["../outside/attempt_0001", "agent_runs/req_creator",
    "/tmp/attempt_0001", "agent_runs/req_creator/../attempt_0001"])
def test_support_origin_path_is_strict_even_when_support_document_digest_is_updated(tmp_path, relative):
    store, directory, destination, record, index = environment(tmp_path)
    _, reference = archive(directory, record)
    summary = save_source_support(store, FT, destination, {record["evidence_id"]: record}, {"req_creator": reference})
    changed = rewrite_support(destination, summary, lambda doc:
        doc["witnesses"][record["evidence_id"]]["origin"].update(path=relative))
    assert not validate_source_support(store, FT, destination, changed, index)


def test_symlink_cannot_redirect_an_immutable_origin_to_another_attempt(tmp_path):
    store, directory, destination, record, index = environment(tmp_path)
    original, reference = archive(directory, record)
    summary = save_source_support(store, FT, destination, {record["evidence_id"]: record}, {"req_creator": reference})
    renamed = original.with_name("attempt_0002")
    original.rename(renamed)
    original.symlink_to(renamed, target_is_directory=True)
    assert not validate_source_support(store, FT, destination, summary, index)


def test_empty_witness_set_has_the_exact_empty_dict_digest(tmp_path):
    store, _, destination, _, index = environment(tmp_path)
    summary = save_source_support(store, FT, destination, {}, {})
    assert summary["witness_digest"] == digest({})
    assert support_rows(destination) == {}
    assert validate_source_support(store, FT, destination, summary, index)
    assert not validate_source_support(store, FT, destination, {**summary, "witness_digest": digest({"extra": {}})}, index)


def test_source_support_is_bound_to_its_exact_transaction_destination(tmp_path):
    store, _, destination, _, index = environment(tmp_path)
    summary = save_source_support(store, FT, destination, {}, {})
    other = destination.with_name("context_revision_" + "b" * 24)
    other.mkdir()
    (other / "source-support.json").write_bytes((destination / "source-support.json").read_bytes())
    assert not validate_source_support(store, FT, other, summary, index)


def test_record_identity_cannot_be_forged_even_inside_an_internally_consistent_carrier(tmp_path):
    store, directory, destination, record, _ = environment(tmp_path)
    # Digest the carrier documents consistently; preserve the stale evidence ID
    # so only the snapshot-bound record identity distinguishes this forgery.
    record = {**record, "content": "forged source content"}
    _, reference = archive(directory, record)
    with pytest.raises(ValueError, match="source_support_origin_not_found"):
        save_source_support(store, FT, destination, {record["evidence_id"]: record}, {"req_creator": reference})
    assert not (destination / "source-support.json").exists()


def test_owned_record_source_sha_is_checked_when_carrier_omits_its_live_source_map(tmp_path):
    store, directory, destination, record, index = environment(tmp_path)
    path, reference = archive(directory, record)
    metadata = read(path / "metadata.json")
    metadata["live_sources"] = {}
    write_json(path / "metadata.json", metadata)
    reference["metadata_digest"] = digest(metadata)
    summary = save_source_support(store, FT, destination, {record["evidence_id"]: record}, {"req_creator": reference})
    assert validate_source_support(store, FT, destination, summary, index)
    (index.root / "api.c").write_text("different source bytes", encoding="utf-8")
    assert not validate_source_support(store, FT, destination, summary, index)
