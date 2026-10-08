"""Artifact-only input verification, atomic output and compatible cache reuse."""
from __future__ import annotations

import json

from ..records import write_json
from ..semantic_discovery.models import digest
from .models import POLICY_VERSION, SCHEMA_VERSION, SliceInput, canonical_slice
from .validation import MinimalFTValidator, issue


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _bad_constant(value):
    raise ValueError("nonfinite JSON constant")


def _load_json(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object, parse_constant=_bad_constant)


def _owned(path, root):
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("artifact path escapes the artifact root")
    return path


def load_legacy_inputs(store, anchors, *, enabled=False):
    """Keep the input record shape without consulting legacy FT artifacts.

    ``store`` and ``enabled`` remain accepted for fixture/data compatibility.
    HG always supplies empty legacy evidence and a disabled manifest, even when
    a caller passes ``enabled=True``. No artifact path is inspected or read.
    """
    result = {anchor: {"found": False, "function_ids": [], "ft_ids": [],
                       "oversized_frontier": [], "relation_facts": [],
                       "comparison_status": "absent", "diagnostics": []}
              for anchor in anchors}
    return result, {"enabled": False}


def load_slice_input(store, cid, *, legacy=None):
    directory = _owned(store.semantic_slice_run(cid), store.root)
    errors, documents = [], {}
    for name in ("slice", "metadata", "evidence", "trace"):
        path = _owned(directory / f"{name}.json", store.root)
        try:
            value = _load_json(path)
            if not isinstance(value, dict):
                raise ValueError("agent document must be an object")
            documents[name] = value
        except (OSError, UnicodeError, ValueError):
            documents[name] = {}
            errors.append(issue("slice_document_missing_or_invalid", path.name))
    meta = documents["metadata"]
    slice_digest = digest(canonical_slice(documents["slice"]))
    for name in ("slice", "evidence", "trace"):
        actual = slice_digest if name == "slice" else digest(documents[name])
        if not isinstance(meta.get("document_digests"), dict) or meta["document_digests"].get(name) != actual:
            errors.append(issue("slice_document_digest_mismatch", f"{name}.json"))
    if (not isinstance(meta.get("configuration"), dict)
            or meta.get("configuration_fingerprint") != digest(meta.get("configuration"))):
        errors.append(issue("slice_configuration_digest_mismatch", "metadata.json"))
    from ..semantic_slicing.persistence import effect_question_policy_versions
    configuration = meta.get("configuration")
    for key, expected in effect_question_policy_versions().items():
        if not isinstance(configuration, dict) or configuration.get(key) != expected:
            errors.append(issue("slice_effect_question_policy_mismatch", "metadata.configuration." + key,
                                {"expected": expected, "received": configuration.get(key) if isinstance(configuration, dict) else None}))
    records, events = documents["evidence"].get("records"), documents["trace"].get("events")
    record_ids, issued = [], set()
    if not isinstance(records, list) or not isinstance(events, list):
        errors.append(issue("invalid_slice_audit_schema", "evidence/trace"))
        documents["evidence"] = {"schema_version": 1, "records": []}
    else:
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("evidence_id"), str):
                errors.append(issue("invalid_evidence_record", "evidence.json"))
            else:
                record_ids.append(record["evidence_id"])
        for event in events:
            if isinstance(event, dict) and event.get("kind") == "tool_call":
                ids = event.get("result_evidence_ids")
                if not isinstance(ids, list) or any(not isinstance(eid, str) for eid in ids):
                    errors.append(issue("invalid_evidence_publication", "trace.json"))
                else:
                    issued.update(ids)
        if len(record_ids) != len(set(record_ids)) or set(record_ids) != issued:
            errors.append(issue("evidence_not_published_in_slice_run", "evidence/trace"))
    validated = None
    if store.validated_candidates.exists():
        try:
            validated = _load_json(_owned(store.validated_candidates, store.root))
            if not isinstance(validated, dict):
                raise ValueError("validated catalog must be an object")
        except (OSError, UnicodeError, ValueError):
            validated = {}
            errors.append(issue("validated_catalog_invalid", "validated_candidates.json"))
    return SliceInput(canonical_slice(documents["slice"]), meta, documents["evidence"], documents["trace"], cid,
        f"semantic_slices/{cid}/slice.json", errors, validated, legacy or {},
        {"metadata": digest(meta), "evidence": digest(documents["evidence"]), "trace": digest(documents["trace"]),
         "validated_catalog": digest(validated) if validated is not None else None})


def build_configuration(source, snapshot, legacy_manifest, *, compare_legacy=True):
    return {"policy_version": POLICY_VERSION, "builder_schema_version": SCHEMA_VERSION,
            "slice_digest": source.digest, "source_fingerprint": snapshot.source_fingerprint,
            "functions_fingerprint": snapshot.functions_fingerprint, "slice_audit_digests": source.input_digests,
            "legacy_inputs": legacy_manifest, "compare_legacy": compare_legacy}


def save_build(store, build, configuration):
    document = build.minimal_ft
    directory = store.minimal_ft_run(document["ft_id"])
    directory.mkdir(parents=True, exist_ok=True)
    metadata = {**build.metadata, "configuration": configuration, "configuration_fingerprint": digest(configuration),
                "minimal_ft_digest": digest(document)}
    write_json(directory / "minimal_ft.json", document, sort_keys=True, allow_nan=False)
    # Final marker; a partial pair is never reused or published as committed.
    write_json(directory / "metadata.json", metadata, sort_keys=True, allow_nan=False)


def load_compatible_build(store, ft_id, configuration, source, snapshot):
    directory = store.minimal_ft_run(ft_id)
    try:
        document = _load_json(_owned(directory / "minimal_ft.json", store.root))
        metadata = _load_json(_owned(directory / "metadata.json", store.root))
        if (not isinstance(metadata, dict) or metadata.get("configuration") != configuration
                or metadata.get("configuration_fingerprint") != digest(configuration)
                or metadata.get("minimal_ft_digest") != digest(document)
                or not isinstance(document, dict) or document.get("ft_id") != ft_id):
            return None
        if MinimalFTValidator().validate(document, source, snapshot):
            return None
        return document
    except (OSError, UnicodeError, ValueError, TypeError, KeyError):
        return None


def write_catalog(store, records):
    path = _owned(store.minimal_ft_catalog, store.root)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_json(path, {"schema_version": SCHEMA_VERSION, "artifact_kind": "minimal_ft_catalog",
                     "policy_version": POLICY_VERSION,
                     "fts": sorted(records, key=lambda row: (row["candidate_id"], row["ft_id"]))},
               sort_keys=True, allow_nan=False)
