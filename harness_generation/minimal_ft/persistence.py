"""Artifact-only input verification, atomic output and compatible cache reuse."""
from __future__ import annotations

import hashlib
import json

from ..records import write_json
from ..semantic_discovery.models import canonical, digest
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


class _JSONStream:
    """Read one legacy array record at a time, including very large FT catalogs."""
    def __init__(self, stream):
        self.stream, self.buffer, self.position, self.ended = stream, "", 0, False
        self.decoder = json.JSONDecoder(object_pairs_hook=_unique_object, parse_constant=_bad_constant)

    def fill(self):
        chunk = self.stream.read(1024 * 1024)
        self.buffer = self.buffer[self.position:] + chunk
        self.position = 0
        if not chunk:
            self.ended = True

    def peek(self):
        while True:
            while self.position < len(self.buffer) and self.buffer[self.position].isspace():
                self.position += 1
            if self.position < len(self.buffer):
                return self.buffer[self.position]
            if self.ended:
                return ""
            self.fill()

    def expect(self, token):
        if self.peek() != token:
            raise ValueError("invalid legacy JSON structure")
        self.position += 1

    def value(self):
        self.peek()
        while True:
            try:
                value, end = self.decoder.raw_decode(self.buffer, self.position)
                # A number at a chunk boundary may be incomplete. Read once
                # more before accepting it or the following punctuation.
                if end == len(self.buffer) and not self.ended:
                    self.fill()
                    continue
                self.position = end
                return value
            except json.JSONDecodeError:
                if self.ended:
                    raise
                self.fill()


def iter_legacy_records(path, array_key):
    with path.open(encoding="utf-8") as stream:
        reader = _JSONStream(stream)
        reader.expect("{")
        seen = set()
        while reader.peek() != "}":
            key = reader.value()
            if not isinstance(key, str) or key in seen:
                raise ValueError("invalid legacy JSON key")
            seen.add(key)
            reader.expect(":")
            if key == array_key:
                reader.expect("[")
                while reader.peek() != "]":
                    yield reader.value()
                    if reader.peek() != "]":
                        reader.expect(",")
                        if reader.peek() == "]":
                            raise ValueError("trailing array comma")
                reader.expect("]")
            else:
                reader.value()
            if reader.peek() != "}":
                reader.expect(",")
                if reader.peek() == "}":
                    raise ValueError("trailing object comma")
        reader.expect("}")
        if reader.peek() or array_key not in seen:
            raise ValueError("invalid legacy catalog")


def load_legacy_inputs(store, anchors, *, enabled=True):
    result = {anchor: {"found": False, "function_ids": set(), "ft_ids": set(), "oversized_frontier": set(),
                       "relation_facts": [], "comparison_status": "absent", "diagnostics": []} for anchor in anchors}
    manifest = {"enabled": enabled}
    if not enabled:
        return result, manifest
    for path, key in ((store.triplets, "triplets"), (store.triplet_exclusions, "excluded")):
        _owned(path, store.root)
        if not path.is_file():
            manifest[path.name] = None
            continue
        checksum = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                checksum.update(chunk)
        manifest[path.name] = checksum.hexdigest()
        temporary = {anchor: {"function_ids": set(), "ft_ids": set(), "oversized_frontier": set(),
                              "facts": [], "found": False} for anchor in anchors}
        try:
            for record in iter_legacy_records(path, key):
                if not isinstance(record, dict):
                    raise ValueError("legacy records must be objects")
                anchor = (record.get("isf", {}).get("function_id") if path == store.triplets
                          and isinstance(record.get("isf"), dict) else record.get("anchor_function_id"))
                if not isinstance(anchor, str) or anchor not in temporary:
                    continue
                target = temporary[anchor]
                if path == store.triplets:
                    target["found"] = True
                    if isinstance(record.get("id"), str):
                        target["ft_ids"].add(record["id"])
                    for function in record.get("functions", []):
                        if isinstance(function, dict) and isinstance(function.get("function_id"), str):
                            target["function_ids"].add(function["function_id"])
                    relation_evidence = record.get("metadata", {}).get("relation_evidence", {})
                    facts = [*relation_evidence.get("strong", []), *record.get("ownership_relations", [])]
                else:
                    frontier = record.get("frontier", {})
                    target["oversized_frontier"].update(fid for fid in frontier.get("function_ids", []) if isinstance(fid, str))
                    facts = frontier.get("relation_evidence", {}).get("strong", [])
                for fact in facts:
                    if isinstance(fact, dict):
                        target["facts"].append({"fact": fact, "provenance": {"artifact": path.name,
                            "kind": "legacy_relation_evidence", "record_id": record.get("id"), "fact_digest": digest(fact)}})
        except (OSError, UnicodeError, ValueError, TypeError, AttributeError):
            for target in result.values():
                target["comparison_status"] = "invalid"
                target["diagnostics"].append({"code": "legacy_artifact_invalid", "artifact": path.name})
            continue
        for anchor, target in temporary.items():
            previous = result[anchor]
            previous["function_ids"].update(target["function_ids"])
            previous["ft_ids"].update(target["ft_ids"])
            previous["oversized_frontier"].update(target["oversized_frontier"])
            previous["relation_facts"].extend(target["facts"])
            previous["found"] |= target["found"]
            if previous["comparison_status"] != "invalid":
                previous["comparison_status"] = "available"
    # Public input records contain only canonical JSON values, never sets.
    for target in result.values():
        for key in ("function_ids", "ft_ids", "oversized_frontier"):
            target[key] = sorted(target[key])
        target["relation_facts"] = sorted(target["relation_facts"], key=canonical)
    return result, manifest


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
