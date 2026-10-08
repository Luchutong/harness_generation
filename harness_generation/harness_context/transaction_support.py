"""Bind framework withdrawal witnesses to existing immutable Agent artifacts.

These records supplement a framework transaction. They never alter an Agent's
trace, evidence document or paid-operation counters, and never issue evidence.
An archived attempt may carry a previously issued record through a legitimate
bootstrap reuse; the reference proves carriage, not a new source-tool call.
"""
from copy import deepcopy
import hashlib
from pathlib import Path
import re

from ..minimal_ft.persistence import _load_json, _owned
from ..records import write_json
from ..semantic_discovery.models import digest
from ..semantic_discovery.persistence import load_run_documents


VERSION = "context-transaction-source-support-v1"
_TRANSACTION = re.compile(r"context_revision_[0-9a-f]{24}")
_ATTEMPT = re.compile(r"attempt_[0-9]{4,}")
_DOCUMENTS = ("result", "trace", "evidence")


def _directory(store, ft_id):
    # Local import permits persistence to import this independent helper.
    from .persistence import context_directory
    directory = context_directory(store, ft_id).absolute()
    _no_symlink(directory, Path(store.root).absolute())
    return directory


def _no_symlink(path, root):
    """Allow the store root itself to be a shared-workspace symlink only."""
    path, root = Path(path).absolute(), Path(root).absolute()
    _owned(path, root)
    relative = path.relative_to(root)
    if any(part in {".", ".."} for part in relative.parts):
        raise ValueError("source_support_path_invalid")
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("source_support_symlink_rejected")
    return path


def _destination(directory, destination):
    destination = Path(destination).absolute()
    relative = destination.relative_to(directory)
    if (len(relative.parts) != 2 or relative.parts[0] != "revision_transactions"
            or not _TRANSACTION.fullmatch(relative.parts[1])):
        raise ValueError("source_support_destination_invalid")
    _no_symlink(destination, directory)
    if not destination.is_dir():
        raise ValueError("source_support_destination_missing")
    return destination


def _origin(directory, relative):
    if not isinstance(relative, str):
        raise ValueError("source_support_origin_path_invalid")
    path = Path(relative)
    if (path.is_absolute() or len(path.parts) != 3 or path.parts[0] != "agent_runs"
            or path.parts[1] in {".", ".."} or not _ATTEMPT.fullmatch(path.parts[2])
            or int(path.parts[2].removeprefix("attempt_")) < 1 or path.as_posix() != relative):
        raise ValueError("source_support_origin_path_invalid")
    return _no_symlink(directory / path, directory)


def _read_attempt(directory, relative, expected=None):
    path = _origin(directory, relative)
    documents = {name: _load_json(_no_symlink(path / (name + ".json"), directory))
        for name in (*_DOCUMENTS, "metadata")}
    metadata = documents["metadata"]
    if metadata["configuration_fingerprint"] != digest(metadata["configuration"]):
        raise ValueError("source_support_origin_configuration_invalid")
    if any(digest(documents[name]) != metadata["document_digests"][name] for name in _DOCUMENTS):
        raise ValueError("source_support_origin_document_invalid")
    rid = path.parent.name
    if (documents["result"].get("requirement_id") != rid
            or metadata.get("requirement_id", rid) != rid):
        raise ValueError("source_support_origin_requirement_invalid")
    if expected and (digest(metadata) != expected["metadata_digest"]
            or digest(documents["result"]) != expected["result_digest"]):
        raise ValueError("source_support_native_attempt_changed")
    rows = documents["evidence"]["records"]
    records = {record["evidence_id"]: record for record in rows}
    issued = {eid for event in documents["trace"]["events"] if event["kind"] == "tool_call"
        for eid in event["result_evidence_ids"]}
    if len(rows) != len(records) or set(records) != issued:
        raise ValueError("source_support_origin_issued_records_invalid")
    return path, documents, records


def _record_identity(eid, record, configuration):
    if not isinstance(eid, str) or not isinstance(record, dict) or record.get("evidence_id") != eid:
        return False
    fingerprint = configuration.get("source_fingerprint")
    return bool(fingerprint) and eid == "ev_" + digest({"snapshot": fingerprint,
        "record": {key: value for key, value in record.items() if key != "evidence_id"}})[:32]


def _historical_paths(directory, rid=None):
    base = directory / "agent_runs"
    _no_symlink(base, directory)
    if rid is not None:
        if not isinstance(rid, str) or Path(rid).name != rid or rid in {".", ".."}:
            return []
        _no_symlink(base / rid, directory)
        candidates = (base / rid).glob("attempt_*")
    else:
        candidates = base.glob("*/attempt_*")
    return sorted(path.relative_to(directory).as_posix() for path in candidates
        if _ATTEMPT.fullmatch(path.name) and int(path.name.removeprefix("attempt_")) >= 1)


def save_source_support(store, ft_id, destination, witnesses, native_attempts):
    """Write support after raw archival and before any latest publication.

    Lookup prefers the current batch, then the record's original requirement
    hint, then other immutable attempts within this FT. An unsupported witness
    fails before this helper writes anything. Empty support is valid as well.
    """
    directory = _directory(store, ft_id)
    destination = _destination(directory, destination)
    filename = _no_symlink(destination / "source-support.json", directory)
    if filename.exists():
        raise ValueError("source_support_already_exists")
    if not isinstance(witnesses, dict) or not isinstance(native_attempts, dict):
        raise ValueError("source_support_input_invalid")
    if any(not isinstance(eid, str) or not isinstance(record, dict)
            for eid, record in witnesses.items()):
        raise ValueError("source_support_witness_invalid")
    native = {}
    for reference in native_attempts.values():
        relative = reference["path"]
        _origin(directory, relative)
        native[relative] = reference
    checked, support = {}, {}
    for eid, record in sorted(witnesses.items()):
        paths = [*sorted(native), *_historical_paths(directory, record.get("requirement_id")),
            *_historical_paths(directory)]
        for relative in dict.fromkeys(paths):
            if relative not in checked:
                try:
                    checked[relative] = _read_attempt(directory, relative, native.get(relative))
                except (OSError, UnicodeError, ValueError, KeyError, TypeError):
                    checked[relative] = None
            origin = checked[relative]
            if origin is None:
                continue
            _, documents, records = origin
            metadata = documents["metadata"]
            if records.get(eid) != record or not _record_identity(eid, record, metadata["configuration"]):
                continue
            support[eid] = {"record": deepcopy(record), "record_digest": digest(record),
                "origin": {"path": relative, "metadata_digest": digest(metadata),
                    "configuration_fingerprint": metadata["configuration_fingerprint"],
                    "document_digests": {name: digest(documents[name]) for name in _DOCUMENTS}}}
            break
        if eid not in support:
            raise ValueError("source_support_origin_not_found:" + str(eid))
    document = {"schema_version": 1, "version": VERSION, "ft_id": ft_id,
        "witnesses": support, "witness_digest": digest(witnesses)}
    write_json(filename, document, sort_keys=True, allow_nan=False)
    return {"path": filename.relative_to(directory).as_posix(), "digest": digest(document),
        "witness_digest": document["witness_digest"]}


def validate_source_support(store, ft_id, destination, summary, index):
    """Authenticate saved support without granting a new semantic proof."""
    try:
        directory = _directory(store, ft_id)
        destination = _destination(directory, destination)
        filename = _no_symlink(destination / "source-support.json", directory)
        if summary["path"] != filename.relative_to(directory).as_posix():
            return False
        document = _load_json(filename)
        if (document["schema_version"] != 1 or document["version"] != VERSION
                or document["ft_id"] != ft_id or digest(document) != summary["digest"]):
            return False
        witnesses = {eid: item["record"] for eid, item in document["witnesses"].items()}
        if digest(witnesses) != document["witness_digest"] or document["witness_digest"] != summary["witness_digest"]:
            return False
        checked = {}
        for eid, item in document["witnesses"].items():
            reference = item["origin"]
            relative = reference["path"]
            if relative not in checked:
                path, documents, records = _read_attempt(directory, relative)
                metadata = documents["metadata"]
                if not load_run_documents(path, metadata["configuration"], index):
                    return False
                checked[relative] = documents, records
            documents, records = checked[relative]
            metadata, record = documents["metadata"], item["record"]
            if (digest(metadata) != reference["metadata_digest"]
                    or metadata["configuration_fingerprint"] != reference["configuration_fingerprint"]
                    or reference["document_digests"] != {name: digest(documents[name]) for name in _DOCUMENTS}
                    or records.get(eid) != record or digest(record) != item["record_digest"]
                    or not _record_identity(eid, record, metadata["configuration"])):
                return False
            if record.get("source") is not None:
                expected = record.get("source_sha256")
                if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                    return False
                with index.owned_path(record["source"]).open("rb") as stream:
                    checksum = hashlib.sha256()
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        checksum.update(chunk)
                    if checksum.hexdigest() != expected:
                        return False
        return True
    except (OSError, UnicodeError, ValueError, KeyError, TypeError, AttributeError):
        return False
