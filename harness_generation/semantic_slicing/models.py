"""Strict terminal schema and deterministic identity/evidence checks for slices."""
from __future__ import annotations

import json

from ..semantic_discovery.models import canonical
from ..semantic_discovery.tools import _schema

SLICE_POLICY_VERSION = "recall-first-semantic-slice-v1"
ROLE_REASONS = {
    "core": ("accepted_anchor", "external_input_injection", "input_consumption", "target_state_progression",
             "core_processing", "core_data_dependency", "core_state_dependency", "wrapper_delegation"),
    "support": ("required_initialization", "resource_creation", "resource_cleanup", "allocator_setup",
                "callback_registration", "minimal_configuration", "wrapper_delegation"),
    "exclude": ("shared_context_only", "shared_struct_only", "same_type_only", "unrelated_behavior",
                "diagnostic_only", "statistics_only", "encoding_outside_target", "unrelated_query"),
    "unresolved": ("insufficient_evidence", "not_investigated", "ambiguous_symbol", "budget_exhausted"),
}
STRING_ARRAY = {"type": "array", "items": {"type": "string", "minLength": 1, "maxLength": 1024}, "maxItems": 64}
SLICE_SCHEMA = {"type": "object", "additionalProperties": False, "required": ["classification"],
    "properties": {"classification": {"type": "array", "minItems": 1, "maxItems": 256,
        "items": {"type": "object", "additionalProperties": False,
            "required": ["function_id", "role", "reason_codes", "evidence_ids", "open_questions"],
            "properties": {"function_id": {"type": "string", "minLength": 1, "maxLength": 512},
                "role": {"type": "string", "enum": list(ROLE_REASONS)},
                "reason_codes": {**STRING_ARRAY, "minItems": 1,
                    "items": {"type": "string", "enum": sorted({r for reasons in ROLE_REASONS.values() for r in reasons})}},
                "evidence_ids": STRING_ARRAY, "open_questions": STRING_ARRAY}}}}}
SLICE_TOOL_SCHEMA = _schema("submit_semantic_slice", "Submit the evidence-backed semantic slice as the ONLY tool call. "
    "Anchor must be CORE. Uninvestigated frontier functions remain unresolved automatically.",
    SLICE_SCHEMA["properties"], SLICE_SCHEMA["required"])


def validate_submission(content, tools):
    if not isinstance(content, str) or len(content) > 64000:
        raise ValueError("invalid slice submission")
    document = json.loads(content)
    if not isinstance(document, dict) or set(document) != {"classification"}:
        raise ValueError("invalid slice fields")
    rows = document["classification"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 256:
        raise ValueError("invalid classification array")
    seen = set()
    canonical_rows = []
    anchor = tools.frontier.candidate.function_id
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"function_id", "role", "reason_codes", "evidence_ids", "open_questions"}:
            raise ValueError("invalid classification fields")
        fid, role = row["function_id"], row["role"]
        if not isinstance(fid, str) or not fid or len(fid) > 512 or fid not in tools.authorized_ids or fid in seen:
            raise ValueError("unknown or duplicate function identity")
        seen.add(fid)
        if not isinstance(role, str) or role not in ROLE_REASONS:
            raise ValueError("unknown role")
        for key in ("reason_codes", "evidence_ids", "open_questions"):
            values = row[key]
            if (not isinstance(values, list) or len(values) > 64
                    or any(not isinstance(v, str) or not v.strip() or len(v) > 1024 for v in values)):
                raise ValueError("invalid classification string array")
        if not row["reason_codes"] or any(reason not in ROLE_REASONS[role] for reason in row["reason_codes"]):
            raise ValueError("reason is incompatible with role")
        if "accepted_anchor" in row["reason_codes"] and fid != anchor:
            raise ValueError("accepted_anchor applies only to the anchor")
        if role == "support" and set(row["reason_codes"]) == {"wrapper_delegation"}:
            raise ValueError("a support wrapper needs a specific setup/lifecycle reason")
        eids = row["evidence_ids"]
        if any(eid not in tools.evidence for eid in eids):
            raise ValueError("evidence was not issued in this run")
        if eids and not any(fid in tools.evidence_functions.get(eid, set()) for eid in eids):
            raise ValueError("evidence does not concern the classified function")
        if role != "unresolved":
            if not eids:
                raise ValueError("decisive classification requires evidence")
            records = [tools.evidence[eid] for eid in eids if fid in tools.evidence_functions.get(eid, set())]
            if fid != anchor and role == "core" and not any(semantic_source_record(r, fid, tools.index) for r in records):
                raise ValueError("weak structural evidence cannot establish CORE")
            if role == "exclude" and not any(semantic_source_record(r, fid, tools.index, complete=True) for r in records):
                raise ValueError("EXCLUDE requires affirmative complete function source")
            if role == "support" and not any(semantic_source_record(r, fid, tools.index) or
                    (r["tool"] == "get_semantic_frontier" and r.get("frontier_kind") == "strong_relation"
                     and not r.get("truncated")) for r in records):
                raise ValueError("SUPPORT requires source or an explicit strong relation")
        elif not row["open_questions"]:
            raise ValueError("UNRESOLVED requires an open question")
        canonical_rows.append({**row, "function": tools.index.functions[fid]["name"],
            "reason_codes": sorted(set(row["reason_codes"])), "evidence_ids": sorted(set(eids)),
            "open_questions": sorted(set(row["open_questions"]))})
    if not any(row["function_id"] == anchor and row["role"] == "core" for row in canonical_rows):
        raise ValueError("accepted anchor must remain CORE")
    return {"classification": sorted(canonical_rows, key=lambda row: row["function_id"])}


def semantic_source_record(record, fid, index, *, complete=False):
    if not record.get("content") or (complete and record.get("truncated")):
        return False
    if record["tool"] == "get_function":
        return record.get("function_id") == fid and record.get("defined", False)
    # A call/reference occurrence alone is only a syntactic hint. An owned live
    # range is source evidence only where it overlaps the actual function body.
    if record["tool"] == "read_source_range":
        f = index.functions[fid]
        body = f.get("body", "")
        if not f.get("defined") or not body or record["source"] != f["file"]:
            return False
        if complete:
            return body in record["content"] and record["line_end"] >= f["end_line"]
        body_start = f["end_line"] - body.count("\n")
        return record["line_start"] <= f["end_line"] and record["line_end"] >= body_start
    return False


def group_classification(classification, universe):
    groups = {"core_functions": [], "support_functions": [], "excluded_functions": [], "unresolved_frontier": []}
    keys = dict(zip(ROLE_REASONS, groups))
    for row in classification:
        groups[keys[row["role"]]].append(row["function_id"])
    groups["unresolved_frontier"].extend(set(universe) - {r["function_id"] for r in classification})
    return {key: sorted(set(value)) for key, value in groups.items()}
