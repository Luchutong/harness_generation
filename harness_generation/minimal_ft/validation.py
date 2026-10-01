"""Identity/projection invariants and proof replay from frozen source metadata."""
from __future__ import annotations

from dataclasses import replace

from ..semantic_discovery.models import candidate_id, digest
from ..semantic_slicing.models import ROLE_REASONS, SLICE_POLICY_VERSION
from .models import (ARTIFACT_KIND, BUILD_STATUSES, CORE_ROLES, POLICY_VERSION, RELATION_KINDS,
                     SCHEMA_VERSION, STRENGTHS, SUPPORT_KINDS, canonical_slice, core_role, support_kind, stable_ft_id)

SLICE_FIELDS = {"schema_version", "artifact_kind", "policy_version", "candidate_id", "anchor_function_id",
                "anchor_function", "classification", "core_functions", "support_functions", "excluded_functions",
                "unresolved_frontier", "budget", "model", "run_status"}
GROUPS = {"core": "core_functions", "support": "support_functions", "exclude": "excluded_functions",
          "unresolved": "unresolved_frontier"}


def issue(code, field, reference=None):
    result = {"code": code, "field": field}
    if reference is not None:
        result["reference"] = reference
    return result


def strings(value):
    return isinstance(value, list) and all(isinstance(x, str) and bool(x.strip()) for x in value)


def validate_slice(source, snapshot):
    errors = list(source.load_errors)
    doc = source.document
    if not isinstance(doc, dict) or set(doc) != SLICE_FIELDS:
        return errors + [issue("invalid_slice_schema", "slice")]
    if (type(doc["schema_version"]) is not int or doc["schema_version"] != 1
            or doc["artifact_kind"] != "semantic_slice" or doc["policy_version"] != SLICE_POLICY_VERSION
            or doc["run_status"] not in ("completed", "completed_with_unresolved")):
        errors.append(issue("unsupported_or_incomplete_slice", "slice.header"))
    if not isinstance(doc["budget"], dict) or not isinstance(doc["model"], dict):
        errors.append(issue("invalid_slice_context", "budget/model"))
    declared = source.metadata.get("document_digests")
    if (not isinstance(declared, dict) or declared.get("slice") != source.digest
            or declared.get("evidence") != digest(source.evidence) or declared.get("trace") != digest(source.trace)):
        errors.append(issue("slice_document_digest_mismatch", "metadata.document_digests"))
    anchor = doc["anchor_function_id"]
    if not isinstance(anchor, str) or anchor not in snapshot.functions:
        errors.append(issue("anchor_identity_unknown", "anchor_function_id", anchor))
    elif (doc["candidate_id"] != candidate_id(anchor) or doc["candidate_id"] != source.candidate_id
          or doc["anchor_function"] != snapshot.functions[anchor]["name"]):
        errors.append(issue("anchor_identity_mismatch", "candidate_id"))
    groups = {}
    for role, key in GROUPS.items():
        values = doc[key]
        if not strings(values):
            errors.append(issue("invalid_identity_array", key))
            groups[role] = set()
            continue
        if len(values) != len(set(values)):
            errors.append(issue("duplicate_function_id", key))
        groups[role] = set(values)
        for fid in sorted(groups[role]):
            if fid not in snapshot.functions or fid == snapshot.functions[fid]["name"]:
                errors.append(issue("function_identity_unknown", key, fid))
    if not groups["core"]:
        errors.append(issue("empty_core", "core_functions"))
    if not isinstance(anchor, str) or anchor not in groups["core"]:
        errors.append(issue("anchor_not_core", "core_functions"))
    all_ids = set()
    for role in GROUPS:
        if all_ids & groups[role]:
            errors.append(issue("overlapping_slice_roles", GROUPS[role]))
        all_ids |= groups[role]
    rows = doc["classification"]
    if not isinstance(rows, list) or not rows:
        return errors + [issue("invalid_classification", "classification")]
    classified, classified_roles = set(), {role: set() for role in GROUPS}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"function_id", "function", "role", "reason_codes", "evidence_ids", "open_questions", "core_inclusion_proof"}:
            errors.append(issue("invalid_classification_fields", "classification"))
            continue
        fid, role = row["function_id"], row["role"]
        if not isinstance(fid, str) or fid not in snapshot.functions:
            errors.append(issue("function_identity_unknown", "classification", fid))
            continue
        if fid in classified:
            errors.append(issue("duplicate_function_id", "classification", fid))
        classified.add(fid)
        if row["function"] != snapshot.functions[fid]["name"]:
            errors.append(issue("source_identity_mismatch", "classification.function", fid))
        if not isinstance(role, str) or role not in ROLE_REASONS:
            errors.append(issue("invalid_role_enum", "classification.role", role))
            continue
        classified_roles[role].add(fid)
        for key in ("reason_codes", "evidence_ids", "open_questions"):
            if not strings(row[key]) or len(row[key]) != len(set(row[key])):
                errors.append(issue("invalid_or_duplicate_string_array", f"classification.{key}", fid))
        if not all(strings(row[key]) for key in ("reason_codes", "evidence_ids", "open_questions")):
            continue
        if not row["reason_codes"] or any(r not in ROLE_REASONS[role] for r in row["reason_codes"]):
            errors.append(issue("invalid_reason_enum", "classification.reason_codes", fid))
        if "accepted_anchor" in row["reason_codes"] and fid != anchor:
            errors.append(issue("anchor_reason_on_other_function", "classification.reason_codes", fid))
        if role != "unresolved" and not row["evidence_ids"]:
            errors.append(issue("decisive_role_without_evidence", "classification.evidence_ids", fid))
        from ..semantic_slicing.core_proofs import inclusion_proofs
        expected = inclusion_proofs(anchor, fid, snapshot.functions, source.records, row["evidence_ids"]) if role == "core" and anchor in snapshot.functions else []
        if row["core_inclusion_proof"] != expected or role == "core" and not expected:
            errors.append(issue("core_inclusion_proof_invalid", "classification.core_inclusion_proof", fid))
        if any(eid not in source.records for eid in row["evidence_ids"]):
            errors.append(issue("unissued_slice_evidence", "classification.evidence_ids", fid))
        if role == "unresolved" and not row["open_questions"]:
            errors.append(issue("unresolved_without_question", "classification.open_questions", fid))
    for role in ("core", "support", "exclude"):
        if classified_roles[role] != groups[role]:
            errors.append(issue("classification_group_mismatch", GROUPS[role]))
    if not classified_roles["unresolved"] <= groups["unresolved"]:
        errors.append(issue("classification_group_mismatch", "unresolved_frontier"))
    meta = source.metadata
    if (meta.get("source_fingerprint") != snapshot.source_fingerprint
            or meta.get("anchor_function_id") != anchor or meta.get("candidate_id") != source.candidate_id):
        errors.append(issue("slice_snapshot_identity_mismatch", "metadata"))
    frontier, discovered = meta.get("initial_frontier_ids"), meta.get("discovered_function_ids")
    if not strings(frontier) or not strings(discovered):
        errors.append(issue("missing_slice_universe", "metadata.frontier"))
    elif (len(frontier) != len(set(frontier)) or len(discovered) != len(set(discovered))
          or set(frontier) & set(discovered) or all_ids != set(frontier) | set(discovered)):
        errors.append(issue("slice_frontier_disappeared_or_expanded", "metadata.frontier"))
    if source.validated_catalog is not None:
        catalog = source.validated_catalog
        records = catalog.get("candidates", [])
        matches = [r for r in records if isinstance(r, dict) and r.get("candidate_id") == source.candidate_id] if isinstance(records, list) else []
        if (catalog.get("source_fingerprint") != snapshot.source_fingerprint or len(matches) != 1
                or matches[0].get("function_id") != anchor or matches[0].get("status") != "accepted"
                or not isinstance(matches[0].get("validation"), dict)
                or matches[0]["validation"].get("run_status") != "completed"):
            errors.append(issue("accepted_validation_mismatch", "validated_candidates"))
    return errors


class MinimalFTValidator:
    """Validate a complete projection, including source-set equality and unknowns."""

    def validate(self, document, source, snapshot):
        source = replace(source, document=canonical_slice(source.document))
        errors = []
        if not isinstance(document, dict):
            return [issue("invalid_minimal_ft_schema", "minimal_ft")]
        required = {"schema_version", "artifact_kind", "policy_version", "ft_id", "candidate_id", "anchor_function_id",
                    "core_functions", "support_candidates", "relations", "unresolved_dependencies", "excluded_functions",
                    "source_slice", "source_snapshot", "build_status", "validation_errors"}
        if set(document) - (required | {"legacy_comparison"}) or not required <= set(document):
            return [issue("invalid_minimal_ft_schema", "minimal_ft")]
        if (type(document["schema_version"]) is not int or document["schema_version"] != SCHEMA_VERSION
                or document["artifact_kind"] != ARTIFACT_KIND or document["policy_version"] != POLICY_VERSION
                or document["build_status"] not in BUILD_STATUSES):
            errors.append(issue("invalid_minimal_ft_header", "minimal_ft.header"))
        if document["build_status"] == "invalid":
            return errors + [issue("invalid_build_cannot_be_reused", "build_status")]
        errors.extend(validate_slice(source, snapshot))
        if errors:
            return errors
        anchor = source.document["anchor_function_id"]
        rows = {r["function_id"]: r for r in source.document["classification"]}
        categories = {}
        for key, role_key, roles in (("core_functions", "role", CORE_ROLES), ("support_candidates", "support_kind", SUPPORT_KINDS)):
            entries = document[key]
            ids = []
            if not isinstance(entries, list):
                errors.append(issue("invalid_function_array", key))
                categories[key] = set()
                continue
            for row in entries:
                expected_fields = {"function_id", "function", role_key, "evidence_ids", "reason_codes"}
                if not isinstance(row, dict) or set(row) != expected_fields:
                    errors.append(issue("invalid_function_fields", key))
                    continue
                fid = row["function_id"]
                if not isinstance(fid, str) or fid not in snapshot.functions:
                    errors.append(issue("function_identity_unknown", key, fid))
                    continue
                ids.append(fid)
                if not isinstance(row[role_key], str) or row[role_key] not in roles:
                    errors.append(issue("invalid_projection_role_enum", role_key, row[role_key]))
                input_row = rows.get(fid)
                if (input_row is None or row["function"] != snapshot.functions[fid]["name"]
                        or row["evidence_ids"] != input_row["evidence_ids"] or row["reason_codes"] != input_row["reason_codes"]):
                    errors.append(issue("projection_changed_slice_facts", key, fid))
                elif row[role_key] != (core_role(fid, anchor, input_row["reason_codes"]) if role_key == "role"
                                      else support_kind(input_row["reason_codes"])):
                    errors.append(issue("projection_role_mismatch", role_key, fid))
            categories[key] = set(ids)
            if len(ids) != len(set(ids)):
                errors.append(issue("duplicate_function_id", key))
        core, support = categories["core_functions"], categories["support_candidates"]
        if not core or anchor not in core or document["anchor_function_id"] != anchor:
            errors.append(issue("anchor_not_core", "core_functions"))
        if core != set(source.document["core_functions"]) or support != set(source.document["support_functions"]):
            errors.append(issue("projection_changed_api_sets", "core_functions/support_candidates"))
        excluded = document["excluded_functions"]
        if not strings(excluded) or excluded != source.document["excluded_functions"] or len(excluded) != len(set(excluded)):
            errors.append(issue("excluded_projection_mismatch", "excluded_functions"))
        elif core & support or core & set(excluded) or support & set(excluded):
            errors.append(issue("overlapping_projection_roles", "functions"))
        deps = document["unresolved_dependencies"]
        unknown = set()
        allowed = core | support | set(source.document["unresolved_frontier"])
        questions, null_count = {}, 0
        if not isinstance(deps, list):
            errors.append(issue("invalid_dependencies", "unresolved_dependencies"))
        else:
            for row in deps:
                if not isinstance(row, dict) or set(row) != {"function_id", "questions", "references"}:
                    errors.append(issue("invalid_dependency_fields", "unresolved_dependencies"))
                    continue
                fid = row["function_id"]
                if not strings(row["questions"]) or not row["questions"] or not isinstance(row["references"], list):
                    errors.append(issue("unresolved_without_question", "unresolved_dependencies"))
                elif (len(row["questions"]) != len(set(row["questions"])) or any(
                        not isinstance(ref, dict) or set(ref) != {"reference", "provenance"}
                        or not isinstance(ref["provenance"], dict) for ref in row["references"])):
                    errors.append(issue("invalid_dependency_references", "unresolved_dependencies"))
                if fid is not None:
                    if not isinstance(fid, str) or fid not in snapshot.functions or fid in unknown:
                        errors.append(issue("invalid_or_duplicate_dependency_identity", "unresolved_dependencies", fid))
                    else:
                        unknown.add(fid)
                        if fid not in allowed:
                            errors.append(issue("dependency_outside_slice", "unresolved_dependencies", fid))
                        if strings(row["questions"]):
                            questions[fid] = set(row["questions"])
                else:
                    null_count += 1
            if null_count > 1:
                errors.append(issue("duplicate_null_dependency", "unresolved_dependencies"))
            if not set(source.document["unresolved_frontier"]) <= unknown:
                errors.append(issue("unresolved_disappeared", "unresolved_dependencies"))
            for row in source.document["classification"]:
                if row["role"] == "unresolved" and not set(row["open_questions"]) <= questions.get(row["function_id"], set()):
                    errors.append(issue("unresolved_question_disappeared", "unresolved_dependencies", row["function_id"]))
        relations = document["relations"]
        relation_ids = set()
        if not isinstance(relations, list):
            errors.append(issue("invalid_relations", "relations"))
        else:
            for relation in relations:
                if (not isinstance(relation, dict) or set(relation) != {"relation_id", "source_function_id", "target_function_id",
                        "kind", "strength", "provenance", "evidence_ids"}):
                    errors.append(issue("invalid_relation_schema", "relations"))
                    continue
                if (not isinstance(relation["kind"], str) or relation["kind"] not in RELATION_KINDS
                        or not isinstance(relation["strength"], str) or relation["strength"] not in STRENGTHS):
                    errors.append(issue("invalid_relation_enum", "relations"))
                if any(not isinstance(relation[k], str) or relation[k] not in allowed for k in ("source_function_id", "target_function_id")):
                    errors.append(issue("relation_endpoint_outside_unit", "relations"))
                if (not strings(relation["evidence_ids"]) or any(eid not in source.records for eid in relation["evidence_ids"])
                        or not isinstance(relation["provenance"], dict) or not relation["provenance"].get("artifact")):
                    errors.append(issue("invalid_relation_provenance", "relations"))
                elif (relation["kind"] == "structural" or relation["provenance"].get("kind") == "syntactic_call") and relation["strength"] != "weak":
                    errors.append(issue("weak_relation_upgraded", "relations.strength"))
                rid = relation["relation_id"]
                if not isinstance(rid, str) or rid in relation_ids:
                    errors.append(issue("duplicate_or_invalid_relation_id", "relations"))
                else:
                    relation_ids.add(rid)
                    from .relations import relation_id
                    if rid != relation_id(relation):
                        errors.append(issue("relation_identity_mismatch", "relations.relation_id"))
        expected_id = stable_ft_id(anchor, core, anchor_name=snapshot.functions[anchor]["name"])
        if document["ft_id"] != expected_id or document["candidate_id"] != source.candidate_id:
            errors.append(issue("ft_identity_mismatch", "ft_id"))
        if document["source_slice"] != {"path": source.path, "digest": source.digest}:
            errors.append(issue("source_slice_digest_mismatch", "source_slice"))
        if document["source_snapshot"] != {"source_fingerprint": snapshot.source_fingerprint,
                                          "functions_fingerprint": snapshot.functions_fingerprint}:
            errors.append(issue("source_snapshot_mismatch", "source_snapshot"))
        if document["build_status"] != ("completed_with_unresolved" if deps else "completed") or document["validation_errors"]:
            errors.append(issue("invalid_build_status", "build_status"))
        # Provenance labels alone cannot authorize a new relation. Replay the
        # persisted facts and gaps to reject invented facts or dropped unknowns.
        from .relations import legacy_comparison, project_relations_and_dependencies
        expected_relations, expected_dependencies = project_relations_and_dependencies(source, snapshot)
        if relations != expected_relations:
            errors.append(issue("relations_changed_persisted_facts", "relations"))
        if deps != expected_dependencies:
            errors.append(issue("dependencies_changed_projection", "unresolved_dependencies"))
        if "legacy_comparison" in document and document["legacy_comparison"] != legacy_comparison(
                source.document["core_functions"], source.legacy):
            errors.append(issue("legacy_comparison_mismatch", "legacy_comparison"))
        return errors
