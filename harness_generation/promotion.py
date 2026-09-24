"""Formal validation gate for candidate-to-stable artifact publication."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .artifacts import TripletArtifacts


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_text(json.dumps(value, sort_keys=True, separators=(",", ":")))


def promote_harness(
    layout: TripletArtifacts,
    *,
    harness_code: str,
    harness_plan: Mapping[str, Any],
    validation_summary: Mapping[str, Any],
    recipe_identity: str | None = None,
    contract_identity: str | None = None,
    candidate_id: str | None = None,
    stage4_policy: str = "strict",
) -> bool:
    """Publish a harness/plan pair only after the selected validation gate passes.

    Ineligible candidates receive a manifest and leave any existing stable pair
    untouched. The two stable files are written only after all gate checks pass.
    """
    if stage4_policy not in {"strict", "hybrid"}:
        raise ValueError("stage4_policy must be strict or hybrid")
    statuses = {
        key: validation_summary.get(key)
        for key in ("intermediate", "compiler", "linker", "runtime")
    }
    recorded_statuses = {}
    for key in statuses:
        path = layout.validation_path(key)
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            recorded_statuses[key] = record.get("status") if isinstance(record, dict) else None
        except (OSError, UnicodeError, json.JSONDecodeError):
            recorded_statuses[key] = None
    candidate_matches = False
    try:
        candidate_matches = (
            layout.stage4_harness.read_text(encoding="utf-8") == harness_code.rstrip() + "\n"
            and json.loads(layout.stage4_harness_plan.read_text(encoding="utf-8"))
            == dict(harness_plan)
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        pass
    plan_matches_contract = (
        harness_plan.get("schema_version") != 2
        or harness_plan.get("contract_id") == contract_identity
    )
    if stage4_policy == "hybrid":
        eligible_statuses = (
            validation_summary.get("overall")
            in {"passed", "passed_with_warnings"}
            and statuses["intermediate"] in {"passed", "passed_with_warnings"}
            and all(
                statuses[key] == "passed"
                for key in ("compiler", "linker", "runtime")
            )
        )
    else:
        eligible_statuses = (
            validation_summary.get("overall") == "passed"
            and all(value == "passed" for value in statuses.values())
        )
    eligible = (
        eligible_statuses
        and recorded_statuses == statuses
        and candidate_matches
        and plan_matches_contract
    )
    persisted_harness = harness_code.rstrip() + "\n"
    manifest = {
        "schema_version": 1,
        "status": "stable_promoted" if eligible else "quarantined",
        "candidate_id": candidate_id,
        "recipe_identity": recipe_identity,
        "contract_identity": contract_identity,
        "stage4_policy": stage4_policy,
        "validation_status": validation_summary.get("overall", "not_recorded"),
        "component_statuses": statuses,
        "recorded_component_statuses": recorded_statuses,
        "source_sha256": _sha256_text(persisted_harness),
        "plan_sha256": _sha256_json(harness_plan),
        "reason": None if eligible else "formal validation did not reach passed",
    }
    if not eligible:
        layout.write_json(layout.promotion, manifest)
        return False

    # The manifest is published last, after both individually atomic artifacts.
    # Readers can verify its two hashes before treating the pair as stable.
    layout.write_text(layout.harness, persisted_harness)
    layout.write_json(layout.stable_harness_plan, dict(harness_plan))
    layout.write_json(layout.promotion, manifest)
    return True


__all__ = ["promote_harness"]
