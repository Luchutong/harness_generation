"""Generation candidates reuse existing finite quality rules and never gain proof.

All observation payloads are controlled fixtures, not real runtime or coverage
claims. No compiler, target subprocess, model or provider is used here.
"""
from copy import deepcopy

import pytest

from harness_generation.orchestration.quality import assess_harness_quality, summarize_harness_quality
from v05_fixtures import quality_outcome as outcome, quality_receipt as receipt


def candidate():
    return {**outcome(experimental=False), "mode": "generate", "statistics_category": "candidate",
        "semantic_verified": False, "generation_allowed": False,
        "code_generated": True, "execution_allowed": True, "feedback_iteration": 0}


def test_generation_candidate_cannot_gain_proof_or_effectiveness_from_saved_labels():
    work = candidate()
    work.update(semantic_verified=True, generation_allowed=True,
        statistics_category="verified", fuzz_effective=True,
        quality={"statistics_category": "verified", "fuzz_effective": True,
                 "semantic_correctness_certified": True})
    work["runtime"].update(fuzz_effective=True, valid_state_call_count=99, target_call_count=99)
    before = deepcopy(work)
    quality = assess_harness_quality(work)
    assert quality["statistics_category"] == "candidate"
    assert quality["buildable"] is True and quality["runtime_stable"] is True
    assert quality["fuzz_effective"] is None and quality["valid_state_call_count"] is None
    assert quality["semantic_correctness_certified"] is False and quality["generation_authority"] is False
    assert work == before  # A quality projection does not rewrite gate identity.


@pytest.mark.parametrize("build,runtime,expected", [
    ({}, {}, (None, None)),
    ({"success": False}, {}, (False, None)),
    ({"success": True}, {"status": "failed"}, (True, False)),
    ({"success": True}, {"status": "passed", "cases": [{"success": False}]}, (True, False)),
])
def test_candidate_quality_preserves_unexecuted_and_failed_stage_boundaries(build, runtime, expected):
    work = {**candidate(), "build": build, "runtime": runtime}
    quality = assess_harness_quality(work)
    assert (quality["buildable"], quality["runtime_stable"]) == expected
    assert quality["fuzz_effective"] is None
    assert quality["statistics_category"] == "candidate"


@pytest.mark.parametrize("effective", [True, False, None])
def test_finite_live_candidate_observation_is_independent_of_semantic_authority(tmp_path, effective):
    work = candidate()
    live = receipt(tmp_path, work, effective)
    quality = assess_harness_quality(work, live_observation=live)
    assert quality["statistics_category"] == "candidate" and quality["fuzz_effective"] is effective
    assert work["semantic_verified"] is False and work["generation_allowed"] is False
    assert quality["semantic_correctness_certified"] is False and quality["generation_authority"] is False
    # A saved observer dictionary can be audited, but cannot be consumed as
    # today's live authority, including the rejected-entry negative fixture.
    current = assess_harness_quality(work, live_observation=live.to_dict())
    assert current["fuzz_effective"] is None
    summary = summarize_harness_quality([quality, current])
    assert summary["effective_successes"] == (1 if effective is True else 0)
