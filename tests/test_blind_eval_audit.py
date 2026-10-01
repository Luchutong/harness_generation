"""Post-hoc observation safety, independent of any blind fixture."""
import json

import pytest

from scripts.blind_eval import evaluate
from scripts.blind_eval_audit import aggregate, audit, observational_extractor


def test_observation_recovery_leaves_native_evaluator_unchanged():
    original = evaluate.semantic_checks
    extract = observational_extractor()
    assert evaluate.semantic_checks is original
    assert extract.__code__ is evaluate.evaluate_trial.__code__
    assert extract.__globals__ is not evaluate.evaluate_trial.__globals__
    result = extract.__globals__['semantic_checks'](None)
    assert all(item['status'] == 'unverified' for item in result.values())
    assert evaluate.semantic_checks is original


def test_observation_recovery_rejects_incomplete_native_cohort(tmp_path):
    native = tmp_path / 'native'
    native.mkdir()
    summary = native / 'summary.json'
    summary.write_text(json.dumps({'registration': {'planned_trials': 240},
                                   'completed_trials': 1}))
    before = summary.read_bytes()
    output = tmp_path / 'analysis'
    with pytest.raises(ValueError, match='sampling must finish'):
        audit(native, output)
    assert not output.exists()
    assert summary.read_bytes() == before


def test_aggregate_retains_early_failures_without_inventing_zero_gaps():
    summary = aggregate([
        {'case': 'unit', 'candidate_status': 'unresolved', 'context_status': 'not_run'},
        {'case': 'unit', 'candidate_status': 'accepted', 'context_status': 'incomplete',
         'hard_gaps': 3, 'core_precision_recall': {'tp': 1, 'fp': 1, 'fn': 0}},
    ])
    assert summary['trials'] == 2
    assert summary['sizes']['hard_gaps']['observations'] == 1
    assert summary['sizes']['hard_gaps']['mean'] == 3
    assert summary['api_set_overlap']['core_precision_recall']['micro_precision'] == .5
    assert summary['api_set_overlap']['support_precision_recall']['micro_recall'] is None
    assert summary['semantic_correctness']['ownership'] == {'unverified': 2}
