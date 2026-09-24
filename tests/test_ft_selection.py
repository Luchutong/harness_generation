import unittest
from dataclasses import replace

from harness_generation.ft_selection import (
    FTScore,
    build_selection_manifest,
    estimate_structural_units,
    rank_triplets,
    select_triplets,
)
from harness_generation.triplet import (
    FunctionTriplet,
    TripletBypassSemantic,
    TripletEdge,
    TripletFunction,
    TripletOwnershipRelation,
)


def function(function_id, name, roles, line):
    return TripletFunction(function_id, name, roles, "src/parser.c", line)


def sample_triplet(ft_id="ft_sample"):
    entry = function("f1", "parse", ("ISF",), 1)
    process = function("f2", "consume", ("PRF",), 5)
    cleanup = function("f3", "destroy", ("HPF",), 9)
    return FunctionTriplet(
        entry,
        (process,),
        (cleanup,),
        (entry, process, cleanup),
        ("Context", "Item"),
        (
            TripletEdge("f1", "parse", "(null)", "Context", ("ISF",),
                        "src/parser.c", 1),
            TripletEdge("f2", "consume", "Context", "Item", ("PRF",),
                        "src/parser.c", 5),
            TripletEdge("f3", "destroy", "Context", "(null)", ("HPF",),
                        "src/parser.c", 9),
        ),
        {},
        ft_id,
        (
            TripletBypassSemantic(
                "s1", "fuzzer_input_binding", "f1", "parse",
                "Bind data and size.",
            ),
            TripletBypassSemantic(
                "s2", "return_status", "f1", "parse", "Check status.",
            ),
        ),
    )


def annotations(stream=True):
    return (
        {
            "function_id": "f1",
            "stream_parameters": [{
                "parameter": "data",
                "is_byte_stream": stream,
                "confidence": 0.9,
            }],
            "decisions": [{"confidence": 0.9, "status": "ok"}],
        },
        {"function_id": "f2", "decisions": [{"confidence": 0.8, "status": "ok"}]},
        {"function_id": "f3", "decisions": [{"confidence": 0.7, "status": "ok"}]},
    )


class FTSelectionTests(unittest.TestCase):
    def test_score_is_evidence_bearing_and_cost_matches_pipeline_shape(self):
        triplet = sample_triplet()
        ranked = rank_triplets((triplet,), annotations())
        self.assertEqual(len(ranked), 1)
        score = ranked[0]
        self.assertTrue(score.eligible)
        self.assertGreater(score.score, 0.0)
        self.assertEqual(estimate_structural_units(triplet), 3)
        self.assertEqual(score.estimated_llm_calls, 9)
        self.assertEqual(
            {metric.name for metric in score.metrics},
            {
                "input_evidence", "structural_confidence",
                "structural_opportunity", "harness_readiness", "usage_support",
            },
        )
        structural = next(
            metric for metric in score.metrics
            if metric.name == "structural_confidence"
        )
        self.assertEqual(structural.evidence["decision_count"], 3)

    def test_missing_positive_stream_evidence_excludes_candidate(self):
        score = rank_triplets((sample_triplet(),), annotations(stream=False))[0]
        self.assertFalse(score.eligible)
        self.assertIsNone(score.score)
        self.assertIn("missing_positive_byte_stream_evidence", score.exclusion_reasons)

    def test_usage_support_is_measured_from_frequency_and_source_diversity(self):
        triplet = sample_triplet()
        relation = TripletOwnershipRelation(
            "own_usage", "f1", "parse", "Context", "f3", "destroy",
            consumers=("consume",), evidence=("tests/a.c:9",), confidence=0.9,
            source="usage_mining", support_total=6,
            support_by_source={"test": 3, "example": 1, "production": 2},
            usage_pattern_id="up_usage",
        )
        triplet = replace(triplet, ownership_relations=(relation,))
        score = rank_triplets((triplet,), annotations())[0]
        metric = next(item for item in score.metrics if item.name == "usage_support")
        self.assertEqual(metric.status, "measured")
        self.assertGreater(metric.score, 0.8)
        self.assertEqual(metric.evidence["support_total"], 6)
        self.assertEqual(metric.evidence["usage_pattern_ids"], ["up_usage"])

    def test_unclosed_opaque_handle_excludes_candidate(self):
        triplet = sample_triplet()
        opaque = TripletBypassSemantic(
            "s3", "opaque_handle_parameter", "f1", "parse",
            "parse consumes opaque handle Parser.",
            metadata={"resource_type": "Parser"},
        )
        triplet = replace(
            triplet,
            bypass_semantics=triplet.bypass_semantics + (opaque,),
        )
        score = rank_triplets((triplet,), annotations())[0]
        self.assertFalse(score.eligible)
        self.assertIn(
            "incomplete_opaque_handle_lifecycle", score.exclusion_reasons
        )

    def test_budgeted_selection_discounts_overlapping_triplets(self):
        def score(ft_id, value, functions, structures):
            return FTScore(
                ft_id, True, value, 5, 1, (), (), functions, structures
            )

        ranked = (
            score("ft_a", 0.90, ("f1", "f2"), ("S",)),
            score("ft_b", 0.88, ("f1", "f2"), ("S",)),
            score("ft_c", 0.80, ("f3", "f4"), ("T",)),
        )
        selected = select_triplets(ranked, max_ft=2, max_calls=10)
        self.assertEqual([item.triplet_id for item in selected], ["ft_a", "ft_c"])
        self.assertEqual(sum(item.estimated_llm_calls for item in selected), 10)

    def test_target_novelty_is_not_lost_when_target_was_only_a_helper(self):
        def score(ft_id, value, functions, anchor):
            return FTScore(
                ft_id, True, value, 5, 1, (), (), functions, ("S",), anchor
            )

        ranked = (
            score("ft_wide", 0.90, ("helper", "target"), "helper"),
            score("ft_target", 0.80, ("target",), "target"),
            score("ft_other", 0.70, ("other",), "other"),
        )
        selected = select_triplets(ranked, max_ft=2, max_calls=10)
        self.assertEqual(
            [item.triplet_id for item in selected], ["ft_wide", "ft_target"]
        )

    def test_quality_precedes_cost_when_the_candidate_fits_the_budget(self):
        expensive = FTScore(
            "ft_high", True, 0.90, 9, 1, (), (), ("f1",), (), "f1"
        )
        cheap = FTScore(
            "ft_low", True, 0.60, 2, 1, (), (), ("f2",), (), "f2"
        )
        selected = select_triplets(
            (expensive, cheap), max_ft=1, max_calls=9
        )
        self.assertEqual(selected[0].triplet_id, "ft_high")

    def test_existing_fuzzer_entrypoint_is_not_a_generation_target(self):
        triplet = sample_triplet()
        entry = replace(triplet.isf, function="LLVMFuzzerTestOneInput")
        triplet = replace(
            triplet,
            isf=entry,
            functions=(entry, *triplet.functions[1:]),
        )
        score = rank_triplets((triplet,), annotations())[0]
        self.assertFalse(score.eligible)
        self.assertIn("existing_fuzzer_entrypoint", score.exclusion_reasons)

    def test_manifest_records_policy_constraints_and_baseline_cost(self):
        manifest = build_selection_manifest(
            (sample_triplet(),), annotations(), max_ft=1, max_calls=9,
            min_score=0.2,
        )
        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["policy_version"], "ft-priority-v4")
        self.assertEqual(len(manifest["inputs"]["triplets_sha256"]), 64)
        self.assertEqual(manifest["summary"]["selected_count"], 1)
        self.assertFalse(manifest["cost_model"]["includes_retries"])

    def test_minimal_selection_excludes_large_structural_assemblies(self):
        triplet = sample_triplet()
        units = len(triplet.structural_steps())
        manifest = build_selection_manifest(
            (triplet,), annotations(), max_ft=1,
            max_structural_units=units - 1,
        )
        self.assertEqual(manifest["selection"], [])
        self.assertIn(
            "too_many_structural_units",
            manifest["ranking"][0]["exclusion_reasons"],
        )

    def test_selection_excludes_ft_over_function_limit(self):
        manifest = build_selection_manifest(
            (sample_triplet(),), annotations(), max_functions=2,
        )
        self.assertEqual(manifest["selection"], [])
        self.assertIn("too_many_functions", manifest["ranking"][0]["exclusion_reasons"])


if __name__ == "__main__":
    unittest.main()
