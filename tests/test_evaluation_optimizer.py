from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from harness_generation.evaluation import (
    CandidateEvaluation, EvaluationOptimizer, OptimizationConfig,
)
from harness_generation.evaluation.types import (
    EvaluationContext, EvaluationRecipe, Evidence, Measurement, MetricId,
    MetricResult, MetricStatus, EvaluationReport,
)


def report(candidate_id, parent_id, round_index, score):
    metric = MetricResult(
        MetricId.COVERAGE, MetricStatus.MEASURED, "test", "1", "measured",
        score=score,
        measurements=(Measurement("coverage", score, "ratio", "target_code"),),
        evidence=(Evidence("coverage.json", "coverage evidence"),),
    )
    return EvaluationReport(
        candidate_id, parent_id, round_index, "source", "harness", (metric,)
    )


class EvaluationOptimizerTests(unittest.TestCase):
    def recipe(self, holdout=()):
        return EvaluationRecipe(
            project_root="/project", recipe_identity="build-1",
            contract_identity="contract-1", target_sources=("target.c",),
            budget=3, seeds=(1, 2), holdout_seeds=holdout,
        )

    def candidate(self, recipe, candidate_id, parent_id, round_index, score, status="passed"):
        return CandidateEvaluation(
            candidate_id, parent_id, round_index, status, recipe.identity,
            recipe.contract_identity, report(candidate_id, parent_id, round_index, score),
        )

    def test_runs_multiple_rounds_and_children_and_selects_score(self):
        recipe = self.recipe()
        calls = []
        scores = {(0, 0): 0.5, (1, 0): 0.3, (1, 1): 0.9, (2, 0): 0.8, (2, 1): 0.7}

        def run(parent, round_index, child_index, seeds, budget):
            self.assertEqual(budget, 3)
            calls.append((parent, round_index, child_index, seeds))
            return self.candidate(
                recipe, f"c{round_index}{child_index}", parent, round_index,
                scores[(round_index, child_index)],
            )

        result = EvaluationOptimizer(
            OptimizationConfig(recipe, rounds=2, children_per_round=2), run,
        ).run()
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.selected_candidate, "c11")
        self.assertEqual(len(result.candidates), 5)
        self.assertEqual(calls[0], (None, 0, 0, (1, 2)))
        self.assertEqual(calls[-1][0], "c11")

    def test_validation_happens_before_scoring_and_all_failures_are_terminal(self):
        recipe = self.recipe()

        def run(parent, round_index, child_index, seeds, budget):
            return self.candidate(
                recipe, f"c{round_index}{child_index}", parent, round_index,
                1.0, status="passed_with_limitations",
            )

        result = EvaluationOptimizer(
            OptimizationConfig(recipe, rounds=2, children_per_round=2), run,
        ).run()
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.completed_rounds, 0)
        self.assertIn("validation-eligible", result.reason)

    def test_identity_mismatch_is_rejected_without_comparison(self):
        recipe = self.recipe()
        other = self.recipe().identity

        def run(parent, round_index, child_index, seeds, budget):
            candidate = self.candidate(recipe, "candidate", parent, round_index, 1.0)
            return replace(candidate, recipe_identity=other + "-different")

        result = EvaluationOptimizer(OptimizationConfig(recipe), run).run()
        self.assertEqual(result.status, "failed")
        self.assertIn("candidate execution failed", result.reason)

    def test_changed_target_source_is_not_compared_under_same_recipe(self):
        recipe = self.recipe()

        def run(parent, round_index, child_index, seeds, budget):
            candidate = self.candidate(
                recipe, f"c{round_index}", parent, round_index, 0.8,
            )
            if round_index:
                return replace(
                    candidate,
                    report=replace(candidate.report, source_sha256="changed-source"),
                )
            return candidate

        result = EvaluationOptimizer(OptimizationConfig(recipe), run).run()
        self.assertEqual(result.status, "failed")
        self.assertIn("candidate execution failed", result.reason)

    def test_holdout_requires_explicit_runner(self):
        recipe = self.recipe(holdout=(99,))

        def run(parent, round_index, child_index, seeds, budget):
            return self.candidate(recipe, f"c{round_index}{child_index}", parent, round_index, 1.0)

        result = EvaluationOptimizer(OptimizationConfig(recipe), run).run()
        self.assertEqual(result.status, "failed")
        self.assertIn("holdout runner", result.reason)


if __name__ == "__main__":
    unittest.main()
