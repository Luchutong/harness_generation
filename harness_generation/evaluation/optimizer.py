"""Recipe-bound, evidence-preserving candidate optimization.

This module owns the campaign mechanics only. Generation and measurement stay
behind callbacks so the same loop can drive a recorded provider, an LLM, or a
local benchmark without changing comparison semantics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, TYPE_CHECKING

from ..records import write_json
from .types import EvaluationRecipe, EvaluationReport

if TYPE_CHECKING:
    from ..iteration import WeightedAggregationPolicy


def _default_policy():
    from ..iteration import WeightedAggregationPolicy
    return WeightedAggregationPolicy()


OPTIMIZER_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class CandidateEvaluation:
    """One candidate's validation and train-seed evaluation evidence."""

    candidate_id: str
    parent_id: str | None
    round_index: int
    validation_status: str
    recipe_identity: str
    contract_identity: str
    report: EvaluationReport
    phase: str = "train"

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise ValueError("candidate_id must be non-empty")
        if self.parent_id == self.candidate_id:
            raise ValueError("candidate cannot be its own parent")
        if type(self.round_index) is not int or self.round_index < 0:
            raise ValueError("round_index must be a non-negative integer")
        if not self.validation_status:
            raise ValueError("validation_status must be non-empty")
        if self.phase not in {"train", "holdout"}:
            raise ValueError("candidate evaluation phase must be train or holdout")
        if not self.recipe_identity or not self.contract_identity:
            raise ValueError("candidate identities must be non-empty")
        if self.report.candidate_id != self.candidate_id:
            raise ValueError("candidate report ID does not match candidate")
        if self.report.parent_id != self.parent_id or self.report.round_index != self.round_index:
            raise ValueError("candidate report lineage does not match candidate")

    @property
    def validation_eligible(self) -> bool:
        """Only formal validation passes may enter score comparison."""

        return self.validation_status == "passed"

    def to_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "parent_id": self.parent_id,
            "round_index": self.round_index,
            "validation_status": self.validation_status,
            "recipe_identity": self.recipe_identity,
            "contract_identity": self.contract_identity,
            "phase": self.phase,
            "evaluation": self.report.to_dict(),
        }


@dataclass(frozen=True)
class OptimizationConfig:
    recipe: EvaluationRecipe
    rounds: int = 1
    children_per_round: int = 1
    policy: "WeightedAggregationPolicy" = field(default_factory=_default_policy)

    def __post_init__(self) -> None:
        if type(self.rounds) is not int or self.rounds < 1:
            raise ValueError("rounds must be a positive integer")
        if type(self.children_per_round) is not int or self.children_per_round < 1:
            raise ValueError("children_per_round must be a positive integer")


@dataclass(frozen=True)
class OptimizationResult:
    status: str
    selected_candidate: str | None
    completed_rounds: int
    candidates: tuple[CandidateEvaluation, ...]
    recipe_identity: str
    contract_identity: str
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"completed", "failed"}:
            raise ValueError("unknown optimization status")
        if self.completed_rounds < 0:
            raise ValueError("completed_rounds must be non-negative")
        if not self.recipe_identity or not self.contract_identity:
            raise ValueError("optimization identities must be non-empty")

    def to_dict(self) -> dict:
        return {
            "schema_version": OPTIMIZER_SCHEMA_VERSION,
            "status": self.status,
            "selected_candidate": self.selected_candidate,
            "completed_rounds": self.completed_rounds,
            "recipe_identity": self.recipe_identity,
            "contract_identity": self.contract_identity,
            "reason": self.reason,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
        }


# The callback receives the parent ID, round, child index, exact train
# seeds, and the fixed per-candidate execution budget. It owns generation,
# validation, and measurement.
CandidateRunner = Callable[[str | None, int, int, tuple[int, ...], int], CandidateEvaluation]
HoldoutRunner = Callable[[CandidateEvaluation, tuple[int, ...], int], CandidateEvaluation]


class EvaluationOptimizer:
    """Run configurable rounds and children under one frozen recipe."""

    def __init__(
        self,
        config: OptimizationConfig,
        run_candidate: CandidateRunner,
        *,
        run_holdout: HoldoutRunner | None = None,
        output: str | Path | None = None,
    ) -> None:
        self.config = config
        self.run_candidate = run_candidate
        self.run_holdout = run_holdout
        self.output = None if output is None else Path(output)
        self._source_sha256: str | None = None

    def run(self) -> OptimizationResult:
        self._source_sha256 = None
        all_candidates: list[CandidateEvaluation] = []
        parent: CandidateEvaluation | None = None
        completed_rounds = 0

        try:
            parent = self._run_one(None, 0, 0, all_candidates)
            if not self._eligible(parent):
                return self._finish(
                    "failed", None, completed_rounds, all_candidates,
                    "initial candidate is not validation-eligible or scoreable",
                )
            for round_index in range(1, self.config.rounds + 1):
                children: list[CandidateEvaluation] = []
                for child_index in range(self.config.children_per_round):
                    child = self._run_one(
                        parent.candidate_id, round_index, child_index, all_candidates,
                    )
                    children.append(child)
                eligible = [candidate for candidate in (parent, *children)
                            if self._eligible(candidate)]
                if not eligible:
                    return self._finish(
                        "failed", parent.candidate_id, completed_rounds,
                        all_candidates,
                        f"round {round_index} produced no validation-eligible scored candidates",
                    )
                parent = self._select(eligible)
                completed_rounds = round_index

            if self.config.recipe.holdout_seeds:
                if self.run_holdout is None:
                    return self._finish(
                        "failed", parent.candidate_id, completed_rounds, all_candidates,
                        "holdout seeds are configured but no holdout runner was supplied",
                    )
                holdout = self.run_holdout(
                    parent, self.config.recipe.holdout_seeds, self.config.recipe.budget,
                )
                self._check_identity(holdout)
                if holdout.phase != "holdout":
                    raise ValueError("holdout runner must return holdout-phase evidence")
                if not self._eligible(holdout):
                    return self._finish(
                        "failed", parent.candidate_id, completed_rounds, all_candidates,
                        "selected candidate failed holdout validation or evidence gating",
                    )
                all_candidates.append(holdout)
            return self._finish("completed", parent.candidate_id, completed_rounds,
                                all_candidates)
        except (OSError, RuntimeError, TypeError, ValueError) as error:
            return self._finish(
                "failed", None if parent is None else parent.candidate_id,
                completed_rounds, all_candidates,
                f"candidate execution failed: {type(error).__name__}",
            )

    def _run_one(
        self,
        parent_id: str | None,
        round_index: int,
        child_index: int,
        all_candidates: list[CandidateEvaluation],
    ) -> CandidateEvaluation:
        candidate = self.run_candidate(
            parent_id, round_index, child_index, self.config.recipe.seeds,
            self.config.recipe.budget,
        )
        self._check_identity(candidate)
        all_candidates.append(candidate)
        return candidate

    def _check_identity(self, candidate: CandidateEvaluation) -> None:
        if candidate.recipe_identity != self.config.recipe.identity:
            raise ValueError("candidate uses a different evaluation recipe")
        if candidate.contract_identity != self.config.recipe.contract_identity:
            raise ValueError("candidate uses a different target contract")
        source_sha256 = candidate.report.source_sha256
        if self._source_sha256 is None:
            self._source_sha256 = source_sha256
        elif source_sha256 != self._source_sha256:
            raise ValueError("candidate uses a different target source")

    def _eligible(self, candidate: CandidateEvaluation) -> bool:
        if not candidate.validation_eligible:
            return False
        aggregate = self.config.policy.aggregate(candidate.report)
        return aggregate.status == "scored" and aggregate.eligible is True

    def _select(self, candidates: Iterable[CandidateEvaluation]) -> CandidateEvaluation:
        ranked: list[tuple[float, str, CandidateEvaluation]] = []
        for candidate in candidates:
            aggregate = self.config.policy.aggregate(candidate.report)
            if aggregate.status == "scored" and aggregate.eligible is True and aggregate.score is not None:
                ranked.append((float(aggregate.score), candidate.candidate_id, candidate))
        if not ranked:
            raise ValueError("no eligible scored candidates")
        ranked.sort(key=lambda item: (-item[0], item[1]))
        return ranked[0][2]

    def _finish(
        self,
        status: str,
        selected: str | None,
        completed_rounds: int,
        candidates: list[CandidateEvaluation],
        reason: str | None = None,
    ) -> OptimizationResult:
        result = OptimizationResult(
            status, selected, completed_rounds, tuple(candidates),
            self.config.recipe.identity, self.config.recipe.contract_identity, reason,
        )
        if self.output is not None:
            self.output.mkdir(parents=True, exist_ok=True)
            write_json(self.output / "optimization.json", result.to_dict(),
                       sort_keys=True, allow_nan=False)
            for candidate in candidates:
                directory = self.output / candidate.candidate_id
                directory.mkdir(parents=True, exist_ok=True)
                filename = (
                    "holdout_evaluation.json" if candidate.phase == "holdout"
                    else "evaluation.json"
                )
                write_json(directory / filename, candidate.report.to_dict(),
                           sort_keys=True, allow_nan=False)
        return result
