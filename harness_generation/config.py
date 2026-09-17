"""Immutable settings for the candidate execution boundary."""

from dataclasses import dataclass
import math
from pathlib import Path

from .core import DEFAULT_MODEL
from .feedback import RevisionContext


@dataclass(frozen=True)
class CandidateConfig:
    source: Path
    function: str
    output: Path
    model: str = DEFAULT_MODEL
    harness: Path | None = None
    protocol: Path | None = None
    fuzz_seconds: int = 0
    smoke_test: bool = False
    corpus: Path | None = None
    temperature: float = 0.2
    generate_only: bool = False
    candidate_id: str = "candidate_0001"
    parent_id: str | None = None
    round_index: int = 0
    revision: RevisionContext | None = None
    automatic_feedback_threshold: float = 0.5
    automatic_feedback_include_unavailable: bool = False

    def __post_init__(self) -> None:
        if (
            isinstance(self.automatic_feedback_threshold, bool)
            or not isinstance(self.automatic_feedback_threshold, (int, float))
            or not math.isfinite(self.automatic_feedback_threshold)
            or not 0 <= self.automatic_feedback_threshold <= 1
        ):
            raise ValueError("automatic_feedback_threshold must be finite and in [0, 1]")
        if not isinstance(self.automatic_feedback_include_unavailable, bool):
            raise ValueError("automatic_feedback_include_unavailable must be boolean")
