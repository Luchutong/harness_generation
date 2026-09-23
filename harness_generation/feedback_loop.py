"""Bounded parent → feedback → LLM revision → evaluation loops.

This module intentionally orchestrates the already-audited single-candidate
pipeline instead of creating a second generator.  Each revision consumes the
exact ``automatic_feedback.json`` produced by its selected parent, so hashes,
evidence snapshots, prompts and child lineage remain verifiable.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import sys
from typing import Any, Mapping

from .candidate import run_candidate
from .config import CandidateConfig
from .core import DEFAULT_MODEL
from .evaluation import EvaluationReport, evaluation_report_from_dict
from .experiment import run_experiment
from .feedback import load_revision
from .iteration import ScoreCandidateSelector, WeightedAggregationPolicy
from .records import write_json
from .runtime_validation import POTENTIAL_TARGET_CRASH


FEEDBACK_LOOP_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class FeedbackLoopConfig:
    """Configuration for a bounded, single-lineage revision loop.

    ``parent_harness`` creates round 0 offline, which is useful for a known
    baseline such as ``mini_parser``'s pass-through Harness.  ``parent_candidate``
    resumes from any existing candidate with an ``automatic_feedback.json``.
    Each later round expands one selected parent into ``children_per_round``
    LLM-generated children, then selects one for the next round.
    """

    source: Path
    function: str
    output: Path
    parent_harness: Path | None = None
    parent_candidate: Path | None = None
    rounds: int = 1
    children_per_round: int = 1
    model: str = DEFAULT_MODEL
    temperature: float = 0.2
    generate_only: bool = False
    smoke_test: bool = False
    fuzz_seconds: int = 0
    corpus: Path | None = None
    protocol: Path | None = None
    feedback_threshold: float = 0.5
    include_unavailable_primary: bool = False

    def __post_init__(self) -> None:
        if bool(self.parent_harness) == bool(self.parent_candidate):
            raise ValueError("Specify exactly one of parent_harness or parent_candidate")
        if type(self.rounds) is not int or self.rounds < 1:
            raise ValueError("rounds must be a positive integer")
        if type(self.children_per_round) is not int or self.children_per_round < 1:
            raise ValueError("children_per_round must be a positive integer")
        if (
            isinstance(self.temperature, bool)
            or not isinstance(self.temperature, (int, float))
            or not math.isfinite(self.temperature)
            or not 0 <= self.temperature <= 2
        ):
            raise ValueError("temperature must be finite and in [0, 2]")
        if (
            isinstance(self.feedback_threshold, bool)
            or not isinstance(self.feedback_threshold, (int, float))
            or not math.isfinite(self.feedback_threshold)
            or not 0 <= self.feedback_threshold <= 1
        ):
            raise ValueError("feedback_threshold must be finite and in [0, 1]")
        if type(self.fuzz_seconds) is not int or self.fuzz_seconds < 0:
            raise ValueError("fuzz_seconds must be a non-negative integer")
        if self.generate_only and (self.smoke_test or self.fuzz_seconds):
            raise ValueError("generate_only cannot be combined with smoke_test or fuzz_seconds")
        if not isinstance(self.include_unavailable_primary, bool):
            raise ValueError("include_unavailable_primary must be boolean")


@dataclass(frozen=True)
class FeedbackLoopResult:
    success: bool
    status: str
    output: Path
    completed_rounds: int
    selected_candidate: str | None
    reason: str | None = None


def run_feedback_loop(config: FeedbackLoopConfig) -> FeedbackLoopResult:
    """Run a bounded feedback loop and persist ``feedback_loop.json``.

    A failed child is retained with its artifacts but never selected for the
    following round.  This is a bounded research loop, not a claim that a
    selected child is semantically superior or that all unknown metrics are low.
    """

    source = config.source.resolve()
    original = source.read_bytes()
    if not original.decode("utf-8").strip():
        raise ValueError("source is empty or not UTF-8 text")
    root = config.output.resolve()
    _prepare_output(root)
    manifest: dict[str, Any] = {
        "schema_version": FEEDBACK_LOOP_SCHEMA_VERSION,
        "status": "running",
        "source": str(source),
        "source_sha256": hashlib.sha256(original).hexdigest(),
        "function": config.function,
        "model": config.model,
        "temperature": config.temperature,
        "rounds_requested": config.rounds,
        "children_per_round": config.children_per_round,
        "feedback_threshold": config.feedback_threshold,
        "include_unavailable_primary": config.include_unavailable_primary,
        "generate_only": config.generate_only,
        "smoke_test": config.smoke_test,
        "fuzz_seconds": config.fuzz_seconds,
        "initial_parent": None,
        "rounds": [],
        "selected_candidate": None,
        "reason": None,
    }

    def persist() -> None:
        write_json(root / "feedback_loop.json", manifest, sort_keys=True, allow_nan=False)

    if config.parent_harness is not None:
        parent = root / "round_000"
        parent.mkdir()
        parent_result, parent_code = run_candidate(
            CandidateConfig(
                source, config.function, parent,
                harness=config.parent_harness.resolve(),
                model=config.model,
                temperature=config.temperature,
                generate_only=config.generate_only,
                smoke_test=config.smoke_test,
                fuzz_seconds=config.fuzz_seconds,
                corpus=config.corpus,
                protocol=config.protocol,
                automatic_feedback_threshold=config.feedback_threshold,
                automatic_feedback_include_unavailable=config.include_unavailable_primary,
            ),
            original,
            config.parent_harness.read_text(encoding="utf-8"),
        )
        manifest["initial_parent"] = {
            "kind": "offline_harness",
            "directory": _relative(root, parent),
            "candidate_id": parent_result["candidate_id"],
            "exit_code": parent_code,
            "failure_stage": parent_result.get("failure_stage"),
            "accepted_for_revision": parent_code == 0,
        }
        if parent_code != 0:
            try:
                load_revision(parent, parent / "automatic_feedback.json",
                              original, config.function)
            except ValueError as error:
                manifest["initial_parent"]["revision_error"] = str(error)
                manifest.update(status="failed", reason="initial_parent_unusable_for_revision")
                persist()
                return FeedbackLoopResult(
                    False, "failed", root, 0, None,
                    "initial_parent_unusable_for_revision",
                )
            manifest["initial_parent"]["accepted_for_revision"] = True
            manifest["initial_parent"]["revision_reason"] = (
                "Initial parent failed execution but produced auditable feedback."
            )
    else:
        assert config.parent_candidate is not None
        parent = config.parent_candidate.resolve()
        _read_object(parent / "result.json", "parent result")
        manifest["initial_parent"] = {
            "kind": "existing_candidate",
            "directory": str(parent),
        }
    persist()

    selected_candidate: str | None = None
    for round_index in range(1, config.rounds + 1):
        feedback_path = parent / "automatic_feedback.json"
        revision = load_revision(parent, feedback_path, original, config.function)
        feedback_digest = hashlib.sha256(feedback_path.read_bytes()).hexdigest()
        parent_record = _read_object(parent / "result.json", "parent result")
        round_directory = root / f"round_{round_index:03d}"
        round_directory.mkdir()
        child_config = CandidateConfig(
            source, config.function, round_directory,
            model=config.model,
            temperature=config.temperature,
            generate_only=config.generate_only,
            smoke_test=config.smoke_test,
            fuzz_seconds=config.fuzz_seconds,
            corpus=config.corpus,
            protocol=config.protocol,
            revision=revision,
            parent_id=revision.feedback.candidate_id,
            round_index=revision.feedback.round_index + 1,
            automatic_feedback_threshold=config.feedback_threshold,
            automatic_feedback_include_unavailable=config.include_unavailable_primary,
        )
        experiment_code = run_experiment(
            child_config, original, config.children_per_round,
        )
        experiment = _read_object(round_directory / "experiment.json", "round experiment")
        candidate_directories = _candidate_directories(
            round_directory, config.children_per_round,
        )
        reports, rejected = _selectable_reports(candidate_directories)
        selection = ScoreCandidateSelector(
            aggregation_policy=WeightedAggregationPolicy(
                require_dynamic_quality=config.fuzz_seconds > 0,
            ),
            use_persisted_aggregate=False,
        ).select(
            tuple(report for report, _directory in reports), limit=1
        )
        by_id = {report.candidate_id: directory for report, directory in reports}
        selected_directory = (
            by_id.get(selection.candidate_ids[0]) if selection.candidate_ids else None
        )
        entry = {
            "round_index": round_index,
            "parent": {
                "candidate_id": parent_record.get("candidate_id"),
                "directory": str(parent),
                "round_index": parent_record.get("round_index"),
            },
            "feedback": {
                "artifact": str(feedback_path),
                "sha256": feedback_digest,
                "item_count": len(revision.feedback.items),
            },
            "experiment_directory": _relative(root, round_directory),
            "experiment_exit_code": experiment_code,
            "experiment_status": experiment.get("status"),
            "experiment_error": experiment.get("error"),
            "candidates": [
                _candidate_manifest_entry(directory) for directory in candidate_directories
            ],
            "rejected_candidates": rejected,
            "selection": asdict(selection),
            "selected_candidate": selection.candidate_ids[0] if selection.candidate_ids else None,
            "selected_directory": (
                None if selected_directory is None else _relative(root, selected_directory)
            ),
        }
        manifest["rounds"].append(entry)
        selected_candidate = entry["selected_candidate"]
        manifest["selected_candidate"] = selected_candidate
        if selected_directory is None:
            detail = experiment.get("error")
            reason = "no_selectable_child"
            if isinstance(detail, str) and detail:
                reason += ": " + detail
            manifest.update(status="stopped", reason=reason)
            persist()
            return FeedbackLoopResult(
                False, "stopped", root, round_index - 1, None, reason
            )
        parent = selected_directory
        persist()

    manifest.update(status="completed", reason=None)
    persist()
    return FeedbackLoopResult(True, "completed", root, config.rounds, selected_candidate)


def main(argv: list[str] | None = None) -> int:
    """CLI for the bounded loop; LLM requests use the existing configured provider."""

    parser = argparse.ArgumentParser(
        prog="harness-generation feedback-loop",
        description="Run bounded automatic-feedback LLM revision rounds.",
    )
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--function", required=True)
    parser.add_argument("--output", required=True, type=Path,
                        help="New directory for loop artifacts")
    parent = parser.add_mutually_exclusive_group(required=True)
    parent.add_argument("--parent-harness", type=Path,
                        help="Offline baseline Harness used to create round 0")
    parent.add_argument("--parent-candidate", type=Path,
                        help="Existing candidate directory containing automatic_feedback.json")
    parser.add_argument("--rounds", type=_positive_int, default=1)
    parser.add_argument("--children-per-round", type=_positive_int, default=1)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--feedback-threshold", type=float, default=0.5,
                        help="Measured score at or below this value becomes feedback")
    parser.add_argument("--include-unavailable-primary", action="store_true")
    parser.add_argument("--generate-only", action="store_true")
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument("--fuzz-seconds", type=int, default=0)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--protocol-spec", type=Path, dest="protocol",
                        help="Optional declarative protocol JSON supplied to child prompts")
    args = parser.parse_args(argv)
    try:
        if args.source.suffix != ".c":
            raise ValueError("source must be a .c file")
        if not args.function.isidentifier():
            raise ValueError("function must be a C identifier")
        if not args.source.is_file():
            raise ValueError("source does not exist")
        if args.parent_harness is not None and not args.parent_harness.is_file():
            raise ValueError("parent_harness does not exist")
        if args.parent_candidate is not None and not args.parent_candidate.is_dir():
            raise ValueError("parent_candidate does not exist")
        if args.corpus is not None and not args.corpus.is_dir():
            raise ValueError("corpus must be an existing directory")
        if args.protocol is not None and not args.protocol.is_file():
            raise ValueError("protocol_spec must be an existing JSON file")
        if args.output.exists():
            raise ValueError("output must not already exist")
        config = FeedbackLoopConfig(**vars(args))
        result = run_feedback_loop(config)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Feedback loop failed: {error}", file=sys.stderr)
        return 1
    print(
        f"feedback-loop={result.status} rounds={result.completed_rounds}/{args.rounds} "
        f"selected={result.selected_candidate or '-'} output={result.output}"
    )
    return 0 if result.success else 1


def _prepare_output(root: Path) -> None:
    if root.exists():
        if any(root.iterdir()):
            raise ValueError("feedback-loop output directory must be empty")
    else:
        root.mkdir(parents=True)


def _candidate_directories(round_directory: Path, count: int) -> tuple[Path, ...]:
    if count == 1:
        return (round_directory,)
    return tuple(round_directory / "candidates" / f"candidate_{index:04d}"
                 for index in range(1, count + 1))


def _selectable_reports(
    directories: tuple[Path, ...],
) -> tuple[list[tuple[EvaluationReport, Path]], list[dict[str, str]]]:
    selectable: list[tuple[EvaluationReport, Path]] = []
    rejected: list[dict[str, str]] = []
    for directory in directories:
        try:
            result = _read_object(directory / "result.json", "candidate result")
            reason = _candidate_failure_reason(result)
            if reason is not None:
                rejected.append({"directory": str(directory), "reason": reason})
                continue
            report = evaluation_report_from_dict(
                _read_object(directory / "evaluation.json", "candidate evaluation")
            )
        except (OSError, UnicodeError, ValueError) as error:
            rejected.append({"directory": str(directory), "reason": type(error).__name__})
            continue
        selectable.append((report, directory))
    return selectable, rejected


def _candidate_failure_reason(result: Mapping[str, Any]) -> str | None:
    if result.get("generation") not in {"passed", "skipped"}:
        return "generation_not_passed"
    target_smoke_finding = _accepted_target_finding(result, "smoke")
    target_fuzz_finding = _accepted_target_finding(result, "fuzzing")
    failure_stage = result.get("failure_stage")
    if failure_stage and not (
        failure_stage == "smoke" and target_smoke_finding
        or failure_stage == "fuzzing" and target_fuzz_finding
    ):
        return "failure_stage_present"
    expected = {
        "compilation": {"passed", "skipped"},
        "smoke": {"passed", "skipped"},
        "fuzzing": {"completed", "skipped"},
    }
    for stage, allowed in expected.items():
        stage_result = result.get(stage)
        status = stage_result.get("status") if isinstance(stage_result, Mapping) else None
        if stage == "smoke" and target_smoke_finding and status == "finding":
            continue
        if stage == "fuzzing" and target_fuzz_finding and status == "finding":
            continue
        if (
            stage == "fuzzing" and target_smoke_finding and status == "blocked"
            and isinstance(stage_result, Mapping)
            and stage_result.get("reason") == "target_finding_observed_during_smoke"
        ):
            continue
        if status not in allowed:
            return f"{stage}_not_accepted"
    return None


def _accepted_target_finding(result: Mapping[str, Any], stage: str) -> bool:
    value = result.get(stage)
    if not isinstance(value, Mapping) or value.get("status") != "finding":
        return False
    classification = value.get("crash_classification")
    return (
        isinstance(classification, Mapping)
        and classification.get("classification") == POTENTIAL_TARGET_CRASH
    )


def _candidate_manifest_entry(directory: Path) -> dict[str, Any]:
    try:
        result = _read_object(directory / "result.json", "candidate result")
    except (OSError, UnicodeError, ValueError) as error:
        return {"directory": str(directory), "status": "unavailable", "reason": type(error).__name__}
    return {
        "directory": str(directory),
        "candidate_id": result.get("candidate_id"),
        "generation": result.get("generation"),
        "compilation": _stage_status(result, "compilation"),
        "smoke": _stage_status(result, "smoke"),
        "fuzzing": _stage_status(result, "fuzzing"),
        "evaluation": result.get("evaluation"),
    }


def _stage_status(result: Mapping[str, Any], stage: str) -> str | None:
    entry = result.get(stage)
    return entry.get("status") if isinstance(entry, Mapping) else None


def _read_object(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"could not read {label}: {type(error).__name__}") from None
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _relative(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed
