"""Validate CLI inputs and launch an independent-candidate experiment."""

import argparse
import sys
from pathlib import Path

from .config import CandidateConfig
from .core import DEFAULT_MODEL
from .experiment import run_experiment
from .feedback import load_revision


def main(
    argv: list[str] | None = None,
    *,
    llm=None,
    validation_config=None,
) -> int:
    import re

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["feedback-loop"]:
        from .feedback_loop import main as feedback_loop_main
        return feedback_loop_main(arguments[1:])
    if arguments[:1] == ["triplets"]:
        from .triplet_cli import main as triplet_main
        return triplet_main(arguments[1:])
    if arguments[:1] in (["generate"], ["generate-all"], ["run"]):
        from .generation_cli import main as generation_main
        return generation_main(
            arguments[1:],
            llm=llm,
            all_triplets=arguments[0] == "generate-all",
            validation_config=validation_config,
            run_command=arguments[0] == "run",
        )
    if arguments[:1] == ["measure-target"]:
        return _measure_target_main(arguments[1:])
    if arguments[:1] == ["protocol-mine"]:
        from .protocol_cli import main as protocol_main
        return protocol_main(arguments[1:], llm=llm)

    parser = argparse.ArgumentParser(description="Generate N independent C libFuzzer harness candidates.")
    parser.add_argument("--source", required=True, type=Path, help="Self-contained UTF-8 C source without main")
    parser.add_argument("--function", required=True, help="Target C function name")
    parser.add_argument("--output", required=True, type=Path, help="New experiment directory (must not exist)")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--candidates", type=int, default=1, help="Number of independent requests (default: 1)")
    parser.add_argument("--temperature", type=float, help="Sampling temperature in [0, 2]; default: 0.8 for N>1, otherwise 0.2")
    parser.add_argument("--generate-only", action="store_true", help="Save and review code without compilation or fuzzing")
    parser.add_argument("--harness", type=Path, help="Review existing harness without API; requires --candidates 1")
    parser.add_argument("--fuzz-seconds", type=int, default=0, help="Fuzz time per candidate; 0 disables it")
    parser.add_argument("--smoke-test", action="store_true", help="Replay fixed inputs after compile; always enabled before fuzz")
    parser.add_argument("--corpus", type=Path, help="Seed directory copied separately for each candidate")
    parser.add_argument("--protocol-spec", type=Path, dest="protocol",
                        help="Optional declarative protocol JSON supplied to the harness prompt")
    parser.add_argument("--parent-candidate", type=Path, help="Parent candidate directory for feedback revision")
    parser.add_argument("--feedback", type=Path, help="Parent-bound FeedbackPacket JSON; requires --parent-candidate")
    args = parser.parse_args(arguments)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.function):
        parser.error("--function must be a C identifier")
    if args.source.suffix != ".c":
        parser.error("--source must be a .c file")
    if args.candidates < 1:
        parser.error("--candidates must be positive")
    if args.harness and args.candidates != 1:
        parser.error("--harness requires --candidates 1")
    if bool(args.parent_candidate) != bool(args.feedback) or (args.feedback and args.harness):
        parser.error("Use --parent-candidate and --feedback together, without --harness")
    if args.temperature is None:
        args.temperature = 0.8 if args.candidates > 1 else 0.2
    if not 0 <= args.temperature <= 2:
        parser.error("--temperature must be finite and in [0, 2]")
    if args.fuzz_seconds < 0 or (args.generate_only and args.fuzz_seconds):
        parser.error("--fuzz-seconds must be nonnegative and cannot be combined with --generate-only")
    if args.generate_only and args.smoke_test:
        parser.error("--smoke-test cannot be combined with --generate-only")
    if args.corpus and (not args.fuzz_seconds or not args.corpus.is_dir()):
        parser.error("--corpus requires a positive --fuzz-seconds and an existing directory")
    if args.protocol and not args.protocol.is_file():
        parser.error("--protocol-spec must be an existing JSON file")
    try:
        original = args.source.read_bytes()
        if not original.decode("utf-8").strip():
            raise ValueError("source is empty")
        existing_code = args.harness.read_text(encoding="utf-8") if args.harness else None
        revision = load_revision(args.parent_candidate, args.feedback, original, args.function) if args.feedback else None
        args.output.mkdir(parents=True, exist_ok=False)
        config = CandidateConfig(**{key: value for key, value in vars(args).items()
                                    if key not in ("candidates", "parent_candidate", "feedback")},
                                 revision=revision,
                                 parent_id=revision.feedback.candidate_id if revision else None,
                                 round_index=revision.feedback.round_index + 1 if revision else 0)
        return run_experiment(config, original, args.candidates, existing_code)
    except (OSError, ValueError) as exc:
        print(f"Input/output error: {exc}", file=sys.stderr)
        return 1


def _measure_target_main(argv: list[str]) -> int:
    from .artifacts import ArtifactStore
    from .target_build import TargetBuildConfig
    from .target_coverage import TargetCoverageCollector, TargetCoverageConfig

    parser = argparse.ArgumentParser(
        prog="harness-generation measure-target",
        description="Measure LLVM source coverage scoped to target source files.",
    )
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--ft", required=True, dest="ft_id")
    parser.add_argument(
        "--harness",
        type=Path,
        help="Harness source; defaults to artifacts/harnesses/<ft>.c",
    )
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument(
        "--target-source",
        action="append",
        type=Path,
        dest="target_sources",
        help="Target C source file; may be repeated. Defaults to simple src/*.c.",
    )
    parser.add_argument(
        "--header",
        action="append",
        type=Path,
        dest="headers",
        default=[],
    )
    parser.add_argument(
        "--include",
        action="append",
        type=Path,
        dest="includes",
        default=[],
    )
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--runs", type=int, default=64)
    parser.add_argument(
        "--harness-includes-target",
        action="store_true",
        help="Do not separately compile target sources; use them only as coverage filters.",
    )
    args = parser.parse_args(argv)
    try:
        store = ArtifactStore(args.artifacts)
        layout = store.for_triplet(args.ft_id)
        harness = args.harness or layout.harness
        if args.target_sources:
            target = TargetBuildConfig(
                project_root=args.project_root,
                source_files=tuple(path.resolve() for path in args.target_sources),
                header_files=tuple(path.resolve() for path in args.headers),
                include_paths=tuple(path.resolve() for path in args.includes),
                compiler_flags=("-std=c11",),
            )
        else:
            target = TargetBuildConfig.for_simple_project(args.project_root)
        if args.includes and not args.target_sources:
            target = TargetBuildConfig(
                project_root=target.project_root,
                source_files=target.source_files,
                header_files=target.header_files,
                include_paths=tuple(path.resolve() for path in args.includes),
                compiler_flags=target.compiler_flags,
                archive_name=target.archive_name,
            )
        result = TargetCoverageCollector(TargetCoverageConfig(
            runs=args.runs,
            compile_target_sources=not args.harness_includes_target,
        )).measure(
            harness,
            target,
            artifacts=args.artifacts,
            ft_id=args.ft_id,
            corpus=args.corpus,
        )
    except (OSError, ValueError) as exc:
        print(f"Target measurement failed: {exc}", file=sys.stderr)
        return 1

    summary = result.summary.get("target_only", {})
    totals = summary.get("totals", {}) if isinstance(summary, dict) else {}
    print(f"Target coverage: {result.status}")
    print(f"Artifact: {result.artifact_directory}")
    for key in ("functions", "lines", "regions", "branches"):
        item = totals.get(key) if isinstance(totals, dict) else None
        if isinstance(item, dict) and "percent" in item:
            print(
                f"{key}: {item.get('covered')}/{item.get('count')} "
                f"({item.get('percent')}%)"
            )
    entered = summary.get("entered_functions", []) if isinstance(summary, dict) else []
    if entered:
        print("Entered functions: " + ", ".join(str(name) for name in entered))
    if result.errors:
        print("Errors: " + "; ".join(result.errors), file=sys.stderr)
    if result.warnings:
        print("Warnings: " + "; ".join(result.warnings), file=sys.stderr)
    return 0 if result.status in {"passed", "unavailable"} else 1
