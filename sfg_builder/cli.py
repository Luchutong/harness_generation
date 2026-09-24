"""Command-line entry point for project-level SFG construction."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

from .parser import DEFAULT_IGNORES, ProjectParseError
from .pipeline import SFGPipeline
from .client import BudgetedSemanticTransport
from .replay import ReplayedSemanticAnalyzer
from .semantic import LLMSemanticAnalyzer, MockSemanticAnalyzer, OpenAICompatibleTransport


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a Structural Flow Graph from a C project")
    parser.add_argument("--project", required=True, type=Path, help="C project root")
    parser.add_argument("--output", required=True, type=Path, help="Artifact directory")
    parser.add_argument("--ignore-dir", action="append", default=[], metavar="PATTERN",
                        help="Additional ignored directory name/glob; repeatable")
    parser.add_argument("--source-glob", action="append", default=[], metavar="GLOB",
                        help="Only parse project-relative source/header paths matching this glob; repeatable")
    parser.add_argument("--semantic-analyzer", choices=("mock", "llm", "replay"), default="mock",
                        help="Semantic backend; mock is deterministic and requires no API key")
    parser.add_argument("--replay-annotations", type=Path,
                        help="Recorded real LLM annotations for zero-network replay")
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--endpoint", default="https://api.deepseek.com/chat/completions")
    parser.add_argument("--thinking", choices=("enabled", "disabled"),
                        help="Set thinking mode for semantic LLM requests")
    parser.add_argument("--max-semantic-requests", type=_positive_integer, default=300,
                        help="Hard cap on real semantic LLM requests (default: 300)")
    parser.add_argument("--paper-minimal", action="store_true",
                        help="Skip usage-pattern mining and LLM review outside paper Phase 1")
    parser.add_argument("--render", action="store_true", help="Render sfg.svg with Graphviz dot")
    args = parser.parse_args(argv)
    if args.semantic_analyzer == "replay":
        if not args.paper_minimal or args.replay_annotations is None:
            parser.error("replay requires --paper-minimal and --replay-annotations")
        analyzer = ReplayedSemanticAnalyzer(args.replay_annotations)
    elif args.semantic_analyzer == "llm":
        api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
        if not api_key:
            parser.error("--semantic-analyzer llm requires DEEPSEEK_API_KEY")
        analyzer = LLMSemanticAnalyzer(
            BudgetedSemanticTransport(
                OpenAICompatibleTransport(api_key, args.endpoint),
                args.max_semantic_requests,
                progress=lambda count, limit: (
                    print(f"[SFG] semantic requests: {count}/{limit}", file=sys.stderr)
                    if count == 1 or count % 10 == 0 else None
                ),
            ), args.model,
            thinking=args.thinking,
        )
    else:
        analyzer = MockSemanticAnalyzer()
    if args.semantic_analyzer != "replay" and args.replay_annotations is not None:
        parser.error("--replay-annotations requires --semantic-analyzer replay")
    try:
        result = SFGPipeline(
            analyzer,
            ignored_directories=DEFAULT_IGNORES + tuple(args.ignore_dir),
            source_globs=tuple(args.source_glob),
            max_semantic_requests=(args.max_semantic_requests
                                   if args.semantic_analyzer == "llm" else None),
            paper_minimal=args.paper_minimal,
        ).run(args.project, args.output)
    except (ProjectParseError, OSError, ValueError) as exc:
        print(f"SFG build failed: {exc}", file=sys.stderr)
        return 1
    _print_summary(result)
    if args.semantic_analyzer == "llm":
        print(f"Semantic HTTP requests: {analyzer.transport.calls}")
    if args.render:
        _render_svg(args.output)
    return 0


def _positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def _render_svg(output: Path) -> None:
    dot = shutil.which("dot")
    if dot is None:
        print("Graphviz 'dot' is unavailable; sfg.dot was still generated", file=sys.stderr)
        return
    try:
        completed = subprocess.run(
            [dot, "-Tsvg", "sfg.dot", "-o", "sfg.svg"], cwd=output,
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        print("Graphviz rendering failed; sfg.dot was still generated", file=sys.stderr)
        return
    if completed.returncode != 0:
        print("Graphviz rendering failed; sfg.dot was still generated", file=sys.stderr)


def _print_summary(result) -> None:
    print(f"Parsed functions: {len(result.parsed.functions)}")
    print(f"Struct types: {len(result.parsed.structs)}")
    if result.usage is not None:
        print(f"Usage traces: {len(result.usage.traces)}")
        print(f"Usage patterns: {len(result.usage.patterns)}")
        print(f"Usage semantic reviews: {len(result.usage.semantic_reviews)}")
    for label in ("ISF", "PRF", "HPF"):
        print(f"\n{label}:")
        for annotation in result.annotations:
            if label in annotation.labels:
                print(f"  {annotation.function}")
    print("\nSFG:")
    for edge in result.graph.edges:
        marker = " [inferred]" if edge.inferred else ""
        print(f"  {edge.source} --{edge.function}--> {edge.target}{marker}")
    for warning in result.graph.warnings:
        print(f"Warning: {warning}", file=sys.stderr)
