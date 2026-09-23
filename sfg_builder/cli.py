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
from .semantic import LLMSemanticAnalyzer, MockSemanticAnalyzer, OpenAICompatibleTransport


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build a Structural Flow Graph from a C project")
    parser.add_argument("--project", required=True, type=Path, help="C project root")
    parser.add_argument("--output", required=True, type=Path, help="Artifact directory")
    parser.add_argument("--ignore-dir", action="append", default=[], metavar="PATTERN",
                        help="Additional ignored directory name/glob; repeatable")
    parser.add_argument("--semantic-analyzer", choices=("mock", "llm"), default="mock",
                        help="Semantic backend; mock is deterministic and requires no API key")
    parser.add_argument("--model", default="deepseek-v4-flash")
    parser.add_argument("--endpoint", default="https://api.deepseek.com/chat/completions")
    parser.add_argument("--render", action="store_true", help="Render sfg.svg with Graphviz dot")
    args = parser.parse_args(argv)
    if args.semantic_analyzer == "llm":
        api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
        if not api_key:
            parser.error("--semantic-analyzer llm requires DEEPSEEK_API_KEY")
        analyzer = LLMSemanticAnalyzer(OpenAICompatibleTransport(api_key, args.endpoint), args.model)
    else:
        analyzer = MockSemanticAnalyzer()
    try:
        result = SFGPipeline(analyzer, ignored_directories=DEFAULT_IGNORES + tuple(args.ignore_dir)).run(
            args.project, args.output)
    except (ProjectParseError, OSError, ValueError) as exc:
        print(f"SFG build failed: {exc}", file=sys.stderr)
        return 1
    _print_summary(result)
    if args.render:
        _render_svg(args.output)
    return 0


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
