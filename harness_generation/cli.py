"""Dispatch the source-grounded HG chain without loading retired pipelines."""
from __future__ import annotations

import argparse
from importlib import import_module
import sys

COMMANDS = {
    "parse": "sfg_builder.cli",
    "candidates": "harness_generation.candidate_cli",
    "candidate-validate": "harness_generation.semantic_discovery.cli",
    "semantic-slice": "harness_generation.semantic_slicing.cli",
    "minimal-ft": "harness_generation.minimal_ft.cli",
    "harness-context": "harness_generation.harness_context.cli",
    "context-generate": "harness_generation.context_generation.cli",
}


def main(argv: list[str] | None = None, *, llm=None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="harness-generation",
        description="HG v0.3: source → Candidate → Slice → Minimal FT → Context → frozen Plan → harness",
    )
    parser.add_argument("command", choices=tuple(COMMANDS), nargs="?")
    if not arguments or arguments[0] in {"-h", "--help"}:
        parser.print_help()
        return 0
    args = parser.parse_args(arguments[:1])
    stage = import_module(COMMANDS[args.command]).main
    if args.command == "context-generate":
        return stage(arguments[1:], llm=llm)
    return stage(arguments[1:])
