"""Dispatch the v0.5 source parser and generation-first execution entry."""
from __future__ import annotations

import argparse
from importlib import import_module
import sys

COMMANDS = {
    "parse": "sfg_builder.cli",
    "harness-run": "harness_generation.orchestration.cli",
}


def main(argv: list[str] | None = None, *, llm=None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="harness-generation",
        description="HG v0.5: source → API scope → Strategy → Preflight → ExecutablePlan → harness → build/runtime",
    )
    parser.add_argument("command", choices=tuple(COMMANDS), nargs="?")
    if not arguments or arguments[0] in {"-h", "--help"}:
        parser.print_help()
        return 0
    args = parser.parse_args(arguments[:1])
    stage = import_module(COMMANDS[args.command]).main
    if args.command == "harness-run":
        return stage(arguments[1:], model=llm)
    return stage(arguments[1:])
