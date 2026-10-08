"""Index C source for HG using the existing parser and source identities."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from harness_generation.records import write_json
from .parser import CProjectParser, DEFAULT_IGNORES, ProjectParseError, write_functions_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness-generation parse", description="Index C source for the HG chain")
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="New artifact directory")
    parser.add_argument("--source-glob", action="append", default=[])
    parser.add_argument("--ignore-dir", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise ValueError("parse requires a new artifact directory")
        result = CProjectParser(
            DEFAULT_IGNORES + tuple(args.ignore_dir), source_globs=args.source_glob,
        ).parse(args.project)
        args.output.mkdir(parents=True, exist_ok=False)
        write_functions_json(result, args.output / "functions.json", project=args.project)
        # Match the parser-only preparation already used by fresh/blind workers.
        # These empty companions do not assert legacy role or flow annotations.
        for filename, key in (("annotations.json", "annotations"), ("flows.json", "flows")):
            write_json(args.output / filename, {"schema_version": 1, key: []})
        write_json(args.output / "sfg.json", {"schema_version": 1, "nodes": [], "edges": [], "functions": []})
    except (ProjectParseError, OSError, ValueError) as error:
        print(f"Source indexing failed: {error}", file=sys.stderr)
        return 1
    print(f"[PARSE] functions={len(result.functions)} files={len(result.files)} output={args.output}")
    for warning in result.warnings:
        print(f"[PARSE] {warning}", file=sys.stderr)
    return 0
