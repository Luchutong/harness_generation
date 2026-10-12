"""Index C source for HG using the existing parser and source identities."""
from __future__ import annotations

import argparse
import json
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
    parser.add_argument("--compile-commands", type=Path, help="Explicit Clang build context; include its owned C translation units in the source index")
    parser.add_argument("--clang", type=Path, help="Trusted Clang frontend for --compile-commands")
    parser.add_argument("--clang-max-ast-bytes", type=int, help="Maximum compact JSON AST bytes per TU (at most 64 MiB)")
    parser.add_argument("--clang-max-ast-stream-bytes", type=int, help="Maximum raw Clang AST stream bytes per TU (at most 512 MiB)")
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise ValueError("parse requires a new artifact directory")
        explicit_sources = ()
        if args.compile_commands:
            from harness_generation.source_analysis.analyzer import AnalysisBudget, load_commands
            database = load_commands(args.project, args.compile_commands, AnalysisBudget())
            explicit_sources = tuple(args.project.resolve() / row["source"] for row in database["entries"])
            if any(path.suffix != ".c" for path in explicit_sources):
                raise ValueError("C source indexing does not support non-C translation units")
        result = CProjectParser(
            DEFAULT_IGNORES + tuple(args.ignore_dir), source_globs=args.source_glob,
            explicit_sources=explicit_sources,
        ).parse(args.project)
        args.output.mkdir(parents=True, exist_ok=False)
        write_functions_json(result, args.output / "functions.json", project=args.project)
        # Match the parser-only preparation already used by fresh/blind workers.
        # These empty companions do not assert legacy role or flow annotations.
        for filename, key in (("annotations.json", "annotations"), ("flows.json", "flows")):
            write_json(args.output / filename, {"schema_version": 1, key: []})
        write_json(args.output / "sfg.json", {"schema_version": 1, "nodes": [], "edges": [], "functions": []})
        if args.compile_commands:
            from harness_generation.source_analysis.analyzer import AnalysisBudget, analyze_build, write_analysis
            from harness_generation.minimal_ft.models import ProjectSnapshot
            from harness_generation.sfg_adapter import load_sfg_artifacts
            snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(args.output))
            document = json.loads((args.output / "functions.json").read_text())
            overrides = {name: value for name, value in (
                ("max_ast_bytes", args.clang_max_ast_bytes),
                ("max_ast_stream_bytes", args.clang_max_ast_stream_bytes)) if value is not None}
            analysis = analyze_build(args.project, args.compile_commands, document, clang=args.clang,
                snapshot=snapshot, budget=AnalysisBudget(**overrides))
            write_analysis(args.output, analysis)
        elif args.clang or args.clang_max_ast_bytes is not None or args.clang_max_ast_stream_bytes is not None:
            raise ValueError("--clang and Clang AST budgets require --compile-commands")
    except (ProjectParseError, OSError, ValueError) as error:
        print(f"Source indexing failed: {error}", file=sys.stderr)
        return 1
    print(f"[PARSE] functions={len(result.functions)} files={len(result.files)} output={args.output}")
    for warning in result.warnings:
        print(f"[PARSE] {warning}", file=sys.stderr)
    return 0
