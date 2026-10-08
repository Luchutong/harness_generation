"""Independent entry discovery stage; no model or FT construction is invoked."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .artifacts import ArtifactStore
from .entry_candidates import discover_candidates
from .sfg_adapter import load_sfg_artifacts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness-generation candidates",
                                     description="Record possible fuzz entries without semantic elimination")
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--policy", choices=("broad",), default="broad",
                        help="Broad discovery retains every parsed function")
    parser.add_argument("--max-candidates", type=_non_negative_integer,
                        help="Limit the processing selection, retaining deferred candidates")
    args = parser.parse_args(argv)
    try:
        artifacts = load_sfg_artifacts(args.artifacts)
        catalog = discover_candidates(artifacts, policy=args.policy,
                                      max_candidates=args.max_candidates)
        output = ArtifactStore(args.artifacts).write_candidate_catalog(catalog)
    except (OSError, ValueError) as error:
        print(f"Candidate discovery failed: {error}", file=sys.stderr)
        return 1
    print(f"[CANDIDATES] policy={catalog.policy} recorded={len(catalog.candidates)} "
          f"selected={len(catalog.selected)} deferred={len(catalog.deferred_reasons)}")
    print(f"[CANDIDATES] Wrote {output}")
    return 0


def _non_negative_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a non-negative integer") from error
    if number < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return number
