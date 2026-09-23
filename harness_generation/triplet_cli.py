"""CLI for extracting and inspecting canonical Function Triplets."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .artifacts import ArtifactStore
from .ft_selection import build_selection_manifest
from .records import write_json
from .sfg_adapter import load_sfg_artifacts
from .triplet import FunctionTriplet, load_triplets_json
from .triplet_extractor import extract_function_triplets


def main(argv: list[str] | None = None) -> int:
    arguments = list(argv or [])
    if arguments[:1] == ["show"]:
        return _show_command(arguments[1:])
    if arguments[:1] == ["rank"]:
        return _rank_command(arguments[1:])
    return _extract_command(arguments)


def _extract_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="harness-generation triplets",
                                     description="Extract Function Triplets from SFG artifacts")
    parser.add_argument("--artifacts", required=True, type=Path,
                        help="Directory containing Phase 1 JSON artifacts")
    parser.add_argument("--individual", action="store_true",
                        help="Also write triplets/<ft_id>.json files")
    args = parser.parse_args(argv)
    try:
        artifacts = load_sfg_artifacts(args.artifacts)
        triplets = extract_function_triplets(artifacts)
        output = ArtifactStore(args.artifacts).write_triplets(
            triplets, individual=args.individual
        )
    except (OSError, ValueError) as exc:
        print(f"Triplet extraction failed: {exc}", file=sys.stderr)
        return 1
    print(f"[FT] Wrote {output}")
    for triplet in triplets:
        print(
            f"[FT] {triplet.id} anchor={triplet.isf.function} "
            f"PRF={len(triplet.prfs)} HPF={len(triplet.hpfs)} "
            f"structures={len(triplet.structures)}"
        )
    _print_statistics(triplet_statistics(
        artifacts.annotations, artifacts.functions, triplets
    ))
    return 0


def _show_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="harness-generation triplets show",
                                     description="Inspect one Function Triplet")
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--id", required=True, dest="triplet_id")
    args = parser.parse_args(argv)
    try:
        triplets = load_triplets_json(args.artifacts / "triplets.json")
        triplet = next(
            (item for item in triplets if item.id == args.triplet_id), None
        )
        if triplet is None:
            raise ValueError(f"unknown Function Triplet: {args.triplet_id}")
    except (OSError, ValueError) as exc:
        print(f"Triplet inspection failed: {exc}", file=sys.stderr)
        return 1
    _print_triplet(triplet)
    return 0


def _rank_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="harness-generation triplets rank",
        description="Rank Function Triplets and select a diverse set under a budget",
    )
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument(
        "--max-ft", type=_non_negative_integer,
        help="Maximum number of FTs to select",
    )
    parser.add_argument(
        "--max-calls", type=_non_negative_integer,
        help="Maximum estimated baseline LLM calls",
    )
    parser.add_argument(
        "--min-score", type=_score, default=0.0,
        help="Minimum intrinsic FT score from 0 to 1 (default: 0)",
    )
    parser.add_argument(
        "--output", type=Path,
        help="Selection manifest path (default: <artifacts>/ft_selection.json)",
    )
    args = parser.parse_args(argv)
    try:
        store = ArtifactStore(args.artifacts)
        artifacts = load_sfg_artifacts(args.artifacts)
        triplets = load_triplets_json(store.triplets)
        manifest = build_selection_manifest(
            triplets,
            artifacts.annotations,
            max_ft=args.max_ft,
            max_calls=args.max_calls,
            min_score=args.min_score,
        )
        output = args.output or store.ft_selection
        write_json(output, manifest, sort_keys=True, allow_nan=False)
    except (OSError, ValueError) as exc:
        print(f"FT ranking failed: {exc}", file=sys.stderr)
        return 1

    selected_ids = {
        item["triplet_id"] for item in manifest["selection"]
    }
    for index, item in enumerate(manifest["ranking"], start=1):
        marker = " selected" if item["triplet_id"] in selected_ids else ""
        if item["eligible"]:
            print(
                f"[FT-RANK] {index:03d} {item['triplet_id']} "
                f"score={item['score']:.3f} calls={item['estimated_llm_calls']}"
                f"{marker}"
            )
        else:
            reasons = ",".join(item["exclusion_reasons"])
            print(f"[FT-RANK] {index:03d} {item['triplet_id']} excluded={reasons}")
    summary = manifest["summary"]
    print(
        f"[FT-RANK] selected={summary['selected_count']}/"
        f"{summary['eligible_count']} estimated_calls="
        f"{summary['estimated_llm_calls']}"
    )
    print(f"[FT-RANK] Wrote {output}")
    return 0


def _non_negative_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def _score(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not 0.0 <= parsed <= 1.0:
        raise argparse.ArgumentTypeError("must be between 0 and 1")
    return parsed


def triplet_statistics(annotations, functions,
                       triplets: tuple[FunctionTriplet, ...]) -> dict:
    """Count unique functions separately from non-exclusive role memberships."""

    roles_by_function: dict[str, set[str]] = {}
    for index, annotation in enumerate(annotations):
        identity = annotation.get("function_id", annotation.get("function", index))
        labels = annotation.get("labels", [])
        roles_by_function.setdefault(str(identity), set()).update(
            label for label in labels if label in {"ISF", "PRF", "HPF"}
        )
    role_counts = {
        role.lower(): sum(role in labels for labels in roles_by_function.values())
        for role in ("ISF", "PRF", "HPF")
    }
    sizes = [len(triplet.functions) for triplet in triplets]
    return {
        "unique_functions": len({
            function.get("id", function.get("name", index))
            for index, function in enumerate(functions)
        }),
        "role_memberships": role_counts,
        "multi_role_functions": sum(
            len(labels) > 1 for labels in roles_by_function.values()
        ),
        "fts": len(triplets),
        "average_ft_size": sum(sizes) / len(sizes) if sizes else 0.0,
        "max_ft_size": max(sizes, default=0),
    }


def _print_statistics(statistics: dict) -> None:
    print("Statistics:")
    print(f"  Unique functions: {statistics['unique_functions']}")
    print("  Role memberships:")
    print(f"    ISF: {statistics['role_memberships']['isf']}")
    print(f"    PRF: {statistics['role_memberships']['prf']}")
    print(f"    HPF: {statistics['role_memberships']['hpf']}")
    print(f"  Multi-role functions: {statistics['multi_role_functions']}")
    print(f"  FTs: {statistics['fts']}")
    print(f"  Average functions per FT: {statistics['average_ft_size']:.2f}")
    print(f"  Max FT size: {statistics['max_ft_size']}")


def _print_triplet(triplet: FunctionTriplet) -> None:
    print(f"Function Triplet: {triplet.id}")
    _print_role("ISF", (triplet.isf,), triplet)
    _print_role("PRFs", triplet.prfs, triplet)
    _print_role("HPFs", triplet.hpfs, triplet)
    print("Structures:")
    for structure in triplet.structures:
        print(f"  {structure}")
    print("Edges:")
    for edge in triplet.edges:
        roles = ",".join(edge.roles)
        marker = " inferred" if edge.inferred else ""
        print(f"  {edge.src} --{edge.function} [{roles}]--> {edge.dst}{marker}")
    data_chain = triplet.metadata.get("data_chain", {})
    structures = data_chain.get("structures", []) if isinstance(data_chain, dict) else []
    chain = " -> ".join(["fuzz_input", *structures])
    print("Data chain:")
    print(f"  {chain}")
    print("Bypass semantics:")
    if not triplet.bypass_semantics:
        print("  (none)")
    for semantic in triplet.bypass_semantics:
        print(f"  {semantic.kind}: {semantic.function} - {semantic.summary}")


def _print_role(label: str, functions, triplet: FunctionTriplet) -> None:
    print(f"{label}:")
    if not functions:
        print("  (none)")
        return
    for function in functions:
        print(f"  {function.function}")
        for edge in triplet.edges:
            if edge.function_id == function.function_id:
                print(f"    {edge.src} -> {edge.dst}")
