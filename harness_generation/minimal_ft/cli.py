"""Standalone deterministic artifact projection; no provider or repository tools."""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

from ..artifacts import ArtifactStore
from ..semantic_discovery.models import candidate_id
from ..sfg_adapter import load_sfg_artifacts
from .builder import MinimalFTBuilder
from .models import ProjectSnapshot, stable_ft_id
from .persistence import (build_configuration, load_compatible_build, load_legacy_inputs, load_slice_input,
                          save_build, write_catalog)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="harness-generation minimal-ft", description="Deterministic Semantic Slice -> Minimal FT")
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--candidate", action="append", default=[], help="Exact project function ID or stable candidate ID; repeatable")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--no-legacy-comparison", action="store_true",
                        help="Compatibility flag; HG never reads legacy FT artifacts")
    args = parser.parse_args(argv)
    processed, resumed, invalid = 0, 0, 0
    try:
        store = ArtifactStore(args.artifacts)
        snapshot = ProjectSnapshot.from_artifacts(load_sfg_artifacts(store.root))
        if not store.semantic_slices_directory.is_dir():
            raise ValueError("missing semantic_slices; supply existing Slice artifacts")
        available = sorted(p.name for p in store.semantic_slices_directory.iterdir()
                           if p.is_dir() and re.fullmatch(r"candidate_[0-9a-f]{24}", p.name))
        selected = set(available)
        if args.candidate:
            selected = set()
            for requested in args.candidate:
                cid = candidate_id(requested) if requested in snapshot.functions else requested
                if cid not in available:
                    raise ValueError("--candidate must identify one existing project Slice")
                selected.add(cid)
        anchors = {snapshot.anchor_for_candidate(cid) for cid in available} - {None}
        legacy, manifest = load_legacy_inputs(store, anchors, enabled=False)
        records = []
        for cid in available:
            anchor = snapshot.anchor_for_candidate(cid)
            source = load_slice_input(store, cid, legacy=legacy.get(anchor, {}))
            configuration = build_configuration(source, snapshot, manifest, compare_legacy=False)
            doc = source.document
            core = doc.get("core_functions", [])
            if not isinstance(core, list):
                core = []
            ft_id = stable_ft_id(anchor or "unknown", [fid for fid in core if isinstance(fid, str)],
                anchor_name=snapshot.functions[anchor]["name"] if anchor else "anchor")
            cached = load_compatible_build(store, ft_id, configuration, source, snapshot)
            if cid not in selected:
                if cached:
                    records.append(_catalog_record(cached))
                continue
            if args.resume and cached:
                document = cached
                resumed += 1
            else:
                build = MinimalFTBuilder().build(source, snapshot, compare_legacy=False)
                save_build(store, build, configuration)
                document = build.minimal_ft
                processed += 1
            invalid += document["build_status"] == "invalid"
            records.append(_catalog_record(document))
            # Each completed pair is indexed immediately for interruption recovery.
            write_catalog(store, records)
            print(f"[MINIMAL FT] {cid}: {document['build_status']} core={len(document['core_functions'])} "
                  f"support_candidates={len(document['support_candidates'])}", flush=True)
        write_catalog(store, records)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"Minimal FT failed: {error}", file=sys.stderr)
        return 1
    print(f"[MINIMAL FT] processed={processed} resumed={resumed} invalid={invalid} "
          f"llm_calls=0 repository_rescans=0 wrote={store.minimal_ft_catalog}")
    return int(bool(invalid))


def _catalog_record(document):
    return {"ft_id": document["ft_id"], "candidate_id": document["candidate_id"],
            "anchor_function_id": document["anchor_function_id"], "status": document["build_status"],
            "path": f"{document['ft_id']}/minimal_ft.json", "source_slice": document["source_slice"]}


if __name__ == "__main__":
    raise SystemExit(main())
