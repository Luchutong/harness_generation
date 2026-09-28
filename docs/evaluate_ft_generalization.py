"""Offline evidence collection for FT_GENERALIZATION_REPORT.md.

Run from any directory with the repository's virtualenv Python. No provider is
contacted; historical model output is evidence, not a new model experiment.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness_generation.ft_selection import build_selection_manifest, rank_triplets
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.triplet_extractor import FunctionTripletExtractor
from sfg_builder.base import SemanticDecision
from sfg_builder.candidates import CandidateDetector
from sfg_builder.directions import needs_semantic_direction
from sfg_builder.mock import MockSemanticAnalyzer
from sfg_builder.parser import CProjectParser, DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.prompts import STREAM_PROMPT_VERSION, stream_prompt


class PositiveStreamOracle(MockSemanticAnalyzer):
    """Approve every static byte candidate to isolate deterministic gates.

    Roles/directions and usage review use the built-in mock. This oracle is
    intentionally unsuitable for estimating a real model's precision/recall.
    """
    semantic_backend = "controlled_oracle"

    def classify_stream_parameter(self, function, parameter, structs, variant):
        data = {"is_byte_stream": True, "kind": "binary", "confidence": 1.0,
                "reason": "controlled positive stream oracle"}
        return SemanticDecision(data, stream_prompt(function, parameter, structs, variant),
                                STREAM_PROMPT_VERSION, data, 1.0)


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def revision(path):
    result = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"],
                            capture_output=True, text=True)
    return result.stdout.strip() if result.returncode == 0 else None


def summarize_triplet(triplet, annotations):
    score = rank_triplets((triplet,), annotations)[0]
    return {"anchor": triplet.isf.function, "id": triplet.id,
            "functions": [f.function for f in triplet.functions],
            "structures": list(triplet.structures),
            "edges": [{"src": e.src, "dst": e.dst, "function": e.function}
                      for e in triplet.edges],
            "bindings": [dict(s.metadata) for s in triplet.bypass_semantics
                         if s.kind == "fuzzer_input_binding"],
            "ownership": [r.to_dict() for r in triplet.ownership_relations],
            "authority": dict(triplet.metadata.get("authority", {})),
            "eligible": score.eligible, "exclusions": list(score.exclusion_reasons),
            "score": score.score, "units": score.structural_units,
            "estimated_calls": score.estimated_llm_calls}


def fixture(name, files, *, paper_minimal=False, limit=20):
    with tempfile.TemporaryDirectory(prefix="ft-generalization-") as temp:
        root = Path(temp) / "project"
        output = Path(temp) / "artifacts"
        root.mkdir()
        for relative, source in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source, encoding="utf-8")
        run = SFGPipeline(PositiveStreamOracle(), ignored_directories=DEFAULT_IGNORES,
                          paper_minimal=paper_minimal).run(root, output)
        loaded = load_sfg_artifacts(output)
        extractor = FunctionTripletExtractor()
        triplets = extractor.extract(loaded, paper_minimal=paper_minimal,
                                     max_functions_per_ft=limit)
        return {"name": name, "paper_minimal": paper_minimal,
                "sources": files, "parsed_files": list(run.parsed.files),
                "parse_warnings": list(run.parsed.warnings),
                "structs": [s.to_dict() for s in run.parsed.structs],
                "candidates": [c.to_dict() for c in run.candidates],
                "annotations": [{"function": a.function, "labels": list(a.labels)}
                                for a in run.annotations],
                "graph_warnings": list(run.graph.warnings),
                "ownership_count": len(run.ownership),
                "usage_patterns": [p.to_dict() for p in run.usage.patterns],
                "triplets": [summarize_triplet(t, loaded.annotations) for t in triplets],
                "excluded": extractor.exclusions}


def collect_probes():
    ctx = "typedef struct Context { int initialized; int value; } Context;\n"
    char_feed = "int feed(Context *c, const char *data, unsigned long len) { return c->value + (len ? data[0] : 0); }\n"
    probes = []
    cases = [
        ("char_len", ctx + char_feed),
        ("void_len", ctx + "int feed(Context *c, const void *data, unsigned long len) { return c->value + (len ? ((const char*)data)[0] : 0); }"),
        ("void_count", ctx + "int feed(Context *c, const void *data, unsigned long count) { return c->value + (count ? ((const char*)data)[0] : 0); }"),
        ("void_byte_count", ctx + "int feed(Context *c, const void *data, unsigned long byte_count) { return c->value + (byte_count ? ((const char*)data)[0] : 0); }"),
        ("signed_char_len", ctx + "int feed(Context *c, const signed char *data, unsigned long len) { return c->value + (len ? data[0] : 0); }"),
        ("char_array_len", ctx + "int feed(Context *c, const char data[], unsigned long len) { return c->value + (len ? data[0] : 0); }"),
        ("path_named_bytes", ctx + "int feed(Context *c, const char *path, unsigned long len) { return c->value + (len ? path[0] : 0); }"),
        ("two_streams", ctx + "int feed(Context *c, const char *header, unsigned long header_len, const char *body, unsigned long len) { return c->value + (header_len ? header[0] : 0) + (len ? body[0] : 0); }"),
        ("in_place_init", ctx + "void context_init(Context *c) { c->initialized=1; c->value=0; }\n" + char_feed),
    ]
    for name, source in cases:
        probes.append(fixture(name, {"api.c": source}))
    scalar = "int parse(const char *data, unsigned long len) { return len ? data[0] : 0; }"
    probes.append(fixture("scalar_default", {"api.c": scalar}))
    probes.append(fixture("scalar_paper_minimal", {"api.c": scalar}, paper_minimal=True))
    probes.append(fixture("cpp_suffix", {"api.cpp": ctx + char_feed}))
    probes.append(fixture("independent_same_tag", {
        "a.c": "typedef struct State { int a; } State; int feed_a(State *s, const char *data, unsigned long len) { return s->a + (len ? data[0] : 0); } int inspect_a(State *s) { return s->a; }",
        "b.c": "typedef struct State { double b; } State; int inspect_b(State *s) { return s->b != 0; }",
    }))
    fanout = ctx + char_feed + "\n" + "\n".join(
        f"int inspect_{i}(Context *c) {{ return c->value + {i}; }}" for i in range(21))
    probes.append(fixture("same_type_fanout", {"api.c": fanout}))
    opaque = "typedef struct Hidden *Handle;\nint handle_open(Handle *out) { *out=(Handle)1; return 0; }\nint handle_feed(Handle h, const char *data, unsigned long len) { return h && (len ? data[0] : 0); }\nvoid handle_close(Handle h) { (void)h; }\n"
    probes.append(fixture("out_parameter_without_caller", {"api.c": opaque}))
    probes.append(fixture("out_parameter_with_caller", {"api.c": opaque + "int example(const char *data, unsigned long len) { Handle h; if (handle_open(&h)) return -1; int r=handle_feed(h,data,len); handle_close(h); return r; }"}))
    # A documented return-value producer/release pair provides a positive
    # lifecycle control with no caller trace, unlike the out-parameter pair.
    owned = "typedef struct Hidden *Handle;\nHandle handle_create(void) { return (Handle)malloc(8); }\nint handle_feed(Handle h, const char *data, unsigned long len) { return h && (len ? data[0] : 0); }\nvoid handle_free(Handle h) { free(h); }"
    probes.append(fixture("owned_return_pair", {"api.c": owned}))
    return probes


def source_census(name, path):
    if not path.is_dir():
        return {"project": name, "available": False, "path": str(path)}
    start = time.monotonic()
    parsed = CProjectParser().parse(path)
    definitions = tuple(f for f in parsed.functions if f.defined)
    candidates = CandidateDetector().detect(definitions)
    candidate_ids = {c.function_id for c in candidates}
    paper_ids = {c.function_id for c in candidates if c.struct_related_candidate}

    def requests(ids):
        return sum(3 * len(c.stream_parameters) + int(c.struct_related_candidate)
                   for c in candidates if c.function_id in ids) + sum(
                       needs_semantic_direction(p, next((h for h in f.access_hints
                                                        if h.parameter == (p.name or "")), None))
                       for f in definitions if f.id in ids for p in f.parameters)
    # Hash only the scanned source set. This captures local changes and does
    # not read credentials or unrelated files in an adjacent workspace.
    digest = hashlib.sha256()
    for relative in parsed.files:
        digest.update(relative.encode() + b"\0")
        digest.update((path / relative).read_bytes())
    entries = []
    for f in definitions:
        if f.name in {"json_parse", "json_parse_ex", "XML_Parse", "XML_ParseBuffer",
                      "XML_ParserCreate", "xmlReadMemory", "xmlParseMemory"}:
            entries.append({"name": f.name, "stream_candidate": any(
                c.function_id == f.id and c.isf_candidate for c in candidates),
                "parameters": [p.to_dict() for p in f.parameters]})
    return {"project": name, "available": True, "path": str(path.resolve()),
            "revision": revision(path), "source_sha256": digest.hexdigest(),
            "files": len(parsed.files), "functions": len(parsed.functions),
            "definitions": len(definitions), "structs": len(parsed.structs),
            "opaque_handles": len(parsed.opaque_handles),
            "warning_files": len(parsed.warnings), "warnings": list(parsed.warnings),
            "candidates": len(candidates),
            "stream_candidates": sum(c.isf_candidate for c in candidates),
            "minimum_semantic_requests_default": requests(candidate_ids),
            "minimum_semantic_requests_paper_minimal": requests(paper_ids),
            "entrypoints": entries, "seconds": round(time.monotonic() - start, 3)}


def historical_summary(directory):
    if not directory.is_dir():
        return {"directory": str(directory.relative_to(ROOT)), "available": False}
    row = {"directory": str(directory.relative_to(ROOT)), "available": True}
    for filename, key in [("functions.json", "functions"), ("annotations.json", "annotations"),
                          ("usage_patterns.json", "patterns"), ("ownership.json", "relations")]:
        path = directory / filename
        if not path.exists():
            continue
        doc = read_json(path)
        row[filename] = {"count": len(doc.get(key, []))}
        if filename == "functions.json":
            row[filename].update(definitions=sum(f.get("defined") is True for f in doc[key]),
                                 files=len(doc.get("files", [])), warnings=len(doc.get("warnings", [])))
        if filename == "annotations.json":
            row[filename].update(backend=doc.get("semantic_backend"), source=doc.get("semantic_source"),
                                 roles=dict(Counter(l for a in doc[key] for l in a.get("labels", []))),
                                 statuses=dict(Counter(t.get("status") for a in doc[key] for t in a.get("decisions", []))),
                                 versions=dict(Counter(t.get("prompt_version") for a in doc[key] for t in a.get("decisions", []))))
    catalog = directory / "triplets.json"
    if catalog.exists():
        row["catalog_bytes"] = catalog.stat().st_size
    selection = directory / "ft_selection.json"
    if selection.exists():
        doc = read_json(selection)
        row["selection"] = {"policy": doc.get("policy_version"), "constraints": doc["constraints"],
                            "summary": doc["summary"], "first_selected": doc["selection"][:3],
                            "footprint_sizes": dict(Counter(len(r["footprint"]["function_ids"])
                                                           for r in doc["ranking"])),
                            "exclusions": dict(Counter(x for r in doc["ranking"] for x in r["exclusion_reasons"]))}
    row["pipeline_results"] = [{"path": str(p.relative_to(ROOT)), "document": read_json(p)}
                               for p in sorted(directory.glob("generation/*/pipeline_result.json"))]
    row["stage4_outcomes"] = [{"path": str(p.relative_to(ROOT)), "document": read_json(p)}
                              for p in sorted(directory.glob("generation/*/stage4/attempt_*/outcome.json"))]
    return row


def reextract(directory):
    if not (directory / "sfg.json").exists():
        return {"directory": str(directory.relative_to(ROOT)), "available": False}
    start = time.monotonic()
    loaded = load_sfg_artifacts(directory)
    extractor = FunctionTripletExtractor()
    triplets = extractor.extract(loaded, max_functions_per_ft=20)
    manifest = build_selection_manifest(triplets, loaded.annotations, max_ft=20, max_calls=300,
                                        max_functions=20, max_structural_units=20)
    # Rename absolute project root only; FT identifiers use project-relative
    # source paths. Legacy relative roots also remain valid for this check.
    relocated = replace(loaded, project="/tmp/ft-relocated-project")
    again = FunctionTripletExtractor().extract(relocated, max_functions_per_ft=20)
    return {"directory": str(directory.relative_to(ROOT)),
            "mode": "current_extractor_on_historical_phase1_not_new_model_evaluation",
            "count": len(triplets), "excluded_count": len(extractor.exclusions),
            "excluded_size_histogram": dict(Counter(e["function_count"] for e in extractor.exclusions)),
            "summary": manifest["summary"], "first_selected": manifest["selection"][:3],
            "triplets": [{"id": t.id, "anchor": t.isf.function, "functions": len(t.functions),
                          "units": len(t.structural_steps())} for t in triplets],
            "root_relocation_ids_equal": [t.id for t in triplets] == [t.id for t in again],
            "seconds": round(time.monotonic() - start, 3)}


def main():
    evidence = {"date_utc": datetime.now(timezone.utc).isoformat(), "revision": revision(ROOT),
                "method": "offline static census, historical artifact audit, controlled positive stream oracle",
                "new_provider_requests": 0, "probes": collect_probes()}
    print(f"Controlled probes: {len(evidence['probes'])}", flush=True)
    evidence["source_census"] = []
    for name, path in [("json_parser", ROOT / "benchmarks/json_parser/project"),
                       ("libexpat", ROOT.parent / "libexpat"), ("libxml2", ROOT.parent / "libxml2")]:
        result = source_census(name, path)
        evidence["source_census"].append(result)
        print(f"Census {name}: {result.get('definitions')} definitions", flush=True)
    names = ["json_parser", "json_parser_pre_fix", "libxml2_20260923",
             "libxml2_xmlio_real_phase1_paper_20260924_0930",
             "libxml2_xmlio_real_replayed_20260924_0940",
             "libxml2_xmlio_real_replayed_struct_20260924_0950",
             "libxml2_xmlio_real_replayed_final_20260924_1000", "libxml2_xmlio_stage4_rerun_v10"]
    evidence["historical"] = [historical_summary(ROOT / "artifacts" / name) for name in names]
    evidence["reextraction"] = []
    for name in ["json_parser", "libxml2_xmlio_real_replayed_final_20260924_1000", "libxml2_20260923"]:
        result = reextract(ROOT / "artifacts" / name)
        evidence["reextraction"].append(result)
        print(f"Reextract {name}: {result.get('count')} retained, {result.get('excluded_count')} oversized", flush=True)
    destination = ROOT / "docs/FT_GENERALIZATION_EVIDENCE.json"
    destination.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Evidence: {destination}", flush=True)


if __name__ == "__main__":
    main()
