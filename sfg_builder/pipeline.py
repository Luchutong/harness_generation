"""End-to-end Phase 1 orchestration and auditable artifact persistence."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .analysis import FunctionAnnotator
from .candidates import CandidateDetector, write_candidates_json
from .graph import (FlowBuilder, SFGBuilder, write_flows_json, write_sfg_dot,
                    write_sfg_json)
from .models import (FunctionAnnotation, FunctionCandidate, FunctionFlow,
                     StructuralFlowGraph)
from .parser import CProjectParser, ParseResult, write_functions_json
from .ownership import derive_ownership_relations, write_ownership_json
from .roles import write_annotations_json
from .semantic import SemanticAnalyzer


@dataclass(frozen=True)
class SFGRunResult:
    parsed: ParseResult
    candidates: tuple[FunctionCandidate, ...]
    annotations: tuple[FunctionAnnotation, ...]
    flows: tuple[FunctionFlow, ...]
    graph: StructuralFlowGraph
    ownership: tuple = ()


class SFGPipeline:
    def __init__(self, analyzer: SemanticAnalyzer, *, ignored_directories: tuple[str, ...]):
        self.parser = CProjectParser(ignored_directories)
        self.detector = CandidateDetector()
        self.annotator = FunctionAnnotator(analyzer)
        self.flow_builder = FlowBuilder()
        self.graph_builder = SFGBuilder()

    def run(self, project: Path, output: Path) -> SFGRunResult:
        parsed = self.parser.parse(project)
        candidates = self.detector.detect(parsed.functions)
        annotations = self.annotator.annotate(parsed.functions, candidates, parsed.structs)
        flows = self.flow_builder.build(parsed.functions, annotations)
        graph = self.graph_builder.build(parsed.structs, flows)
        ownership = derive_ownership_relations(parsed.functions)
        output.mkdir(parents=True, exist_ok=True)
        write_functions_json(parsed, output / "functions.json", project=project)
        write_ownership_json(ownership, output / "ownership.json")
        write_candidates_json(candidates, output / "candidates.json")
        write_annotations_json(annotations, output / "annotations.json")
        write_flows_json(flows, output / "flows.json")
        write_sfg_json(graph, output / "sfg.json")
        write_sfg_dot(graph, output / "sfg.dot")
        return SFGRunResult(parsed, candidates, annotations, flows, graph, ownership)
