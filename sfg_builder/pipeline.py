"""End-to-end Phase 1 orchestration and auditable artifact persistence."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .analysis import FunctionAnnotator
from .directions import needs_semantic_direction
from .candidates import CandidateDetector, write_candidates_json
from .graph import (FlowBuilder, SFGBuilder, write_flows_json, write_sfg_dot,
                    write_sfg_json)
from .models import (FunctionAnnotation, FunctionCandidate, FunctionFlow,
                     StructuralFlowGraph)
from .parser import CProjectParser, ParseResult, write_functions_json
from .ownership import derive_ownership_relations, write_ownership_json
from .roles import write_annotations_json
from .semantic import SemanticAnalyzer
from .usage import UsageMiningResult, mine_usage_patterns, write_usage_json
from .usage_semantics import review_usage_semantics


@dataclass(frozen=True)
class SFGRunResult:
    parsed: ParseResult
    candidates: tuple[FunctionCandidate, ...]
    annotations: tuple[FunctionAnnotation, ...]
    flows: tuple[FunctionFlow, ...]
    graph: StructuralFlowGraph
    ownership: tuple = ()
    usage: UsageMiningResult | None = None


class SFGPipeline:
    def __init__(
        self,
        analyzer: SemanticAnalyzer,
        *,
        ignored_directories: tuple[str, ...],
        source_globs: tuple[str, ...] = (),
        max_semantic_requests: int | None = None,
        paper_minimal: bool = False,
    ):
        self.analyzer = analyzer
        self.parser = CProjectParser(
            ignored_directories, source_globs=source_globs
        )
        self.detector = CandidateDetector()
        self.max_semantic_requests = max_semantic_requests
        self.paper_minimal = paper_minimal
        self.annotator = FunctionAnnotator(analyzer)
        self.flow_builder = FlowBuilder()
        self.graph_builder = SFGBuilder()

    def run(self, project: Path, output: Path) -> SFGRunResult:
        parsed = self.parser.parse(project)
        # Declarations remain in functions.json for type resolution, but only
        # definitions have a body to support semantic and graph analysis.
        definitions = tuple(function for function in parsed.functions if function.defined)
        candidates = self.detector.detect(definitions)
        if self.paper_minimal:
            # An ISF must connect byte input to an internal structure in the
            # paper's SFG. A stream-only function has no representable FT flow.
            candidates = tuple(candidate for candidate in candidates
                               if candidate.struct_related_candidate)
        if (getattr(self.analyzer, "semantic_backend", None) == "llm"
                and self.max_semantic_requests is not None):
            by_id = {function.id: function for function in definitions}
            minimum_requests = sum(
                3 * len(candidate.stream_parameters)
                + int(candidate.struct_related_candidate)
                for candidate in candidates
            )
            minimum_requests += sum(
                needs_semantic_direction(
                    parameter,
                    next((hint for hint in function.access_hints
                          if hint.parameter == (parameter.name or "")), None),
                )
                for candidate in candidates
                for function in (by_id[candidate.function_id],)
                for parameter in function.parameters
            )
            if minimum_requests > self.max_semantic_requests:
                raise ValueError(
                    f"Phase 1 needs at least {minimum_requests} semantic requests "
                    f"for {len(candidates)} defined candidates; limit is "
                    f"{self.max_semantic_requests}. Narrow --source-glob or "
                    "raise --max-semantic-requests"
                )
        annotations = self.annotator.annotate(parsed.functions, candidates, parsed.structs)
        flows = self.flow_builder.build(parsed.functions, annotations)
        graph = self.graph_builder.build(parsed.structs, flows)
        ownership = derive_ownership_relations(
            parsed.functions,
            opaque_resource_types=(handle.name for handle in parsed.opaque_handles),
            struct_resource_types=(info.name for info in parsed.structs),
        )
        usage = (UsageMiningResult((), ()) if self.paper_minimal else
                 review_usage_semantics(
                     mine_usage_patterns(parsed.functions),
                     parsed.functions,
                     annotations,
                     self.analyzer,
                 ))
        output.mkdir(parents=True, exist_ok=True)
        write_functions_json(parsed, output / "functions.json", project=project)
        write_ownership_json(ownership, output / "ownership.json")
        write_usage_json(usage, output / "usage_patterns.json")
        write_candidates_json(candidates, output / "candidates.json")
        write_annotations_json(
            annotations, output / "annotations.json",
            semantic_backend=getattr(self.analyzer, "semantic_backend", "custom"),
            semantic_source=getattr(self.analyzer, "semantic_source", None),
        )
        write_flows_json(flows, output / "flows.json")
        write_sfg_json(graph, output / "sfg.json")
        write_sfg_dot(graph, output / "sfg.dot")
        return SFGRunResult(parsed, candidates, annotations, flows, graph, ownership, usage)
