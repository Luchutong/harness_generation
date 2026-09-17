import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from sfg_builder.cli import main
from sfg_builder.graph import FlowBuilder, SFGBuilder, to_dot
from sfg_builder.analysis import FunctionAnnotator
from sfg_builder.candidates import CandidateDetector
from sfg_builder.parser import CProjectParser
from sfg_builder.semantic import MockSemanticAnalyzer
from sfg_builder.models import FunctionFlow, StructInfo


PROJECT = Path(__file__).parent / "fixtures/simple_project"


class GraphTests(unittest.TestCase):
    def build(self):
        parsed = CProjectParser().parse(PROJECT)
        candidates = CandidateDetector().detect(parsed.functions)
        annotations = FunctionAnnotator(MockSemanticAnalyzer()).annotate(
            parsed.functions, candidates, parsed.structs)
        flows = FlowBuilder().build(parsed.functions, annotations)
        return parsed, flows, SFGBuilder().build(parsed.structs, flows)

    def test_expected_reference_edges(self):
        _, flows, graph = self.build()
        edges = {(edge.source, edge.function, edge.target): edge for edge in graph.edges}
        self.assertIn(("(null)", "parser_from_memory", "Parser"), edges)
        self.assertIn(("Parser", "parser_next", "Node"), edges)
        self.assertIn(("Node", "node_process", "(null)"), edges)
        self.assertIn(("Parser", "parser_free", "(null)"), edges)
        self.assertEqual(edges[("(null)", "parser_from_memory", "Parser")].labels,
                         ("ISF", "HPF"))
        process = next(flow for flow in flows if flow.function == "node_process")
        self.assertTrue(any("BOTH" in warning for warning in process.warnings))
        dot = to_dot(graph)
        self.assertIn('"Parser" -> "Node" [label="parser_next [PRF]"]', dot)

    def test_cli_writes_all_audit_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "sfg"
            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--project", str(PROJECT), "--output", str(output)]), 0)
            expected = {"functions.json", "candidates.json", "annotations.json",
                        "flows.json", "sfg.json", "sfg.dot"}
            self.assertEqual({path.name for path in output.iterdir()}, expected)
            graph = json.loads((output / "sfg.json").read_text())
            self.assertEqual(len(graph["nodes"]), 3)
            self.assertEqual(len(graph["edges"]), 4)
            annotations = json.loads((output / "annotations.json").read_text())["annotations"]
            parse = next(item for item in annotations if item["function"] == "parser_from_memory")
            self.assertEqual(parse["labels"], ["ISF", "HPF"])
            self.assertEqual(len(parse["decisions"]), 5)
            self.assertIn("Parsed functions: 4", stdout.getvalue())

    def test_complex_flow_edges_are_explicitly_inferred(self):
        structs = tuple(StructInfo(name, (name,), "", "types.h", 1, 1)
                        for name in ("A", "B", "C", "D"))
        flow = FunctionFlow("id", "combine", ("PRF",), ("A", "B"), ("C", "D"),
                            (), "combine.c", 9, True, ("complex fixture",))
        graph = SFGBuilder().build(structs, (flow,))
        self.assertEqual(len(graph.edges), 4)
        self.assertTrue(all(edge.inferred for edge in graph.edges))
        self.assertTrue(all(
            (edge.inference_reason or "").startswith(
                "engineering choice, not specified by SynapseFlow Phase 1"
            )
            for edge in graph.edges
        ))


if __name__ == "__main__":
    unittest.main()
