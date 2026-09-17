import json
from pathlib import Path
import tempfile
import unittest

from sfg_builder.analysis import FunctionAnnotator
from sfg_builder.candidates import CandidateDetector
from sfg_builder.graph import (FlowBuilder, SFGBuilder, write_flows_json,
                               write_sfg_json)
from sfg_builder.mock import MockSemanticAnalyzer
from sfg_builder.models import FunctionFlow, StructInfo
from sfg_builder.parser import CProjectParser


PROJECT = Path(__file__).parent / "fixtures/simple_project"


class FlowAndGraphBuilderTests(unittest.TestCase):
    def setUp(self):
        self.parsed = CProjectParser().parse(PROJECT)
        candidates = CandidateDetector().detect(self.parsed.functions)
        annotations = FunctionAnnotator(MockSemanticAnalyzer()).annotate(
            self.parsed.functions, candidates, self.parsed.structs)
        self.flows = FlowBuilder().build(self.parsed.functions, annotations)
        self.graph = SFGBuilder().build(self.parsed.structs, self.flows)

    def test_function_flows_preserve_labels_parameters_and_source(self):
        flows = {flow.function: flow for flow in self.flows}
        parse = flows["parser_from_memory"]
        self.assertEqual(parse.labels, ("ISF", "HPF"))
        self.assertEqual(parse.input_structs, ())
        self.assertEqual(parse.output_structs, ("Parser",))
        self.assertEqual(parse.parameters[0].name, "parser")
        self.assertEqual(parse.file, "src/parser.c")
        self.assertGreater(parse.line, 0)
        serialized = parse.to_dict()
        self.assertEqual(serialized["source"], {"file": "src/parser.c", "line": parse.line})

        next_flow = flows["parser_next"]
        self.assertEqual(next_flow.input_structs, ("Parser",))
        self.assertEqual(next_flow.output_structs, ("Node",))
        self.assertEqual(flows["parser_free"].output_structs, ())

    def test_graph_has_unique_struct_and_null_nodes_and_endpoint_rules(self):
        node_ids = [node.id for node in self.graph.nodes]
        self.assertEqual(node_ids.count("(null)"), 1)
        self.assertEqual(set(node_ids), {"(null)", "Parser", "Node"})
        self.assertEqual(len(node_ids), len(set(node_ids)))
        edges = {(edge.source, edge.function, edge.target): edge
                 for edge in self.graph.edges}
        self.assertIn(("(null)", "parser_from_memory", "Parser"), edges)
        self.assertIn(("Parser", "parser_next", "Node"), edges)
        self.assertIn(("Parser", "parser_free", "(null)"), edges)
        edge = edges[("Parser", "parser_next", "Node")]
        self.assertEqual(edge.labels, ("PRF",))
        self.assertEqual(edge.file, "src/parser.c")
        self.assertGreater(edge.line, 0)
        self.assertFalse(edge.inferred)
        self.assertIsNone(edge.inference_reason)

    def test_complex_flow_is_explicitly_inferred_and_warned(self):
        structs = tuple(StructInfo(name, (name,), "", "types.h", 1, 1)
                        for name in ("A", "B", "C", "D"))
        flow = FunctionFlow(
            "combine-id", "combine", ("PRF",), ("A", "B"), ("C", "D"), (),
            "combine.c", 17, True,
            ("combine: multiple struct inputs/outputs use inferred Cartesian candidate edges",),
        )
        graph = SFGBuilder().build(structs, (flow,))
        self.assertEqual(
            {(edge.source, edge.target) for edge in graph.edges},
            {("A", "C"), ("A", "D"), ("B", "C"), ("B", "D")},
        )
        self.assertTrue(all(edge.inferred for edge in graph.edges))
        self.assertTrue(all(edge.inference_reason for edge in graph.edges))
        self.assertTrue(all(
            edge.inference_reason.startswith(
                "engineering choice, not specified by SynapseFlow Phase 1"
            )
            for edge in graph.edges
        ))
        self.assertTrue(any("Cartesian" in warning for warning in graph.warnings))

    def test_flow_builder_marks_multiple_inputs_and_outputs_complex(self):
        source = r'''
typedef struct A { int value; } A;
typedef struct B { int value; } B;
typedef struct C { int value; } C;
typedef struct D { int value; } D;
void combine(A *a, B *b, C *c, D *d) {
    c->value = a->value;
    d->value = b->value;
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / "combine.c").write_text(source)
            parsed = CProjectParser().parse(project)
        candidates = CandidateDetector().detect(parsed.functions)
        annotations = FunctionAnnotator(MockSemanticAnalyzer()).annotate(
            parsed.functions, candidates, parsed.structs)
        flow = FlowBuilder().build(parsed.functions, annotations)[0]
        self.assertEqual(flow.input_structs, ("A", "B"))
        self.assertEqual(flow.output_structs, ("C", "D"))
        self.assertTrue(flow.complex_flow)
        self.assertTrue(any("Cartesian" in warning for warning in flow.warnings))
        graph = SFGBuilder().build(parsed.structs, (flow,))
        self.assertEqual(len(graph.edges), 4)
        self.assertTrue(all(edge.inferred for edge in graph.edges))

    def test_graph_builder_never_silently_cartesianizes_unmarked_flow(self):
        structs = tuple(StructInfo(name, (name,), "", "types.h", 1, 1)
                        for name in ("A", "B", "C"))
        flow = FunctionFlow(
            "legacy-id", "legacy", ("PRF",), ("A", "B"), ("C",), (),
            "legacy.c", 5,
        )
        graph = SFGBuilder().build(structs, (flow,))
        self.assertTrue(graph.functions[0].complex_flow)
        self.assertTrue(all(edge.inferred for edge in graph.edges))
        self.assertTrue(all(edge.inference_reason for edge in graph.edges))
        self.assertTrue(any("normalized" in warning for warning in graph.warnings))

    def test_flows_and_sfg_json_are_written_independently(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifacts"
            flows_path = write_flows_json(self.flows, output / "flows.json")
            graph_path = write_sfg_json(self.graph, output / "sfg.json")
            flows = json.loads(flows_path.read_text())
            graph = json.loads(graph_path.read_text())
        self.assertEqual(flows["schema_version"], 1)
        self.assertEqual(len(flows["flows"]), 4)
        self.assertIn("source", flows["flows"][0])
        self.assertEqual(graph["schema_version"], 1)
        self.assertEqual(len(graph["nodes"]), 3)
        self.assertEqual(len(graph["edges"]), 4)
        self.assertEqual(len(graph["functions"]), 4)


if __name__ == "__main__":
    unittest.main()
