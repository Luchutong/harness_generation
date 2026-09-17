import json
from pathlib import Path
import tempfile
import unittest

from sfg_builder.candidates import CandidateDetector
from sfg_builder.mock import MockSemanticAnalyzer
from sfg_builder.parser import CProjectParser
from sfg_builder.roles import FunctionRoleAnnotator, write_annotations_json


PROJECT = Path(__file__).parent / "fixtures/simple_project"


class RecordingAnalyzer(MockSemanticAnalyzer):
    def __init__(self):
        self.stream_calls = []
        self.role_calls = []
        self.direction_calls = []

    def classify_stream_parameter(self, function, parameter, structs, variant):
        self.stream_calls.append((function.name, parameter.name, variant))
        return super().classify_stream_parameter(function, parameter, structs, variant)

    def classify_function_role(self, function, structs):
        self.role_calls.append(function.name)
        return super().classify_function_role(function, structs)

    def infer_struct_direction(self, *args):
        self.direction_calls.append(args)
        raise AssertionError("role annotation must not infer struct direction")


class BrokenAnalyzer:
    def classify_stream_parameter(self, *args):
        raise TimeoutError("private stream failure")

    def classify_function_role(self, *args):
        raise ValueError("private role failure")

    def infer_struct_direction(self, *args):
        raise AssertionError("direction analysis is out of scope")


class FunctionRoleAnnotationTests(unittest.TestCase):
    def setUp(self):
        self.parsed = CProjectParser().parse(PROJECT)
        self.candidates = CandidateDetector().detect(self.parsed.functions)

    def test_mock_assigns_isf_prf_hpf_and_allows_multiple_labels(self):
        analyzer = RecordingAnalyzer()
        annotations = FunctionRoleAnnotator(analyzer).annotate(
            self.parsed.functions, self.candidates, self.parsed.structs)
        by_name = {annotation.function: annotation for annotation in annotations}
        self.assertEqual(by_name["parser_from_memory"].labels, ("ISF", "HPF"))
        self.assertEqual(by_name["parser_next"].labels, ("PRF",))
        self.assertEqual(by_name["node_process"].labels, ("PRF",))
        self.assertEqual(by_name["parser_free"].labels, ("HPF",))
        self.assertTrue(all(annotation.struct_directions == ()
                            for annotation in annotations))
        self.assertEqual(len(analyzer.stream_calls), 3)
        self.assertEqual(set(analyzer.role_calls), set(by_name))
        self.assertEqual(analyzer.direction_calls, [])

    def test_semantic_calls_only_match_candidate_kinds(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / "stream.c").write_text(
                "int consume(const uint8_t *data) { return data[0]; }\n")
            parsed = CProjectParser().parse(project)
        candidates = CandidateDetector().detect(parsed.functions)
        analyzer = RecordingAnalyzer()
        annotations = FunctionRoleAnnotator(analyzer).annotate(
            parsed.functions, candidates, parsed.structs)
        self.assertEqual(annotations[0].labels, ("ISF",))
        self.assertEqual(len(analyzer.stream_calls), 3)
        self.assertEqual(analyzer.role_calls, [])
        self.assertEqual(annotations[0].reason, "not a struct-related candidate")

    def test_failures_are_recorded_and_do_not_abort_annotation(self):
        annotations = FunctionRoleAnnotator(BrokenAnalyzer()).annotate(
            self.parsed.functions, self.candidates, self.parsed.structs)
        parse = next(annotation for annotation in annotations
                     if annotation.function == "parser_from_memory")
        self.assertEqual(parse.labels, ())
        self.assertEqual(parse.operation, "other")
        self.assertEqual(parse.reason, "semantic analyzer failed")
        self.assertEqual(len(parse.decisions), 4)
        self.assertTrue(all(decision.status == "error" for decision in parse.decisions))
        self.assertTrue(all("private" not in (decision.error or "")
                            for decision in parse.decisions))

    def test_annotations_json_contains_labels_and_audit_records(self):
        annotations = FunctionRoleAnnotator(MockSemanticAnalyzer()).annotate(
            self.parsed.functions, self.candidates, self.parsed.structs)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifacts" / "annotations.json"
            written = write_annotations_json(annotations, path)
            payload = json.loads(path.read_text())
        self.assertEqual(written, path)
        parse = next(annotation for annotation in payload["annotations"]
                     if annotation["function"] == "parser_from_memory")
        self.assertEqual(parse["labels"], ["ISF", "HPF"])
        self.assertFalse(parse["is_prf"])
        self.assertTrue(parse["is_hpf"])
        self.assertEqual(parse["struct_directions"], [])
        self.assertEqual(len(parse["decisions"]), 4)
        for decision in parse["decisions"]:
            self.assertEqual(decision["function"], "parser_from_memory")
            self.assertEqual(decision["file"], "src/parser.c")
            self.assertIsInstance(decision["line"], int)
            self.assertIn(decision["task"], {"stream_parameter", "function_role"})
            self.assertTrue(decision["prompt_version"])
            self.assertIsInstance(decision["response"], dict)
            self.assertIsInstance(decision["confidence"], (int, float))
        role = next(decision for decision in parse["decisions"]
                    if decision["task"] == "function_role")
        self.assertEqual(role["response"]["is_hpf"], True)
        self.assertIn("operation", role["response"])


if __name__ == "__main__":
    unittest.main()
