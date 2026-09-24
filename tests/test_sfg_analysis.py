from pathlib import Path
import tempfile
import unittest

from sfg_builder.analysis import FunctionAnnotator
from sfg_builder.candidates import CandidateDetector
from sfg_builder.parser import CProjectParser
from sfg_builder.semantic import LLMSemanticAnalyzer, MockSemanticAnalyzer, SemanticError


PROJECT = Path(__file__).parent / "fixtures/simple_project"


class BrokenSemanticAnalyzer:
    def classify_stream_parameter(self, *args):
        raise TimeoutError("private transport detail")

    def classify_function_role(self, *args):
        raise ValueError("bad JSON with secret")

    def infer_struct_direction(self, *args):
        raise RuntimeError("unavailable")


class OneStreamVoteFails(MockSemanticAnalyzer):
    def classify_stream_parameter(self, function, parameter, structs, variant):
        if variant == "direct":
            raise TimeoutError
        return super().classify_stream_parameter(function, parameter, structs, variant)


class AnnotationTests(unittest.TestCase):
    def setUp(self):
        parsed = CProjectParser().parse(PROJECT)
        candidates = CandidateDetector().detect(parsed.functions)
        self.parsed = parsed
        self.candidates = candidates

    def test_mock_annotations_and_directions(self):
        annotations = {item.function: item for item in
                       FunctionAnnotator(MockSemanticAnalyzer()).annotate(
                           self.parsed.functions, self.candidates, self.parsed.structs)}
        self.assertEqual(annotations["parser_from_memory"].labels, ("ISF", "HPF"))
        stream = annotations["parser_from_memory"].stream_parameters[0]
        self.assertTrue(stream.is_byte_stream)
        self.assertEqual(stream.positive_votes, 3)
        self.assertEqual(annotations["parser_from_memory"].struct_directions[0].direction, "output")
        self.assertEqual(annotations["parser_next"].labels, ("PRF",))
        self.assertEqual(annotations["parser_next"].struct_directions[0].direction, "input")
        self.assertEqual(annotations["node_process"].labels, ("PRF",))
        self.assertEqual(annotations["node_process"].struct_directions[0].direction, "both")
        self.assertEqual(annotations["parser_free"].labels, ("HPF",))
        self.assertEqual(annotations["parser_free"].struct_directions[0].direction, "input")
        self.assertEqual(len(annotations["parser_from_memory"].decisions), 5)
        stream_prompts = [decision.prompt for decision in
                          annotations["parser_from_memory"].decisions
                          if decision.task == "stream_parameter"]
        self.assertEqual(len(set(stream_prompts)), 3)

    def test_semantic_errors_are_recorded_and_do_not_escape(self):
        annotations = FunctionAnnotator(BrokenSemanticAnalyzer()).annotate(
            self.parsed.functions, self.candidates, self.parsed.structs)
        parse = next(item for item in annotations if item.function == "parser_from_memory")
        errors = [decision for decision in parse.decisions if decision.status == "error"]
        self.assertEqual(len(errors), 4)
        self.assertTrue(all("private" not in (decision.error or "") for decision in errors))
        self.assertFalse(parse.stream_parameters[0].is_byte_stream)
        # The AST write hint resolves direction without a semantic request.
        self.assertEqual(parse.struct_directions[0].direction, "output")

    def test_two_valid_positive_votes_survive_one_failed_variant(self):
        annotations = FunctionAnnotator(OneStreamVoteFails()).annotate(
            self.parsed.functions, self.candidates, self.parsed.structs)
        parse = next(item for item in annotations if item.function == "parser_from_memory")
        stream = parse.stream_parameters[0]
        self.assertTrue(stream.is_byte_stream)
        self.assertEqual((stream.positive_votes, stream.valid_votes), (2, 2))

    def test_llm_adapter_accepts_only_strict_structured_json(self):
        function = next(item for item in self.parsed.functions
                        if item.name == "parser_from_memory")
        parameter = function.parameters[1]

        def valid_transport(_payload):
            return {"choices": [{"finish_reason": "stop", "message": {"content":
                '{"is_byte_stream":true,"kind":"binary","confidence":0.8,"reason":"bytes"}'}}]}

        decision = LLMSemanticAnalyzer(valid_transport, "test").classify_stream_parameter(
            function, parameter, (), "yes_no")
        self.assertTrue(decision.data["is_byte_stream"])
        invalid = LLMSemanticAnalyzer(lambda _: {"choices": []}, "test")
        with self.assertRaises(SemanticError):
            invalid.classify_stream_parameter(function, parameter, (), "direct")

    def test_filename_pointer_is_candidate_but_not_isf(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / "file.c").write_text(
                'int open_file(const char *filename) { return filename != 0; }\n')
            parsed = CProjectParser().parse(project)
        candidates = CandidateDetector().detect(parsed.functions)
        self.assertTrue(candidates[0].isf_candidate)
        annotation = FunctionAnnotator(MockSemanticAnalyzer()).annotate(
            parsed.functions, candidates, parsed.structs)[0]
        self.assertNotIn("ISF", annotation.labels)
        self.assertEqual(annotation.stream_parameters[0].kind, "filename")

    def test_parser_value_parameter_is_stream_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / "parser.c").write_text(
                """
                typedef struct Node { int type; } Node;
                Node *parse_value(const char *value, size_t buffer_length,
                                  const char **return_parse_end) {
                    (void)return_parse_end;
                    return value && buffer_length ? (Node *)value : 0;
                }
                """
            )
            parsed = CProjectParser().parse(project)
        candidates = CandidateDetector().detect(parsed.functions)
        annotation = FunctionAnnotator(MockSemanticAnalyzer()).annotate(
            parsed.functions, candidates, parsed.structs)[0]
        streams = {item.parameter: item for item in annotation.stream_parameters}
        self.assertIn("ISF", annotation.labels)
        self.assertTrue(streams["value"].is_byte_stream)
        self.assertFalse(streams["return_parse_end"].is_byte_stream)


if __name__ == "__main__":
    unittest.main()
