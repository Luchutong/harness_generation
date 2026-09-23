from pathlib import Path
import json
import unittest

from sfg_builder.analysis import FunctionAnnotator
from sfg_builder.candidates import CandidateDetector
from sfg_builder.client import LLMSemanticAnalyzer
from sfg_builder.parser import CProjectParser
from sfg_builder.prompts import STREAM_VARIANTS, stream_prompt
from sfg_builder.semantic import MockSemanticAnalyzer, SemanticDecision, SemanticError
from sfg_builder.voting import vote_stream_parameter


PROJECT = Path(__file__).parent / "fixtures/simple_project"


class AlwaysFailsAnalyzer(MockSemanticAnalyzer):
    def classify_stream_parameter(self, *args):
        raise TimeoutError("provider details must not escape")


class SemanticIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parsed = CProjectParser().parse(PROJECT)
        cls.function = next(function for function in cls.parsed.functions
                            if function.name == "parser_from_memory")
        cls.stream_parameter = cls.function.parameters[1]
        cls.struct_parameter = cls.function.parameters[0]

    def test_mock_implements_all_semantic_operations(self):
        analyzer = MockSemanticAnalyzer()
        stream = analyzer.classify_stream_parameter(
            self.function, self.stream_parameter, self.parsed.structs, "direct")
        role = analyzer.classify_function_role(self.function, self.parsed.structs)
        direction = analyzer.infer_struct_direction(
            self.function, self.struct_parameter, self.function.access_hints[0],
            self.parsed.structs)
        for decision in (stream, role, direction):
            self.assertIsInstance(decision, SemanticDecision)
            self.assertEqual(decision.status, "ok")
            self.assertIsInstance(decision.response, dict)
            self.assertGreaterEqual(decision.confidence, 0.0)
            self.assertTrue(decision.prompt_version)

    def test_prompt_variants_are_distinct_and_function_local(self):
        prompts = [stream_prompt(self.function, self.stream_parameter, (), variant)
                   for variant in STREAM_VARIANTS]
        self.assertEqual(STREAM_VARIANTS, ("direct", "yes_no", "multiple_choice"))
        self.assertEqual(len(set(prompts)), 3)
        self.assertTrue(all(self.function.signature in prompt for prompt in prompts))
        with self.assertRaises(ValueError):
            stream_prompt(self.function, self.stream_parameter, (), "unsupported")

    def test_voting_converts_provider_errors_to_conservative_decisions(self):
        result = vote_stream_parameter(
            AlwaysFailsAnalyzer(), self.function, self.stream_parameter, self.parsed.structs)
        self.assertFalse(result.is_byte_stream)
        self.assertEqual((result.positive_votes, result.valid_votes), (0, 0))
        self.assertEqual(len(result.decisions), 3)
        self.assertTrue(all(decision.status == "error" for decision in result.decisions))
        self.assertTrue(all(decision.error == "TimeoutError" for decision in result.decisions))
        self.assertTrue(all("provider details" not in (decision.error or "")
                            for decision in result.decisions))

    def test_llm_requires_raw_json_object_and_strict_schema(self):
        valid = _transport(
            '{"is_byte_stream":true,"kind":"binary","confidence":0.8,"reason":"bytes"}')
        decision = LLMSemanticAnalyzer(valid, "test").classify_stream_parameter(
            self.function, self.stream_parameter, (), "yes_no")
        self.assertTrue(decision.data["is_byte_stream"])

        invalid_contents = (
            '```json\n{"is_byte_stream":true}\n```',
            '[{"is_byte_stream":true}]',
            '{"is_byte_stream":"yes","kind":"binary","confidence":0.8,"reason":"bytes"}',
            '{"is_byte_stream":true,"kind":"binary","confidence":true,"reason":"bytes"}',
        )
        for content in invalid_contents:
            with self.subTest(content=content):
                analyzer = LLMSemanticAnalyzer(_transport(content), "test")
                with self.assertRaises(SemanticError):
                    analyzer.classify_stream_parameter(
                        self.function, self.stream_parameter, (), "direct")

    def test_llm_usage_review_has_a_strict_batched_contract(self):
        pattern = {
            "id": "up_one", "lifecycle_kind": "owned_resource",
            "resource_type": "Parser", "producer_function": "create",
            "producer_binding": "return_value", "producer_argument_index": None,
            "consumers": ["parser_from_memory"], "consumer_argument_indices": [0],
            "cleanup_function": "destroy", "cleanup_argument_index": 0,
            "sequence": ["create", "parser_from_memory", "destroy"],
            "conditions": [], "path_kind": "normal", "support_total": 1,
            "support_by_source": {"test": 1},
        }
        content = json.dumps({"decisions": [{
            "pattern_id": "up_one", "is_valid_lifecycle": True,
            "lifecycle_kind": "owned_resource",
            "required_sequence": ["create", "parser_from_memory", "destroy"],
            "optional_calls": [], "merge_group": "basic", "confidence": 0.9,
            "reason": "create/use/destroy lifecycle",
        }]})
        decision = LLMSemanticAnalyzer(
            _transport(content), "test"
        ).review_usage_patterns((pattern,), (self.function,))
        self.assertEqual(decision.data["decisions"][0]["merge_group"], "basic")
        self.assertEqual(decision.prompt_version, "sfg-usage-review-v1")

        invalid = json.dumps({"decisions": [{
            "pattern_id": "up_one", "is_valid_lifecycle": "yes",
            "lifecycle_kind": "owned_resource", "required_sequence": [],
            "optional_calls": [], "merge_group": "basic", "confidence": 0.9,
            "reason": "bad",
        }]})
        with self.assertRaises(SemanticError):
            LLMSemanticAnalyzer(
                _transport(invalid), "test"
            ).review_usage_patterns((pattern,), (self.function,))

    def test_decision_trace_records_required_audit_fields(self):
        candidates = CandidateDetector().detect(self.parsed.functions)
        annotations = FunctionAnnotator(MockSemanticAnalyzer()).annotate(
            self.parsed.functions, candidates, self.parsed.structs)
        annotation = next(item for item in annotations
                          if item.function == "parser_from_memory")
        self.assertTrue(annotation.decisions)
        for trace in annotation.decisions:
            self.assertEqual(trace.function, "parser_from_memory")
            self.assertIn(trace.task, {"stream_parameter", "function_role", "struct_direction"})
            self.assertTrue(trace.prompt_version)
            self.assertIsInstance(trace.response, dict)
            self.assertGreaterEqual(trace.confidence, 0.0)


def _transport(content):
    return lambda _payload: {
        "choices": [{"finish_reason": "stop", "message": {"content": content}}]
    }


if __name__ == "__main__":
    unittest.main()
