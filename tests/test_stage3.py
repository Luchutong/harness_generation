import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.llm import MockLLM
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.stage3 import (
    Stage2Snippet,
    Stage3Assembler,
    Stage3Error,
    assemble_stage3,
    load_stage2_snippets,
)
from harness_generation.triplet_extractor import extract_function_triplets
from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.semantic import MockSemanticAnalyzer


REPOSITORY = Path(__file__).resolve().parents[1]
SIMPLE_PROJECT = REPOSITORY / "tests" / "fixtures" / "simple_project"


class Stage3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.phase1_artifacts = Path(cls.temporary.name) / "phase1"
        SFGPipeline(
            MockSemanticAnalyzer(), ignored_directories=DEFAULT_IGNORES
        ).run(SIMPLE_PROJECT, cls.phase1_artifacts)
        cls.triplet = extract_function_triplets(
            load_sfg_artifacts(cls.phase1_artifacts)
        )[0]

    def snippets(self):
        # Deliberately reverse the structural order to exercise dependency ordering.
        return (
            Stage2Snippet(
                "unit_parser_cleanup", "Parser", "(null)",
                ("parser_free",), (), "parser_free(parser);",
            ),
            Stage2Snippet(
                "unit_node_consume", "Node", "(null)",
                ("node_process",), (), "node_process(&node);",
            ),
            Stage2Snippet(
                "unit_next", "Parser", "Node", ("parser_next",), (),
                "Node node = parser_next(parser);",
            ),
            Stage2Snippet(
                "unit_parse", "(null)", "Parser", ("parser_from_memory",), (),
                "parser_from_memory(parser, data, size);",
            ),
        )

    @staticmethod
    def rough_code():
        return """void rough_sequence(
    Parser *parser,
    const unsigned char *data,
    unsigned long size)
{
    if (parser_from_memory(parser, data, size) != 0) return;
    Node node = parser_next(parser);
    node_process(&node);
    parser_free(parser);
}"""

    def test_stage3_assembles_once_and_writes_required_artifacts(self):
        llm = MockLLM([self.rough_code()])
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts" / "project"
            result = assemble_stage3(
                self.triplet,
                llm,
                snippets=self.snippets(),
                functions_json=self.phase1_artifacts / "functions.json",
                artifacts=artifacts,
            )
            persisted_code = result.rough_code_path.read_text(encoding="utf-8")
            persisted_metadata = json.loads(
                result.metadata_path.read_text(encoding="utf-8")
            )
            attempt = artifacts / "generation" / self.triplet.id / "stage3" / "attempt_001"
            attempt_files = {path.name for path in attempt.iterdir()}
            attempt_metadata = json.loads((attempt / "metadata.json").read_text())

        self.assertEqual(len(llm.calls), 1)
        self.assertEqual(persisted_code, self.rough_code() + "\n")
        self.assertEqual(
            result.rough_code_path,
            artifacts / "generation" / self.triplet.id / "stage3_rough.c",
        )
        self.assertEqual(
            result.metadata_path,
            artifacts / "generation" / self.triplet.id / "stage3_metadata.json",
        )
        self.assertEqual(
            persisted_metadata["invoked_functions"],
            ["node_process", "parser_free", "parser_from_memory", "parser_next"],
        )
        self.assertEqual(persisted_metadata["missing_functions"], [])
        self.assertEqual(persisted_metadata["unexpected_functions"], [])
        self.assertEqual(persisted_metadata["involved_structures"], ["Node", "Parser"])
        self.assertEqual(
            persisted_metadata["assembly_order"],
            ["unit_parse", "unit_next", "unit_node_consume", "unit_parser_cleanup"],
        )
        self.assertEqual(
            persisted_metadata["generation_metadata"]["prompt_version"],
            "stage3-rough-assembly-v3",
        )
        self.assertEqual(
            attempt_files,
            {"prompt.txt", "response.txt", "parsed.json", "rough.c", "metadata.json"},
        )
        self.assertEqual(attempt_metadata["attempt"], 1)
        self.assertEqual(attempt_metadata["provider"], "mock")
        self.assertEqual(attempt_metadata["model"], "mock-model")
        self.assertEqual(
            attempt_metadata["prompt_version"], "stage3-rough-assembly-v3"
        )
        self.assertEqual(attempt_metadata["stage"], "stage3")
        self.assertEqual(attempt_metadata["ft_id"], self.triplet.id)
        self.assertIn("timestamp", attempt_metadata)
        self.assertIsNone(attempt_metadata["rollback_source"])
        self.assertIsNone(attempt_metadata["retry_reason"])
        self.assertIsNone(attempt_metadata["temperature"])
        self.assertIsNone(attempt_metadata["max_tokens"])

    def test_prompt_contains_ordered_snippets_dependencies_and_only_ft_metadata(self):
        llm = MockLLM([self.rough_code()])
        with tempfile.TemporaryDirectory() as temporary:
            functions = json.loads(
                (self.phase1_artifacts / "functions.json").read_text(encoding="utf-8")
            )
            functions["functions"].append({
                "id": "src/secret.c:1:unrelated_secret",
                "name": "unrelated_secret",
            })
            functions_path = Path(temporary) / "functions.json"
            functions_path.write_text(json.dumps(functions), encoding="utf-8")
            Stage3Assembler(llm).run(
                self.triplet,
                snippets=self.snippets(),
                functions_json=functions_path,
                artifacts=Path(temporary) / "output",
            )

        prompt = llm.calls[0]["prompt"]
        positions = [
            prompt.index(f'"id": "{unit_id}"')
            for unit_id in (
                "unit_parse", "unit_next", "unit_node_consume", "unit_parser_cleanup"
            )
        ]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('"ft_edges"', prompt)
        self.assertIn('"signature"', prompt)
        self.assertIn('"include": "parser.h"', prompt)
        self.assertIn("typedef struct { int state; } Parser;", prompt)
        self.assertNotIn("unrelated_secret", prompt)
        self.assertNotIn("LLVMFuzzerTestOneInput", result_text_without_instructions(prompt))

    def test_metadata_reports_missing_and_unexpected_calls(self):
        code = """void rough_sequence(Parser *parser, const unsigned char *data) {
    parser_from_memory(parser, data, 1);
    invented_helper();
}"""
        with tempfile.TemporaryDirectory() as temporary:
            result = Stage3Assembler(MockLLM([code])).run(
                self.triplet,
                snippets=self.snippets(),
                functions_json=self.phase1_artifacts / "functions.json",
                artifacts=Path(temporary),
            )
        self.assertEqual(
            result.metadata.invoked_functions,
            ("invented_helper", "parser_from_memory"),
        )
        self.assertEqual(
            result.metadata.missing_functions,
            ("node_process", "parser_free", "parser_next"),
        )
        self.assertEqual(result.metadata.unexpected_functions, ("invented_helper",))

    def test_stage2_json_adapter_and_null_normalization(self):
        document = {
            "schema_version": 1,
            "triplet_id": self.triplet.id,
            "snippets": [{
                "unit_id": "unit_parse",
                "input_structure": None,
                "output_structure": "Parser",
                "functions": ["parser_from_memory"],
                "dependencies": [],
                "generated_code": "parser_from_memory(parser, data, size);",
            }],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "stage2_snippets.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            snippets = load_stage2_snippets(path, triplet_id=self.triplet.id)
        self.assertEqual(len(snippets), 1)
        self.assertEqual(snippets[0].id, "unit_parse")
        self.assertEqual(snippets[0].input_structure, "(null)")

    def test_rejects_project_api_redefinition_and_final_harness(self):
        cases = (
            (
                "void parser_free(Parser *parser) { (void)parser; }",
                "redefines project API",
            ),
            (
                "int main(void) { return 0; }",
                "must not define main",
            ),
            (
                "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) "
                "{ (void)data; return (int)size; }",
                "final fuzzer entry point",
            ),
        )
        for code, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(Stage3Error, message):
                    Stage3Assembler(MockLLM([code])).run(
                        self.triplet,
                        snippets=self.snippets(),
                        functions_json=self.phase1_artifacts / "functions.json",
                        artifacts=Path(temporary),
                    )


def result_text_without_instructions(prompt):
    """Return data sections; the template instruction itself names Stage 4's symbol."""
    return prompt.split("Snippets:\n", 1)[1]


if __name__ == "__main__":
    unittest.main()
