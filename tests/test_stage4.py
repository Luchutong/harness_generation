import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.llm import MockLLM
from harness_generation.policy import FORBIDDEN_LOGGING_FUNCTIONS
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.stage4 import (
    Stage4Error,
    Stage4Generator,
    generate_stage4_harness,
    parse_harness_plan,
)
from harness_generation.triplet_extractor import extract_function_triplets
from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.semantic import MockSemanticAnalyzer


REPOSITORY = Path(__file__).resolve().parents[1]
SIMPLE_PROJECT = REPOSITORY / "tests" / "fixtures" / "simple_project"


class Stage4Tests(unittest.TestCase):
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

    @staticmethod
    def rough_code():
        return """void rough_sequence(
    Parser *parser,
    const unsigned char *input,
    unsigned long input_size)
{
    parser_from_memory(parser, input, input_size);
    Node node = parser_next(parser);
    node_process(&node);
    parser_free(parser);
}"""

    @staticmethod
    def harness_code():
        return """#include <stddef.h>
#include <stdint.h>
extern "C" {
#include "parser.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) return 0;
    Parser parser = {0};
    if (parser_from_memory(&parser, data, (unsigned long)size) != 0) return 0;
    Node node = parser_next(&parser);
    node_process(&node);
    parser_free(&parser);
    return 0;
}"""

    def harness_plan(self):
        return json.dumps({
            "schema_version": 1,
            "triplet_id": self.triplet.id,
            "entrypoint": "LLVMFuzzerTestOneInput",
            "input_strategy": {
                "description": "Pass fuzzer bytes into parser_from_memory.",
                "data_identifier": "data",
                "size_identifier": "size",
                "bounded_steps": 1,
                "notes": [],
            },
            "state_objects": [
                {
                    "name": "parser",
                    "type": "Parser",
                    "initialization": "zero initialize before ISF",
                }
            ],
            "call_sequence": [
                {
                    "function": "parser_from_memory",
                    "roles": ["ISF", "HPF"],
                    "purpose": "initialize Parser from fuzzer input",
                    "arguments": ["&parser", "data", "(unsigned long)size"],
                    "uses_fuzzer_data": True,
                    "uses_fuzzer_size": True,
                    "outputs": ["Parser"],
                    "conditions": [],
                },
                {
                    "function": "parser_next",
                    "roles": ["PRF"],
                    "purpose": "derive Node from Parser",
                    "arguments": ["&parser"],
                    "uses_fuzzer_data": False,
                    "uses_fuzzer_size": False,
                    "outputs": ["Node"],
                    "conditions": [],
                },
                {
                    "function": "node_process",
                    "roles": ["PRF"],
                    "purpose": "consume the derived Node",
                    "arguments": ["&node"],
                    "uses_fuzzer_data": False,
                    "uses_fuzzer_size": False,
                    "outputs": [],
                    "conditions": [],
                },
            ],
            "cleanup_sequence": [
                {
                    "function": "parser_free",
                    "purpose": "release Parser after downstream processing",
                    "arguments": ["&parser"],
                    "after": ["parser_next", "node_process"],
                }
            ],
            "constraints": ["cleanup after processing"],
            "notes": [],
        })

    def test_stage4_generates_and_publishes_an_audited_harness(self):
        llm = MockLLM([self.harness_plan(), self.harness_code()])
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts" / "project"
            result = generate_stage4_harness(
                self.triplet,
                llm,
                rough_code=self.rough_code(),
                functions_json=self.phase1_artifacts / "functions.json",
                artifacts=artifacts,
            )
            generated = result.harness_path.read_text(encoding="utf-8")
            stable = result.stable_path.read_text(encoding="utf-8")
            stable_plan = json.loads((
                artifacts / "generation" / self.triplet.id /
                "stage4_harness_plan.json"
            ).read_text(encoding="utf-8"))
            attempt = artifacts / "generation" / self.triplet.id / "stage4" / "attempt_001"
            attempt_files = {path.name for path in attempt.iterdir()}
            attempt_metadata = json.loads((attempt / "metadata.json").read_text())
            plan = json.loads((attempt / "plan.json").read_text())

        expected = self.harness_code() + "\n"
        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(
            [call["prompt_name"] for call in llm.calls],
            ["stage4_harness_plan", "stage4_harness_transform"],
        )
        self.assertEqual(generated, expected)
        self.assertEqual(stable, expected)
        self.assertEqual(result.harness_plan["entrypoint"], "LLVMFuzzerTestOneInput")
        self.assertEqual(plan["call_sequence"][0]["function"], "parser_from_memory")
        self.assertEqual(stable_plan, plan)
        self.assertIn(self.triplet.id, llm.calls[0]["prompt"])
        self.assertIn(
            f'"triplet_id":"{self.triplet.id}"',
            llm.calls[0]["prompt"],
        )
        self.assertIn("Do not use a function id", llm.calls[0]["prompt"])
        self.assertIn("HarnessPlan JSON", llm.calls[1]["prompt"])
        self.assertEqual(
            result.harness_path,
            artifacts / "generation" / self.triplet.id / "stage4_harness.c",
        )
        self.assertEqual(
            result.stable_path,
            artifacts / "harnesses" / f"{self.triplet.id}.c",
        )
        self.assertEqual(
            result.generation_metadata["prompt_version"],
            "stage4-harness-transform-v6",
        )
        self.assertEqual(
            attempt_files,
            {
                "plan_prompt.txt", "plan_response.txt", "plan.json",
                "prompt.txt", "response.txt", "parsed.json", "harness.c",
                "metadata.json", "outcome.json",
            },
        )
        self.assertEqual(attempt_metadata["stage"], "stage4")
        self.assertEqual(attempt_metadata["attempt"], 1)
        self.assertEqual(attempt_metadata["provider"], "mock")
        self.assertEqual(attempt_metadata["model"], "mock-model")
        self.assertEqual(
            attempt_metadata["prompt_version"], "stage4-harness-transform-v6"
        )
        self.assertEqual(
            attempt_metadata["plan_prompt_version"], "stage4-harness-plan-v7"
        )
        self.assertIn("timestamp", attempt_metadata)
        self.assertIsNone(attempt_metadata["rollback_source"])
        self.assertIsNone(attempt_metadata["retry_reason"])

    def test_failed_then_successful_attempts_are_both_preserved(self):
        invalid = self.harness_code().replace("    node_process(&node);\n", "")
        llm = MockLLM([
            self.harness_plan(), invalid,
            self.harness_plan(), self.harness_code(),
        ])
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            generator = Stage4Generator(llm)
            with self.assertRaisesRegex(Stage4Error, "omits FT functions"):
                generator.run(
                    self.triplet,
                    rough_code=self.rough_code(),
                    functions_json=self.phase1_artifacts / "functions.json",
                    artifacts=artifacts,
                )
            result = generator.run(
                self.triplet,
                rough_code=self.rough_code(),
                functions_json=self.phase1_artifacts / "functions.json",
                artifacts=artifacts,
            )
            stage = artifacts / "generation" / self.triplet.id / "stage4"
            first = json.loads((stage / "attempt_001" / "parsed.json").read_text())
            second = json.loads((stage / "attempt_002" / "parsed.json").read_text())

        self.assertEqual(first["status"], "failed")
        self.assertEqual(second["status"], "passed")
        self.assertEqual(result.harness_code, self.harness_code())

    def test_normalizes_missing_headers_and_c_linkage_for_cpp_harness(self):
        raw = """#include "parser.h"
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Parser parser = {0};
    if (parser_from_memory(&parser, data, (unsigned long)size) != 0) return 0;
    Node node = parser_next(&parser);
    node_process(&node);
    parser_free(&parser);
    return 0;
}"""
        llm = MockLLM([self.harness_plan(), raw])
        with tempfile.TemporaryDirectory() as temporary:
            result = Stage4Generator(llm).run(
                self.triplet,
                rough_code=self.rough_code(),
                functions_json=self.phase1_artifacts / "functions.json",
                artifacts=Path(temporary) / "artifacts",
                publish=False,
            )

        self.assertIn("#include <stddef.h>", result.harness_code)
        self.assertIn("#include <stdint.h>", result.harness_code)
        self.assertIn('extern "C" {\n#include "parser.h"\n}', result.harness_code)
        self.assertIn(
            'extern "C" int LLVMFuzzerTestOneInput',
            result.harness_code,
        )

    def test_prompt_contains_rough_code_unique_isf_and_only_ft_metadata(self):
        llm = MockLLM([self.harness_plan(), self.harness_code()])
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
            Stage4Generator(llm).run(
                self.triplet,
                rough_code=self.rough_code(),
                functions_json=functions_path,
                artifacts=Path(temporary) / "output",
                publish=False,
            )

        plan_prompt = llm.calls[0]["prompt"]
        code_prompt = llm.calls[1]["prompt"]
        self.assertIn(self.rough_code(), plan_prompt)
        self.assertIn(self.triplet.id, plan_prompt)
        self.assertIn("FunctionTriplet identity", plan_prompt)
        self.assertIn('"name": "parser_from_memory"', plan_prompt)
        self.assertIn('"roles"', plan_prompt)
        self.assertIn('"include": "parser.h"', plan_prompt)
        self.assertIn("typedef struct { int state; } Parser;", plan_prompt)
        self.assertIn("FT bypass semantics", plan_prompt)
        self.assertIn("fuzzer_input_binding", plan_prompt)
        self.assertNotIn("unrelated_secret", plan_prompt)
        self.assertIn('"function": "parser_from_memory"', code_prompt)

    def test_retry_feedback_warns_not_to_use_function_id_as_triplet_id(self):
        llm = MockLLM([self.harness_plan(), self.harness_code()])
        retry_context = {
            "failed_stage": "STAGE_4_HARNESS",
            "validator": "orchestrator",
            "failure_type": "run_exception",
            "attempt": 1,
            "rollback_target": "STAGE_4_HARNESS",
            "reason": "Stage4Error: HarnessPlan triplet_id does not match the FT",
        }
        with tempfile.TemporaryDirectory() as temporary:
            Stage4Generator(llm).run(
                self.triplet,
                rough_code=self.rough_code(),
                functions_json=self.phase1_artifacts / "functions.json",
                artifacts=Path(temporary) / "output",
                publish=False,
                retry_context=retry_context,
            )

        plan_prompt = llm.calls[0]["prompt"]
        self.assertIn("stage4_triplet_id_correction", plan_prompt)
        self.assertIn('"required_triplet_id": "' + self.triplet.id + '"', plan_prompt)
        self.assertIn(
            '"do_not_use_as_triplet_id": "'
            + self.triplet.isf.function_id
            + '"',
            plan_prompt,
        )

    def test_accepts_stage3_rough_path_and_can_skip_stable_publish(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rough_path = root / "stage3_rough.c"
            rough_path.write_text(self.rough_code(), encoding="utf-8")
            result = Stage4Generator(MockLLM([
                self.harness_plan(), self.harness_code(),
            ])).run(
                self.triplet,
                rough_code=rough_path,
                functions_json=self.phase1_artifacts / "functions.json",
                artifacts=root / "artifacts",
                publish=False,
            )
            self.assertTrue(result.harness_path.is_file())
            self.assertIsNone(result.stable_path)
            self.assertFalse((root / "artifacts" / "harnesses").exists())

    def test_rejects_invalid_entry_fixed_input_and_missing_ft_calls(self):
        variants = (
            (
                self.harness_code().replace("const uint8_t *data", "const char *data"),
                "first fuzzer parameter",
            ),
            (
                self.harness_code().replace(
                    "parser_from_memory(&parser, data, (unsigned long)size)",
                    'parser_from_memory(&parser, (const unsigned char *)"fixed", 5)',
                ),
                "external data.*size",
            ),
            (
                self.harness_code().replace("    node_process(&node);\n", ""),
                "omits FT functions",
            ),
        )
        for code, message in variants:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(Stage4Error, message):
                    Stage4Generator(MockLLM([self.harness_plan(), code])).run(
                        self.triplet,
                        rough_code=self.rough_code(),
                        functions_json=self.phase1_artifacts / "functions.json",
                        artifacts=Path(temporary),
                    )

    def test_rejects_demo_logging_file_io_unknown_api_and_redefinition(self):
        insertion = "    parser_free(&parser);\n"
        variants = (
            (
                self.harness_code() + "\nint main(void) { return 0; }",
                "demo main",
            ),
            (
                self.harness_code().replace(insertion, "    printf(\"done\");\n" + insertion),
                "logging calls",
            ),
            (
                self.harness_code().replace(insertion, "    fopen(\"x\", \"rb\");\n" + insertion),
                "file I/O",
            ),
            (
                self.harness_code().replace(insertion, "    invented_api();\n" + insertion),
                "unknown APIs",
            ),
            (
                self.harness_code() + "\nvoid parser_free(Parser *parser) { (void)parser; }",
                "redefines project APIs",
            ),
        )
        for code, message in variants:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(Stage4Error, message):
                    Stage4Generator(MockLLM([self.harness_plan(), code])).run(
                        self.triplet,
                        rough_code=self.rough_code(),
                        functions_json=self.phase1_artifacts / "functions.json",
                        artifacts=Path(temporary),
                    )

    def test_rejects_every_forbidden_logging_function(self):
        """All seven names, not the two the Stage 4 copy happened to list.

        ``puts`` and ``perror`` are the interesting ones: they were refused by
        the intermediate validator and accepted here, so a harness reached the
        published artifact depending on which audit ran.
        """

        insertion = "    parser_free(&parser);\n"
        for name in sorted(FORBIDDEN_LOGGING_FUNCTIONS):
            with self.subTest(function=name), tempfile.TemporaryDirectory() as temporary:
                code = self.harness_code().replace(
                    insertion, f'    {name}(0, "x");\n' + insertion,
                )
                with self.assertRaisesRegex(Stage4Error, "logging calls"):
                    Stage4Generator(MockLLM([self.harness_plan(), code])).run(
                        self.triplet,
                        rough_code=self.rough_code(),
                        functions_json=self.phase1_artifacts / "functions.json",
                        artifacts=Path(temporary),
                    )

    def test_rejects_cleanup_before_isf(self):
        code = self.harness_code().replace(
            "    Parser parser = {0};\n",
            "    Parser parser = {0};\n    parser_free(&parser);\n",
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(Stage4Error, "cleanup occurs before ISF"):
                Stage4Generator(MockLLM([self.harness_plan(), code])).run(
                    self.triplet,
                    rough_code=self.rough_code(),
                    functions_json=self.phase1_artifacts / "functions.json",
                    artifacts=Path(temporary),
                )

    def test_a_refused_harness_leaves_its_attempt_an_outcome(self):
        """A refusal raises, so the attempt has to record itself on the way out.

        The attempt directory is written before the audit runs, and the audit's
        refusal propagates as an exception -- nothing after it executes.  Without
        an outcome written at the refusal, the attempt is a directory with a
        ``harness.c`` and no statement about why it was not published.
        """

        code = self.harness_code().replace(
            "    Parser parser = {0};\n",
            "    Parser parser = {0};\n    parser_free(&parser);\n",
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(Stage4Error, "cleanup occurs before ISF"):
                Stage4Generator(MockLLM([self.harness_plan(), code])).run(
                    self.triplet,
                    rough_code=self.rough_code(),
                    functions_json=self.phase1_artifacts / "functions.json",
                    artifacts=Path(temporary),
                )
            attempt = (
                Path(temporary) / "generation" / self.triplet.id
                / "stage4" / "attempt_001"
            )
            parsed = json.loads((attempt / "parsed.json").read_text(encoding="utf-8"))
            outcome = json.loads((attempt / "outcome.json").read_text(encoding="utf-8"))

        self.assertEqual(parsed["status"], "failed")
        self.assertEqual(parsed["phase"], "harness_code")
        self.assertEqual(outcome["status"], "failed")
        self.assertEqual(outcome["phase"], "harness_code")
        self.assertEqual(outcome["failure_type"], "harness_code_error")
        self.assertEqual(outcome["error_type"], "Stage4Error")
        self.assertIn("cleanup occurs before ISF", outcome["error"])
        self.assertEqual(outcome["parsed_status"], "failed")

    def test_rejects_cleanup_before_downstream_processing(self):
        code = self.harness_code()
        code = code.replace("    parser_free(&parser);\n", "")
        code = code.replace(
            "    Node node = parser_next(&parser);\n",
            "    parser_free(&parser);\n    Node node = parser_next(&parser);\n",
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(Stage4Error, "before downstream processing"):
                Stage4Generator(MockLLM([self.harness_plan(), code])).run(
                    self.triplet,
                    rough_code=self.rough_code(),
                    functions_json=self.phase1_artifacts / "functions.json",
                    artifacts=Path(temporary),
                )

    def test_rejects_invalid_harness_plan_before_generating_c(self):
        invalid_plan = json.loads(self.harness_plan())
        invalid_plan["call_sequence"][0]["uses_fuzzer_size"] = False
        llm = MockLLM([json.dumps(invalid_plan), self.harness_code()])
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(Stage4Error, "fuzzer data and fuzzer size"):
                Stage4Generator(llm).run(
                    self.triplet,
                    rough_code=self.rough_code(),
                    functions_json=self.phase1_artifacts / "functions.json",
                    artifacts=Path(temporary),
                )
            self.assertEqual(len(llm.calls), 1)
            attempt = (
                Path(temporary) / "generation" / self.triplet.id /
                "stage4" / "attempt_001"
            )
            parsed = json.loads((attempt / "parsed.json").read_text())
            self.assertEqual(parsed["phase"], "harness_plan")

    def test_parse_harness_plan_rejects_embedded_final_c(self):
        invalid = json.loads(self.harness_plan())
        invalid["harness_code"] = "int LLVMFuzzerTestOneInput(void) { return 0; }"
        metadata = json.loads(
            (self.phase1_artifacts / "functions.json").read_text(encoding="utf-8")
        )
        isf = next(
            function for function in metadata["functions"]
            if function["name"] == "parser_from_memory"
        )
        with self.assertRaisesRegex(Stage4Error, "final C source"):
            parse_harness_plan(
                json.dumps(invalid),
                triplet=self.triplet,
                isf_metadata=isf,
            )


if __name__ == "__main__":
    unittest.main()
