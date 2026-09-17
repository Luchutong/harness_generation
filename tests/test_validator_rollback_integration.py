"""Regression coverage for validator-driven staged rollback.

The first harness passes Stage 4 AST checks, but a macro expands an allowed
call into an undeclared function at compile time.  The real compiler failure
must travel through the production CLI and orchestrator before Stage 4 is
regenerated and revalidated.
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from harness_generation.cli import main
from harness_generation.llm import MockLLM
from harness_generation.pipeline_validation import PipelineValidationConfig
from harness_generation.triplet import load_triplets_json
from tests.toolchain_probe import LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ARTIFACTS = ROOT / "artifacts" / "simple"
SIMPLE_PROJECT = ROOT / "tests" / "fixtures" / "simple_project"
NO_FUZZ_VALIDATION = PipelineValidationConfig(fuzz_smoke=None)


ROUGH_CODE = """#include "parser.h"

void rough_sequence(
    Parser *parser,
    const unsigned char *data,
    unsigned long size)
{
    parser_from_memory(parser, data, size);
    Node node = parser_next(parser);
    node_process(&node);
    parser_free(parser);
}"""


# Stage4's AST audit sees the allowed abort() call.  The real C preprocessor
# exposes undefined_function() to Clang, making this a compiler-owned failure.
COMPILER_FAILURE_HARNESS = """#include <stddef.h>
#include <stdint.h>
extern "C" {
#include "parser.h"
}

#define abort() undefined_function()

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Parser parser = {0};
    int status = parser_from_memory(
        &parser, data, (unsigned long)size);
    if (status == 0) {
        Node node = parser_next(&parser);
        node_process(&node);
    }
    parser_free(&parser);
    if (size == (size_t)-1) {
        abort();
    }
    return 0;
}"""


# The declaration makes the macro expansion compile, but no target object
# provides the symbol, so this variant must fail at the real linker step.
LINK_FAILURE_HARNESS = COMPILER_FAILURE_HARNESS.replace(
    "#define abort() undefined_function()",
    "extern void undefined_function(void);\n#define abort() undefined_function()",
)


VALID_HARNESS = """#include <stddef.h>
#include <stdint.h>
extern "C" {
#include "parser.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Parser parser = {0};
    int status = parser_from_memory(
        &parser, data, (unsigned long)size);
    if (status == 0) {
        Node node = parser_next(&parser);
        node_process(&node);
    }
    parser_free(&parser);
    return 0;
}"""


def harness_plan(triplet_id: str) -> str:
    return json.dumps({
        "schema_version": 1,
        "triplet_id": triplet_id,
        "entrypoint": "LLVMFuzzerTestOneInput",
        "input_strategy": {
            "description": "Feed parser_from_memory from data and size.",
            "data_identifier": "data",
            "size_identifier": "size",
            "bounded_steps": 1,
            "notes": [],
        },
        "state_objects": [
            {"name": "parser", "type": "Parser", "initialization": "zero"}
        ],
        "call_sequence": [
            {
                "function": "parser_from_memory",
                "roles": ["ISF", "HPF"],
                "purpose": "initialize parser",
                "arguments": ["&parser", "data", "(unsigned long)size"],
                "uses_fuzzer_data": True,
                "uses_fuzzer_size": True,
                "outputs": ["Parser"],
                "conditions": [],
            },
            {
                "function": "parser_next",
                "roles": ["PRF"],
                "purpose": "produce node",
                "arguments": ["&parser"],
                "uses_fuzzer_data": False,
                "uses_fuzzer_size": False,
                "outputs": ["Node"],
                "conditions": [],
            },
            {
                "function": "node_process",
                "roles": ["PRF"],
                "purpose": "process node",
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
                "purpose": "release parser",
                "arguments": ["&parser"],
                "after": ["parser_next", "node_process"],
            }
        ],
        "constraints": [],
        "notes": [],
    }, sort_keys=True)


@unittest.skipUnless(LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON)
class ValidatorRollbackIntegrationTests(unittest.TestCase):
    def test_stage4_compiler_failure_retries_and_then_succeeds(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copy2(SOURCE_ARTIFACTS / name, artifacts / name)

            triplet = load_triplets_json(artifacts / "triplets.json")[0]
            llm = MockLLM([
                *self._stage1_responses(artifacts, triplet),
                "parser_from_memory(parser, data, size);",
                "node_process(&node);",
                "parser_free(parser);",
                "Node node = parser_next(parser);",
                ROUGH_CODE,
                harness_plan(triplet.id),
                COMPILER_FAILURE_HARNESS,
                harness_plan(triplet.id),
                VALID_HARNESS,
            ])

            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                exit_code = main([
                    "generate",
                    "--artifacts", str(artifacts),
                    "--ft", triplet.id,
                    "--project-root", str(SIMPLE_PROJECT),
                ], llm=llm, validation_config=NO_FUZZ_VALIDATION)

            generation = artifacts / "generation" / triplet.id
            first_attempt = generation / "stage4" / "attempt_001"
            second_attempt = generation / "stage4" / "attempt_002"
            first_compiler = first_attempt / "validation" / "compiler.json"
            second_compiler = second_attempt / "validation" / "compiler.json"

            self.assertEqual(exit_code, 0)
            self.assertTrue(first_compiler.is_file())
            self.assertTrue(second_compiler.is_file())

            first_result = json.loads(first_compiler.read_text(encoding="utf-8"))
            second_result = json.loads(second_compiler.read_text(encoding="utf-8"))
            state = json.loads(
                (generation / "pipeline_state.json").read_text(encoding="utf-8")
            )

            self.assertEqual(first_result["validator"], "compiler")
            self.assertEqual(first_result["status"], "failed")
            self.assertFalse(first_result["metadata"]["syntax_valid"])
            self.assertNotEqual(first_result["return_code"], 0)
            self.assertEqual(
                Path(first_result["command"][0]).name,
                Path(shutil.which("clang++") or "clang++").name,
            )
            self.assertIn("undefined_function", first_result["stderr"])

            self.assertEqual(second_result["validator"], "compiler")
            self.assertEqual(second_result["status"], "passed")
            self.assertTrue(second_result["metadata"]["syntax_valid"])
            self.assertEqual(second_result["return_code"], 0)
            self.assertTrue((
                artifacts / "build" / triplet.id / "fuzzer"
            ).is_file())

            rollbacks = [
                event for event in state["history"]
                if event["event"] == "rollback"
            ]
            self.assertEqual(state["status"], "completed")
            self.assertEqual(len(rollbacks), 1)
            self.assertEqual(rollbacks[0]["failed_stage"], "STAGE_4_HARNESS")
            self.assertEqual(rollbacks[0]["restart_stage"], "STAGE_4_HARNESS")
            self.assertEqual(rollbacks[0]["validator"], "compiler")
            self.assertEqual(rollbacks[0]["failure_type"], "compile_error")
            self.assertEqual(
                rollbacks[0]["rollback_target"], "STAGE_4_HARNESS"
            )
            self.assertIn("undefined_function", rollbacks[0]["reason"])
            retry_metadata = json.loads((
                second_attempt / "metadata.json"
            ).read_text(encoding="utf-8"))
            self.assertEqual(retry_metadata["failed_stage"], "STAGE_4_HARNESS")
            self.assertEqual(retry_metadata["validator"], "compiler")
            self.assertEqual(retry_metadata["failure_type"], "compile_error")
            self.assertEqual(
                retry_metadata["rollback_target"], "STAGE_4_HARNESS"
            )
            self.assertEqual(len(llm.calls), 13)

    def test_stage4_link_failure_retries_and_is_revalidated(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copy2(SOURCE_ARTIFACTS / name, artifacts / name)
            triplet = load_triplets_json(artifacts / "triplets.json")[0]
            llm = MockLLM([
                *self._stage1_responses(artifacts, triplet),
                *self._stage2_responses(),
                ROUGH_CODE,
                harness_plan(triplet.id),
                LINK_FAILURE_HARNESS,
                harness_plan(triplet.id),
                VALID_HARNESS,
            ])

            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                exit_code = main([
                    "generate", "--artifacts", str(artifacts),
                    "--ft", triplet.id,
                    "--project-root", str(SIMPLE_PROJECT),
                ], llm=llm, validation_config=NO_FUZZ_VALIDATION)

            generation = artifacts / "generation" / triplet.id
            first = generation / "stage4/attempt_001/validation"
            second = generation / "stage4/attempt_002/validation"
            first_compiler = json.loads((
                first / "compiler.json"
            ).read_text(encoding="utf-8"))
            first_linker = json.loads((
                first / "linker.json"
            ).read_text(encoding="utf-8"))
            second_linker = json.loads((
                second / "linker.json"
            ).read_text(encoding="utf-8"))
            state = json.loads((
                generation / "pipeline_state.json"
            ).read_text(encoding="utf-8"))
            rollback = next(
                event for event in state["history"]
                if event["event"] == "rollback"
            )

            self.assertEqual(exit_code, 0)
            self.assertEqual(first_compiler["status"], "passed")
            self.assertEqual(first_linker["status"], "failed")
            self.assertNotEqual(first_linker["return_code"], 0)
            self.assertIn("undefined_function", first_linker["stderr"])
            self.assertEqual(rollback["validator"], "linker")
            self.assertEqual(rollback["failure_type"], "link_error")
            self.assertEqual(rollback["rollback_target"], "STAGE_4_HARNESS")
            self.assertEqual(second_linker["status"], "passed")
            self.assertEqual(state["status"], "completed")

    def test_repeated_real_compiler_failures_escalate_to_stage1_then_revalidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copy2(SOURCE_ARTIFACTS / name, artifacts / name)
            triplet = load_triplets_json(artifacts / "triplets.json")[0]
            docs = self._stage1_responses(artifacts, triplet)
            snippets = self._stage2_responses()
            llm = MockLLM([
                # Initial Stage 1-4 run: real Stage 4 compile failure.
                *docs, *snippets, ROUGH_CODE,
                harness_plan(triplet.id), COMPILER_FAILURE_HARNESS,
                # Nearest-checkpoint Stage 4 regeneration still fails.
                harness_plan(triplet.id), COMPILER_FAILURE_HARNESS,
                # Roll back Stage 3, regenerate Stage 3/4, still fail.
                ROUGH_CODE, harness_plan(triplet.id), COMPILER_FAILURE_HARNESS,
                # Roll back Stage 2, regenerate Stage 2-4, still fail.
                *snippets, ROUGH_CODE,
                harness_plan(triplet.id), COMPILER_FAILURE_HARNESS,
                # Roll back Stage 1, regenerate every stage, then pass.
                *docs, *snippets, ROUGH_CODE,
                harness_plan(triplet.id), VALID_HARNESS,
            ])

            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                exit_code = main([
                    "generate",
                    "--artifacts", str(artifacts),
                    "--ft", triplet.id,
                    "--project-root", str(SIMPLE_PROJECT),
                    "--max-regen-per-level", "1",
                ], llm=llm, validation_config=NO_FUZZ_VALIDATION)

            generation = artifacts / "generation" / triplet.id
            state = json.loads((
                generation / "pipeline_state.json"
            ).read_text(encoding="utf-8"))
            rollbacks = [
                event for event in state["history"]
                if event["event"] == "rollback"
            ]
            stage_starts = [
                event["stage"] for event in state["history"]
                if event["event"] == "stage_started"
            ]

            self.assertEqual(exit_code, 0)
            self.assertEqual(state["status"], "completed")
            self.assertEqual(
                [event["rollback_target"] for event in rollbacks],
                [
                    "STAGE_4_HARNESS",
                    "STAGE_3_ROUGH",
                    "STAGE_2_SNIPPETS",
                    "STAGE_1_DOCS",
                ],
            )
            for event in rollbacks:
                for field in (
                    "failed_stage", "validator", "failure_type", "attempt",
                    "rollback_target", "reason",
                ):
                    self.assertIn(field, event)
                self.assertEqual(event["failed_stage"], "STAGE_4_HARNESS")
                self.assertEqual(event["validator"], "compiler")
                self.assertEqual(event["failure_type"], "compile_error")
                self.assertIn("undefined_function", event["reason"])
            self.assertEqual(stage_starts.count("STAGE_1_DOCS"), 2)
            self.assertEqual(stage_starts.count("STAGE_2_SNIPPETS"), 3)
            self.assertEqual(stage_starts.count("STAGE_3_ROUGH"), 4)
            self.assertEqual(stage_starts.count("STAGE_4_HARNESS"), 5)
            stage4 = generation / "stage4"
            for number in range(1, 5):
                validation = json.loads((
                    stage4 / f"attempt_{number:03d}"
                    / "validation/compiler.json"
                ).read_text(encoding="utf-8"))
                self.assertEqual(validation["status"], "failed")
                self.assertIn("undefined_function", validation["stderr"])
            final_validation = json.loads((
                stage4 / "attempt_005/validation/compiler.json"
            ).read_text(encoding="utf-8"))
            self.assertEqual(final_validation["status"], "passed")
            self.assertTrue((
                artifacts / "build" / triplet.id / "fuzzer"
            ).is_file())
            self.assertEqual(len(llm.calls), 34)

    @staticmethod
    def _stage1_responses(artifacts, triplet):
        functions = json.loads(
            (artifacts / "functions.json").read_text(encoding="utf-8")
        )
        by_id = {function["id"]: function for function in functions["functions"]}
        return [
            json.dumps({
                "function": function.function,
                "signature": by_id[function.function_id]["signature"],
                "functionality": f"Use {function.function} in this FT.",
                "application_scenario": "In-memory parser processing.",
                "example_code": f"{function.function}(...);",
                "parameter_notes": [],
                "return_semantics": None,
                "resource_lifecycle_notes": [],
                "notes": [],
            }, sort_keys=True)
            for function in triplet.functions
        ]

    @staticmethod
    def _stage2_responses():
        return [
            "parser_from_memory(parser, data, size);",
            "node_process(&node);",
            "parser_free(parser);",
            "Node node = parser_next(parser);",
        ]


if __name__ == "__main__":
    unittest.main()
