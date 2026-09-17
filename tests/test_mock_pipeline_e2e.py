"""Deterministic offline acceptance test for the FT generation pipeline."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from harness_generation.artifacts import ArtifactStore
from harness_generation.cli import main
from harness_generation.compiler_validation import (
    LINK_UNAVAILABLE,
    CompilerConfig,
    CompilerValidator,
)
from harness_generation.llm import MockLLM
from harness_generation.pipeline_validation import PipelineValidationConfig
from harness_generation.triplet import FunctionTriplet, load_triplets_json
from harness_generation.validation import IntermediateValidator


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ARTIFACTS = ROOT / "artifacts" / "simple"
SIMPLE_PROJECT = ROOT / "tests" / "fixtures" / "simple_project"
PHASE1_ARTIFACTS = (
    "annotations.json",
    "candidates.json",
    "flows.json",
    "functions.json",
    "sfg.dot",
    "sfg.json",
)

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

HARNESS_CODE = """#include <stddef.h>
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
            "description": "Use data/size for parser_from_memory.",
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
                "purpose": "consume node",
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


class MockPipelineEndToEndTests(unittest.TestCase):
    """Exercise real artifacts and source with a network-free LLM boundary."""

    def _new_artifact_copy(self, parent: Path, name: str) -> Path:
        destination = parent / name
        destination.mkdir()
        for artifact in PHASE1_ARTIFACTS:
            shutil.copy2(SOURCE_ARTIFACTS / artifact, destination / artifact)
        # The checked-in artifact records its source root. Keep the test portable
        # when the repository is checked out at another absolute path.
        functions_path = destination / "functions.json"
        functions = json.loads(functions_path.read_text(encoding="utf-8"))
        functions["project"] = str(SIMPLE_PROJECT.resolve())
        functions_path.write_text(
            json.dumps(functions, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return destination

    def _responses(
        self,
        artifacts: Path,
        triplet: FunctionTriplet,
    ) -> list[str]:
        functions = json.loads(
            (artifacts / "functions.json").read_text(encoding="utf-8")
        )
        by_id = {item["id"]: item for item in functions["functions"]}
        stage1 = []
        for reference in triplet.functions:
            function = by_id[reference.function_id]
            stage1.append(json.dumps({
                "function": reference.function,
                "signature": function["signature"],
                "functionality": f"Use {reference.function} in this FT.",
                "application_scenario": "In-memory parser processing.",
                "example_code": f"{reference.function}(...);",
                "parameter_notes": [],
                "return_semantics": None,
                "resource_lifecycle_notes": [],
                "notes": [],
            }, sort_keys=True))

        # Stage 2 consumes structural units sorted by (input, output).
        stage2 = [
            "parser_from_memory(parser, data, size);",
            "node_process(&node);",
            "parser_free(parser);",
            "Node node = parser_next(parser);",
        ]
        return [*stage1, *stage2, ROUGH_CODE, harness_plan(triplet.id), HARNESS_CODE]

    def _run_offline_pipeline(self, artifacts: Path):
        triplets_stdout = io.StringIO()
        with redirect_stdout(triplets_stdout), redirect_stderr(io.StringIO()):
            triplets_code = main([
                "triplets", "--artifacts", str(artifacts),
            ])
        self.assertEqual(triplets_code, 0)
        triplets = load_triplets_json(artifacts / "triplets.json")
        self.assertEqual(len(triplets), 1)
        triplet = triplets[0]

        llm = MockLLM(self._responses(artifacts, triplet))
        generation_stdout = io.StringIO()
        with redirect_stdout(generation_stdout), redirect_stderr(io.StringIO()):
            generation_code = main([
                "generate",
                "--artifacts", str(artifacts),
                "--ft", triplet.id,
            ], llm=llm, validation_config=PipelineValidationConfig(
                fuzz_smoke=None
            ))
        self.assertEqual(generation_code, 0)

        layout = ArtifactStore(artifacts).for_triplet(triplet.id)
        validation = IntermediateValidator().validate_triplet(
            layout.stage4_harness,
            triplet,
            functions_json=artifacts / "functions.json",
            artifacts=artifacts,
            stage="stage4_harness",
        )
        return triplet, llm, validation, triplets_stdout.getvalue(), \
            generation_stdout.getvalue()

    def test_mock_pipeline_from_phase1_artifacts_is_complete_and_deterministic(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        parent = Path(temporary.name)
        first = self._new_artifact_copy(parent, "first")
        second = self._new_artifact_copy(parent, "second")

        triplet, llm, validation, triplet_log, generation_log = \
            self._run_offline_pipeline(first)
        second_triplet, second_llm, second_validation, _, _ = \
            self._run_offline_pipeline(second)

        self.assertTrue(triplet.id.startswith("ft_parser_from_memory_"))
        self.assertEqual(second_triplet.id, triplet.id)
        self.assertEqual(triplet.isf.function, "parser_from_memory")
        self.assertTrue(validation.success, validation.errors)
        self.assertTrue(second_validation.success, second_validation.errors)
        self.assertEqual(len(llm.calls), 11)
        self.assertEqual(llm.calls, second_llm.calls)
        self.assertEqual(
            [call["prompt_name"] for call in llm.calls],
            [
                "stage1_function_doc",
                "stage1_function_doc",
                "stage1_function_doc",
                "stage1_function_doc",
                "stage2_structure_snippet",
                "stage2_structure_snippet",
                "stage2_structure_snippet",
                "stage2_structure_snippet",
                "stage3_rough_assembly",
                "stage4_harness_plan",
                "stage4_harness_transform",
            ],
        )

        layout = ArtifactStore(first).for_triplet(triplet.id)
        required = (
            first / "triplets.json",
            layout.stage1_docs,
            layout.stage1_scoped_docs,
            layout.stage2_snippets,
            layout.stage2_scoped_snippets,
            layout.stage3_rough,
            layout.stage3_metadata,
            layout.stage4_harness_plan,
            layout.stage4_harness,
            layout.harness,
            layout.stage4_attempts / "attempt_001" / "plan.json",
            layout.validation,
            layout.pipeline_state,
        )
        for path in required:
            self.assertTrue(path.is_file(), str(path.relative_to(first)))

        stage1_document = json.loads(layout.stage1_docs.read_text(encoding="utf-8"))
        stage2_document = json.loads(layout.stage2_snippets.read_text(encoding="utf-8"))
        self.assertEqual(
            json.loads(layout.stage1_scoped_docs.read_text(encoding="utf-8")),
            stage1_document,
        )
        self.assertEqual(
            json.loads(layout.stage2_scoped_snippets.read_text(encoding="utf-8")),
            stage2_document,
        )
        stage3_document = json.loads(layout.stage3_metadata.read_text(encoding="utf-8"))
        self.assertEqual(len(stage1_document["documents"]), 4)
        self.assertTrue(all(
            item["generation_metadata"]["provider"] == "mock"
            for item in stage1_document["documents"]
        ))
        self.assertEqual(len(stage2_document["units"]), 4)
        self.assertTrue(all(
            item["metadata"]["provider"] == "mock"
            for item in stage2_document["units"]
        ))
        self.assertEqual(
            stage3_document["invoked_functions"],
            [
                "node_process",
                "parser_free",
                "parser_from_memory",
                "parser_next",
            ],
        )
        self.assertEqual(stage3_document["missing_functions"], [])
        self.assertEqual(stage3_document["unexpected_functions"], [])
        self.assertEqual(len(tuple(layout.raw.glob("*.txt"))), 8)
        stage2_metadata = tuple(layout.raw.glob("stage2_*.metadata.json"))
        self.assertEqual(len(stage2_metadata), 4)
        for path in stage2_metadata:
            metadata = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["provider"], "mock")
            self.assertEqual(metadata["model"], "mock-model")
            self.assertEqual(metadata["attempt"], 1)
            self.assertIn("timestamp", metadata)
        self.assertEqual(len(tuple(layout.snippets.glob("*.c"))), 4)
        self.assertEqual(len(tuple(layout.prompts.glob("*.json"))), 8)
        self.assertEqual(len(tuple(layout.stage1_prompts.glob("*.json"))), 4)
        self.assertEqual(len(tuple(layout.stage1_raw.glob("*.txt"))), 4)
        self.assertEqual(len(tuple(layout.stage2_prompts.glob("*.json"))), 4)
        self.assertEqual(len(tuple(layout.stage2_raw.glob("*.txt"))), 4)
        self.assertEqual(len(tuple(layout.stage2_code_snippets.glob("*.c"))), 4)

        # Exclude diagnostics whose absolute temporary paths are expected to
        # differ. All semantic and generated outputs must be byte-for-byte stable.
        deterministic = (
            "triplets.json",
            f"generation/{triplet.id}/stage1_docs.json",
            f"generation/{triplet.id}/stage2_snippets.json",
            f"generation/{triplet.id}/stage3_rough.c",
            f"generation/{triplet.id}/stage3_metadata.json",
            f"generation/{triplet.id}/stage4_harness.c",
            f"generation/{triplet.id}/validation/intermediate.json",
            f"harnesses/{triplet.id}.c",
        )
        for relative in deterministic:
            self.assertEqual(
                (first / relative).read_bytes(),
                (second / relative).read_bytes(),
                relative,
            )

        self.assertIn(f"[FT] {triplet.id}", triplet_log)
        for stage in range(1, 5):
            self.assertIn(f"[S{stage}]", generation_log)

        # The fixture supplies declarations/includes, so perform a real syntax
        # compile. It intentionally has no library/link config; unavailable is
        # recorded instead of being reported as a successful link.
        clang = shutil.which("clang")
        clangxx = shutil.which("clang++")
        if clang is not None and clangxx is not None:
            compile_result = CompilerValidator(CompilerConfig(
                compiler=clangxx,
                include_paths=(SIMPLE_PROJECT / "include",),
                compiler_flags=("-x", "c++", "-std=c++17"),
            )).validate_triplet(
                layout.stage4_harness,
                artifacts=first,
                ft_id=triplet.id,
                stage="stage4_compile",
            )
            self.assertTrue(compile_result.success, compile_result.errors)
            self.assertIs(compile_result.metadata["syntax_valid"], True)
            self.assertEqual(
                compile_result.metadata["link_validation"], LINK_UNAVAILABLE
            )
            self.assertTrue(layout.compiler_validation.is_file())
            self.assertTrue(layout.linker_validation.is_file())


if __name__ == "__main__":
    unittest.main()
