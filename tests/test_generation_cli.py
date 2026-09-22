from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from harness_generation.cli import main
from harness_generation.llm import MockLLM
from harness_generation.llm import OpenAICompatibleLLM
from harness_generation.artifacts import ArtifactStore
from harness_generation.generation_cli import _publish_harness, _resolve_llm
from harness_generation.pipeline_validation import PipelineValidationConfig
from harness_generation.stage4 import Stage4Result
from harness_generation.triplet import load_triplets_json
from tests.toolchain_probe import LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ARTIFACTS = ROOT / "artifacts" / "simple"
SIMPLE_PROJECT = ROOT / "tests" / "fixtures" / "simple_project"
NO_FUZZ_VALIDATION = PipelineValidationConfig(fuzz_smoke=None)


ROUGH_CODE = """void rough_sequence(
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
    parser_from_memory(&parser, data, (unsigned long)size);
    Node node = parser_next(&parser);
    node_process(&node);
    parser_free(&parser);
    return 0;
}"""


def harness_plan(triplet_id):
    return json.dumps({
        "schema_version": 1,
        "triplet_id": triplet_id,
        "entrypoint": "LLVMFuzzerTestOneInput",
        "input_strategy": {
            "description": "Use data and size for parser_from_memory.",
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
                "purpose": "initialize Parser",
                "arguments": ["&parser", "data", "(unsigned long)size"],
                "uses_fuzzer_data": True,
                "uses_fuzzer_size": True,
                "outputs": ["Parser"],
                "conditions": [],
            },
            {
                "function": "parser_next",
                "roles": ["PRF"],
                "purpose": "produce Node",
                "arguments": ["&parser"],
                "uses_fuzzer_data": False,
                "uses_fuzzer_size": False,
                "outputs": ["Node"],
                "conditions": [],
            },
            {
                "function": "node_process",
                "roles": ["PRF"],
                "purpose": "consume Node",
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
                "purpose": "cleanup Parser",
                "arguments": ["&parser"],
                "after": ["parser_next", "node_process"],
            }
        ],
        "constraints": [],
        "notes": [],
    })


class GenerationCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.artifacts = Path(temporary.name) / "not-simple"
        self.artifacts.mkdir()
        for name in ("functions.json", "triplets.json"):
            shutil.copy2(SOURCE_ARTIFACTS / name, self.artifacts / name)
        self.triplet = load_triplets_json(self.artifacts / "triplets.json")[0]

    def responses(self, until_stage=4):
        functions = json.loads(
            (self.artifacts / "functions.json").read_text(encoding="utf-8")
        )
        by_id = {function["id"]: function for function in functions["functions"]}
        responses = [
            json.dumps({
                "function": function.function,
                "signature": by_id[function.function_id]["signature"],
                "functionality": f"Use {function.function} in the FT.",
                "application_scenario": "Structural processing.",
                "example_code": f"{function.function}(...);",
                "parameter_notes": [],
                "return_semantics": None,
                "resource_lifecycle_notes": [],
                "notes": [],
            })
            for function in self.triplet.functions
        ]
        if until_stage >= 2:
            responses.extend([
                "parser_from_memory(parser, data, size);",
                "node_process(&node);",
                "parser_free(parser);",
                "Node node = parser_next(parser);",
            ])
        if until_stage >= 3:
            responses.append(ROUGH_CODE)
        if until_stage >= 4:
            responses.append(harness_plan(self.triplet.id))
            responses.append(HARNESS_CODE)
        return responses

    def test_generate_runs_all_stages_with_injected_mock_llm(self):
        llm = MockLLM(self.responses())
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = main([
                "generate", "--artifacts", str(self.artifacts),
                "--ft", self.triplet.id, "--project-root", str(SIMPLE_PROJECT),
            ], llm=llm, validation_config=NO_FUZZ_VALIDATION)

        self.assertEqual(code, 0)
        self.assertEqual(len(llm.calls), 11)
        directory = self.artifacts / "generation" / self.triplet.id
        for name in (
            "stage1_docs.json", "stage2_snippets.json", "stage3_rough.c",
            "stage3_metadata.json", "stage4_harness.c", "pipeline_state.json",
        ):
            self.assertTrue((directory / name).is_file(), name)
        self.assertTrue(
            (self.artifacts / "harnesses" / f"{self.triplet.id}.c").is_file()
        )
        state = json.loads((directory / "pipeline_state.json").read_text())
        self.assertEqual(state["status"], "completed")
        self.assertEqual(state["current_stage"], 4)
        validations = [
            event for event in state["history"]
            if event["event"] == "stage_validated"
        ]
        self.assertEqual(
            [event["status"] for event in validations],
            ["passed", "passed", "passed", "passed"],
        )
        validation = directory / "validation"
        self.assertEqual(
            [
                json.loads((validation / f"{name}.json").read_text())["status"]
                for name in ("intermediate", "compiler", "linker", "runtime")
            ],
            ["passed", "passed", "passed", "passed"],
        )
        self.assertTrue((
            self.artifacts / "build" / self.triplet.id / "fuzzer"
        ).is_file())
        for expected in (
            "[S1] STAGE_1_DOCS", "[S2] STAGE_2_SNIPPETS",
            "[S3] STAGE_3_ROUGH", "[S4] STAGE_4_HARNESS",
        ):
            self.assertIn(expected, stdout.getvalue())

    def test_run_without_capability_flags_only_generates(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = main([
                "run", "--artifacts", str(self.artifacts),
                "--ft", self.triplet.id, "--project-root", str(SIMPLE_PROJECT),
            ], llm=MockLLM(self.responses()))

        result = json.loads((
            self.artifacts / "generation" / self.triplet.id /
            "pipeline_result.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        self.assertEqual(result["capability"], "generate")
        self.assertTrue(result["generated"])
        self.assertFalse(result["validated"])
        self.assertFalse(result["compiled"])
        self.assertFalse(result["linked"])
        self.assertFalse(result["runtime_checked"])
        self.assertFalse(result["fuzz_smoke_completed"])
        self.assertTrue(result["success"])
        self.assertIsNone(result["failure_reason"])
        self.assertFalse((self.artifacts / "build" / self.triplet.id).exists())
        self.assertIn("Stage4: generated", stdout.getvalue())
        self.assertIn("Compiler: not_requested", stdout.getvalue())
        self.assertIn("Result: SUCCESS", stdout.getvalue())

    def test_run_validate_does_not_compile_or_execute(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = main([
                "run", "--artifacts", str(self.artifacts),
                "--ft", self.triplet.id, "--validate",
                "--project-root", str(SIMPLE_PROJECT),
            ], llm=MockLLM(self.responses()))

        result = json.loads((
            self.artifacts / "generation" / self.triplet.id /
            "pipeline_result.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        self.assertEqual(result["capability"], "validate")
        self.assertTrue(result["generated"])
        self.assertTrue(result["validated"])
        self.assertFalse(result["compiled"])
        self.assertFalse(result["linked"])
        self.assertFalse(result["runtime_checked"])
        self.assertEqual(result["validator_statuses"]["intermediate"], "passed")
        self.assertEqual(result["validator_statuses"]["compiler"], "not_requested")
        self.assertFalse((self.artifacts / "build" / self.triplet.id).exists())
        self.assertIn("Intermediate: passed", stdout.getvalue())
        self.assertIn("Runtime: not_requested", stdout.getvalue())

    @unittest.skipUnless(LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON)
    def test_run_full_e2e_prints_all_milestones(self):
        class FuzzRunner:
            def __init__(self):
                self.calls = []

            def __call__(self, command, **kwargs):
                self.calls.append((command, kwargs))
                stderr = (
                    "INFO: Running with entropic power schedule.\n"
                    "INFO: Seed: 1\n"
                    "#5 DONE cov: 4 ft: 5 corp: 4/7b exec/s: 10\n"
                    "stat::number_of_executed_units: 5\n"
                    "stat::average_exec_per_sec: 10\n"
                )
                return subprocess.CompletedProcess(command, 0, "", stderr)

        runner = FuzzRunner()
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = main([
                "run", "--artifacts", str(self.artifacts),
                "--ft", self.triplet.id, "--build", "--smoke-fuzz",
                "--fuzz-seconds", "30", "--project-root", str(SIMPLE_PROJECT),
            ], llm=MockLLM(self.responses()), validation_config=
            PipelineValidationConfig(fuzz_runner=runner))

        result = json.loads((
            self.artifacts / "generation" / self.triplet.id /
            "pipeline_result.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        self.assertEqual(result["capability"], "e2e")
        for field in (
            "generated", "validated", "compiled", "linked",
            "runtime_checked", "fuzz_smoke_completed", "success",
        ):
            self.assertTrue(result[field], field)
        self.assertEqual(result["rollback_count"], 0)
        self.assertEqual(len(runner.calls), 1)
        self.assertIn("-max_total_time=30", runner.calls[0][0])
        for expected in (
            "FT:", "Stage1: passed", "Stage4: passed",
            "Intermediate: passed", "Compiler: passed", "Linker: passed",
            "Runtime: passed", "Rollback: none", "Fuzz smoke: passed",
            "Result: SUCCESS",
        ):
            self.assertIn(expected, stdout.getvalue())

    def test_run_smoke_fuzz_requires_build_and_bounds_duration(self):
        with self.assertRaises(SystemExit):
            main([
                "run", "--artifacts", str(self.artifacts),
                "--ft", self.triplet.id, "--smoke-fuzz",
            ], llm=MockLLM([]))
        with self.assertRaises(SystemExit):
            main([
                "run", "--artifacts", str(self.artifacts),
                "--ft", self.triplet.id, "--build", "--smoke-fuzz",
                "--fuzz-seconds", "121",
            ], llm=MockLLM([]))

    def test_run_summary_reports_automatic_rollback(self):
        invalid = HARNESS_CODE.replace("    node_process(&node);\n", "")
        llm = MockLLM([
            *self.responses()[:-1],
            invalid,
            harness_plan(self.triplet.id),
            HARNESS_CODE,
        ])
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = main([
                "run", "--artifacts", str(self.artifacts),
                "--ft", self.triplet.id, "--validate",
                "--project-root", str(SIMPLE_PROJECT),
            ], llm=llm)

        result = json.loads((
            self.artifacts / "generation" / self.triplet.id /
            "pipeline_result.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        self.assertTrue(result["success"])
        self.assertEqual(result["rollback_count"], 1)
        self.assertEqual(result["rollback_targets"], ["STAGE_4_HARNESS"])
        self.assertIn("Rollback: 1 (STAGE_4_HARNESS)", stdout.getvalue())

    def test_until_stage_then_resume_uses_existing_checkpoints(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            first = main([
                "generate", "--artifacts", str(self.artifacts),
                "--ft", self.triplet.id, "--until-stage", "2",
                "--project-root", str(SIMPLE_PROJECT),
            ], llm=MockLLM(self.responses(until_stage=2)))
        self.assertEqual(first, 0)
        directory = self.artifacts / "generation" / self.triplet.id
        state_path = directory / "pipeline_state.json"
        paused = json.loads(state_path.read_text())
        self.assertEqual(paused["status"], "paused")
        self.assertEqual(paused["current_stage"], 2)
        self.assertFalse((directory / "stage3_rough.c").exists())

        resume_llm = MockLLM([ROUGH_CODE, harness_plan(self.triplet.id), HARNESS_CODE])
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            resumed = main([
                "generate", "--artifacts", str(self.artifacts),
                "--ft", self.triplet.id, "--resume",
                "--project-root", str(SIMPLE_PROJECT),
            ], llm=resume_llm, validation_config=NO_FUZZ_VALIDATION)
        self.assertEqual(resumed, 0)
        self.assertEqual(len(resume_llm.calls), 3)
        completed = json.loads(state_path.read_text())
        self.assertEqual(completed["status"], "completed")
        self.assertGreater(len(completed["history"]), len(paused["history"]))

    def test_stage4_retry_records_rollback_context_per_attempt(self):
        invalid = HARNESS_CODE.replace("    node_process(&node);\n", "")
        llm = MockLLM([
            *self.responses()[:-1],
            invalid,
            harness_plan(self.triplet.id),
            HARNESS_CODE,
        ])
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main([
                "generate", "--artifacts", str(self.artifacts),
                "--ft", self.triplet.id, "--project-root", str(SIMPLE_PROJECT),
            ], llm=llm, validation_config=NO_FUZZ_VALIDATION)
        self.assertEqual(code, 0)
        stage4 = self.artifacts / "generation" / self.triplet.id / "stage4"
        first = json.loads((stage4 / "attempt_001" / "metadata.json").read_text())
        second = json.loads((stage4 / "attempt_002" / "metadata.json").read_text())
        self.assertIsNone(first["rollback_source"])
        self.assertEqual(second["rollback_source"], "STAGE_3_ROUGH")
        self.assertIn("omits FT functions", second["retry_reason"])

    def test_generate_all_uses_artifact_triplets_without_simple_hardcoding(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = main([
                "generate-all", "--artifacts", str(self.artifacts),
                "--until-stage", "1", "--project-root", str(SIMPLE_PROJECT),
            ], llm=MockLLM(self.responses(until_stage=1)))
        self.assertEqual(code, 0)
        state = json.loads((
            self.artifacts / "generation" / self.triplet.id / "pipeline_state.json"
        ).read_text())
        self.assertEqual(state["current_stage"], 1)
        self.assertEqual(state["status"], "paused")

    def test_module_cli_accepts_offline_mock_response_file(self):
        responses_path = self.artifacts / "mock.json"
        responses_path.write_text(
            json.dumps({"responses": self.responses(until_stage=1)}),
            encoding="utf-8",
        )
        completed = subprocess.run(
            [
                sys.executable, "-m", "harness_generation", "generate",
                "--artifacts", str(self.artifacts), "--ft", self.triplet.id,
                "--until-stage", "1", "--mock-responses", str(responses_path),
                "--project-root", str(SIMPLE_PROJECT),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("STAGE_1_DOCS", completed.stdout)

    def test_generate_rejects_unknown_triplet_without_calling_llm(self):
        llm = MockLLM([])
        stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            code = main([
                "generate", "--artifacts", str(self.artifacts),
                "--ft", "ft_missing",
            ], llm=llm)
        self.assertEqual(code, 1)
        self.assertEqual(llm.calls, [])
        self.assertIn("unknown FunctionTriplet", stderr.getvalue())

    def test_limited_build_is_quarantined_without_overwriting_stable_harness(self):
        store = ArtifactStore(self.artifacts)
        layout = store.for_triplet(self.triplet.id)
        layout.ensure_generation()
        layout.harness.parent.mkdir(parents=True, exist_ok=True)
        old_source = "/* previously accepted harness */\n"
        layout.harness.write_text(old_source, encoding="utf-8")
        layout.write_json(layout.validation_summary, {
            "schema_version": 1,
            "overall": "passed_with_limitations",
            "intermediate": "passed",
            "compiler": "passed",
            "linker": "unavailable",
            "runtime": "skipped",
        })
        generated = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return 0; }\n"
        result = Stage4Result(
            triplet_id=self.triplet.id,
            harness_code=generated,
            harness_path=layout.stage4_harness,
            stable_path=None,
            generation_metadata={},
            attempt_directory=layout.stage4_attempts / "attempt_001",
            harness_plan={"schema_version": 1, "triplet_id": self.triplet.id},
        )

        published = _publish_harness(layout, result)

        self.assertIsNone(published.stable_path)
        self.assertEqual(layout.harness.read_text(encoding="utf-8"), old_source)
        quarantine = json.loads((layout.generation / "quarantine.json").read_text())
        self.assertEqual(quarantine["status"], "quarantined")
        self.assertEqual(quarantine["validation_status"], "passed_with_limitations")
        self.assertEqual(quarantine["component_statuses"]["linker"], "unavailable")
        self.assertEqual(quarantine["component_statuses"]["runtime"], "skipped")
        self.assertTrue(quarantine["source_sha256"])
        self.assertTrue(quarantine["plan_sha256"])

    def test_unrecorded_validation_is_quarantined(self):
        store = ArtifactStore(self.artifacts)
        layout = store.for_triplet(self.triplet.id)
        layout.ensure_generation()
        generated = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return 0; }\n"
        result = Stage4Result(
            triplet_id=self.triplet.id,
            harness_code=generated,
            harness_path=layout.stage4_harness,
            stable_path=None,
            generation_metadata={},
            attempt_directory=layout.stage4_attempts / "attempt_001",
            harness_plan={"schema_version": 1, "triplet_id": self.triplet.id},
        )

        published = _publish_harness(layout, result)

        self.assertIsNone(published.stable_path)
        self.assertFalse(layout.harness.exists())
        quarantine = json.loads((layout.generation / "quarantine.json").read_text())
        self.assertEqual(quarantine["validation_status"], "not_recorded")

    def test_real_provider_requires_explicit_environment_configuration(self):
        stderr = io.StringIO()
        with patch.dict(
            "os.environ",
            {},
            clear=True,
        ), redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            code = main([
                "generate", "--artifacts", str(self.artifacts),
                "--ft", self.triplet.id,
                "--provider", "openai-compatible",
                "--until-stage", "1",
            ])

        self.assertEqual(code, 1)
        self.assertIn("missing LLM configuration", stderr.getvalue())
        self.assertIn("LLM_API_KEY", stderr.getvalue())
        self.assertFalse((
            self.artifacts / "generation" / self.triplet.id
        ).exists())

    def test_real_provider_is_constructed_from_environment_without_network(self):
        client = _resolve_llm(
            None,
            provider="openai-compatible",
            model=None,
            mock_responses=None,
            recorded_responses=None,
            environ={
                "LLM_BASE_URL": "https://llm.example.test/v1",
                "LLM_API_KEY": "unit-test-only",
                "LLM_MODEL": "configured-model",
                "LLM_THINKING": "disabled",
            },
        )

        self.assertIsInstance(client, OpenAICompatibleLLM)
        self.assertEqual(client.config.model, "configured-model")
        self.assertEqual(client.config.base_url, "https://llm.example.test/v1")
        self.assertEqual(client.config.api_key_env_name, "LLM_API_KEY")
        self.assertEqual(client.config.thinking, "disabled")
        self.assertNotIn("unit-test-only", json.dumps(client.config.to_dict()))

    def test_real_provider_rejects_invalid_thinking_mode(self):
        with self.assertRaisesRegex(ValueError, "LLM_THINKING"):
            _resolve_llm(
                None,
                provider="openai-compatible",
                model=None,
                mock_responses=None,
                recorded_responses=None,
                environ={
                    "LLM_BASE_URL": "https://llm.example.test/v1",
                    "LLM_API_KEY": "unit-test-only",
                    "LLM_MODEL": "configured-model",
                    "LLM_THINKING": "automatic",
                },
            )


if __name__ == "__main__":
    unittest.main()
