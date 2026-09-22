import json
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from harness_generation.artifacts import ArtifactStore
from harness_generation.fuzzer_build import FuzzerBuildValidator
from harness_generation.llm import MockLLM
from harness_generation.policy import FORBIDDEN_LOGGING_FUNCTIONS
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.stage4 import (
    HarnessPlan,
    Stage4Error,
    Stage4Generator,
    _analyze_cpp,
    _validate_ownership_calls,
    _validate_parent_plan_revision,
    generate_stage4_harness,
    parse_harness_plan,
)
from harness_generation.target_contract import TargetContract
from harness_generation.target_build import TargetBuildConfig
from harness_generation.triplet import TripletOwnershipRelation
from harness_generation.triplet_extractor import extract_function_triplets
from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.semantic import MockSemanticAnalyzer
from tests.toolchain_probe import LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON


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

    def test_v2_plan_binds_contract_and_fact_ids(self):
        contract = TargetContract.from_triplet(self.triplet)
        fact_ids = sorted(resource.id for resource in contract.resources)
        plan = json.loads(self.harness_plan())
        plan.update({
            "schema_version": 2,
            "contract_id": contract.contract_id,
            "contract_fact_ids": fact_ids,
            "immutable_fields": [
                "triplet_id", "entrypoint", "contract_fact_ids", "state_objects",
                "call_sequence", "cleanup_sequence", "constraints",
            ],
            "tunable_fields": ["input_strategy", "notes"],
        })
        parsed = parse_harness_plan(
            json.dumps(plan), triplet=self.triplet,
            isf_metadata=json.loads(
                (self.phase1_artifacts / "functions.json").read_text()
            )["functions"][0],
            contract_id=contract.contract_id,
            contract_fact_ids=fact_ids,
        )
        self.assertEqual(parsed.schema_version, 2)
        self.assertEqual(parsed.contract_fact_ids, tuple(fact_ids))

    def test_plan_revision_rejects_immutable_changes(self):
        parent = json.loads(self.harness_plan())
        child = json.loads(self.harness_plan())
        child["constraints"] = ["changed immutable binding"]
        with self.assertRaisesRegex(Stage4Error, "only tunable"):
            _validate_parent_plan_revision(parent, child, contract_id="unused")

    def test_stage4_generates_an_audited_candidate_without_publishing(self):
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
            stable_exists = (artifacts / "harnesses" / f"{self.triplet.id}.c").exists()
            stable_plan = json.loads((
                artifacts / "generation" / self.triplet.id /
                "stage4_harness_plan.json"
            ).read_text(encoding="utf-8"))
            attempt = artifacts / "generation" / self.triplet.id / "stage4" / "attempt_001"
            attempt_files = {path.name for path in attempt.iterdir()}
            attempt_metadata = json.loads((attempt / "metadata.json").read_text())
            attempt_outcome = json.loads((attempt / "outcome.json").read_text())
            plan = json.loads((attempt / "plan.json").read_text())

        expected = self.harness_code() + "\n"
        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(
            [call["prompt_name"] for call in llm.calls],
            ["stage4_harness_plan", "stage4_harness_transform"],
        )
        self.assertEqual(generated, expected)
        self.assertFalse(stable_exists)
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
        self.assertIsNone(result.stable_path)
        self.assertEqual(
            result.generation_metadata["prompt_version"],
            "stage4-harness-transform-v7",
        )
        self.assertEqual(
            attempt_files,
            {
                "plan_prompt.txt", "plan_response.txt", "plan.json",
                "prompt.txt", "response.txt", "parsed.json", "outcome.json", "harness.c",
                "metadata.json",
            },
        )
        self.assertEqual(attempt_outcome["status"], "pending_validation")
        self.assertEqual(attempt_metadata["stage"], "stage4")
        self.assertEqual(attempt_metadata["attempt"], 1)
        self.assertEqual(attempt_metadata["provider"], "mock")
        self.assertEqual(attempt_metadata["model"], "mock-model")
        self.assertEqual(
            attempt_metadata["prompt_version"], "stage4-harness-transform-v7"
        )
        self.assertEqual(
            attempt_metadata["plan_prompt_version"], "stage4-harness-plan-v5"
        )
        self.assertIn("timestamp", attempt_metadata)
        self.assertIsNone(attempt_metadata["rollback_source"])
        self.assertIsNone(attempt_metadata["retry_reason"])

    def test_stage4_cannot_publish_before_formal_validation(self):
        llm = MockLLM([])
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            with self.assertRaisesRegex(Stage4Error, "formal pipeline validation"):
                Stage4Generator(llm).run(
                    self.triplet, rough_code=self.rough_code(),
                    functions_json=self.phase1_artifacts / "functions.json",
                    artifacts=artifacts, publish=True,
                )
            self.assertFalse((artifacts / "harnesses").exists())
        self.assertEqual(llm.calls, [])

    @unittest.skipUnless(LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON)
    def test_grammar_contract_can_build_fuzzer_controlled_payload(self):
        contract = TargetContract.from_protocol_document({
            "entry_function": self.triplet.isf.function,
            "contract": {"grammar": {
                "start": "value", "rules": {"value": "'{' digit '}'",
                                              "digit": "'0' | '1'"},
            }},
        })
        plan = json.loads(self.harness_plan())
        plan["input_strategy"].update(
            mode="grammar", start_symbol="value", max_depth=2,
            max_output_bytes=16,
        )
        plan["call_sequence"][0]["arguments"] = [
            "&parser", "payload", "payload_len",
        ]
        code = '''#include <stddef.h>
#include <stdint.h>
extern "C" {
#include "parser.h"
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Parser parser = {0};
    unsigned char payload[16] = {'{', '0', '}'};
    if (size > 0) payload[1] = (unsigned char)('0' + data[0] % 10);
    unsigned long payload_len = 3;
    parser_from_memory(&parser, payload, payload_len);
    Node node = parser_next(&parser);
    node_process(&node);
    parser_free(&parser);
    return 0;
}'''
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            ArtifactStore(artifacts).write_target_contract(contract)
            result = Stage4Generator(MockLLM([json.dumps(plan), code])).run(
                self.triplet, rough_code=self.rough_code(),
                functions_json=self.phase1_artifacts / "functions.json",
                artifacts=artifacts,
            )
            build = FuzzerBuildValidator().validate(
                result.harness_path,
                TargetBuildConfig.for_simple_project(SIMPLE_PROJECT),
                artifacts=artifacts, ft_id=self.triplet.id,
            )
            unconnected = code.replace(
                "Parser parser = {0};",
                "Parser parser = {0}; (void)data;",
            ).replace("data[0] % 10", "7 % 10")
            with self.assertRaisesRegex(Stage4Error, "not connected"):
                Stage4Generator(MockLLM([json.dumps(plan), unconnected])).run(
                    self.triplet, rough_code=self.rough_code(),
                    functions_json=self.phase1_artifacts / "functions.json",
                    artifacts=artifacts,
                )
        self.assertEqual(build.status, "passed", build.errors)

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
            first_outcome = json.loads((stage / "attempt_001" / "outcome.json").read_text())
            second_outcome = json.loads((stage / "attempt_002" / "outcome.json").read_text())

        self.assertEqual(first["status"], "failed")
        self.assertEqual(second["status"], "passed")
        self.assertEqual(first_outcome["status"], "failed")
        self.assertEqual(first_outcome["phase"], "harness_code")
        self.assertEqual(second_outcome["status"], "pending_validation")
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
        insertion = "    parser_free(&parser);\n"
        for name in sorted(FORBIDDEN_LOGGING_FUNCTIONS):
            code = self.harness_code().replace(
                insertion, f"    {name}(0);\n" + insertion,
            )
            with self.subTest(function=name), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaisesRegex(Stage4Error, f"logging calls: {name}"):
                    Stage4Generator(MockLLM([self.harness_plan(), code])).run(
                        self.triplet,
                        rough_code=self.rough_code(),
                        functions_json=self.phase1_artifacts / "functions.json",
                        artifacts=Path(temporary),
                    )

    def test_rejects_non_linkable_project_api(self):
        document = json.loads((self.phase1_artifacts / "functions.json").read_text())
        document["functions"].append({
            "id": "src/parser.c:99:internal_api",
            "name": "internal_api",
            "defined": True,
            "storage": ["static"],
            "file": "src/parser.c",
            "start_line": 99,
        })
        functions = self.phase1_artifacts / "functions_non_linkable.json"
        functions.write_text(json.dumps(document), encoding="utf-8")
        code = self.harness_code().replace(
            "    parser_free(&parser);", "    internal_api();\n    parser_free(&parser);"
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(Stage4Error, "non-linkable project APIs"):
                Stage4Generator(MockLLM([self.harness_plan(), code])).run(
                    self.triplet,
                    rough_code=self.rough_code(),
                    functions_json=functions,
                    artifacts=Path(temporary),
                )

        code = self.harness_code().replace(
            "#include <stdint.h>",
            "#include <stdint.h>\n#include <algorithm>\n#include <vector>",
        ).replace(
            "    Parser parser = {0};",
            "    constexpr size_t max_bytes = 32;\n"
            "    std::vector<uint8_t> bytes(data, data + std::min(size, max_bytes));\n"
            "    Parser parser = {0};",
        )
        with tempfile.TemporaryDirectory() as temporary:
            result = Stage4Generator(MockLLM([self.harness_plan(), code])).run(
                self.triplet,
                rough_code=self.rough_code(),
                functions_json=self.phase1_artifacts / "functions.json",
                artifacts=Path(temporary),
                publish=False,
            )
            self.assertIn("std::vector<uint8_t>", result.harness_code)
            self.assertIn("constexpr size_t", result.harness_code)

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
            outcome = json.loads((attempt / "outcome.json").read_text())
            self.assertEqual(parsed["phase"], "harness_plan")
            self.assertEqual(outcome["phase"], "harness_plan")
            self.assertEqual(outcome["status"], "failed")

    def _ownership_triplet_and_plan(self, relation_id):
        relation = TripletOwnershipRelation(
            id=relation_id,
            producer_function_id=self.triplet.isf.function_id,
            producer_function=self.triplet.isf.function,
            resource_type="Parser",
            cleanup_function_id="src/parser.c:1:parser_free",
            cleanup_function="parser_free",
            consumers=("parser_next", "node_process"),
            nullable=True,
            evidence=("test evidence",),
            confidence=1.0,
        )
        triplet = replace(self.triplet, ownership_relations=(relation,))
        plan = json.loads(self.harness_plan())
        plan["cleanup_sequence"][0].update({
            "relation_id": relation.id,
            "producer_function": relation.producer_function,
            "resource_type": relation.resource_type,
            "producer_return_binding": {
                "kind": "return_value", "identifier": "item"
            },
            "arguments": ["item"],
            "after": ["parser_from_memory", "parser_next", "node_process"],
            "conditions": ["item != NULL"],
        })
        return triplet, json.dumps(plan)

    def test_stage4_run_rejects_cleanup_only_on_null_branch(self):
        triplet, plan = self._ownership_triplet_and_plan("own_e2e_null_branch")
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) return 0;
    Parser parser = {0};
    Parser *item = (Parser *)parser_from_memory(&parser, data, (unsigned long)size);
    Node node = parser_next(&parser);
    node_process(&node);
    if (!item) { parser_free(item); }
    return 0;
}"""
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(Stage4Error, "lacks a null guard"):
                Stage4Generator(MockLLM([plan, code])).run(
                    triplet,
                    rough_code=self.rough_code(),
                    functions_json=self.phase1_artifacts / "functions.json",
                    artifacts=Path(temporary),
                )

    def test_stage4_run_rejects_cleanup_after_non_null_early_return(self):
        triplet, plan = self._ownership_triplet_and_plan("own_e2e_early_return")
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) return 0;
    Parser parser = {0};
    Parser *item = (Parser *)parser_from_memory(&parser, data, (unsigned long)size);
    Node node = parser_next(&parser);
    node_process(&node);
    if (item) return 0;
    if (item != NULL) { parser_free(item); }
    return 0;
}"""
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(Stage4Error, "unreachable on a non-null return path"):
                Stage4Generator(MockLLM([plan, code])).run(
                    triplet,
                    rough_code=self.rough_code(),
                    functions_json=self.phase1_artifacts / "functions.json",
                    artifacts=Path(temporary),
                )

    def test_stage4_allows_multiple_ownership_relations_with_same_cleanup(self):
        first = TripletOwnershipRelation(
            id="own_parser_from_memory",
            producer_function_id=self.triplet.isf.function_id,
            producer_function=self.triplet.isf.function,
            resource_type="Parser",
            cleanup_function_id="src/parser.c:1:parser_free",
            cleanup_function="parser_free",
            consumers=("parser_next", "node_process"),
            nullable=True,
            evidence=("test evidence",),
            confidence=1.0,
        )
        second = TripletOwnershipRelation(
            id="own_parser_next",
            producer_function_id="src/parser.c:13:parser_next",
            producer_function="parser_next",
            resource_type="Node",
            cleanup_function_id="src/parser.c:1:parser_free",
            cleanup_function="parser_free",
            consumers=("node_process",),
            nullable=True,
            evidence=("test evidence",),
            confidence=1.0,
        )
        triplet = replace(self.triplet, ownership_relations=(first, second))
        plan = json.loads(self.harness_plan())
        plan["cleanup_sequence"] = [
            {
                "function": "parser_free",
                "purpose": "release parser_from_memory result",
                "relation_id": first.id,
                "producer_function": first.producer_function,
                "resource_type": first.resource_type,
                "producer_return_binding": {
                    "kind": "return_value", "identifier": "item"
                },
                "arguments": ["item"],
                "after": ["parser_from_memory", "parser_next", "node_process"],
                "conditions": ["item != NULL"],
            },
            {
                "function": "parser_free",
                "purpose": "release parser_next result",
                "relation_id": second.id,
                "producer_function": second.producer_function,
                "resource_type": second.resource_type,
                "producer_return_binding": {
                    "kind": "return_value", "identifier": "node_item"
                },
                "arguments": ["node_item"],
                "after": ["parser_next", "node_process"],
                "conditions": ["node_item != NULL"],
            },
        ]
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0) return 0;
    Parser parser = {0};
    Parser *item = (Parser *)parser_from_memory(&parser, data, (unsigned long)size);
    Node *node_item = (Node *)parser_next(&parser);
    node_process(node_item);
    if (item != NULL) { parser_free(item); }
    if (node_item != NULL) { parser_free(node_item); }
    return 0;
}"""
        with tempfile.TemporaryDirectory() as temporary:
            Stage4Generator(MockLLM([json.dumps(plan), code])).run(
                triplet,
                rough_code=self.rough_code(),
                functions_json=self.phase1_artifacts / "functions.json",
                artifacts=Path(temporary),
            )

    def test_stage4_rejects_missing_cleanup_for_one_shared_cleanup_relation(self):
        triplet, plan_text = self._ownership_triplet_and_plan("own_missing_argument")
        relation = triplet.ownership_relations[0]
        second = TripletOwnershipRelation(
            id="own_missing_second",
            producer_function_id="src/parser.c:13:parser_next",
            producer_function="parser_next",
            resource_type="Node",
            cleanup_function_id=relation.cleanup_function_id,
            cleanup_function=relation.cleanup_function,
            consumers=("node_process",),
            nullable=True,
            evidence=("test evidence",),
            confidence=1.0,
        )
        triplet = replace(triplet, ownership_relations=(relation, second))
        plan = json.loads(plan_text)
        plan["cleanup_sequence"].append({
            "function": "parser_free",
            "purpose": "release parser_next result",
            "relation_id": second.id,
            "producer_function": second.producer_function,
            "resource_type": second.resource_type,
            "producer_return_binding": {
                "kind": "return_value", "identifier": "node_item"
            },
            "arguments": ["node_item"],
            "after": ["parser_next", "node_process"],
            "conditions": ["node_item != NULL"],
        })
        parsed_plan = parse_harness_plan(
            json.dumps(plan), triplet=triplet,
            isf_metadata=json.loads(
                (self.phase1_artifacts / "functions.json").read_text()
            )["functions"][0],
        )
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Parser *item = (Parser *)parser_from_memory((Parser *)data, data, (unsigned long)size);
    Node *node_item = (Node *)parser_next((Parser *)data);
    node_process(node_item);
    if (item != NULL) { parser_free(item); }
    return 0;
}"""
        with self.assertRaisesRegex(Stage4Error, "parser_free must release node_item exactly once"):
            _validate_ownership_calls(_analyze_cpp(code).calls, triplet, parsed_plan)

    def test_rejects_ownership_cleanup_on_null_branch(self):
        relation = TripletOwnershipRelation(
            id="own_parser_parse",
            producer_function_id=self.triplet.isf.function_id,
            producer_function=self.triplet.isf.function,
            resource_type="Parser",
            cleanup_function_id="src/parser.c:1:parser_free",
            cleanup_function="parser_free",
            consumers=("parser_next", "node_process"),
            nullable=True,
            evidence=("test evidence",),
            confidence=1.0,
        )
        triplet = replace(self.triplet, ownership_relations=(relation,))
        plan = json.loads(self.harness_plan())
        cleanup = plan["cleanup_sequence"][0]
        cleanup.update({
            "relation_id": relation.id,
            "producer_function": relation.producer_function,
            "resource_type": relation.resource_type,
            "producer_return_binding": {
                "kind": "return_value", "identifier": "item"
            },
            "arguments": ["item"],
            "after": ["parser_from_memory", "parser_next", "node_process"],
            "conditions": ["item"],
        })
        plan = parse_harness_plan(
            json.dumps(plan), triplet=triplet,
            isf_metadata=json.loads(
                (self.phase1_artifacts / "functions.json").read_text()
            )["functions"][0],
        )
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Parser *item = (Parser *)parser_from_memory((Parser *)data, data, (unsigned long)size);
    if (!item) { parser_free(item); }
    return 0;
}"""
        with self.assertRaisesRegex(Stage4Error, "lacks a null guard"):
            _validate_ownership_calls(_analyze_cpp(code).calls, triplet, plan)

    def test_rejects_ownership_cleanup_after_non_null_early_return(self):
        relation = TripletOwnershipRelation(
            id="own_parser_return",
            producer_function_id=self.triplet.isf.function_id,
            producer_function=self.triplet.isf.function,
            resource_type="Parser",
            cleanup_function_id="src/parser.c:1:parser_free",
            cleanup_function="parser_free",
            consumers=("parser_next", "node_process"),
            nullable=True,
            evidence=("test evidence",),
            confidence=1.0,
        )
        triplet = replace(self.triplet, ownership_relations=(relation,))
        plan = json.loads(self.harness_plan())
        cleanup = plan["cleanup_sequence"][0]
        cleanup.update({
            "relation_id": relation.id,
            "producer_function": relation.producer_function,
            "resource_type": relation.resource_type,
            "producer_return_binding": {
                "kind": "return_value", "identifier": "item"
            },
            "arguments": ["item"],
            "after": ["parser_from_memory", "parser_next", "node_process"],
            "conditions": ["item"],
        })
        plan = parse_harness_plan(
            json.dumps(plan), triplet=triplet,
            isf_metadata=json.loads(
                (self.phase1_artifacts / "functions.json").read_text()
            )["functions"][0],
        )
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Parser *item = (Parser *)parser_from_memory((Parser *)data, data, (unsigned long)size);
    if (item) return 0;
    if (item != NULL) { parser_free(item); }
    return 0;
}"""
        with self.assertRaisesRegex(Stage4Error, "unreachable on a non-null return path"):
            _validate_ownership_calls(_analyze_cpp(code).calls, triplet, plan)

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
