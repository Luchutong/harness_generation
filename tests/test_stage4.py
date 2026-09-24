import json
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from harness_generation.artifacts import ArtifactStore
from harness_generation.fuzzer_build import FuzzerBuildValidator
from harness_generation.llm import MockLLM
from harness_generation.policy import FORBIDDEN_LOGGING_FUNCTIONS
from harness_generation.prompts import get_prompt_template
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.stage4 import (
    HarnessPlan,
    Stage4Error,
    Stage4Generator,
    _analyze_cpp,
    _isf_uses_external_input,
    _validate_non_null_encoder_arguments,
    _validate_callback_bindings,
    _validate_ownership_calls,
    _validate_parent_plan_revision,
    generate_stage4_harness,
    parse_harness_plan,
)
from harness_generation.target_contract import TargetContract
from harness_generation.target_build import TargetBuildConfig
from harness_generation.triplet import (
    FunctionTriplet,
    TripletEdge,
    TripletFunction,
    TripletOwnershipRelation,
)
from harness_generation.triplet_extractor import extract_function_triplets
from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.semantic import MockSemanticAnalyzer
from tests.toolchain_probe import LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON


REPOSITORY = Path(__file__).resolve().parents[1]
SIMPLE_PROJECT = REPOSITORY / "tests" / "fixtures" / "simple_project"

_MD_PARSER_FIELDS = (
    ("enter_block", "int", ["MD_BLOCKTYPE", "void*", "void*"]),
    ("leave_block", "int", ["MD_BLOCKTYPE", "void*", "void*"]),
    ("enter_span", "int", ["MD_SPANTYPE", "void*", "void*"]),
    ("leave_span", "int", ["MD_SPANTYPE", "void*", "void*"]),
    ("text", "int", ["MD_TEXTTYPE", "const MD_CHAR*", "MD_SIZE", "void*"]),
    ("debug_log", "void", ["const char*", "void*"]),
    ("syntax", "void", []),
)
# ``syntax`` and ``debug_log`` are the two members md4c's header documents as
# reserved/optional; every other member is dereferenced unconditionally.
_OPTIONAL_MEMBERS = frozenset({"debug_log", "syntax"})
_MD_PARSER_REQUIRED = frozenset(
    name for name, _return, _parameters in _MD_PARSER_FIELDS
    if name not in _OPTIONAL_MEMBERS
)


def _md_parser_context(required=_MD_PARSER_REQUIRED):
    return {
        "callback_tables": [{
            "type": "MD_PARSER",
            "file": "md4c.h",
            "fields": [
                {
                    "name": name,
                    "declarator": f"{return_type} (*{name})(...)",
                    "return_type": return_type,
                    "parameter_types": list(parameters),
                    "required": name in required,
                }
                for name, return_type, parameters in _MD_PARSER_FIELDS
            ],
        }],
    }


CALLBACK_CONTEXT = {
    **_md_parser_context(),
    "callback_typedefs": [{
        "name": "JSTextFilterFun",
        "file": "common.h",
        "declaration": (
            "typedef int(*JSTextFilterFun)( const char* metaptr, u32 metalen, "
            "const char* inptr, u32 inlen, const char** outptrp);"
        ),
        "return_type": "int",
        "parameter_types": ["const char*", "u32", "const char*", "u32", "const char**"],
    }],
}

MD_PARSE_METADATA = {
    "name": "md_parse",
    "parameters": [
        {"name": "text", "base_type": "char", "type": "const char *",
         "pointer_depth": 1, "is_pointer": True, "is_struct_like": False},
        {"name": "size", "base_type": "unsigned", "type": "MD_SIZE",
         "pointer_depth": 0, "is_pointer": False, "is_struct_like": False},
        {"name": "parser", "base_type": "MD_PARSER", "type": "const MD_PARSER *",
         "pointer_depth": 1, "is_pointer": True, "is_struct_like": True},
        {"name": "userdata", "base_type": "void", "type": "void *",
         "pointer_depth": 1, "is_pointer": True, "is_struct_like": False},
    ],
}

PARSE_UTF8_METADATA = {
    "name": "parseUTF8",
    "parameters": [
        {"name": "inbufptr", "base_type": "char", "type": "const char *",
         "pointer_depth": 1, "is_pointer": True, "is_struct_like": False},
        {"name": "inbuflen", "base_type": "uint32_t", "type": "u32",
         "pointer_depth": 0, "is_pointer": False, "is_struct_like": False},
        {"name": "parser_flags", "base_type": "uint32_t", "type": "u32",
         "pointer_depth": 0, "is_pointer": False, "is_struct_like": False},
        {"name": "outflags", "base_type": "OutputFlags", "type": "OutputFlags",
         "pointer_depth": 0, "is_pointer": False, "is_struct_like": False},
        {"name": "outptr", "base_type": "char", "type": "const char **",
         "pointer_depth": 2, "is_pointer": True, "is_struct_like": False},
        {"name": "onCodeBlock", "base_type": "JSTextFilterFun",
         "type": "JSTextFilterFun", "pointer_depth": 0, "is_pointer": False,
         "is_struct_like": False},
    ],
}


class Stage4Tests(unittest.TestCase):
    def test_cpp_casts_are_not_project_calls(self):
        analysis = _analyze_cpp("""#include <stddef.h>
#include <stdint.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_input(reinterpret_cast<const char *>(data),
                static_cast<unsigned>(size));
    return 0;
}
""")
        self.assertEqual([call.name for call in analysis.calls], ["parse_input"])

    @staticmethod
    def _string_isf_uses_fuzzer_input(statements):
        code = f"""#include <stddef.h>
#include <stdint.h>
#include <string.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    {statements}
    return 0;
}}"""
        analysis = _analyze_cpp(code)
        entry = next(
            function for function in analysis.functions
            if function.name == "LLVMFuzzerTestOneInput"
        )
        call = next(call for call in entry.calls if call.name == "write_string")
        metadata = {"parameters": [
            {"name": "out", "base_type": "void", "is_pointer": True,
             "is_struct_like": True},
            {"name": "str", "base_type": "char", "is_pointer": True,
             "is_struct_like": False},
        ]}
        return _isf_uses_external_input(call, metadata, entry.assignments)

    def test_copy_into_nul_terminated_buffer_reaches_string_isf(self):
        self.assertTrue(self._string_isf_uses_fuzzer_input("""
    char *copy = (char *)malloc(size + 1);
    memcpy(copy, data, size);
    copy[size] = '\\0';
    write_string(out, copy);"""))

    def test_copy_into_vector_data_reaches_string_isf(self):
        self.assertTrue(self._string_isf_uses_fuzzer_input("""
    std::vector<char> buffer;
    buffer.resize(size + 1);
    std::memcpy(buffer.data(), data, size);
    buffer[size] = '\\0';
    write_string(out, buffer.data());"""))

    def test_transitive_copy_reaches_string_isf(self):
        self.assertTrue(self._string_isf_uses_fuzzer_input("""
    char a[128], b[128];
    memcpy(a, data, size);
    memmove(b, a, size);
    write_string(out, b);"""))

    def test_bytewise_copy_still_reaches_string_isf(self):
        self.assertTrue(self._string_isf_uses_fuzzer_input("""
    char copy[128];
    copy[0] = data[0];
    write_string(out, copy);"""))

    def test_copy_from_unrelated_bytes_does_not_reach_string_isf(self):
        self.assertFalse(self._string_isf_uses_fuzzer_input("""
    char copy[128], unrelated[128];
    memcpy(copy, unrelated, size);
    write_string(out, copy);"""))
        self.assertFalse(self._string_isf_uses_fuzzer_input("""
    char copy[128];
    memset(copy, 'A', size);
    write_string(out, copy);"""))
        self.assertFalse(self._string_isf_uses_fuzzer_input("""
    write_string(out, "constant");
    (void)data; (void)size;"""))

    def test_copy_n_from_fuzzer_data_reaches_string_isf(self):
        self.assertTrue(self._string_isf_uses_fuzzer_input("""
    char copy[128];
    std::copy_n(data, size, copy);
    write_string(out, copy);"""))

    def test_copy_after_isf_does_not_supply_input(self):
        self.assertFalse(self._string_isf_uses_fuzzer_input("""
    char copy[128];
    write_string(out, copy);
    memcpy(copy, data, size);"""))

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
            get_prompt_template("stage4_harness_transform").version,
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
            attempt_metadata["prompt_version"],
            get_prompt_template("stage4_harness_transform").version,
        )
        self.assertEqual(
            attempt_metadata["plan_prompt_version"],
            get_prompt_template("stage4_harness_plan").version,
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

    def test_rejects_a_plan_that_calls_a_function_twice(self):
        # Nothing else exercises this rule. With no ownership relation recording
        # a repetition, every FT function is owed exactly one call, so a second
        # entry is a plan that would acquire or release the same thing twice.
        plan = json.loads(self.harness_plan())
        plan["call_sequence"].append(dict(plan["call_sequence"][1]))
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(
                Stage4Error, "duplicates FT functions: parser_next"
            ):
                Stage4Generator(
                    MockLLM([json.dumps(plan), self.harness_code()])
                ).run(
                    self.triplet,
                    rough_code=self.rough_code(),
                    functions_json=self.phase1_artifacts / "functions.json",
                    artifacts=Path(temporary),
                )

    def test_allows_the_repetition_an_ownership_relation_records(self):
        # The exception to the rule above: when a relation's observed_sequence
        # records a function more than once, repeating it that many times is
        # the proven usage, not a duplicate.
        relation = TripletOwnershipRelation(
            id="or_parser_reused_0001",
            producer_function_id=self.triplet.isf.function_id,
            producer_function=self.triplet.isf.function,
            resource_type="Parser",
            cleanup_argument="address_of_return_value",
            cleanup_function="parser_free",
            cleanup_function_id=next(
                function.function_id for function in self.triplet.functions
                if function.function == "parser_free"
            ),
            consumers=("parser_next",),
            path_kind="normal",
            nullable=False,
            observed_sequence=(
                "parser_from_memory", "parser_from_memory", "parser_free"
            ),
        )
        triplet = replace(self.triplet, ownership_relations=(relation,))
        plan = json.loads(self.harness_plan())
        plan["call_sequence"].insert(1, dict(plan["call_sequence"][0]))
        plan["cleanup_sequence"][0].update({
            "relation_id": relation.id,
            "producer_function": relation.producer_function,
            "resource_type": relation.resource_type,
            "after": [*plan["cleanup_sequence"][0]["after"],
                      relation.producer_function],
            "producer_binding": {
                "kind": "return_value", "identifier": "parser",
            },
        })
        parsed = parse_harness_plan(
            json.dumps(plan), triplet=triplet,
            isf_metadata=json.loads(
                (self.phase1_artifacts / "functions.json").read_text()
            )["functions"][0],
        )
        self.assertEqual(
            [item["function"] for item in parsed.call_sequence].count(
                "parser_from_memory"
            ),
            2,
        )
        # The same plan is a duplicate the moment no relation records the
        # repetition, so the allowance above is what let it through.
        with self.assertRaisesRegex(Stage4Error, "duplicates FT functions"):
            parse_harness_plan(
                json.dumps(plan),
                triplet=replace(triplet, ownership_relations=()),
                isf_metadata=json.loads(
                    (self.phase1_artifacts / "functions.json").read_text()
                )["functions"][0],
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

    def test_out_parameter_ownership_binds_producer_and_cleanup_arguments(self):
        relation = TripletOwnershipRelation(
            id="own_out_parser",
            producer_function_id=self.triplet.isf.function_id,
            producer_function=self.triplet.isf.function,
            resource_type="Parser",
            cleanup_function_id="src/parser.c:1:parser_free",
            cleanup_function="parser_free",
            cleanup_argument="address_of_return_value",
            consumers=("parser_next", "node_process"),
            nullable=False,
            evidence=("tests/parser_test.c:8",),
            confidence=0.9,
            source="usage_mining",
            producer_binding="out_parameter",
            producer_argument_index=0,
            lifecycle_kind="owned_resource",
            support_total=2,
            support_by_source={"test": 2},
            usage_pattern_id="up_out_parser",
        )
        triplet = replace(self.triplet, ownership_relations=(relation,))
        plan = json.loads(self.harness_plan())
        plan["cleanup_sequence"][0].update({
            "relation_id": relation.id,
            "producer_function": relation.producer_function,
            "resource_type": relation.resource_type,
            "producer_binding": {"kind": "out_parameter", "identifier": "parser"},
            "arguments": ["&parser"],
            "after": ["parser_from_memory", "parser_next", "node_process"],
        })
        parsed = parse_harness_plan(
            json.dumps(plan), triplet=triplet,
            isf_metadata=json.loads(
                (self.phase1_artifacts / "functions.json").read_text()
            )["functions"][0],
        )
        _validate_ownership_calls(
            _analyze_cpp(self.harness_code()).calls, triplet, parsed
        )

    def _parallel_producer_triplet_and_plan(self, relation_id, cleanup_item=True,
                                            producer="parse"):
        """Build a triplet whose step has two implementations, each with a relation.

        ``parse`` and ``parse_alt`` share the ``(null) -> Context`` structural
        step, exactly as ``json_parse`` and ``json_parse_ex`` share
        ``(null) -> json_value``.  Each one produces a value that ``destroy``
        releases, so both relations describe the same obligation.
        """

        def declared(name, roles, line):
            return TripletFunction(
                f"src/parser.c:{line}:{name}", name, roles, "src/parser.c", line
            )

        isf = declared("parse", ("ISF", "PRF"), 3)
        alternate = declared("parse_alt", ("PRF",), 13)
        hpf = declared("destroy", ("HPF",), 25)
        edges = tuple(
            TripletEdge(
                function.function_id, function.function, "(null)", "Context",
                function.roles, function.file, function.line,
            )
            for function in (isf, alternate)
        ) + (TripletEdge(
            hpf.function_id, hpf.function, "Context", "(null)",
            hpf.roles, hpf.file, hpf.line,
        ),)
        relations = {
            name: TripletOwnershipRelation(
                id=name,
                producer_function_id=source.function_id,
                producer_function=source.function,
                resource_type="Context",
                cleanup_function_id=hpf.function_id,
                cleanup_function=hpf.function,
                nullable=False,
                evidence=("tests/parser_test.c:8",),
                confidence=0.9,
            )
            for name, source in (("own_parse", isf), ("own_parse_alt", alternate))
        }
        triplet = FunctionTriplet(
            isf, (isf, alternate), (hpf,), (isf, alternate, hpf),
            ("Context",), edges,
            {"structural_alternatives": [{
                "functions": ["parse", "parse_alt"],
                "evidence": "parse delegates to parse_alt",
            }]},
            ownership_relations=tuple(relations.values()),
        )
        plan = {
            "schema_version": 1,
            "triplet_id": triplet.id,
            "entrypoint": "LLVMFuzzerTestOneInput",
            "input_strategy": {
                "description": "Pass fuzzer bytes into parse.",
                "data_identifier": "data",
                "size_identifier": "size",
                "bounded_steps": 1,
                "notes": [],
            },
            "state_objects": [],
            "call_sequence": [{
                "function": producer,
                "roles": ["ISF", "PRF"],
                "purpose": "build a Context from fuzzer input",
                "arguments": ["data", "size"],
                "uses_fuzzer_data": True,
                "uses_fuzzer_size": True,
                "outputs": ["Context*"],
                "conditions": [],
            }],
            "cleanup_sequence": [{
                "function": "destroy",
                "purpose": "release the Context",
                "arguments": ["context"],
                "relation_id": relation_id,
                "producer_function": relations[relation_id].producer_function,
                "resource_type": "Context",
                "producer_binding": {"kind": "return_value", "identifier": "context"},
                "after": [relations[relation_id].producer_function],
                "conditions": [],
            }] if cleanup_item else [],
            "constraints": [],
            "notes": [],
        }
        return triplet, json.dumps(plan)

    def test_stage4_plan_owes_one_cleanup_per_called_producer(self):
        triplet, plan = self._parallel_producer_triplet_and_plan("own_parse")
        parsed = parse_harness_plan(
            plan, triplet=triplet, isf_metadata={"name": "parse"}
        )
        self.assertEqual(
            [item["relation_id"] for item in parsed.cleanup_sequence], ["own_parse"]
        )
        _validate_ownership_calls(
            _analyze_cpp("""#include <stddef.h>
#include <stdint.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Context *context = parse(data, size);
    if (context != NULL) { destroy(context); }
    return 0;
}""").calls,
            triplet,
            parsed,
        )

    def test_stage4_plan_owes_a_cleanup_for_the_producer_it_calls(self):
        triplet, plan = self._parallel_producer_triplet_and_plan(
            "own_parse", cleanup_item=False
        )
        with self.assertRaisesRegex(
            Stage4Error,
            "must include exactly one cleanup for ownership relations: own_parse",
        ):
            parse_harness_plan(plan, triplet=triplet, isf_metadata={"name": "parse"})

    def test_stage4_plan_rejects_a_cleanup_bound_to_an_uncalled_alternative(self):
        triplet, plan = self._parallel_producer_triplet_and_plan("own_parse_alt")
        with self.assertRaisesRegex(Stage4Error, "must include exactly one cleanup"):
            parse_harness_plan(plan, triplet=triplet, isf_metadata={"name": "parse"})

    def test_error_path_cleanup_requires_a_real_code_guard(self):
        relation = TripletOwnershipRelation(
            id="own_error_parser",
            producer_function_id=self.triplet.isf.function_id,
            producer_function=self.triplet.isf.function,
            resource_type="Parser",
            cleanup_function_id="src/parser.c:1:parser_free",
            cleanup_function="parser_free",
            cleanup_argument="address_of_return_value",
            consumers=("parser_next", "node_process"),
            nullable=False,
            evidence=("src/client.c:20",), confidence=0.9,
            source="usage_mining", producer_binding="out_parameter",
            producer_argument_index=0, lifecycle_kind="owned_resource",
            conditions=("rc != 0",), path_kind="error", support_total=1,
            support_by_source={"production": 1}, usage_pattern_id="up_error_parser",
        )
        triplet = replace(self.triplet, ownership_relations=(relation,))
        plan_value = json.loads(self.harness_plan())
        plan_value["cleanup_sequence"][0].update({
            "relation_id": relation.id, "producer_function": relation.producer_function,
            "resource_type": relation.resource_type,
            "producer_binding": {"kind": "out_parameter", "identifier": "parser"},
            "arguments": ["&parser"],
            "after": ["parser_from_memory", "parser_next", "node_process"],
            "conditions": ["status != 0"],
        })
        parsed = parse_harness_plan(
            json.dumps(plan_value), triplet=triplet,
            isf_metadata=json.loads(
                (self.phase1_artifacts / "functions.json").read_text()
            )["functions"][0],
        )
        unguarded = self.harness_code()
        with self.assertRaisesRegex(Stage4Error, "error-path cleanup parser_free lacks a guard"):
            _validate_ownership_calls(_analyze_cpp(unguarded).calls, triplet, parsed)
        guarded = unguarded.replace(
            "    parser_free(&parser);",
            "    if (size > 1) { parser_free(&parser); }",
        )
        _validate_ownership_calls(_analyze_cpp(guarded).calls, triplet, parsed)

    def test_reference_count_relation_binds_existing_argument(self):
        relation = TripletOwnershipRelation(
            id="own_ref_parser",
            producer_function_id="src/parser.c:13:parser_next",
            producer_function="parser_next",
            resource_type="Parser",
            cleanup_function_id="src/parser.c:1:parser_free",
            cleanup_function="parser_free",
            cleanup_argument="address_of_return_value",
            consumers=("node_process",), nullable=False,
            evidence=("src/client.c:11",), confidence=0.9,
            source="usage_mining", producer_binding="existing_argument",
            producer_argument_index=0, lifecycle_kind="reference_count",
            support_total=1, support_by_source={"production": 1},
            usage_pattern_id="up_ref_parser",
        )
        triplet = replace(self.triplet, ownership_relations=(relation,))
        plan_value = json.loads(self.harness_plan())
        plan_value["cleanup_sequence"][0].update({
            "relation_id": relation.id, "producer_function": "parser_next",
            "resource_type": "Parser",
            "producer_binding": {"kind": "existing_argument", "identifier": "parser"},
            "arguments": ["&parser"],
            "after": ["parser_next", "node_process"],
        })
        parsed = parse_harness_plan(
            json.dumps(plan_value), triplet=triplet,
            isf_metadata=json.loads(
                (self.phase1_artifacts / "functions.json").read_text()
            )["functions"][0],
        )
        _validate_ownership_calls(
            _analyze_cpp(self.harness_code()).calls, triplet, parsed
        )

    def test_observed_sequence_preserves_repeated_api_calls_in_plan_and_code(self):
        relation = TripletOwnershipRelation(
            id="own_repeated_parse",
            producer_function_id=self.triplet.isf.function_id,
            producer_function=self.triplet.isf.function,
            resource_type="Parser",
            cleanup_function_id="src/parser.c:1:parser_free",
            cleanup_function="parser_free",
            cleanup_argument="address_of_return_value",
            consumers=("parser_next", "node_process"), nullable=False,
            evidence=("tests/repeated.c:8",), confidence=0.9,
            source="usage_mining+llm", producer_binding="out_parameter",
            producer_argument_index=0, lifecycle_kind="owned_resource",
            support_total=2, support_by_source={"test": 2},
            usage_pattern_id="usg_repeated",
            observed_sequence=(
                "parser_from_memory", "parser_next", "parser_next",
                "node_process", "parser_free",
            ),
        )
        triplet = replace(self.triplet, ownership_relations=(relation,))
        plan_value = json.loads(self.harness_plan())
        repeated = dict(plan_value["call_sequence"][1])
        repeated["purpose"] = "read a second node"
        plan_value["call_sequence"].insert(2, repeated)
        plan_value["cleanup_sequence"][0].update({
            "relation_id": relation.id,
            "producer_function": relation.producer_function,
            "resource_type": relation.resource_type,
            "producer_binding": {"kind": "out_parameter", "identifier": "parser"},
            "arguments": ["&parser"],
            "after": ["parser_from_memory", "parser_next", "node_process"],
        })
        metadata = json.loads(
            (self.phase1_artifacts / "functions.json").read_text()
        )["functions"][0]
        parsed = parse_harness_plan(
            json.dumps(plan_value), triplet=triplet, isf_metadata=metadata
        )
        code = self.harness_code().replace(
            "    Node node = parser_next(&parser);",
            "    Node node = parser_next(&parser);\n"
            "    Node node2 = parser_next(&parser);\n"
            "    (void)node2;",
        )
        _validate_ownership_calls(_analyze_cpp(code).calls, triplet, parsed)

        missing_repeat = json.loads(json.dumps(plan_value))
        del missing_repeat["call_sequence"][2]
        with self.assertRaisesRegex(Stage4Error, "preserve observed usage sequence"):
            parse_harness_plan(
                json.dumps(missing_repeat), triplet=triplet, isf_metadata=metadata
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

    def test_unnamed_pointer_parameters_keep_their_pointer_depth(self):
        # A callback implemented with commented-out parameter names still has to
        # match the declared signature; ``void*`` parses as an abstract
        # declarator, which the depth counter has to recognize.
        analysis = _analyze_cpp("""#include <stddef.h>
#include <stdint.h>
int render(MD_BLOCKTYPE /*type*/, void* /*detail*/, const MD_CHAR* /*text*/)
{
    return 0;
}
""")
        render = next(
            function for function in analysis.functions if function.name == "render"
        )
        self.assertEqual(
            [
                (parameter.base_type, parameter.pointer_depth)
                for parameter in render.parameters
            ],
            [("MD_BLOCKTYPE", 0), ("void", 1), ("MD_CHAR", 1)],
        )

    def test_callback_bindings_reject_a_zeroed_required_callback_table(self):
        # md4c dereferences every rendering callback unconditionally, so a table
        # that is only zero-initialized crashes the moment it renders the doc.
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" int md_parse(const char *text, int size, const MD_PARSER *parser,
                        void *userdata);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    MD_PARSER parser = {0};
    parser.flags = 1;
    (void)md_parse((const char *)data, (int)size, &parser, NULL);
    return 0;
}"""
        with self.assertRaisesRegex(Stage4Error, r"MD_PARSER\.enter_block"):
            self._validate_callback_bindings(code, MD_PARSE_METADATA)

    def test_callback_bindings_accept_the_reference_md_parse_shape(self):
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" int md_parse(const char *text, int size, const MD_PARSER *parser,
                        void *userdata);
static int enter_block(MD_BLOCKTYPE type, void *detail, void *userdata) {
    (void)type; (void)detail; (void)userdata; return 0;
}
static int leave_block(MD_BLOCKTYPE type, void *detail, void *userdata) {
    (void)type; (void)detail; (void)userdata; return 0;
}
static int enter_span(MD_SPANTYPE type, void *detail, void *userdata) {
    (void)type; (void)detail; (void)userdata; return 0;
}
static int leave_span(MD_SPANTYPE type, void *detail, void *userdata) {
    (void)type; (void)detail; (void)userdata; return 0;
}
static int text(MD_TEXTTYPE type, const MD_CHAR *value, MD_SIZE size,
                void *userdata) {
    (void)type; (void)value; (void)size; (void)userdata; return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    MD_PARSER parser = {0};
    parser.flags = 1;
    parser.enter_block = enter_block;
    parser.leave_block = leave_block;
    parser.enter_span = enter_span;
    parser.leave_span = leave_span;
    parser.text = text;
    (void)md_parse((const char *)data, (int)size, &parser, NULL);
    return 0;
}"""
        self._validate_callback_bindings(code, MD_PARSE_METADATA)

    def test_callback_bindings_allow_a_null_optional_member(self):
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" int md_parse(const char *text, int size, const MD_PARSER *parser,
                        void *userdata);
static int enter_block(MD_BLOCKTYPE type, void *detail, void *userdata) {
    (void)type; (void)detail; (void)userdata; return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    MD_PARSER parser = {0};
    parser.enter_block = enter_block;
    (void)md_parse((const char *)data, (int)size, &parser, NULL);
    return 0;
}"""
        # debug_log and syntax are documented optional/reserved; the rest are
        # required, so only the assigned member may carry a null.
        self._validate_callback_bindings(
            code, MD_PARSE_METADATA,
            project_context=_md_parser_context(required={"enter_block"}),
        )

    def test_callback_bindings_reject_a_mismatched_table_member(self):
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" int md_parse(const char *text, int size, const MD_PARSER *parser,
                        void *userdata);
static int enter_block(void *userdata) { (void)userdata; return 0; }
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    MD_PARSER parser = {0};
    parser.enter_block = enter_block;
    (void)md_parse((const char *)data, (int)size, &parser, NULL);
    return 0;
}"""
        with self.assertRaisesRegex(Stage4Error, "must have signature|takes 1 parameter"):
            self._validate_callback_bindings(code, MD_PARSE_METADATA)

    def test_callback_bindings_reject_an_invented_callback_signature(self):
        # fmt_html calls onCodeBlock through JSTextFilterFun; a 3-argument
        # helper handed to that slot is undefined behaviour at call time.
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" unsigned long parseUTF8(const char *inbufptr, unsigned inbuflen,
                                   unsigned parser_flags, int outflags,
                                   const char **outptr,
                                   JSTextFilterFun onCodeBlock);
static int code_block_filter(void *userdata, const char *text, size_t len) {
    (void)userdata; (void)text; (void)len; return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const char *output = nullptr;
    (void)parseUTF8((const char *)data, (unsigned)size, 0, 1, &output,
                    code_block_filter);
    return 0;
}"""
        with self.assertRaisesRegex(Stage4Error, "takes 3 parameter"):
            self._validate_callback_bindings(code, PARSE_UTF8_METADATA)

    def test_callback_bindings_accept_a_null_or_matching_typedef_argument(self):
        template = """#include <stddef.h>
#include <stdint.h>
extern "C" unsigned long parseUTF8(const char *inbufptr, unsigned inbuflen,
                                   unsigned parser_flags, int outflags,
                                   const char **outptr,
                                   JSTextFilterFun onCodeBlock);
static int filter(const char *metaptr, uint32_t metalen, const char *inptr,
                  uint32_t inlen, const char **outptrp) {
    (void)metaptr; (void)metalen; (void)inptr; (void)inlen; (void)outptrp;
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const char *output = nullptr;
    (void)parseUTF8((const char *)data, (unsigned)size, 0, 1, &output, %s);
    return 0;
}"""
        self._validate_callback_bindings(template % "nullptr", PARSE_UTF8_METADATA)
        self._validate_callback_bindings(template % "filter", PARSE_UTF8_METADATA)
        self._validate_callback_bindings(
            template % "reinterpret_cast<void *>(filter)", PARSE_UTF8_METADATA
        )

    def test_callback_bindings_accept_a_matching_function_pointer_variable(self):
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" unsigned long parseUTF8(const char *inbufptr, unsigned inbuflen,
                                   unsigned parser_flags, int outflags,
                                   const char **outptr,
                                   JSTextFilterFun onCodeBlock);
static int filter_a(const char *metaptr, uint32_t metalen, const char *inptr,
                    uint32_t inlen, const char **outptrp) {
    (void)metaptr; (void)metalen; (void)inptr; (void)inlen; (void)outptrp;
    return 0;
}
static int filter_b(const char *metaptr, uint32_t metalen, const char *inptr,
                    uint32_t inlen, const char **outptrp) {
    (void)metaptr; (void)metalen; (void)inptr; (void)inlen; (void)outptrp;
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const char *output = nullptr;
    JSTextFilterFun cb = filter_a;
    if (size != 0 && data[0] != 0) cb = filter_b;
    (void)parseUTF8((const char *)data, (unsigned)size, 0, 1, &output,
                    reinterpret_cast<void *>(cb));
    return 0;
}"""
        self._validate_callback_bindings(code, PARSE_UTF8_METADATA)

    def test_callback_bindings_accept_a_non_null_helper_ternary(self):
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" unsigned long parseUTF8(const char *inbufptr, unsigned inbuflen,
                                   unsigned parser_flags, int outflags,
                                   const char **outptr,
                                   JSTextFilterFun onCodeBlock);
static int filter_a(const char *metaptr, uint32_t metalen, const char *inptr,
                    uint32_t inlen, const char **outptrp) {
    (void)metaptr; (void)metalen; (void)inptr; (void)inlen; (void)outptrp;
    return 0;
}
static int filter_b(const char *metaptr, uint32_t metalen, const char *inptr,
                    uint32_t inlen, const char **outptrp) {
    (void)metaptr; (void)metalen; (void)inptr; (void)inlen; (void)outptrp;
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const char *output = nullptr;
    JSTextFilterFun cb = (size != 0 && data[0] != 0) ? filter_a : filter_b;
    (void)parseUTF8((const char *)data, (unsigned)size, 0, 1, &output, cb);
    return 0;
}"""
        self._validate_callback_bindings(code, PARSE_UTF8_METADATA)

    def test_callback_signature_comparison_ignores_declared_parameter_names(self):
        context = {
            "callback_typedefs": [{
                "name": "EscapeFun",
                "return_type": "int",
                "parameter_types": [
                    "unsigned char *out",
                    "int *outlen",
                    "const unsigned char *in",
                    "int *inlen",
                ],
            }]
        }
        metadata = {
            "name": "writeEscape",
            "parameters": [
                {"name": "cb", "base_type": "EscapeFun", "type": "EscapeFun",
                 "is_pointer": False, "is_struct_like": False},
            ],
        }
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" int writeEscape(EscapeFun cb);
static int escape(unsigned char *out, int *outlen, const unsigned char *in,
                  int *inlen) {
    (void)out; (void)outlen; (void)in; (void)inlen;
    return 0;
}
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)data; (void)size;
    return writeEscape(escape);
}"""
        self._validate_callback_bindings(code, metadata, context)

    def test_callback_bindings_reject_null_typedef_argument_in_aggressive_mode(self):
        code = """#include <stddef.h>
#include <stdint.h>
extern "C" unsigned long parseUTF8(const char *inbufptr, unsigned inbuflen,
                                   unsigned parser_flags, int outflags,
                                   const char **outptr,
                                   JSTextFilterFun onCodeBlock);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const char *output = nullptr;
    (void)parseUTF8((const char *)data, (unsigned)size, 0, 1, &output, nullptr);
    return 0;
}"""
        analysis = _analyze_cpp(code)
        entry = next(
            function for function in analysis.functions
            if function.name == "LLVMFuzzerTestOneInput"
        )
        calls = [call for call in entry.calls if call.name == "parseUTF8"]
        with self.assertRaisesRegex(Stage4Error, "non-null harness function"):
            _validate_callback_bindings(
                analysis,
                entry,
                calls,
                PARSE_UTF8_METADATA,
                CALLBACK_CONTEXT,
                require_non_null_typedef_callbacks=True,
            )

    def test_aggressive_encoder_validation_rejects_null_encoder(self):
        code = """#include <stddef.h>
#include <stdint.h>
typedef struct Encoder Encoder;
extern "C" int writeWithEncoder(const uint8_t *data, size_t size, Encoder *encoder);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return writeWithEncoder(data, size, nullptr);
}"""
        analysis = _analyze_cpp(code)
        entry = next(
            function for function in analysis.functions
            if function.name == "LLVMFuzzerTestOneInput"
        )
        metadata = {
            "writeWithEncoder": {
                "name": "writeWithEncoder",
                "parameters": [
                    {"name": "data", "base_type": "uint8_t", "type": "const uint8_t *",
                     "is_pointer": True},
                    {"name": "size", "base_type": "size_t", "type": "size_t",
                     "is_pointer": False},
                    {"name": "encoder", "base_type": "Encoder", "type": "Encoder *",
                     "is_pointer": True},
                ],
            }
        }
        with self.assertRaisesRegex(Stage4Error, "encoder argument"):
            _validate_non_null_encoder_arguments(tuple(entry.calls), metadata)

    def _validate_callback_bindings(
        self, code, isf_metadata, project_context=None
    ):
        analysis = _analyze_cpp(code)
        entry = next(
            function for function in analysis.functions
            if function.name == "LLVMFuzzerTestOneInput"
        )
        isf_name = isf_metadata["name"]
        isf_calls = [call for call in entry.calls if call.name == isf_name]
        self.assertTrue(isf_calls)
        _validate_callback_bindings(
            analysis,
            entry,
            isf_calls,
            isf_metadata,
            project_context if project_context is not None else CALLBACK_CONTEXT,
        )

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
