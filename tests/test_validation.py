import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.policy import FORBIDDEN_LOGGING_FUNCTIONS
from harness_generation.triplet import (
    FunctionTriplet,
    TripletEdge,
    TripletFunction,
)
from harness_generation.triplet_extractor import extract_function_triplets
from harness_generation.validation import (
    IntermediateValidator,
    ValidationResult,
    is_stable_eligible,
    validate_intermediate,
)
from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.semantic import MockSemanticAnalyzer


REPOSITORY = Path(__file__).resolve().parents[1]
SIMPLE_PROJECT = REPOSITORY / "tests" / "fixtures" / "simple_project"


class IntermediateValidationTests(unittest.TestCase):
    def test_successful_validation_is_written_with_uniform_schema(self):
        source = """#include <string.h>
void generated(void) {
    parse_input();
    memcpy(0, 0, 0);
}"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "generation" / "validation.json"
            result = validate_intermediate(
                source,
                expected_functions=("parse_input",),
                target_functions=("parse_input", "process_item"),
                validation_path=path,
                stage="stage3",
            )
            persisted = json.loads(path.read_text(encoding="utf-8"))

        self.assertTrue(result.success)
        self.assertEqual(result.errors, ())
        self.assertEqual(
            set(persisted),
            {"validator", "status", "success", "errors", "warnings", "metadata"},
        )
        self.assertEqual(persisted["validator"], "intermediate")
        self.assertEqual(persisted["status"], "passed")
        self.assertEqual(persisted, result.to_dict())
        self.assertEqual(persisted["metadata"]["parser"], "tree-sitter-c")
        self.assertEqual(
            persisted["metadata"]["observed_function_calls"],
            ["memcpy", "parse_input"],
        )

    def test_reports_missing_unexpected_and_unknown_calls(self):
        source = """void generated(void) {
    other_target();
    invented_api();
}"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "validation.json"
            result = IntermediateValidator().validate(
                source,
                expected_functions=("parse_input",),
                target_functions=("parse_input", "other_target"),
                validation_path=path,
            )
            persisted = json.loads(path.read_text(encoding="utf-8"))

        self.assertFalse(result.success)
        self.assertTrue(any("missing expected functions" in error for error in result.errors))
        self.assertTrue(any("unexpected target function" in error for error in result.errors))
        self.assertTrue(any("unknown target APIs" in error for error in result.errors))
        self.assertEqual(
            result.metadata["unexpected_function_calls"],
            ["invented_api", "other_target"],
        )
        self.assertEqual(result.metadata["unknown_target_api_calls"], ["invented_api"])
        self.assertEqual(persisted, result.to_dict())

    def test_detects_duplicate_definitions_and_target_redefinition(self):
        source = """void parse_input(void) {}
void parse_input(void) {}
"""
        with tempfile.TemporaryDirectory() as temporary:
            result = validate_intermediate(
                source,
                expected_functions=(),
                target_functions=("parse_input",),
                validation_path=Path(temporary) / "validation.json",
            )

        self.assertFalse(result.success)
        self.assertEqual(
            result.metadata["duplicate_function_definitions"],
            {"parse_input": 2},
        )
        self.assertEqual(result.metadata["redefined_target_functions"], ["parse_input"])
        self.assertTrue(any("duplicate function definitions" in error for error in result.errors))
        self.assertTrue(any("redefined target functions" in error for error in result.errors))

    def test_cpp_harness_uses_tree_sitter_cpp_and_allows_simple_std_helpers(self):
        source = """#include <stddef.h>
#include <stdint.h>
#include <algorithm>
#include <vector>
extern "C" {
#include "parser.h"
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::vector<uint8_t> bytes(data, data + size);
    auto limit = std::min<size_t>(size, 32);
    auto call_parse = [&]() {
        parse_input(bytes.data(), limit);
    };
    call_parse();
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            result = validate_intermediate(
                source,
                expected_functions=("parse_input",),
                target_functions=("parse_input", "other_target"),
                validation_path=Path(temporary) / "validation.json",
                allowed_functions=("LLVMFuzzerTestOneInput",),
            )

        self.assertTrue(result.success)
        self.assertEqual(result.metadata["parser"], "tree-sitter-cpp")
        self.assertEqual(result.metadata["cpp_evidence"], [])
        self.assertEqual(
            result.metadata["observed_function_calls"],
            ["parse_input", "std::min"],
        )
        self.assertEqual(result.metadata["indirect_function_calls"], ["call_parse", "data"])

    def test_cpp_casts_are_not_counted_as_api_calls(self):
        source = """#include <stddef.h>
#include <stdint.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_input(reinterpret_cast<const char *>(data),
                static_cast<unsigned>(size));
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            result = validate_intermediate(
                source,
                expected_functions=("parse_input",),
                target_functions=("parse_input",),
                validation_path=Path(temporary) / "validation.json",
            )
        self.assertTrue(result.success, result.errors)
        self.assertEqual(result.metadata["observed_function_calls"], ["parse_input"])

    def test_cpp_syntax_errors_are_reported_with_cpp_parser(self):
        source = """#include <vector>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::vector<uint8_t> bytes(data, data + size)
    parse_input(bytes.data(), size);
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            result = validate_intermediate(
                source,
                expected_functions=("parse_input",),
                target_functions=("parse_input",),
                validation_path=Path(temporary) / "validation.json",
            )

        self.assertFalse(result.success)
        self.assertEqual(result.metadata["parser"], "tree-sitter-cpp")
        self.assertTrue(any("invalid tree-sitter-cpp syntax" in error
                            for error in result.errors))

    def test_detects_forbidden_io_and_logging_from_call_nodes(self):
        source = """void generated(void) {
    parse_input();
    printf("log");
    fprintf(0, "log");
    fopen("fixed", "rb");
}"""
        with tempfile.TemporaryDirectory() as temporary:
            result = validate_intermediate(
                source,
                expected_functions=("parse_input",),
                target_functions=("parse_input",),
                validation_path=Path(temporary) / "validation.json",
            )

        self.assertFalse(result.success)
        self.assertEqual(result.metadata["forbidden_logging_calls"],
                         ["fprintf", "printf"])
        self.assertEqual(result.metadata["forbidden_io_calls"], ["fopen"])
        self.assertTrue(any("forbidden logging" in error for error in result.errors))
        self.assertTrue(any("forbidden I/O" in error for error in result.errors))

    def test_rejects_every_forbidden_logging_function(self):
        self.assertEqual(FORBIDDEN_LOGGING_FUNCTIONS, frozenset({
            "fprintf", "perror", "printf", "putchar", "puts", "vfprintf", "vprintf",
        }))
        for name in sorted(FORBIDDEN_LOGGING_FUNCTIONS):
            source = f"void generated(void) {{ parse_input(); {name}(0); }}"
            with self.subTest(function=name), tempfile.TemporaryDirectory() as temporary:
                result = validate_intermediate(
                    source,
                    expected_functions=("parse_input",),
                    target_functions=("parse_input",),
                    validation_path=Path(temporary) / "validation.json",
                )
                self.assertEqual(result.metadata["forbidden_logging_calls"], [name])
                self.assertTrue(any("forbidden logging calls" in error
                                    for error in result.errors))

    def test_validate_triplet_uses_real_functions_and_artifact_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phase1 = root / "phase1"
            SFGPipeline(
                MockSemanticAnalyzer(), ignored_directories=DEFAULT_IGNORES
            ).run(SIMPLE_PROJECT, phase1)
            triplet = extract_function_triplets(load_sfg_artifacts(phase1))[0]
            source = """void generated(Parser *parser, const unsigned char *data) {
    parser_from_memory(parser, data, 1);
    Node node = parser_next(parser);
    node_process(&node);
    parser_free(parser);
}"""
            result = IntermediateValidator().validate_triplet(
                source,
                triplet,
                functions_json=phase1 / "functions.json",
                artifacts=root / "artifacts",
                stage="stage3",
            )
            output = (
                root / "artifacts" / "generation" / triplet.id
                / "validation" / "intermediate.json"
            )
            persisted = json.loads(output.read_text(encoding="utf-8"))

        self.assertTrue(result.success)
        self.assertEqual(persisted, result.to_dict())
        self.assertEqual(
            result.metadata["expected_functions"],
            ["node_process", "parser_free", "parser_from_memory", "parser_next"],
        )

    def test_validate_triplet_accepts_one_implementation_per_structural_step(self):
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
        triplet = FunctionTriplet(
            isf, (alternate,), (hpf,), (isf, alternate, hpf), ("Context",), edges,
            {"structural_alternatives": [{
                "functions": ["parse", "parse_alt"],
                "evidence": "parse delegates to parse_alt",
            }]},
        )

        def validate(source, root):
            functions_json = root / "functions.json"
            functions_json.write_text(json.dumps({
                "schema_version": 1,
                "functions": [{"name": "parse"}, {"name": "parse_alt"},
                              {"name": "destroy"}],
            }), encoding="utf-8")
            return IntermediateValidator().validate_triplet(
                source,
                triplet,
                functions_json=functions_json,
                artifacts=root / "artifacts",
                stage="stage3",
            )

        with tempfile.TemporaryDirectory() as temporary:
            accepted = validate("""void generated(void) {
    Context *context = parse_alt(0, 0);
    destroy(context);
}""", Path(temporary))
        with tempfile.TemporaryDirectory() as temporary:
            rejected = validate("""void generated(void) {
    Context *context = parse_alt(0, 0);
}""", Path(temporary))
        with tempfile.TemporaryDirectory() as temporary:
            empty = validate("void generated(void) {}", Path(temporary))

        self.assertTrue(accepted.success)
        self.assertEqual(accepted.metadata["missing_expected_functions"], [])
        self.assertEqual(
            accepted.metadata["expected_function_alternatives"],
            [["parse", "parse_alt"], ["destroy"]],
        )
        self.assertFalse(rejected.success)
        self.assertEqual(rejected.metadata["missing_expected_functions"], ["destroy"])
        self.assertEqual(
            empty.metadata["missing_expected_functions"],
            ["destroy", "parse or parse_alt"],
        )
        self.assertTrue(any("missing expected functions: destroy, parse or parse_alt"
                            in error for error in empty.errors))

    def test_function_pointer_call_is_a_warning_not_an_unknown_api(self):
        source = """void generated(void (*callback)(void)) {
    parse_input();
    callback();
}"""
        with tempfile.TemporaryDirectory() as temporary:
            result = validate_intermediate(
                source,
                expected_functions=("parse_input",),
                target_functions=("parse_input",),
                validation_path=Path(temporary) / "validation.json",
            )
        self.assertTrue(result.success)
        self.assertEqual(result.metadata["unknown_target_api_calls"], [])
        self.assertEqual(result.metadata["indirect_function_calls"], ["callback"])
        self.assertTrue(any("could not be resolved" in warning
                            for warning in result.warnings))

    def test_result_rejects_inconsistent_success_flag(self):
        with self.assertRaisesRegex(ValueError, "must agree"):
            ValidationResult(True, ("error",), (), {})

    def test_result_represents_non_success_terminal_statuses(self):
        for status in ("skipped", "unavailable"):
            with self.subTest(status=status):
                result = ValidationResult(
                    None,
                    (),
                    (f"validation {status}",),
                    {"validator": "test"},
                    status=status,
                )
                self.assertIsNone(result.success)
                self.assertFalse(result.accepted)
                self.assertEqual(result.to_dict()["status"], status)

        limited = ValidationResult(
            True,
            (),
            ("link validation unavailable",),
            {"validator": "stage4"},
            status="passed_with_limitations",
        )
        self.assertTrue(limited.success)
        self.assertTrue(limited.accepted)
        self.assertFalse(limited.stable_eligible)
        self.assertEqual(limited.to_dict()["status"], "passed_with_limitations")

    def test_only_unqualified_pass_is_stable_eligible(self):
        for status in ("passed_with_limitations", "skipped", "unavailable"):
            with self.subTest(status=status):
                self.assertFalse(is_stable_eligible(status))
        self.assertTrue(is_stable_eligible("passed"))
        self.assertFalse(is_stable_eligible(None))


if __name__ == "__main__":
    unittest.main()
