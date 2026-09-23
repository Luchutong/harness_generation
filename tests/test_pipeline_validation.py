import json
from pathlib import Path
import shutil
import tempfile
import unittest

from harness_generation.artifacts import ArtifactStore
from harness_generation.pipeline_validation import PipelineStageValidator
from harness_generation.stage1 import Stage1Result
from harness_generation.stage2 import Stage2Result, required_processing_units
from harness_generation.stage3 import Stage3Metadata, Stage3Result
from harness_generation.stage4 import Stage4Result
from harness_generation.triplet import (
    FunctionTriplet,
    TripletEdge,
    TripletFunction,
    load_triplets_json,
)


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ARTIFACTS = ROOT / "artifacts" / "simple"
SIMPLE_PROJECT = ROOT / "tests" / "fixtures" / "simple_project"

class PipelineStageValidatorTests(unittest.TestCase):
    def test_persisted_target_build_is_preferred_over_simple_discovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copy2(SOURCE_ARTIFACTS / name, artifacts / name)
            store = ArtifactStore(artifacts)
            from harness_generation.target_build import TargetBuildConfig
            config = TargetBuildConfig(
                project_root=SIMPLE_PROJECT,
                source_files=(SIMPLE_PROJECT / "src" / "parser.c",),
                archive_name="libpersisted.a",
                provenance="explicit_recipe",
            )
            store.write_target_build(config)
            triplet = load_triplets_json(artifacts / "triplets.json")[0]
            validator = PipelineStageValidator(
                triplet,
                artifacts=artifacts,
                functions_json=artifacts / "functions.json",
                project_root=SIMPLE_PROJECT,
            )
            self.assertEqual(validator.target_build.archive_name, "libpersisted.a")
            self.assertEqual(validator.target_build.provenance, "explicit_recipe")

    def test_existing_but_incomplete_stage1_artifact_is_failed(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copy2(SOURCE_ARTIFACTS / name, artifacts / name)
            triplet = load_triplets_json(artifacts / "triplets.json")[0]
            output = artifacts / "generation" / triplet.id / "stage1_docs.json"
            output.parent.mkdir(parents=True)
            output.write_text(json.dumps({
                "schema_version": 1,
                "triplet_id": triplet.id,
                "documents": [],
            }), encoding="utf-8")
            result = PipelineStageValidator(
                triplet,
                artifacts=artifacts,
                functions_json=artifacts / "functions.json",
                project_root=SIMPLE_PROJECT,
            ).validate_stage1(Stage1Result(
                triplet_id=triplet.id,
                documents=(),
                output_path=output,
                raw_directory=output.parent / "raw",
            ))

        self.assertFalse(result.success)
        self.assertEqual(result.status, "failed")
        self.assertIn("does not match the FT", result.errors[0])

    def test_stage2_enforces_units_calls_known_apis_and_parseable_c(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copy2(SOURCE_ARTIFACTS / name, artifacts / name)
            triplet = load_triplets_json(artifacts / "triplets.json")[0]
            units = [dict(unit) for unit in required_processing_units(triplet)]
            snippets = {
                "parser_from_memory": "(void)0;",
                "node_process": "node_process(&node); invented_api();",
                "parser_free": "parser_free(parser",
                "parser_next": "Node node = parser_next(parser);",
            }
            for unit in units:
                unit["generated_code"] = snippets[unit["functions"][0]]
            units.pop()

            output = artifacts / "generation" / triplet.id / "stage2_snippets.json"
            output.parent.mkdir(parents=True)
            output.write_text(json.dumps({
                "schema_version": 1,
                "triplet_id": triplet.id,
                "units": units,
            }), encoding="utf-8")
            result = PipelineStageValidator(
                triplet,
                artifacts=artifacts,
                functions_json=artifacts / "functions.json",
                project_root=SIMPLE_PROJECT,
            ).validate_stage2(Stage2Result(
                triplet_id=triplet.id,
                snippets=(),
                output_path=output,
                snippets_directory=output.parent / "snippets",
                raw_directory=output.parent / "raw",
                prompts_directory=output.parent / "prompts",
            ))

        self.assertEqual(result.status, "failed")
        diagnostics = "\n".join(result.errors)
        self.assertIn("calls no declared function", diagnostics)
        self.assertIn("unknown APIs", diagnostics)
        self.assertIn("not valid C syntax", diagnostics)
        self.assertIn("omits required processing units", diagnostics)

    def test_stage2_accepts_one_implementation_per_parallel_step(self):
        def declared(name, roles, line):
            return TripletFunction(
                f"src/parser.c:{line}:{name}", name, roles, "src/parser.c", line
            )

        isf = declared("parse", ("ISF", "PRF"), 3)
        alternate = declared("parse_alt", ("PRF",), 13)
        edges = tuple(
            TripletEdge(
                function.function_id, function.function, "(null)", "Context",
                function.roles, function.file, function.line,
            )
            for function in (isf, alternate)
        )
        triplet = FunctionTriplet(
            isf, (alternate,), (), (isf, alternate), ("Context",), edges,
            {"structural_alternatives": [{
                "functions": ["parse", "parse_alt"],
                "evidence": "parse delegates to parse_alt",
            }]},
        )
        units = [dict(unit) for unit in required_processing_units(triplet)]
        self.assertEqual(len(units), 1)
        self.assertEqual(set(units[0]["functions"]), {"parse", "parse_alt"})

        def run(code, root):
            units[0]["generated_code"] = code
            output = root / "generation" / triplet.id / "stage2_snippets.json"
            output.parent.mkdir(parents=True)
            output.write_text(json.dumps({
                "schema_version": 1,
                "triplet_id": triplet.id,
                "units": units,
            }), encoding="utf-8")
            functions_json = root / "functions.json"
            functions_json.write_text(json.dumps({
                "schema_version": 1,
                "functions": [{"name": "parse"}, {"name": "parse_alt"}],
            }), encoding="utf-8")
            return PipelineStageValidator(
                triplet,
                artifacts=root,
                functions_json=functions_json,
                project_root=SIMPLE_PROJECT,
            ).validate_stage2(Stage2Result(
                triplet_id=triplet.id,
                snippets=(),
                output_path=output,
                snippets_directory=output.parent / "snippets",
                raw_directory=output.parent / "raw",
                prompts_directory=output.parent / "prompts",
            ))

        with tempfile.TemporaryDirectory() as temporary:
            one = run("Context *context = parse_alt(data, 1);", Path(temporary))
        with tempfile.TemporaryDirectory() as temporary:
            none = run("(void)0;", Path(temporary))

        self.assertEqual(one.status, "passed", one.errors)
        self.assertFalse(none.success)
        self.assertTrue(any("calls no declared function in unit_0001: parse or parse_alt"
                            in error for error in none.errors), none.errors)

    def test_same_endpoints_without_delegation_receive_separate_units(self):
        isf = TripletFunction(
            "src/api.c:1:parse", "parse", ("ISF",), "src/api.c", 1
        )
        configure = TripletFunction(
            "src/api.c:2:configure", "configure", ("PRF",), "src/api.c", 2
        )
        edges = tuple(TripletEdge(
            function.function_id, function.function, "(null)", "Context",
            function.roles, function.file, function.line,
        ) for function in (isf, configure))
        triplet = FunctionTriplet(
            isf, (configure,), (), (isf, configure), ("Context",), edges, {}
        )
        units = required_processing_units(triplet)
        self.assertEqual([unit["id"] for unit in units], ["unit_0001", "unit_0002"])
        self.assertEqual(
            {unit["functions"] for unit in units},
            {("parse",), ("configure",)},
        )

    def test_stage3_reports_missing_unexpected_and_target_redefinition(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copy2(SOURCE_ARTIFACTS / name, artifacts / name)
            functions_path = artifacts / "functions.json"
            functions = json.loads(functions_path.read_text(encoding="utf-8"))
            functions["functions"].append({
                "id": "src/extra.c:1:other_target",
                "name": "other_target",
            })
            functions_path.write_text(json.dumps(functions), encoding="utf-8")
            triplet = load_triplets_json(artifacts / "triplets.json")[0]
            generation = artifacts / "generation" / triplet.id
            attempt = generation / "stage3" / "attempt_001"
            attempt.mkdir(parents=True)
            rough = generation / "stage3_rough.c"
            rough.write_text("""#include "parser.h"
void parser_free(Parser *parser) { (void)parser; }
void rough_sequence(Parser *parser, const unsigned char *data) {
    parser_from_memory(parser, data, 1);
    other_target();
    parser_free(parser);
}
""", encoding="utf-8")
            metadata = Stage3Metadata(
                triplet_id=triplet.id,
                invoked_functions=(),
                missing_functions=(),
                unexpected_functions=(),
                involved_structures=(),
                assembly_order=(),
                dependency_warnings=(),
                generation_metadata={},
            )
            result = PipelineStageValidator(
                triplet,
                artifacts=artifacts,
                functions_json=functions_path,
                project_root=SIMPLE_PROJECT,
            ).validate_stage3(Stage3Result(
                triplet_id=triplet.id,
                rough_code=rough.read_text(encoding="utf-8"),
                metadata=metadata,
                rough_code_path=rough,
                metadata_path=generation / "stage3_metadata.json",
                attempt_directory=attempt,
            ))

        self.assertEqual(result.status, "failed")
        self.assertIn("node_process", result.metadata["missing_expected_functions"])
        self.assertIn("other_target", result.metadata["unexpected_function_calls"])
        self.assertEqual(
            result.metadata["redefined_target_functions"], ["parser_free"]
        )

    def test_stage4_intermediate_failure_prevents_real_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copy2(SOURCE_ARTIFACTS / name, artifacts / name)
            triplet = load_triplets_json(artifacts / "triplets.json")[0]
            generation = artifacts / "generation" / triplet.id
            attempt = generation / "stage4" / "attempt_001"
            attempt.mkdir(parents=True)
            harness = generation / "stage4_harness.c"
            harness.write_text(
                "int LLVMFuzzerTestOneInput(const unsigned char *data, "
                "unsigned long size) { (void)data; (void)size; return 0; }\n",
                encoding="utf-8",
            )

            result = PipelineStageValidator(
                triplet,
                artifacts=artifacts,
                functions_json=artifacts / "functions.json",
                project_root=SIMPLE_PROJECT,
            ).validate_stage4(Stage4Result(
                triplet_id=triplet.id,
                harness_code=harness.read_text(encoding="utf-8"),
                harness_path=harness,
                stable_path=None,
                generation_metadata={},
                attempt_directory=attempt,
            ))

            self.assertEqual(result.status, "failed")
            self.assertEqual(
                result.metadata["failure_type"], "intermediate_validation"
            )
            outcome = json.loads((attempt / "outcome.json").read_text())
            self.assertEqual(outcome["status"], "failed")
            self.assertEqual(outcome["phase"], "intermediate")
            self.assertEqual(outcome["parsed_status"], "not_recorded")
            self.assertEqual(outcome["validation_artifacts"], {
                "intermediate": "validation/intermediate.json",
            })
            self.assertFalse((artifacts / "build" / triplet.id).exists())
            self.assertFalse((
                attempt / "validation" / "compiler.json"
            ).exists())


if __name__ == "__main__":
    unittest.main()
