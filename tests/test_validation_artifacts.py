import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from harness_generation.artifacts import ArtifactStore
from harness_generation.compiler_validation import CompilerConfig, CompilerValidator
from harness_generation.runtime_validation import RuntimeValidator
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.triplet_extractor import extract_function_triplets
from harness_generation.validation import IntermediateValidator
from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.semantic import MockSemanticAnalyzer


ROOT = Path(__file__).resolve().parents[1]
SIMPLE_PROJECT = ROOT / "tests" / "fixtures" / "simple_project"


class SequenceRunner:
    def __init__(self, *results):
        self.results = list(results)

    def __call__(self, command, **_kwargs):
        return subprocess.CompletedProcess(command, *self.results.pop(0))


class ValidationArtifactIsolationTests(unittest.TestCase):
    def test_validators_coexist_and_compiler_rerun_is_isolated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            phase1 = root / "phase1"
            artifacts = root / "artifacts"
            SFGPipeline(
                MockSemanticAnalyzer(), ignored_directories=DEFAULT_IGNORES
            ).run(SIMPLE_PROJECT, phase1)
            triplet = extract_function_triplets(load_sfg_artifacts(phase1))[0]
            layout = ArtifactStore(artifacts).for_triplet(triplet.id)
            source = """void generated(Parser *parser, const unsigned char *data) {
    parser_from_memory(parser, data, 1);
    Node node = parser_next(parser);
    node_process(&node);
    parser_free(parser);
}"""

            IntermediateValidator().validate_triplet(
                source,
                triplet,
                functions_json=phase1 / "functions.json",
                artifacts=artifacts,
                stage="stage4",
            )
            source_path = root / "harness.c"
            source_path.write_text("int generated(void) { return 0; }\n")
            CompilerValidator(
                CompilerConfig(), runner=SequenceRunner((0, "first", ""))
            ).validate_triplet(source_path, artifacts=artifacts, ft_id=triplet.id)
            RuntimeValidator().validate_triplet(
                None, artifacts=artifacts, ft_id=triplet.id
            )

            before = {
                "intermediate": layout.intermediate_validation.read_bytes(),
                "runtime": layout.runtime_validation.read_bytes(),
            }
            linker_before = json.loads(layout.linker_validation.read_text())
            linker_before["metadata"]["preserved_marker"] = True
            layout.write_validation("linker", linker_before)
            before["linker"] = layout.linker_validation.read_bytes()
            CompilerValidator(
                CompilerConfig(), runner=SequenceRunner((0, "second", ""))
            ).validate_triplet(source_path, artifacts=artifacts, ft_id=triplet.id)

            self.assertEqual(layout.intermediate_validation.read_bytes(), before["intermediate"])
            self.assertEqual(layout.linker_validation.read_bytes(), before["linker"])
            self.assertEqual(layout.runtime_validation.read_bytes(), before["runtime"])
            compiler = json.loads(layout.compiler_validation.read_text())
            intermediate = json.loads(layout.intermediate_validation.read_text())
            linker = json.loads(layout.linker_validation.read_text())
            runtime = json.loads(layout.runtime_validation.read_text())
            summary = json.loads(layout.validation_summary.read_text())

        for name, document in (
            ("intermediate", intermediate),
            ("compiler", compiler),
            ("linker", linker),
            ("runtime", runtime),
        ):
            self.assertEqual(document["validator"], name)
            self.assertIn(document["status"], {"passed", "failed", "skipped", "unavailable"})
            self.assertIsInstance(document["errors"], list)
            self.assertIsInstance(document["warnings"], list)
            self.assertIsInstance(document["metadata"], dict)
        self.assertEqual(compiler["validator"], "compiler")
        self.assertEqual(compiler["status"], "passed")
        self.assertEqual(compiler["stdout"], "second")
        self.assertEqual(linker["status"], "unavailable")
        self.assertIs(linker["metadata"]["preserved_marker"], True)
        self.assertEqual(runtime["status"], "skipped")
        self.assertEqual(summary, {
            "schema_version": 1,
            "intermediate": "passed",
            "compiler": "passed",
            "linker": "unavailable",
            "runtime": "skipped",
            "overall": "passed_with_limitations",
        })


if __name__ == "__main__":
    unittest.main()
