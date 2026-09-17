import json
from pathlib import Path
import shutil
import tempfile
import unittest

from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.source_paths import SourcePathResolver
from harness_generation.triplet_extractor import extract_function_triplets
from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.semantic import MockSemanticAnalyzer


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "simple_project"


class PortableSourcePathTests(unittest.TestCase):
    def _build(self, root: Path):
        project = root / "project"
        output = root / "artifacts"
        shutil.copytree(FIXTURE, project)
        SFGPipeline(
            MockSemanticAnalyzer(), ignored_directories=DEFAULT_IGNORES
        ).run(project, output)
        document = json.loads((output / "functions.json").read_text())
        resolver = SourcePathResolver.from_functions_document(
            document, output / "functions.json"
        )
        triplet = extract_function_triplets(load_sfg_artifacts(output))[0]
        return project, output, document, resolver, triplet

    def test_artifacts_and_ft_identity_are_portable_across_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = self._build(root / "machine-a")
            second = self._build(root / "machine-b")

        for project, _output, document, resolver, _triplet in (first, second):
            self.assertEqual(document["schema_version"], 2)
            self.assertFalse(Path(document["project"]).is_absolute())
            self.assertEqual(resolver.project_root, project.resolve())
            self.assertEqual(
                resolver.resolve("src/parser.c"),
                (project / "src" / "parser.c").resolve(),
            )
            self.assertTrue(all(
                not Path(function["file"]).is_absolute()
                for function in document["functions"]
            ))
        first_logical = {key: value for key, value in first[2].items() if key != "project"}
        second_logical = {key: value for key, value in second[2].items() if key != "project"}
        self.assertEqual(first_logical, second_logical)
        self.assertEqual(first[4].id, second[4].id)

    def test_legacy_absolute_project_root_remains_supported(self):
        document = {"schema_version": 1, "project": str(FIXTURE.resolve())}
        resolver = SourcePathResolver.from_functions_document(
            document, ROOT / "artifacts" / "legacy" / "functions.json"
        )
        self.assertEqual(resolver.project_root, FIXTURE.resolve())
        self.assertEqual(
            resolver.resolve((FIXTURE / "src" / "parser.c").resolve()),
            (FIXTURE / "src" / "parser.c").resolve(),
        )


if __name__ == "__main__":
    unittest.main()
