import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.artifacts import ArtifactStore
from harness_generation.target_build import TargetBuildConfig
from harness_generation.triplet import load_triplets_json


ROOT = Path(__file__).resolve().parents[1]
SIMPLE_ARTIFACTS = ROOT / "artifacts" / "simple"

class ArtifactPersistenceTests(unittest.TestCase):
    def test_target_build_recipe_is_persisted_and_loaded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "artifacts"
            config = TargetBuildConfig.for_simple_project(SIMPLE_ARTIFACTS.parent / ".." / "tests" / "fixtures" / "simple_project")
            store = ArtifactStore(root)
            path = store.write_target_build(config)
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document["schema_version"], 1)
            self.assertEqual(document["recipe"]["source_files"], ["src/parser.c"])
            loaded = store.load_target_build(project_root=config.project_root)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded.to_recipe().identity, config.to_recipe().identity)

    def test_missing_target_build_remains_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.assertIsNone(ArtifactStore(Path(temporary)).load_target_build())

    def test_additive_layout_preserves_existing_phase1_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project-artifacts"
            root.mkdir()
            originals = {
                "functions.json": b'{"phase": "functions"}\n',
                "annotations.json": b'{"phase": "annotations"}\n',
                "flows.json": b'{"phase": "flows"}\n',
                "sfg.json": b'{"phase": "sfg"}\n',
                "sfg.dot": b"digraph SFG {}\n",
            }
            for name, content in originals.items():
                (root / name).write_bytes(content)

            store = ArtifactStore(root).ensure_catalogs()
            layout = store.for_triplet("ft_custom_001").ensure_generation()

            for name, content in originals.items():
                self.assertEqual((root / name).read_bytes(), content)
            for directory in (
                store.triplets_directory,
                store.generation_directory,
                store.harnesses_directory,
                store.build_directory,
                store.fuzz_directory,
                layout.generation,
                layout.stage1,
                layout.stage1_prompts,
                layout.stage1_raw,
                layout.stage2,
                layout.stage2_prompts,
                layout.stage2_raw,
                layout.stage2_code_snippets,
                layout.prompts,
                layout.raw,
                layout.validation_directory,
                layout.stage3_attempts,
                layout.stage4_attempts,
            ):
                self.assertTrue(directory.is_dir(), directory)

    def test_triplet_layout_exposes_all_canonical_generation_paths(self):
        store = ArtifactStore(Path("artifacts") / "project-name")
        layout = store.for_triplet("ft_0042")
        expected = {
            "triplet": store.root / "triplets" / "ft_0042.json",
            "generation": store.root / "generation" / "ft_0042",
            "harness": store.root / "harnesses" / "ft_0042.c",
            "build": store.root / "build" / "ft_0042",
            "fuzz": store.root / "fuzz" / "ft_0042",
            "coverage": store.root / "coverage" / "ft_0042",
            "stage1_docs": store.root / "generation" / "ft_0042" / "stage1_docs.json",
            "stage1": store.root / "generation" / "ft_0042" / "stage1",
            "stage1_scoped_docs": store.root / "generation" / "ft_0042" / "stage1" / "stage1_docs.json",
            "stage1_prompts": store.root / "generation" / "ft_0042" / "stage1" / "prompts",
            "stage1_raw": store.root / "generation" / "ft_0042" / "stage1" / "raw",
            "stage2_snippets": store.root / "generation" / "ft_0042" / "stage2_snippets.json",
            "stage2": store.root / "generation" / "ft_0042" / "stage2",
            "stage2_scoped_snippets": store.root / "generation" / "ft_0042" / "stage2" / "stage2_snippets.json",
            "stage2_prompts": store.root / "generation" / "ft_0042" / "stage2" / "prompts",
            "stage2_raw": store.root / "generation" / "ft_0042" / "stage2" / "raw",
            "stage2_code_snippets": store.root / "generation" / "ft_0042" / "stage2" / "snippets",
            "stage3_rough": store.root / "generation" / "ft_0042" / "stage3_rough.c",
            "stage3_metadata": store.root / "generation" / "ft_0042" / "stage3_metadata.json",
            "stage4_harness": store.root / "generation" / "ft_0042" / "stage4_harness.c",
            "stage4_harness_plan": store.root / "generation" / "ft_0042" / "stage4_harness_plan.json",
            "validation": store.root / "generation" / "ft_0042" / "validation" / "intermediate.json",
            "validation_directory": store.root / "generation" / "ft_0042" / "validation",
            "intermediate_validation": store.root / "generation" / "ft_0042" / "validation" / "intermediate.json",
            "compiler_validation": store.root / "generation" / "ft_0042" / "validation" / "compiler.json",
            "linker_validation": store.root / "generation" / "ft_0042" / "validation" / "linker.json",
            "runtime_validation": store.root / "generation" / "ft_0042" / "validation" / "runtime.json",
            "validation_summary": store.root / "generation" / "ft_0042" / "validation" / "summary.json",
            "pipeline_state": store.root / "generation" / "ft_0042" / "pipeline_state.json",
            "pipeline_result": store.root / "generation" / "ft_0042" / "pipeline_result.json",
            "prompts": store.root / "generation" / "ft_0042" / "prompts",
            "raw": store.root / "generation" / "ft_0042" / "raw",
            "stage3_attempts": store.root / "generation" / "ft_0042" / "stage3",
            "stage4_attempts": store.root / "generation" / "ft_0042" / "stage4",
        }
        self.assertEqual(layout.manifest(), expected)

    def test_central_writers_are_atomic_and_reject_escaping_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = ArtifactStore(Path(temporary) / "artifacts")
            layout = store.for_triplet("ft_atomic").ensure_generation()
            layout.write_json(layout.validation, {"success": True})
            layout.write_text(layout.stage4_harness, "int harness;\n")

            self.assertEqual(
                json.loads(layout.validation.read_text(encoding="utf-8")),
                {"success": True},
            )
            self.assertEqual(
                layout.stage4_harness.read_text(encoding="utf-8"),
                "int harness;\n",
            )
            self.assertFalse(layout.validation.with_suffix(".json.tmp").exists())
            with self.assertRaisesRegex(ValueError, "escapes"):
                layout.write_text(Path(temporary) / "outside.c", "unsafe")
            self.assertFalse((Path(temporary) / "outside.c").exists())

    def test_complete_pipeline_layout_is_persisted_under_one_artifact_store(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = ArtifactStore(Path(temporary) / "artifacts").ensure_catalogs()
            layout = store.for_triplet("ft_layout_e2e").ensure_generation()
            layout.write_json_copies(
                (layout.stage1_scoped_docs, layout.stage1_docs),
                {"schema_version": 1, "documents": []},
            )
            layout.write_json_copies(
                (layout.stage2_scoped_snippets, layout.stage2_snippets),
                {"schema_version": 1, "units": []},
            )
            _, stage3 = layout.next_attempt("stage3")
            _, stage4 = layout.next_attempt("stage4")
            layout.write_text(stage3 / "rough.c", "void rough(void) {}\n")
            layout.write_text(stage4 / "harness.c", "int harness;\n")
            for validator in (
                "intermediate", "compiler", "linker", "runtime"
            ):
                layout.write_validation(validator, {
                    "validator": validator,
                    "status": "passed",
                    "errors": [],
                    "warnings": [],
                    "metadata": {},
                })
            layout.write_json(layout.pipeline_state, {
                "schema_version": 1, "ft_id": layout.ft_id,
            })
            layout.ensure_build().write_text(
                layout.build / "fuzzer", "executable-placeholder\n"
            )
            _, smoke = layout.next_fuzz_smoke()
            (smoke / "corpus").mkdir()
            (smoke / "crashes").mkdir()
            for name in (
                "command.txt", "stdout.txt", "stderr.txt",
                "final_stats.json", "metadata.json",
            ):
                layout.write_text(smoke / name, "{}\n" if name.endswith(".json") else "")

            required = (
                layout.stage1_scoped_docs,
                layout.stage2_scoped_snippets,
                stage3 / "rough.c",
                stage4 / "harness.c",
                layout.intermediate_validation,
                layout.compiler_validation,
                layout.linker_validation,
                layout.runtime_validation,
                layout.validation_summary,
                layout.pipeline_state,
                layout.build / "fuzzer",
                smoke / "metadata.json",
                smoke / "corpus",
                smoke / "crashes",
            )
            self.assertEqual(stage3.name, "attempt_001")
            self.assertEqual(stage4.name, "attempt_001")
            self.assertEqual(smoke.name, "smoke_001")
            for path in required:
                self.assertTrue(path.exists(), path)
            summary = json.loads(layout.validation_summary.read_text())
            self.assertEqual(summary["overall"], "passed")

    def test_triplet_collection_and_individual_records_are_stable(self):
        triplets = load_triplets_json(SIMPLE_ARTIFACTS / "triplets.json")
        with tempfile.TemporaryDirectory() as temporary:
            store = ArtifactStore(Path(temporary) / "named-project")
            output = store.write_triplets(triplets, individual=True)
            first = output.read_bytes()
            individual = store.for_triplet(triplets[0].id).triplet
            individual_document = json.loads(individual.read_text(encoding="utf-8"))
            store.write_triplets(reversed(triplets), individual=True)

            self.assertEqual(output.read_bytes(), first)
            self.assertEqual(individual_document["triplet"]["id"], triplets[0].id)
            self.assertEqual(load_triplets_json(output), triplets)

    def test_triplet_ids_cannot_escape_artifact_root(self):
        store = ArtifactStore(Path("artifacts"))
        for invalid in ("../ft_bad", "ft_bad/name", "not_a_triplet", ""):
            with self.subTest(ft_id=invalid), self.assertRaises(ValueError):
                store.for_triplet(invalid)


if __name__ == "__main__":
    unittest.main()
