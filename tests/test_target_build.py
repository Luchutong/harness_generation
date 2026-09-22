import json
from pathlib import Path
import shutil
import tempfile
import unittest

from harness_generation.target_build import TargetBuildAdapter, TargetBuildConfig
from project_catalog import BuildRecipe


ROOT = Path(__file__).resolve().parents[1]
SIMPLE_PROJECT = ROOT / "tests" / "fixtures" / "simple_project"


class TargetBuildTests(unittest.TestCase):
    def test_simple_config_reflects_actual_target_layout(self):
        config = TargetBuildConfig.for_simple_project(SIMPLE_PROJECT)

        self.assertEqual(
            tuple(path.relative_to(config.project_root).as_posix()
                  for path in config.source_files),
            ("src/parser.c",),
        )
        self.assertEqual(
            tuple(path.relative_to(config.project_root).as_posix()
                  for path in config.header_files),
            ("include/parser.h",),
        )
        self.assertEqual(config.include_paths, (config.project_root / "include",))
        self.assertEqual(config.compiler_flags, ("-std=c11",))
        self.assertNotIn(
            config.project_root / "vendor" / "ignored.c", config.source_files
        )

    @unittest.skipUnless(shutil.which("clang") and shutil.which("ar"),
                         "clang and ar are required for the real build test")
    def test_builds_real_object_and_static_library_inside_artifacts(self):
        config = TargetBuildConfig.for_simple_project(SIMPLE_PROJECT)
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts" / "simple"
            result = TargetBuildAdapter().build(
                config,
                artifacts=artifacts,
                ft_id="ft_parser_from_memory_test",
            )
            build = artifacts / "build" / "ft_parser_from_memory_test"
            manifest = json.loads((build / "build.json").read_text(encoding="utf-8"))
            compilation_database = json.loads(
                (build / "compile_commands.json").read_text(encoding="utf-8")
            )

            self.assertTrue(result.success, result.errors)
            self.assertEqual(result.status, "passed")
            self.assertEqual(result.object_files, (build / "objects/src/parser.o",))
            self.assertEqual(result.library, build / "libsimple_target.a")
            self.assertTrue(result.object_files[0].is_file())
            self.assertTrue(result.library.is_file())
            self.assertEqual(manifest["status"], "passed")
            self.assertEqual(manifest["ft_id"], "ft_parser_from_memory_test")
            self.assertEqual(len(manifest["commands"]), 2)
            self.assertEqual(len(compilation_database), 1)
            self.assertEqual(
                compilation_database[0]["file"],
                str(SIMPLE_PROJECT.resolve() / "src/parser.c"),
            )
            self.assertTrue((build / "stdout.txt").is_file())
            self.assertTrue((build / "stderr.txt").is_file())
            self.assertFalse((ROOT / "parser.o").exists())
            self.assertFalse((ROOT / "libsimple_target.a").exists())

    def test_persisted_recipe_round_trips_with_relative_paths_and_identity(self):
        recipe = BuildRecipe(
            project_root=SIMPLE_PROJECT,
            source_files=(SIMPLE_PROJECT / "src/parser.c",),
            header_files=(SIMPLE_PROJECT / "include/parser.h",),
            include_paths=(SIMPLE_PROJECT / "include",),
            provenance="explicit_recipe",
        )
        document = recipe.to_dict()
        self.assertEqual(document["source_files"], ["src/parser.c"])
        self.assertEqual(document["header_files"], ["include/parser.h"])
        loaded = BuildRecipe.from_dict(document, project_root=SIMPLE_PROJECT)
        self.assertEqual(loaded.identity, recipe.identity)
        self.assertEqual(loaded.source_files, recipe.source_files)

    def test_persisted_recipe_rejects_root_and_identity_mismatch(self):
        recipe = BuildRecipe(
            project_root=SIMPLE_PROJECT,
            source_files=(SIMPLE_PROJECT / "src/parser.c",),
        )
        document = recipe.to_dict()
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "project_root does not match"):
                BuildRecipe.from_dict(document, project_root=temporary)
        document["identity"] = "counterfeit"
        with self.assertRaisesRegex(ValueError, "identity does not match"):
            BuildRecipe.from_dict(document)

    def test_target_build_config_loads_nested_recipe(self):
        recipe = BuildRecipe(
            project_root=SIMPLE_PROJECT,
            source_files=(SIMPLE_PROJECT / "src/parser.c",),
            provenance="explicit_recipe",
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "target-build.json"
            path.write_text(json.dumps({"schema_version": 1, "recipe": recipe.to_dict()}), encoding="utf-8")
            loaded = TargetBuildConfig.load(path, project_root=SIMPLE_PROJECT)
        self.assertEqual(loaded.to_recipe().identity, recipe.identity)
        self.assertEqual(loaded.provenance, "explicit_recipe")

    def test_target_build_config_load_rejects_malformed_document(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "target-build.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "cannot load target build config"):
                TargetBuildConfig.load(path, project_root=SIMPLE_PROJECT)

    def test_recipe_link_settings_round_trip_through_target_config(self):
        recipe = BuildRecipe(
            project_root=SIMPLE_PROJECT,
            source_files=(SIMPLE_PROJECT / "src/parser.c",),
            header_files=(SIMPLE_PROJECT / "include/parser.h",),
            include_paths=(SIMPLE_PROJECT / "include",),
            compiler_flags=("-std=c11",),
            archive_name="libparser.a",
            linker="clang++",
            link_flags=("-lstdc++", "-lm"),
            provenance="test",
        )

        config = TargetBuildConfig.from_recipe(recipe)

        self.assertEqual(config.linker, "clang++")
        self.assertEqual(config.link_flags, ("-lstdc++", "-lm"))
        self.assertEqual(config.to_recipe()._identity_document(), recipe._identity_document())
        self.assertEqual(config.to_dict()["linker"], "clang++")
        self.assertEqual(config.to_dict()["link_flags"], ["-lstdc++", "-lm"])

    def test_rejects_invalid_link_configuration(self):
        for kwargs, message in (
            ({"linker": ""}, "linker must be non-empty"),
            ({"link_flags": "-lm"}, "link_flags must be a sequence"),
            ({"link_flags": ("",)}, "link_flags must contain"),
        ):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, message):
                TargetBuildConfig(
                    project_root=SIMPLE_PROJECT,
                    source_files=(SIMPLE_PROJECT / "src/parser.c",),
                    **kwargs,
                )

    def test_rejects_target_paths_outside_project_root(self):
        with self.assertRaisesRegex(ValueError, "outside project_root"):
            TargetBuildConfig(
                project_root=SIMPLE_PROJECT,
                source_files=(ROOT / "README.md",),
            )


if __name__ == "__main__":
    unittest.main()
