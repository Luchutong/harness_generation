import json
from pathlib import Path
import shutil
import tempfile
import unittest

from harness_generation.target_build import TargetBuildAdapter, TargetBuildConfig


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

    def test_rejects_target_paths_outside_project_root(self):
        with self.assertRaisesRegex(ValueError, "outside project_root"):
            TargetBuildConfig(
                project_root=SIMPLE_PROJECT,
                source_files=(ROOT / "README.md",),
            )


if __name__ == "__main__":
    unittest.main()
