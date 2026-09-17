import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from harness_generation.fuzzer_build import FuzzerBuildValidator
from harness_generation.target_build import TargetBuildConfig
from tests.toolchain_probe import LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON


ROOT = Path(__file__).resolve().parents[1]
SIMPLE_PROJECT = ROOT / "tests" / "fixtures" / "simple_project"

VALID_HARNESS = """#include <stddef.h>
#include <stdint.h>
extern "C" {
#include "parser.h"
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Parser parser = {0};
    if (parser_from_memory(&parser, data, (unsigned long)size) == 0) {
        Node node = parser_next(&parser);
        node_process(&node);
    }
    parser_free(&parser);
    return 0;
}
"""


@unittest.skipUnless(LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON)
class FuzzerBuildValidatorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.artifacts = Path(temporary.name) / "artifacts" / "simple"
        self.ft_id = "ft_parser_from_memory_compile"
        self.config = TargetBuildConfig.for_simple_project(SIMPLE_PROJECT)

    def write_harness(self, source):
        path = Path(self.artifacts.parent) / "generated_harness.c"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        return path

    def test_real_target_and_harness_compile_then_libfuzzer_link(self):
        result = FuzzerBuildValidator().validate(
            self.write_harness(VALID_HARNESS),
            self.config,
            artifacts=self.artifacts,
            ft_id=self.ft_id,
        )
        build = self.artifacts / "build" / self.ft_id
        compiler = json.loads((
            self.artifacts / "generation" / self.ft_id
            / "validation/compiler.json"
        ).read_text(encoding="utf-8"))
        linker = json.loads((
            self.artifacts / "generation" / self.ft_id
            / "validation/linker.json"
        ).read_text(encoding="utf-8"))
        manifest = json.loads((build / "build.json").read_text(encoding="utf-8"))

        self.assertTrue(result.success, result.errors)
        self.assertEqual(compiler["status"], "passed")
        self.assertEqual(linker["status"], "passed")
        self.assertEqual(linker["return_code"], 0)
        self.assertIn("-fsanitize=fuzzer,address,undefined", linker["command"])
        harness_compile = next(
            command for command in compiler["metadata"]["commands"]
            if command["command"][-1].endswith("harness.o")
        )
        self.assertEqual(harness_compile["command"][0], "clang++")
        self.assertIn("-x", harness_compile["command"])
        self.assertIn("c++", harness_compile["command"])
        self.assertIn("-std=c++17", harness_compile["command"])
        self.assertTrue((build / "objects/src/parser.o").is_file())
        self.assertTrue((build / "objects/harness.o").is_file())
        self.assertTrue((build / "libsimple_target.a").is_file())
        self.assertTrue((build / "fuzzer").is_file())
        self.assertEqual(manifest["fuzzer"], str(build / "fuzzer"))
        smoke = subprocess.run(
            [str(build / "fuzzer"), "-runs=1"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(smoke.returncode, 0, smoke.stderr)

    def test_compile_failure_is_bounded_but_full_stderr_is_persisted(self):
        invalid = VALID_HARNESS.replace(
            "    return 0;", "    undefined_function();\n    return 0;"
        )
        result = FuzzerBuildValidator().validate(
            self.write_harness(invalid),
            self.config,
            artifacts=self.artifacts,
            ft_id=self.ft_id,
        )
        validation_root = (
            self.artifacts / "generation" / self.ft_id / "validation"
        )
        compiler = json.loads(
            (validation_root / "compiler.json").read_text(encoding="utf-8")
        )
        linker = json.loads(
            (validation_root / "linker.json").read_text(encoding="utf-8")
        )

        self.assertFalse(result.success)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.metadata["failure_type"], "compile_error")
        self.assertEqual(result.metadata["failed_stage"], "harness_compile")
        self.assertIn("undefined_function", result.metadata["error_summary"])
        self.assertLessEqual(len(result.metadata["relevant_stderr_tail"]), 4000)
        self.assertIn("undefined_function", compiler["stderr"])
        self.assertEqual(linker["status"], "skipped")
        self.assertFalse((
            self.artifacts / "build" / self.ft_id / "fuzzer"
        ).exists())

    def test_undefined_external_symbol_is_a_real_link_failure(self):
        invalid = VALID_HARNESS.replace(
            "#include \"parser.h\"",
            "#include \"parser.h\"\nextern void unresolved_symbol(void);",
        ).replace("    return 0;", "    unresolved_symbol();\n    return 0;")
        result = FuzzerBuildValidator().validate(
            self.write_harness(invalid),
            self.config,
            artifacts=self.artifacts,
            ft_id=self.ft_id,
        )
        linker = json.loads((
            self.artifacts / "generation" / self.ft_id
            / "validation/linker.json"
        ).read_text(encoding="utf-8"))

        self.assertEqual(result.status, "failed")
        self.assertEqual(result.metadata["failure_type"], "link_error")
        self.assertEqual(result.metadata["failed_stage"], "link")
        self.assertEqual(linker["status"], "failed")
        self.assertNotEqual(linker["return_code"], 0)
        self.assertIn("unresolved_symbol", linker["stderr"])


if __name__ == "__main__":
    unittest.main()
