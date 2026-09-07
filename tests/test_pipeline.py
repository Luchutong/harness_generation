import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from harness_generation.cli import main
from harness_generation.core import GenerationError, call_api, compile_harness, extract_code, review_harness

ROOT = Path(__file__).resolve().parents[1]
HARNESS = '''#include <stddef.h>
#include <stdint.h>
#include "target.c"
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uint16_t value = 0;
    volatile int result = parse_u16(Data, Size, &value);
    (void)result;
    return 0;
}
'''


def completion(code=HARNESS, reason="stop"):
    return {"model": "test-model", "choices": [{"finish_reason": reason, "message": {"content": code}}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 30, "total_tokens": 50}}


class ExtractionTests(unittest.TestCase):
    def test_literals_are_not_comments_or_calls(self):
        code = HARNESS.replace('    uint16_t value = 0;',
                               '    const char *url = "https://example.com/main()";\n    uint16_t value = 0;')
        self.assertEqual(extract_code(completion(code)), code)

    def test_review_detects_original_optimization_risk(self):
        original = HARNESS.replace('volatile int result = parse_u16(Data, Size, &value);',
                                   'parse_u16(Data, Size, &value);').replace('    (void)result;\n', '')
        review = review_harness(original + '\n/* volatile */', "parse_u16")
        self.assertEqual(len(review["warnings"]), 1)
        self.assertIn("sink", review["warnings"][0])
        self.assertEqual(review_harness(HARNESS, "parse_u16")["warnings"], [])
        self.assertEqual(review_harness(HARNESS, "parse_u16")["status"], "needs_review")

    def test_fake_call_in_string_does_not_pass_review(self):
        review = review_harness('const char *s = "parse_u16(Data, Size) volatile";', "parse_u16")
        self.assertEqual(len(review["warnings"]), 2)

    def test_plain_and_fenced(self):
        for code in (HARNESS, "```c\n" + HARNESS + "```", "```\n" + HARNESS + "```"):
            self.assertEqual(extract_code(completion(code)), HARNESS)

    def test_invalid_responses(self):
        cases = [completion(""), completion(None), completion(reason="length"), {},
                 completion("explanation\n```c\n" + HARNESS + "```"),
                 completion(HARNESS + "\n```c\nint x;\n```"),
                 completion(HARNESS.replace('#include "target.c"', "")),
                 completion(HARNESS + "int main(void) {return 0;}"),
                 completion("/* " + HARNESS + " */")]
        for response in cases:
            with self.subTest(response=response), self.assertRaises(GenerationError):
                extract_code(response)


class ApiTests(unittest.TestCase):
    @patch("harness_generation.core.http.client.HTTPSConnection")
    def test_one_request_and_redacted_response(self, connection):
        conn = connection.return_value
        conn.getresponse.return_value.status = 401
        conn.getresponse.return_value.read.return_value = b'echo test-secret'
        status, raw = call_api({"model": "test"}, "test-secret")
        self.assertEqual(status, 401)
        self.assertNotIn("test-secret", raw)
        conn.request.assert_called_once()
        connection.assert_called_once_with("api.deepseek.com", timeout=120)
        conn.close.assert_called_once()

    @patch("harness_generation.core.http.client.HTTPSConnection")
    def test_timeout_no_retry(self, connection):
        conn = connection.return_value
        conn.request.side_effect = TimeoutError("test-secret")
        with self.assertRaises(GenerationError) as error:
            call_api({}, "test-secret")
        self.assertNotIn("test-secret", str(error.exception))
        conn.request.assert_called_once()
        conn.close.assert_called_once()


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "experiment"
        self.args = ["--source", str(ROOT / "examples/parse_u16.c"), "--function", "parse_u16",
                     "--output", str(self.output)]

    def run_cli(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return main(self.args)

    def result(self):
        return json.loads((self.output / "result.json").read_text())

    @patch.dict(os.environ, {}, clear=True)
    @patch("harness_generation.cli.call_api")
    def test_missing_key(self, api):
        self.assertEqual(self.run_cli(), 1)
        api.assert_not_called()
        self.assertEqual(self.result()["generation"], "failed")
        self.assertTrue((self.output / "target.c").exists())

    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"})
    @patch("harness_generation.cli.call_api", return_value=(429, '{"error":"rate limited"}'))
    def test_http_error(self, api):
        self.assertEqual(self.run_cli(), 1)
        api.assert_called_once()
        self.assertEqual(self.result()["http_status"], 429)
        self.assertTrue((self.output / "response.txt").exists())
        self.assertFalse((self.output / "harness.c").exists())

    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"})
    def test_bad_json_empty_and_truncation(self):
        for index, raw in enumerate(("not json", "[]", json.dumps(completion("")),
                                      json.dumps(completion(reason="length")))):
            self.output = Path(self.temp.name) / str(index)
            self.args[-1] = str(self.output)
            with patch("harness_generation.cli.call_api", return_value=(200, raw)):
                self.assertEqual(self.run_cli(), 1)
            self.assertEqual(self.result()["compilation"]["status"], "not_started")
            self.assertTrue((self.output / "response.txt").exists())

    @patch("harness_generation.cli.call_api")
    def test_existing_directory_untouched(self, api):
        self.output.mkdir()
        sentinel = self.output / "result.json"
        sentinel.write_text("existing")
        self.assertEqual(self.run_cli(), 1)
        self.assertEqual(sentinel.read_text(), "existing")
        api.assert_not_called()

    @unittest.skipUnless(shutil.which("clang"), "clang not installed")
    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"})
    def test_real_compilation_success_and_failure(self):
        for index, code in enumerate((HARNESS, HARNESS + "\ninvalid C code;")):
            self.output = Path(self.temp.name) / str(index)
            self.args[-1] = str(self.output)
            with patch("harness_generation.cli.call_api", return_value=(200, json.dumps(completion(code)))) as api:
                self.assertEqual(self.run_cli(), index)
                api.assert_called_once()
            result = self.result()
            self.assertEqual(result["generation"], "passed")
            self.assertEqual(result["compilation"]["status"], "passed" if index == 0 else "failed")
            self.assertEqual(result["usage"]["total_tokens"], 50)
            self.assertEqual((self.output / "target.c").read_bytes(), (ROOT / "examples/parse_u16.c").read_bytes())
            self.assertEqual((self.output / "fuzz_target").exists(), index == 0)
            for file in self.output.iterdir():
                if file.name != "fuzz_target":
                    self.assertNotIn("test-secret", file.read_text())

    @patch("harness_generation.core.subprocess.run")
    def test_compile_timeout_preserves_diagnostics(self, run):
        self.output.mkdir()
        run.side_effect = subprocess.TimeoutExpired("clang", 30, output=b"partial stdout", stderr=b"partial error")
        result = compile_harness(self.output)
        self.assertEqual(result["status"], "timeout")
        self.assertIn("partial error", (self.output / "compile_stderr.txt").read_text())

    @unittest.skipUnless(shutil.which("clang"), "clang not installed")
    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": ""})
    @patch("harness_generation.cli.call_api")
    def test_offline_reference_harnesses(self, api):
        for name in ("parse_u16", "classify_string", "mix_scalars"):
            self.output = Path(self.temp.name) / name
            self.args = ["--source", str(ROOT / f"examples/{name}.c"), "--function", name,
                         "--output", str(self.output), "--harness",
                         str(ROOT / f"examples/reference_harnesses/{name}.c")]
            with self.subTest(name=name):
                self.assertEqual(self.run_cli(), 0)
                result = self.result()
                self.assertEqual(result["mode"], "offline")
                self.assertEqual(result["generation"], "skipped")
                self.assertIsNone(result["usage"])
                self.assertIsNone(result["model"])
                self.assertEqual(result["review"]["warnings"], [])
                self.assertFalse((self.output / "response.txt").exists())
                self.assertEqual(len(result["source_sha256"]), 64)
                self.assertTrue((self.output / "review.json").exists())
        api.assert_not_called()

    @patch("harness_generation.cli.call_api")
    def test_invalid_offline_harness_preserves_input(self, api):
        path = Path(self.temp.name) / "broken.c"
        path.write_text("invalid harness")
        self.args += ["--harness", str(path)]
        self.assertEqual(self.run_cli(), 1)
        self.assertEqual(self.result()["failure_stage"], "validation")
        self.assertEqual(self.result()["generation"], "skipped")
        self.assertEqual((self.output / "input_harness.txt").read_text(), "invalid harness")
        api.assert_not_called()

    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"})
    @patch("harness_generation.cli.call_api", side_effect=KeyboardInterrupt)
    def test_interrupted_request_records_status(self, api):
        self.assertEqual(self.run_cli(), 130)
        self.assertEqual(self.result()["generation"], "interrupted")
        self.assertEqual(self.result()["failure_stage"], "api")
        api.assert_called_once()

    @unittest.skipUnless(shutil.which("clang"), "clang not installed")
    def test_optimized_reference_retains_input_computation(self):
        self.output.mkdir()
        shutil.copyfile(ROOT / "examples/parse_u16.c", self.output / "target.c")
        reference = (ROOT / "examples/reference_harnesses/parse_u16.c").read_text()
        original = reference.replace('volatile int result = ', '').replace(
            '    volatile uint16_t observed_out = out;\n', '').replace(
            '    (void)result;\n', '').replace('    (void)observed_out;\n', '')
        ir = []
        for code in (original, reference):
            (self.output / "harness.c").write_text(code)
            process = subprocess.run(["clang", "-std=c11", "-O1", "-S", "-emit-llvm",
                                      "harness.c", "-o", "-"], cwd=self.output,
                                     capture_output=True, text=True, timeout=30, check=True)
            ir.append(process.stdout)
        # Inspect compiler output without running the generated binary.
        self.assertNotRegex(ir[0], r"\bload i(?:8|16)\b")
        self.assertRegex(ir[1], r"\bload i(?:8|16)\b")
        self.assertIn("store volatile", ir[1])


if __name__ == "__main__":
    unittest.main()
