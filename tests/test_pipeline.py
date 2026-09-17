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
from tests.toolchain_probe import LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON

from harness_generation.cli import main
from harness_generation.core import GenerationError, call_api, compile_harness, extract_code, make_request, review_harness
from harness_generation.source_analysis import analyze_c_source
from harness_generation.isf import apply_isf_filter, pointer_parameter_items

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "benchmarks/mini_parser/target.c"
REFERENCE = ROOT / "benchmarks/mini_parser/harnesses/structured.c"
FUNCTION = "mp_parse"
HARNESS = '''#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "target.c"
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    mp_context ctx;
    mp_init(&ctx);
    uint8_t frame[MP_HEADER_SIZE + MP_MAX_PAYLOAD] = {'M', 'P', 1, MP_READ};
    size_t len = Size < MP_MAX_PAYLOAD ? Size : MP_MAX_PAYLOAD;
    if (len) memcpy(frame + MP_HEADER_SIZE, Data, len);
    frame[4] = (uint8_t)len;
    frame[5] = (uint8_t)(len >> 8);
    uint16_t sum = mp_checksum(frame + MP_HEADER_SIZE, len);
    frame[6] = (uint8_t)sum;
    frame[7] = (uint8_t)(sum >> 8);
    volatile int result = mp_parse(&ctx, frame, MP_HEADER_SIZE + len);
    volatile uint32_t observed = ctx.observation;
    (void)result;
    (void)observed;
    mp_destroy(&ctx);
    return 0;
}
'''


def completion(code=HARNESS, reason="stop"):
    return {"model": "test-model", "choices": [{"finish_reason": reason, "message": {"content": code}}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 30, "total_tokens": 50}}


def classification_responses():
    positive = {"f0003:p0001", "f0004:p0002", "f0005:p0001"}
    ids = ["f0001:p0001", "f0002:p0001", "f0003:p0001",
           "f0004:p0001", "f0004:p0002", "f0005:p0001"]
    contents = [
        {"byte_stream_parameter_ids": sorted(positive)},
        {"answers": [{"id": item, "answer": "yes" if item in positive else "no"} for item in ids]},
        {"classifications": [{"id": item, "choice": "A" if item in positive else "C"} for item in ids]},
    ]
    return [(200, json.dumps(completion(json.dumps(content)))) for content in contents]


def rejecting_classification_responses():
    ids = ["f0001:p0001", "f0002:p0001", "f0003:p0001",
           "f0004:p0001", "f0004:p0002", "f0005:p0001"]
    contents = [
        {"byte_stream_parameter_ids": []},
        {"answers": [{"id": item, "answer": "no"} for item in ids]},
        {"classifications": [{"id": item, "choice": "C"} for item in ids]},
    ]
    return [(200, json.dumps(completion(json.dumps(content)))) for content in contents]


def filtered(summary):
    decisions = []
    for item in pointer_parameter_items(summary):
        yes = item["parameter"] in {"payload", "data", "p"}
        decisions.append({**item, "category": "A" if yes else "C",
                          "positive_votes": 3 if yes else 0, "is_byte_stream": yes})
    return apply_isf_filter(summary, {"prompt_version": "test", "vote_threshold": 2,
                                     "decisions": decisions})


class ExtractionTests(unittest.TestCase):
    def test_literals_are_not_comments_or_calls(self):
        code = HARNESS.replace('    mp_context ctx;',
                               '    const char *url = "https://example.com/main()";\n    mp_context ctx;')
        self.assertEqual(extract_code(completion(code)), code)

    def test_review_detects_original_optimization_risk(self):
        original = HARNESS.replace('volatile int result = mp_parse(&ctx, frame, MP_HEADER_SIZE + len);',
                                   'mp_parse(&ctx, frame, MP_HEADER_SIZE + len);').replace('    (void)result;\n', '')
        original = original.replace('    volatile uint32_t observed = ctx.observation;\n', '').replace(
            '    (void)observed;\n', '')
        review = review_harness(original + '\n/* volatile */', FUNCTION)
        self.assertEqual(len(review["warnings"]), 1)
        self.assertIn("sink", review["warnings"][0])
        self.assertEqual(review_harness(HARNESS, FUNCTION)["warnings"], [])
        self.assertEqual(review_harness(HARNESS, FUNCTION)["status"], "needs_review")

    def test_fake_call_in_string_does_not_pass_review(self):
        review = review_harness('const char *s = "mp_parse(Data, Size) volatile";', FUNCTION)
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

    def test_tree_sitter_summary_drives_prompt_without_full_source(self):
        summary = analyze_c_source(SOURCE.read_bytes(), FUNCTION)
        self.assertEqual(summary["target"]["signature"],
                         "int mp_parse(mp_context *ctx, const uint8_t *data, size_t size);")
        cases = summary["target"]["body_facts"]["switches"][0]["cases"]
        self.assertIn("MP_STORE", cases)
        self.assertIn("MP_USE", cases)
        self.assertIn("mp_checksum", summary["target"]["body_facts"]["called_functions"])
        self.assertNotIn("functions", summary)
        self.assertEqual({item["name"] for item in summary["pointer_candidates"]},
                         {"mp_init", "mp_destroy", "mp_checksum", "mp_parse", "le16"})

        payload = make_request(filtered(summary), FUNCTION, "test-model")
        prompt = payload["messages"][1]["content"]
        self.assertIn("Tree-sitter C syntax summary", prompt)
        self.assertIn('"signature": "int mp_parse', prompt)
        self.assertNotIn('"signature": "void mp_init', prompt)
        self.assertNotIn("pointer_candidates", prompt)
        self.assertIn("(data[0] != 'M'", prompt)
        self.assertNotIn("Original source:", prompt)
        self.assertNotIn("BUG 4", prompt)
        self.assertNotIn("switch (data[3]) {", prompt)


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
        self.args = ["--source", str(SOURCE), "--function", FUNCTION,
                     "--output", str(self.output)]

    def run_cli(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return main(self.args)

    def result(self):
        return json.loads((self.output / "result.json").read_text())

    @patch.dict(os.environ, {}, clear=True)
    @patch("harness_generation.candidate.call_api")
    def test_missing_key(self, api):
        self.assertEqual(self.run_cli(), 1)
        api.assert_not_called()
        self.assertEqual(self.result()["generation"], "failed")
        self.assertTrue((self.output / "target.c").exists())

    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"})
    @patch("harness_generation.candidate.call_api", side_effect=rejecting_classification_responses())
    def test_rejected_target_stops_before_harness_request(self, api):
        self.assertEqual(self.run_cli(), 1)
        self.assertEqual(api.call_count, 3)
        result = self.result()
        self.assertEqual(result["failure_stage"], "isf_filter")
        self.assertEqual(result["isf_classification"]["status"], "passed")
        self.assertFalse((self.output / "prompt.json").exists())
        self.assertEqual(json.loads((self.output / "source_summary.json").read_text())["isf_functions"], [])

    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"})
    @patch("harness_generation.candidate.call_api",
           side_effect=classification_responses() + [(429, '{"error":"rate limited"}')])
    def test_http_error(self, api):
        self.assertEqual(self.run_cli(), 1)
        self.assertEqual(api.call_count, 4)
        self.assertEqual(self.result()["http_status"], 429)
        self.assertTrue((self.output / "response.txt").exists())
        self.assertFalse((self.output / "harness.c").exists())

    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"})
    def test_bad_json_empty_and_truncation(self):
        for index, raw in enumerate(("not json", "[]", json.dumps(completion("")),
                                      json.dumps(completion(reason="length")))):
            self.output = Path(self.temp.name) / str(index)
            self.args[-1] = str(self.output)
            with patch("harness_generation.candidate.call_api",
                       side_effect=classification_responses() + [(200, raw)]):
                self.assertEqual(self.run_cli(), 1)
            self.assertEqual(self.result()["compilation"]["status"], "not_started")
            self.assertTrue((self.output / "response.txt").exists())

    @patch("harness_generation.candidate.call_api")
    def test_existing_directory_untouched(self, api):
        self.output.mkdir()
        sentinel = self.output / "result.json"
        sentinel.write_text("existing")
        self.assertEqual(self.run_cli(), 1)
        self.assertEqual(sentinel.read_text(), "existing")
        api.assert_not_called()

    @unittest.skipUnless(LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON)
    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"})
    def test_real_compilation_success_and_failure(self):
        for index, code in enumerate((HARNESS, HARNESS + "\ninvalid C code;")):
            self.output = Path(self.temp.name) / str(index)
            self.args[-1] = str(self.output)
            with patch("harness_generation.candidate.call_api",
                       side_effect=classification_responses() + [(200, json.dumps(completion(code)))]) as api:
                self.assertEqual(self.run_cli(), index)
                self.assertEqual(api.call_count, 4)
                self.assertNotIn("BUG 4", json.dumps(api.call_args.args[0]))
                self.assertIn("source_summary.json", [path.name for path in self.output.iterdir()])
            result = self.result()
            self.assertEqual(result["source_analysis"]["status"], "passed")
            self.assertEqual(result["generation"], "passed")
            self.assertEqual(result["compilation"]["status"], "passed" if index == 0 else "failed")
            self.assertEqual(result["usage"]["total_tokens"], 50)
            self.assertEqual((self.output / "target.c").read_bytes(), SOURCE.read_bytes())
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

    @unittest.skipUnless(LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON)
    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": ""})
    @patch("harness_generation.candidate.call_api")
    def test_offline_reference_harness(self, api):
        self.output = Path(self.temp.name) / "mini_parser"
        self.args = ["--source", str(SOURCE), "--function", FUNCTION,
                     "--output", str(self.output), "--harness", str(REFERENCE)]
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

    @patch("harness_generation.candidate.call_api")
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
    @patch("harness_generation.candidate.call_api",
           side_effect=classification_responses() + [KeyboardInterrupt])
    def test_interrupted_request_records_status(self, api):
        self.assertEqual(self.run_cli(), 130)
        self.assertEqual(self.result()["generation"], "interrupted")
        self.assertEqual(self.result()["failure_stage"], "api")
        self.assertEqual(api.call_count, 4)

    @unittest.skipUnless(shutil.which("clang"), "clang not installed")
    def test_optimized_reference_retains_input_computation(self):
        self.output.mkdir()
        shutil.copyfile(SOURCE, self.output / "target.c")
        (self.output / "harness.c").write_text(REFERENCE.read_text())
        process = subprocess.run(["clang", "-std=c11", "-O1", "-S", "-emit-llvm",
                                  "harness.c", "-o", "-"], cwd=self.output,
                                 capture_output=True, text=True, timeout=30, check=True)
        self.assertIn("@LLVMFuzzerTestOneInput", process.stdout)
        self.assertIn("store volatile", process.stdout)


if __name__ == "__main__":
    unittest.main()
