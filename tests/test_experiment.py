import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

from harness_generation.cli import main

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "benchmarks/mini_parser/target.c"
REFERENCE = ROOT / "benchmarks/mini_parser/harnesses/structured.c"
FUNCTION = "mp_parse"
CODE = REFERENCE.read_text()


def response(code=CODE):
    return 200, json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": code}}],
                           "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}})


def classification_responses():
    positive = {"f0003:p0001", "f0004:p0002", "f0005:p0001"}
    ids = ["f0001:p0001", "f0002:p0001", "f0003:p0001",
           "f0004:p0001", "f0004:p0002", "f0005:p0001"]
    contents = [
        {"byte_stream_parameter_ids": sorted(positive)},
        {"answers": [{"id": item, "answer": "yes" if item in positive else "no"} for item in ids]},
        {"classifications": [{"id": item, "choice": "A" if item in positive else "C"} for item in ids]},
    ]
    return [(200, json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(item)}}],
                              "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}}))
            for item in contents]


@patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"})
class ExperimentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name) / "experiment"
        self.args = ["--source", str(SOURCE), "--function", FUNCTION,
                     "--output", str(self.output), "--candidates", "3", "--generate-only"]

    def run_cli(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return main(self.args)

    def summary(self):
        return json.loads((self.output / "experiment.json").read_text())

    @patch("harness_generation.assessment.compile_harness")
    @patch("harness_generation.candidate.call_api",
           side_effect=classification_responses() + [response(), response(), response(CODE + "\n/* another */")])
    def test_three_independent_candidates_and_duplicates(self, api, compile_mock):
        self.assertEqual(self.run_cli(), 0)
        self.assertEqual(api.call_count, 6)
        compile_mock.assert_not_called()
        summary = self.summary()
        self.assertEqual(summary["api_attempts"], 6)
        self.assertEqual(summary["generated_candidates"], 3)
        self.assertEqual(summary["unique_harnesses"], 2)
        self.assertEqual(summary["reported_usage_totals"]["total_tokens"], 180)
        self.assertEqual(summary["candidates"][1]["duplicate_of"], "candidate_0001")
        for index, call in enumerate(api.call_args_list[3:], 1):
            self.assertEqual(call.args[0]["temperature"], 0.8)
            self.assertEqual(len(call.args[0]["messages"]), 2)
            candidate = self.output / f"candidates/candidate_{index:04d}"
            self.assertTrue((candidate / "harness.c").exists())
            self.assertTrue((candidate / "response.txt").exists())
            result = json.loads((candidate / "result.json").read_text())
            self.assertEqual(result["compilation"]["status"], "skipped")
            self.assertIsNone(result["parent_id"])

    @patch("harness_generation.candidate.call_api",
           side_effect=classification_responses() + [response(), (429, "rate limited"), response()])
    def test_failed_candidate_does_not_discard_siblings(self, api):
        self.assertEqual(self.run_cli(), 1)
        summary = self.summary()
        self.assertEqual(summary["status"], "partial_failure")
        self.assertEqual(summary["generated_candidates"], 2)
        self.assertEqual(api.call_count, 6)
        self.assertEqual(summary["usage_missing_candidates"], ["candidate_0002"])
        self.assertEqual(summary["reported_usage_totals"]["total_tokens"], 150)

    @patch("harness_generation.candidate.call_api",
           side_effect=classification_responses() + [(401, "unauthorized")])
    def test_auth_failure_stops_batch(self, api):
        self.assertEqual(self.run_cli(), 1)
        self.assertEqual(api.call_count, 4)
        self.assertEqual(self.summary()["candidates"][1]["status"], "not_started")

    @patch("harness_generation.candidate.call_api", return_value=(429, "rate limited"))
    def test_failed_shared_classification_is_not_retried_per_candidate(self, api):
        self.assertEqual(self.run_cli(), 1)
        api.assert_called_once()
        summary = self.summary()
        self.assertEqual(summary["api_attempts"], 1)
        self.assertEqual([entry["status"] for entry in summary["candidates"]],
                         ["failed", "failed", "failed"])
        for index in range(1, 4):
            artifact = self.output / f"candidates/candidate_{index:04d}/isf_classification.json"
            report = json.loads(artifact.read_text())
            self.assertEqual(report["status"], "failed")

    @patch("harness_generation.candidate.call_api")
    def test_missing_key_does_not_send_requests(self, api):
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": ""}):
            self.assertEqual(self.run_cli(), 1)
        api.assert_not_called()
        self.assertEqual(self.summary()["api_attempts"], 0)

    @patch("harness_generation.candidate.call_api",
           side_effect=classification_responses() + [response(), KeyboardInterrupt])
    def test_interrupted_batch_keeps_completed_candidate(self, api):
        self.assertEqual(self.run_cli(), 130)
        self.assertEqual(api.call_count, 5)
        summary = self.summary()
        self.assertEqual(summary["status"], "interrupted")
        self.assertEqual([e["status"] for e in summary["candidates"]], ["passed", "interrupted", "not_started"])

    @patch("harness_generation.candidate.call_api",
           side_effect=classification_responses() + [response(), response(), response()])
    @patch("harness_generation.assessment.compile_harness", side_effect=[{"status": "passed"}, {"status": "failed"}, {"status": "passed"}])
    def test_compile_failure_continues_and_temperature_override(self, compile_mock, api):
        self.args.remove("--generate-only")
        self.args += ["--temperature", "0.5"]
        self.assertEqual(self.run_cli(), 1)
        self.assertEqual(compile_mock.call_count, 3)
        self.assertEqual(self.summary()["generated_candidates"], 3)
        self.assertTrue(all(call.args[0]["temperature"] == 0 for call in api.call_args_list[:3]))
        self.assertTrue(all(call.args[0]["temperature"] == 0.5 for call in api.call_args_list[3:]))

    @patch("harness_generation.candidate.call_api")
    def test_invalid_options_fail_before_output_creation(self, api):
        for option in (["--candidates", "0"], ["--temperature", "nan"],
                       ["--harness", str(REFERENCE)],
                       ["--fuzz-seconds", "1"]):
            original_args = self.args[:]
            self.args += option
            with self.subTest(option=option), self.assertRaises(SystemExit) as exc:
                self.run_cli()
            self.assertEqual(exc.exception.code, 2)
            self.assertFalse(self.output.exists())
            self.args = original_args
        api.assert_not_called()
