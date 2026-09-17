"""Network-free closure test: mini_parser baseline → feedback → LLM revision."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from harness_generation.cli import main
from harness_generation.feedback_loop import _candidate_failure_reason


ROOT = Path(__file__).resolve().parents[1]
MINI_PARSER = ROOT / "benchmarks" / "mini_parser"
SOURCE = MINI_PARSER / "target.c"
REFERENCE = MINI_PARSER / "harnesses" / "structured.c"
BASELINE = MINI_PARSER / "harnesses" / "pass_through.c"


def _classification_responses() -> list[tuple[int, str]]:
    positive = {"f0003:p0001", "f0004:p0002", "f0005:p0001"}
    ids = ["f0001:p0001", "f0002:p0001", "f0003:p0001",
           "f0004:p0001", "f0004:p0002", "f0005:p0001"]
    answers = [
        {"byte_stream_parameter_ids": sorted(positive)},
        {"answers": [
            {"id": item, "answer": "yes" if item in positive else "no"}
            for item in ids
        ]},
        {"classifications": [
            {"id": item, "choice": "A" if item in positive else "C"}
            for item in ids
        ]},
    ]
    return [
        (200, json.dumps({
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": json.dumps(answer)},
            }],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }))
        for answer in answers
    ]


def _generated_reference() -> tuple[int, str]:
    return 200, json.dumps({
        "choices": [{
            "finish_reason": "stop",
            "message": {"content": REFERENCE.read_text(encoding="utf-8")},
        }],
        "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7},
    })


class FeedbackLoopTests(unittest.TestCase):
    def test_target_finding_candidate_is_selectable_but_harness_crash_is_not(self) -> None:
        base = {
            "generation": "passed",
            "compilation": {"status": "passed"},
        }
        target = {
            **base,
            "smoke": {"status": "passed"},
            "failure_stage": "fuzzing",
            "fuzzing": {
                "status": "finding",
                "crash_classification": {"classification": "potential_target_crash"},
            },
        }
        smoke_target = {
            **base,
            "failure_stage": "smoke",
            "smoke": {
                "status": "finding",
                "crash_classification": {"classification": "potential_target_crash"},
            },
            "fuzzing": {
                "status": "blocked",
                "reason": "target_finding_observed_during_smoke",
            },
        }
        harness = {
            **base,
            "smoke": {"status": "passed"},
            "failure_stage": "fuzzing",
            "fuzzing": {
                "status": "finding",
                "crash_classification": {"classification": "generated_harness_crash"},
            },
        }

        self.assertIsNone(_candidate_failure_reason(target))
        self.assertIsNone(_candidate_failure_reason(smoke_target))
        self.assertEqual(_candidate_failure_reason(harness), "failure_stage_present")

    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"})
    @patch("harness_generation.candidate.call_api")
    def test_miniparser_feedback_is_injected_into_next_llm_revision(self, api) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        output = root / "loop"
        api.side_effect = (
            _classification_responses() + [_generated_reference()]
            + _classification_responses() + [_generated_reference()]
        )

        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = main([
                "feedback-loop",
                "--source", str(SOURCE),
                "--function", "mp_parse",
                "--parent-harness", str(BASELINE),
                "--output", str(output),
                "--rounds", "2",
                "--children-per-round", "1",
                "--feedback-threshold", "0.9",
                "--generate-only",
            ])

        self.assertEqual(code, 0, stdout.getvalue())
        self.assertEqual(api.call_count, 8)

        parent_feedback = json.loads(
            (output / "round_000" / "automatic_feedback.json").read_text(encoding="utf-8")
        )
        self.assertIn(
            "input_expressiveness",
            [item["metric_id"] for item in parent_feedback["items"]],
        )
        child = output / "round_001"
        grandchild = output / "round_002"
        child_result = json.loads((child / "result.json").read_text(encoding="utf-8"))
        grandchild_result = json.loads((grandchild / "result.json").read_text(encoding="utf-8"))
        child_feedback = json.loads((child / "feedback.json").read_text(encoding="utf-8"))
        prompt = json.loads((child / "prompt.json").read_text(encoding="utf-8"))
        grandchild_prompt = json.loads((grandchild / "prompt.json").read_text(encoding="utf-8"))
        prompt_context = json.loads(prompt["messages"][2]["content"].split("\n", 1)[1])
        loop = json.loads((output / "feedback_loop.json").read_text(encoding="utf-8"))

        self.assertEqual(child_result["parent_id"], "candidate_0001")
        self.assertEqual(child_result["round_index"], 1)
        self.assertEqual(child_feedback["candidate_id"], "candidate_0001")
        self.assertEqual(prompt_context["feedback"]["items"], parent_feedback["items"])
        self.assertIn("input_expressiveness", prompt["messages"][2]["content"])
        self.assertIn("protocol_contract", prompt["messages"][1]["content"])
        self.assertIn("payload_length", prompt["messages"][1]["content"])
        self.assertIn("mp_checksum", prompt["messages"][1]["content"])
        self.assertEqual(api.call_args_list[3].args[0]["messages"][2], prompt["messages"][2])
        self.assertEqual(grandchild_result["parent_id"], child_result["candidate_id"])
        self.assertIn("reachability", grandchild_prompt["messages"][2]["content"])
        self.assertEqual(api.call_args_list[7].args[0]["messages"][2],
                         grandchild_prompt["messages"][2])
        self.assertEqual(loop["status"], "completed")
        self.assertEqual(len(loop["rounds"]), 2)
        self.assertTrue(all(item["selection"]["status"] == "selected"
                            for item in loop["rounds"]))
        self.assertEqual(loop["selected_candidate"], grandchild_result["candidate_id"])
        self.assertTrue((child / "automatic_feedback.json").is_file())

    @patch("harness_generation.feedback_loop.run_experiment")
    @patch("harness_generation.feedback_loop.run_candidate")
    def test_failed_initial_parent_with_feedback_still_drives_revision(
        self, run_candidate, run_experiment,
    ) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        output = root / "loop"

        def fake_parent(config, original, existing_code):
            source_hash = hashlib.sha256(original).hexdigest()
            harness_hash = hashlib.sha256(existing_code.encode("utf-8")).hexdigest()
            config.output.mkdir(parents=True, exist_ok=True)
            (config.output / "target.c").write_bytes(original)
            (config.output / "harness.c").write_text(existing_code, encoding="utf-8")
            result = {
                "candidate_id": "candidate_0001",
                "round_index": 0,
                "source_sha256": source_hash,
                "harness_sha256": harness_hash,
                "function": "mp_parse",
                "generation": "skipped",
                "compilation": {"status": "passed"},
                "smoke": {"status": "passed"},
                "fuzzing": {"status": "finding"},
                "failure_stage": "fuzzing",
                "error": "Short fuzz run did not complete; see fuzz_result.json",
            }
            (config.output / "result.json").write_text(
                json.dumps(result, indent=2), encoding="utf-8",
            )
            feedback = {
                "schema_version": 1,
                "candidate_id": "candidate_0001",
                "round_index": 0,
                "source_sha256": source_hash,
                "harness_sha256": harness_hash,
                "items": [{
                    "metric_id": None,
                    "observation": "fuzzing status is finding.",
                    "hypothesis": "The target exposed a sanitizer finding.",
                    "suggestion": "Preserve the target call and improve structure.",
                    "evidence": [{
                        "artifact": "result.json",
                        "description": "Candidate result",
                    }],
                }],
            }
            (config.output / "automatic_feedback.json").write_text(
                json.dumps(feedback, indent=2), encoding="utf-8",
            )
            return result, 1

        def fake_experiment(config, original, count):
            self.assertEqual(count, 1)
            source_hash = hashlib.sha256(original).hexdigest()
            harness_hash = "a" * 64
            config.output.mkdir(parents=True, exist_ok=True)
            result = {
                "candidate_id": "candidate_0001",
                "parent_id": "candidate_0001",
                "round_index": 1,
                "source_sha256": source_hash,
                "harness_sha256": harness_hash,
                "function": "mp_parse",
                "generation": "passed",
                "compilation": {"status": "passed"},
                "smoke": {"status": "passed"},
                "fuzzing": {"status": "completed"},
                "evaluation": {"status": "complete", "report": "evaluation.json"},
            }
            evaluation = {
                "schema_version": 1,
                "candidate_id": "candidate_0001",
                "parent_id": "candidate_0001",
                "round_index": 1,
                "source_sha256": source_hash,
                "harness_sha256": harness_hash,
                "metrics": [{
                    "metric_id": "reachability",
                    "status": "measured",
                    "evaluator": "test",
                    "version": "1",
                    "reason": "target is called",
                    "score": 1.0,
                    "measurements": [{
                        "name": "called",
                        "value": True,
                        "unit": "bool",
                        "scope": "target_api",
                    }],
                    "evidence": [{
                        "artifact": "result.json",
                        "description": "Child result",
                    }],
                }],
                "aggregate": {
                    "status": "scored",
                    "score": 1.0,
                    "eligible": True,
                    "reason": "test aggregate",
                    "policy": "test",
                    "version": "1",
                },
                "status": "complete",
            }
            (config.output / "experiment.json").write_text(
                json.dumps({"status": "completed"}, indent=2), encoding="utf-8",
            )
            (config.output / "result.json").write_text(
                json.dumps(result, indent=2), encoding="utf-8",
            )
            (config.output / "evaluation.json").write_text(
                json.dumps(evaluation, indent=2), encoding="utf-8",
            )
            return 0

        run_candidate.side_effect = fake_parent
        run_experiment.side_effect = fake_experiment
        stdout = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
            code = main([
                "feedback-loop",
                "--source", str(SOURCE),
                "--function", "mp_parse",
                "--parent-harness", str(BASELINE),
                "--output", str(output),
                "--rounds", "1",
            ])

        self.assertEqual(code, 0, stdout.getvalue())
        self.assertEqual(run_experiment.call_count, 1)
        loop = json.loads((output / "feedback_loop.json").read_text(encoding="utf-8"))
        self.assertEqual(loop["status"], "completed")
        self.assertTrue(loop["initial_parent"]["accepted_for_revision"])
        self.assertEqual(loop["initial_parent"]["failure_stage"], "fuzzing")
        self.assertEqual(loop["rounds"][0]["feedback"]["item_count"], 1)
        self.assertEqual(loop["rounds"][0]["selected_candidate"], "candidate_0001")

    def test_loop_cli_requires_new_output_and_one_parent_source(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        occupied = root / "occupied"
        occupied.mkdir()
        (occupied / "sentinel").write_text("keep", encoding="utf-8")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main([
                "feedback-loop",
                "--source", str(SOURCE),
                "--function", "mp_parse",
                "--parent-harness", str(REFERENCE),
                "--output", str(occupied),
            ])
        self.assertEqual(code, 1)
        self.assertEqual((occupied / "sentinel").read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
