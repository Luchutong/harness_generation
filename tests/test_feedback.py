import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

from harness_generation.cli import main
from harness_generation.feedback import load_revision, StructuredFeedbackPromptBuilder
from harness_generation.source_analysis import analyze_c_source
from harness_generation.isf import apply_isf_filter, pointer_parameter_items

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "benchmarks/mini_parser/target.c"
REFERENCE = ROOT / "benchmarks/mini_parser/harnesses/structured.c"
FUNCTION = "mp_parse"


def filtered(summary):
    decisions = []
    for item in pointer_parameter_items(summary):
        yes = item["parameter"] in {"payload", "data", "p"}
        decisions.append({**item, "category": "A" if yes else "C",
                          "positive_votes": 3 if yes else 0, "is_byte_stream": yes})
    return apply_isf_filter(summary, {"prompt_version": "test", "vote_threshold": 2,
                                     "decisions": decisions})


def classification_responses():
    positive = {"f0003:p0001", "f0004:p0002", "f0005:p0001"}
    ids = ["f0001:p0001", "f0002:p0001", "f0003:p0001",
           "f0004:p0001", "f0004:p0002", "f0005:p0001"]
    contents = [
        {"byte_stream_parameter_ids": sorted(positive)},
        {"answers": [{"id": item, "answer": "yes" if item in positive else "no"} for item in ids]},
        {"classifications": [{"id": item, "choice": "A" if item in positive else "C"} for item in ids]},
    ]
    return [(200, json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(item)}}]}))
            for item in contents]


class FeedbackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.parent = self.root / "parent"
        self.parent.mkdir()
        self.source = SOURCE.read_bytes()
        self.harness = REFERENCE.read_text()
        (self.parent / "target.c").write_bytes(self.source)
        (self.parent / "harness.c").write_text(self.harness)
        self.record = {"candidate_id": "candidate_0005", "round_index": 0,
                       "source_sha256": hashlib.sha256(self.source).hexdigest(),
                       "harness_sha256": hashlib.sha256(self.harness.encode()).hexdigest(), "function": FUNCTION}
        (self.parent / "result.json").write_text(json.dumps(self.record))
        self.packet = {key: value for key, value in self.record.items() if key != "function"}
        self.packet.update(schema_version=1, items=[{
            "metric_id": "reachability", "observation": "Synthetic observation for interface testing",
            "hypothesis": "Synthetic hypothesis", "suggestion": "Check the length guard",
            "evidence": [{"artifact": "harness.c", "description": "Parent source"}]}])
        self.feedback = self.root / "feedback.json"
        self.save()
        self.output = self.root / "children"

    def save(self):
        self.feedback.write_text(json.dumps(self.packet))

    def args(self):
        return ["--source", str(self.parent / "target.c"), "--function", FUNCTION,
                "--parent-candidate", str(self.parent), "--feedback", str(self.feedback),
                "--output", str(self.output), "--candidates", "2", "--generate-only"]

    def test_prompt_contains_context_and_no_invented_scores(self):
        revision = load_revision(self.parent, self.feedback, self.source, FUNCTION)
        summary = filtered(analyze_c_source(self.source, FUNCTION))
        summary["protocol_contract"] = {
            "entry_function": "mp_parse",
            "contract": {
                "command_loop": {"max_steps": 32},
                "frame": {"fields": [{"name": "payload_length", "offset": 4}]},
            },
            "requirements": ["Use a bounded multi-frame command loop."],
        }
        payload = StructuredFeedbackPromptBuilder().build(summary, FUNCTION, "test", 0.8, revision)
        self.assertEqual(len(payload["messages"]), 3)
        self.assertIn("Tree-sitter C syntax summary", payload["messages"][1]["content"])
        self.assertNotIn("BUG 4", payload["messages"][1]["content"])
        self.assertIn("protocol_contract", payload["messages"][1]["content"])
        self.assertIn("payload_length", payload["messages"][1]["content"])
        self.assertIn("multi-frame command loop", payload["messages"][0]["content"])
        self.assertIn("raw pass-through call", payload["messages"][0]["content"])
        context = json.loads(payload["messages"][2]["content"].split("\n", 1)[1])
        self.assertEqual(context["parent_harness"], self.harness)
        self.assertEqual(context["feedback"]["items"][0]["hypothesis"], "Synthetic hypothesis")
        self.assertEqual(context["evidence_snapshots"][0]["text"], self.harness)

    @patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-secret"})
    @patch("harness_generation.candidate.call_api")
    def test_two_children_preserve_lineage_and_parent(self, api):
        generated = (200, json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": self.harness}}]}))
        api.side_effect = classification_responses() + [generated, generated]
        before = (self.parent / "result.json").read_bytes()
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(self.args()), 0)
        self.assertEqual(api.call_count, 5)
        self.assertEqual(before, (self.parent / "result.json").read_bytes())
        summary = json.loads((self.output / "experiment.json").read_text())
        self.assertEqual(summary["strategy"], "feedback_revision")
        for i in (1, 2):
            child = self.output / f"candidates/candidate_{i:04d}"
            result = json.loads((child / "result.json").read_text())
            self.assertEqual(result["parent_id"], "candidate_0005")
            self.assertEqual(result["round_index"], 1)
            self.assertNotEqual(result["candidate_id"], "candidate_0005")
            self.assertTrue((child / "feedback_evidence.json").exists())
            self.assertTrue((child / "parent_harness.c").exists())

    @patch("harness_generation.candidate.call_api")
    def test_stale_hash_rejected_before_output_and_api(self, api):
        self.packet["harness_sha256"] = "stale"
        self.save()
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(self.args()), 1)
        api.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_wrong_round_target_and_missing_feedback_rejected(self):
        for field, value in (("round_index", 2), ("source_sha256", "wrong"),
                             ("items", []), ("schema_version", 2), ("candidate_id", "other")):
            original = self.packet[field]
            self.packet[field] = value
            self.save()
            with self.subTest(field=field), self.assertRaises(ValueError):
                load_revision(self.parent, self.feedback, self.source, FUNCTION)
            self.packet[field] = original

    def test_outside_evidence_rejected(self):
        self.packet["items"][0]["evidence"][0]["artifact"] = "../feedback.json"
        self.save()
        with self.assertRaises(ValueError):
            load_revision(self.parent, self.feedback, self.source, FUNCTION)

    def test_truncated_evidence_explicit(self):
        (self.parent / "probe.txt").write_text("a" * 5000)
        self.packet["items"][0]["evidence"][0]["artifact"] = "probe.txt"
        self.save()
        evidence = load_revision(self.parent, self.feedback, self.source, FUNCTION).evidence_snapshots[0]
        self.assertTrue(evidence["truncated"])
        self.assertEqual(len(evidence["text"]), 4096)
