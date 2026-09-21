"""The one-shot source baseline remains tied to its prompt and measurement."""

import json
from pathlib import Path
import re
import unittest

from harness_generation.coverage_arms import digest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "direct_source_baseline"


class DirectSourceEvidenceTests(unittest.TestCase):
    def test_prompt_response_harness_and_measurement_agree(self):
        manifest = json.loads((FIXTURE / "input_manifest.json").read_text())
        generation = json.loads((FIXTURE / "generation.json").read_text())
        measured = json.loads((FIXTURE / "measurements.json").read_text())
        exact = json.loads((FIXTURE / "exact_reference_comparison.json").read_text())

        self.assertEqual(digest(FIXTURE / "prompt.txt"),
                         manifest["prompt_sha256"])
        self.assertEqual(digest(FIXTURE / "harness.cpp"),
                         manifest["harness_sha256"])
        match = re.fullmatch(
            r"```cpp\n(.*?)\n```", generation["content"].strip(), re.DOTALL
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1).strip(),
                         (FIXTURE / "harness.cpp").read_text().strip())
        self.assertEqual(generation["response_id"], manifest["response_id"])
        self.assertEqual(generation["finish_reason"], "stop")
        self.assertEqual(measured["harness_sha256"], manifest["harness_sha256"])
        self.assertEqual(measured["target_sha256"], exact["target_sha256"])
        self.assertEqual(measured["corpus_digests"], exact["corpus_digests"])
        self.assertEqual(measured["recipe"], exact["recipe"])

        self.assertEqual([row["seed"] for row in measured["records"]], [1, 2, 3])
        for row in measured["records"]:
            self.assertEqual(row["status"], "passed")
            self.assertEqual(row["runs"], 20_000)
            self.assertEqual(row["totals"]["lines"]["covered"], 10)
            self.assertNotIn("mp_checksum", row["entered_functions"])
        for row in exact["records"]:
            self.assertEqual(row["status"], "passed")
            self.assertEqual(row["runs"], 20_000)
            self.assertEqual(row["totals"]["branches"]["covered"], 56)


if __name__ == "__main__":
    unittest.main()
