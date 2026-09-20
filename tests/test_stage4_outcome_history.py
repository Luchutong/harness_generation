"""Check a recorded failure table against both parse and build evidence."""

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests/fixtures/stage4_build_attempts/manifest.json"


class RecordedBuildOutcomeTests(unittest.TestCase):
    def test_buckets_join_parse_and_build_results(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        source = ROOT / manifest["source"]
        attempts = manifest["attempts"]
        self.assertEqual(
            {row["attempt"] for row in attempts},
            {path.name for path in source.glob("attempt_*")},
        )

        build_failures = 0
        for row in attempts:
            with self.subTest(attempt=row["attempt"]):
                attempt = source / row["attempt"]
                parsed = json.loads((attempt / "parsed.json").read_text())
                compiler = json.loads(
                    (attempt / "validation/compiler.json").read_text()
                )
                runtime = json.loads(
                    (attempt / "validation/runtime.json").read_text()
                )
                context = compiler.get("metadata", {}).get("failure_context") or {}
                self.assertEqual(row["parsed_status"], parsed["status"])
                if compiler["status"] == "failed":
                    build_failures += 1
                    self.assertEqual(parsed["status"], "passed")
                    self.assertEqual(row["recorded_status"], compiler["status"])
                    self.assertEqual(row["recorded_phase"], context["failed_stage"])
                    self.assertEqual(row["failure_type"], context["failure_type"])
                    self.assertEqual(
                        row["recorded_error"],
                        context["error_summary"].split("error: ", 1)[-1],
                    )
                else:
                    self.assertEqual(row["recorded_status"], runtime["status"])
                    self.assertEqual(row["recorded_phase"], "validated")
                    self.assertIsNone(row["failure_type"])
                    self.assertIsNone(row["recorded_error"])

        self.assertGreater(build_failures, 0)


if __name__ == "__main__":
    unittest.main()
