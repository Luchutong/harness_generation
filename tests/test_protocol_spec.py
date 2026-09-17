import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.core import make_request
from harness_generation.protocol_spec import (
    discover_protocol_spec,
    load_protocol_spec,
)
from harness_generation.source_analysis import analyze_c_source
from harness_generation.isf import apply_isf_filter, pointer_parameter_items


ROOT = Path(__file__).resolve().parents[1]
MINI_PARSER = ROOT / "benchmarks" / "mini_parser"
SOURCE = MINI_PARSER / "target.c"


def _filtered_summary():
    summary = analyze_c_source(SOURCE.read_bytes(), "mp_parse")
    decisions = [
        {
            **item,
            "category": "A" if item["function"] == "mp_parse" and item["parameter"] == "data" else "C",
            "positive_votes": 3 if item["function"] == "mp_parse" and item["parameter"] == "data" else 0,
            "is_byte_stream": item["function"] == "mp_parse" and item["parameter"] == "data",
        }
        for item in pointer_parameter_items(summary)
    ]
    return apply_isf_filter(summary, {
        "prompt_version": "test",
        "vote_threshold": 2,
        "decisions": decisions,
    })


class ProtocolSpecTests(unittest.TestCase):
    def test_mini_parser_protocol_spec_is_discovered_and_prompted(self):
        discovered = discover_protocol_spec(SOURCE)
        self.assertEqual(discovered, MINI_PARSER / "protocol.json")
        contract = load_protocol_spec(discovered, "mp_parse")
        summary = _filtered_summary()
        summary["protocol_contract"] = contract

        payload = make_request(summary, "mp_parse", "test-model")
        rendered = "\n".join(message["content"] for message in payload["messages"])

        self.assertIn("multi-frame command loop", rendered)
        self.assertIn("payload_length", rendered)
        self.assertIn("little_endian", rendered)
        self.assertIn("mp_checksum", rendered)
        self.assertIn("raw pass-through", rendered)

    def test_protocol_spec_rejects_wrong_entry_function(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "protocol.json"
            path.write_text(json.dumps({
                "schema_version": 1,
                "entry_function": "other",
                "contract": {},
            }), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "does not match"):
                load_protocol_spec(path, "mp_parse")


if __name__ == "__main__":
    unittest.main()
