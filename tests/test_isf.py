import json
import unittest

from harness_generation.core import GenerationError, make_request
from harness_generation.isf import (IsfClassificationError, apply_isf_filter, classify_isf_parameters,
                                    make_isf_requests, pointer_parameter_items,
                                    target_is_isf)


SUMMARY = {
    "pointer_candidates": [
        {"name": "parse", "signature": "int parse(void *ctx, const uint8_t *data, size_t len);",
         "defined": True, "line": 1, "pointer_parameters": [
             {"name": "ctx", "declaration": "void *ctx", "pointer_depth": 1},
             {"name": "data", "declaration": "const uint8_t *data", "pointer_depth": 1},
         ]},
        {"name": "scalar", "signature": "void scalar(float *value);", "defined": True, "line": 2,
         "pointer_parameters": [{"name": "value", "declaration": "float *value", "pointer_depth": 1}]},
    ],
    "target": {"name": "parse"},
}


def response(content):
    return 200, json.dumps({
        "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(content)}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
    })


class IsfTests(unittest.TestCase):
    def test_pointer_pre_filter_and_three_distinct_prompts(self):
        items = pointer_parameter_items(SUMMARY)
        self.assertEqual([item["parameter"] for item in items], ["ctx", "data", "value"])
        requests = make_isf_requests(SUMMARY, "model")
        self.assertEqual(len(requests), 3)
        self.assertTrue(all(request["temperature"] == 0 for request in requests))
        self.assertEqual(len({request["messages"][1]["content"] for request in requests}), 3)

    def test_majority_vote_and_category_are_preserved(self):
        answers = iter([
            response({"byte_stream_parameter_ids": ["f0001:p0002", "f0002:p0001"]}),
            response({"answers": [
                {"id": "f0001:p0001", "answer": "no"},
                {"id": "f0001:p0002", "answer": "yes"},
                {"id": "f0002:p0001", "answer": "no"},
            ]}),
            response({"classifications": [
                {"id": "f0001:p0001", "choice": "C"},
                {"id": "f0001:p0002", "choice": "B"},
                {"id": "f0002:p0001", "choice": "D"},
            ]}),
        ])
        report = classify_isf_parameters(SUMMARY, "model", "secret", lambda *_: next(answers))
        decisions = {decision["parameter"]: decision for decision in report["decisions"]}
        self.assertFalse(decisions["ctx"]["is_byte_stream"])
        self.assertTrue(decisions["data"]["is_byte_stream"])
        self.assertEqual(decisions["data"]["category_label"], "text_data")
        self.assertFalse(decisions["value"]["is_byte_stream"])
        self.assertEqual(decisions["value"]["positive_votes"], 1)
        self.assertEqual(report["usage"]["total_tokens"], 9)

        filtered = apply_isf_filter(SUMMARY, report)
        self.assertNotIn("pointer_candidates", filtered)
        self.assertEqual([item["name"] for item in filtered["isf_functions"]], ["parse"])
        self.assertEqual(filtered["isf_functions"][0]["byte_stream_parameters"][0]["name"], "data")
        self.assertTrue(target_is_isf(filtered, "parse"))
        make_request(filtered, "parse", "model")
        with self.assertRaises(GenerationError):
            make_request(SUMMARY, "parse", "model")

    def test_incomplete_vote_is_rejected(self):
        answers = iter([
            response({"byte_stream_parameter_ids": []}),
            response({"answers": []}),
            response({"classifications": []}),
        ])
        with self.assertRaises(GenerationError):
            classify_isf_parameters(SUMMARY, "model", "secret", lambda *_: next(answers))

    def test_http_failure_retains_partial_audit_report(self):
        with self.assertRaises(IsfClassificationError) as caught:
            classify_isf_parameters(SUMMARY, "model", "secret", lambda *_: (429, "rate limited"))
        self.assertEqual(caught.exception.report["status"], "failed")
        self.assertEqual(caught.exception.report["api_attempts"], 1)
        self.assertEqual(caught.exception.report["responses"][0]["http_status"], 429)


if __name__ == "__main__":
    unittest.main()
