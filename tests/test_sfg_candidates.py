import json
from pathlib import Path
import tempfile
import unittest

from sfg_builder.candidates import (CandidateDetector, ISFCandidateDetector,
                                    PRFHPFCandidateDetector, write_candidates_json)
from sfg_builder.parser import CProjectParser


SOURCE = r'''
typedef struct Context { int state; } Context;
typedef struct Result { int value; } Result;

int parse(Context *ctx, const char *filename, const char *path,
          char *error_message, void *memory, char *text,
          unsigned char *raw, uint8_t *bytes, const uint8_t *constant_bytes,
          int8_t *signed_bytes, float *values);
Result process(Context context);
Context *create_context(void);
int scalar_only(int value);
'''


class CandidateDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        project = Path(self.temporary.name)
        (project / "api.h").write_text(SOURCE)
        self.functions = CProjectParser().parse(project).functions

    def test_isf_detector_is_high_recall_and_does_not_assign_labels(self):
        candidates = ISFCandidateDetector().detect(self.functions)
        self.assertEqual([candidate.function for candidate in candidates], ["parse"])
        candidate = candidates[0]
        self.assertEqual(
            {parameter.name for parameter in candidate.candidate_parameters},
            {"filename", "path", "error_message", "memory", "text", "raw", "bytes",
             "constant_bytes", "signed_bytes"},
        )
        self.assertNotIn("ctx", {parameter.name for parameter in candidate.stream_parameters})
        self.assertNotIn("values", {parameter.name for parameter in candidate.stream_parameters})
        self.assertTrue(candidate.isf_candidate)
        self.assertFalse(candidate.struct_related_candidate)
        self.assertTrue(all(function.labels == () for function in self.functions))

    def test_struct_detector_covers_parameters_and_return_values(self):
        candidates = {candidate.function: candidate for candidate in
                      PRFHPFCandidateDetector().detect(self.functions)}
        self.assertEqual(set(candidates), {"parse", "process", "create_context"})
        self.assertEqual(candidates["parse"].struct_parameters[0].name, "ctx")
        self.assertEqual(candidates["process"].struct_parameters[0].name, "context")
        self.assertEqual(candidates["process"].return_struct, "Result")
        self.assertEqual(candidates["create_context"].return_struct, "Context")
        self.assertTrue(all(candidate.prf_candidate for candidate in candidates.values()))
        self.assertTrue(all(candidate.hpf_candidate for candidate in candidates.values()))
        self.assertTrue(all(not candidate.isf_candidate for candidate in candidates.values()))

    def test_combined_detector_and_candidates_json(self):
        candidates = CandidateDetector().detect(self.functions)
        by_name = {candidate.function: candidate for candidate in candidates}
        self.assertEqual(set(by_name), {"parse", "process", "create_context"})
        self.assertTrue(by_name["parse"].isf_candidate)
        self.assertTrue(by_name["parse"].struct_related_candidate)
        self.assertNotIn("scalar_only", by_name)

        path = Path(self.temporary.name) / "artifacts" / "candidates.json"
        written = write_candidates_json(candidates, path)
        payload = json.loads(path.read_text())
        self.assertEqual(written, path)
        self.assertEqual(payload["isf"], ["parse"])
        self.assertEqual(payload["prf"], ["parse", "process", "create_context"])
        self.assertEqual(payload["hpf"], ["parse", "process", "create_context"])
        serialized = next(item for item in payload["candidates"]
                          if item["function"] == "parse")
        self.assertTrue(serialized["isf_candidate"])
        self.assertEqual(serialized["stream_parameters"][0]["name"], "filename")


if __name__ == "__main__":
    unittest.main()
