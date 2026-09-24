import json
from pathlib import Path
import tempfile
import unittest

from sfg_builder.candidates import CandidateDetector
from sfg_builder.directions import StructDirectionAnalyzer
from sfg_builder.mock import MockSemanticAnalyzer
from sfg_builder.parser import CProjectParser
from sfg_builder.roles import FunctionRoleAnnotator, write_annotations_json


SOURCE = r'''
typedef struct Item { int value; int counter; } Item;

Item read_and_return(Item *source) {
    Item result;
    result.value = source->value;
    return result;
}

void fill(Item *output) { output->value = 1; }
void bump(Item *item) { item->counter++; }
int inspect(const Item *input) { return input->value; }
void opaque(Item *unknown) { (void)unknown; }
int by_value(Item item) { return item.value; }
'''


class RecordingDirectionAnalyzer(MockSemanticAnalyzer):
    def __init__(self):
        self.calls = []

    def infer_struct_direction(self, function, parameter, hint, structs):
        self.calls.append((function, parameter, hint, structs))
        return super().infer_struct_direction(function, parameter, hint, structs)


class FailingDirectionAnalyzer(MockSemanticAnalyzer):
    def infer_struct_direction(self, *args):
        raise TimeoutError("private provider failure")


class DirectionAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        project = Path(self.temporary.name)
        (project / "direction.c").write_text(SOURCE)
        self.parsed = CProjectParser().parse(project)
        candidates = CandidateDetector().detect(self.parsed.functions)
        self.roles = FunctionRoleAnnotator(MockSemanticAnalyzer()).annotate(
            self.parsed.functions, candidates, self.parsed.structs)

    def test_ast_hints_cover_member_read_write_and_increment(self):
        functions = {function.name: function for function in self.parsed.functions}
        read = functions["read_and_return"].access_hints[0]
        write = functions["fill"].access_hints[0]
        both = functions["bump"].access_hints[0]
        self.assertEqual((read.reads, read.writes), (True, False))
        self.assertEqual((write.reads, write.writes), (False, True))
        self.assertEqual((both.reads, both.writes), (True, True))
        self.assertTrue(any("read+write" in evidence for evidence in both.evidence))

    def test_only_ambiguous_struct_pointers_use_semantic_analyzer(self):
        analyzer = RecordingDirectionAnalyzer()
        results = StructDirectionAnalyzer(analyzer).analyze(
            self.parsed.functions, self.roles, self.parsed.structs)
        by_name = {result.function: result for result in results}
        self.assertEqual(len(analyzer.calls), 1)
        self.assertEqual(by_name["read_and_return"].struct_directions[0].direction, "input")
        self.assertEqual(by_name["fill"].struct_directions[0].direction, "output")
        self.assertEqual(by_name["bump"].struct_directions[0].direction, "both")
        self.assertEqual(by_name["inspect"].struct_directions[0].direction, "input")
        self.assertEqual(by_name["opaque"].struct_directions[0].direction, "unknown")
        self.assertEqual(by_name["by_value"].struct_directions[0].direction, "input")
        self.assertEqual(by_name["read_and_return"].output_struct_candidates, ("Item",))
        self.assertEqual(by_name["fill"].output_struct_candidates, ())

        for function, parameter, hint, structs in analyzer.calls:
            self.assertTrue(parameter.is_pointer)
            self.assertIsNotNone(hint)
            self.assertEqual({struct.name for struct in structs}, {"Item"})
            trace = next(trace for trace in by_name[function.name].decisions
                         if trace.task == "struct_direction")
            self.assertIn(function.signature, trace.prompt)
            self.assertIn(function.body, trace.prompt)
            self.assertIn("AST access hints", trace.prompt)
        self.assertEqual(analyzer.calls[0][0].name, "opaque")
        for name in ("read_and_return", "fill", "bump", "inspect"):
            trace = next(trace for trace in by_name[name].decisions
                         if trace.task == "struct_direction")
            self.assertEqual(trace.prompt_version, "sfg-direction-static-v1")

    def test_semantic_failure_uses_ast_fallback_without_aborting(self):
        results = StructDirectionAnalyzer(FailingDirectionAnalyzer()).analyze(
            self.parsed.functions, self.roles, self.parsed.structs)
        by_name = {result.function: result for result in results}
        self.assertEqual(by_name["fill"].struct_directions[0].direction, "output")
        self.assertEqual(by_name["bump"].struct_directions[0].direction, "both")
        self.assertEqual(by_name["inspect"].struct_directions[0].direction, "input")
        self.assertEqual(by_name["opaque"].struct_directions[0].direction, "unknown")
        trace = next(trace for trace in by_name["opaque"].decisions
                     if trace.task == "struct_direction")
        self.assertEqual(trace.status, "error")
        self.assertEqual(trace.error, "TimeoutError")
        self.assertNotIn("private provider failure", trace.error)

    def test_direction_results_are_serialized_in_annotations_json(self):
        results = StructDirectionAnalyzer(MockSemanticAnalyzer()).analyze(
            self.parsed.functions, self.roles, self.parsed.structs)
        path = Path(self.temporary.name) / "artifacts" / "annotations.json"
        write_annotations_json(results, path)
        payload = json.loads(path.read_text())
        returned = next(item for item in payload["annotations"]
                        if item["function"] == "read_and_return")
        self.assertEqual(returned["output_struct_candidates"], ["Item"])
        self.assertEqual(returned["struct_directions"][0]["direction"], "input")
        self.assertTrue(returned["struct_directions"][0]["access_hint"]["reads"])
        decision = next(item for item in returned["decisions"]
                        if item["task"] == "struct_direction")
        self.assertEqual(decision["response"]["parameter"], "source")
        self.assertEqual(decision["response"]["struct_type"], "Item")
        self.assertIn(decision["response"]["direction"],
                      {"input", "output", "both", "unknown"})
        self.assertIsInstance(decision["response"]["reason"], str)


if __name__ == "__main__":
    unittest.main()
