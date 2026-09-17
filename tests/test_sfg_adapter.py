from pathlib import Path
import unittest

from harness_generation.sfg_adapter import (CANONICAL_NULL_NODE, SFGLoadError,
    adapt_sfg_document, is_null_node, load_sfg_artifacts, normalize_null_node)


ARTIFACTS = Path(__file__).resolve().parents[1] / "artifacts" / "simple"


def edge(function, function_id, source="Context", target="Result", labels=None):
    return {
        "source": source,
        "target": target,
        "function": function,
        "function_id": function_id,
        "labels": labels or ["PRF"],
        "file": "src/example.c",
        "line": 10,
        "inferred": False,
        "inference_reason": None,
    }


class SFGAdapterTests(unittest.TestCase):
    def test_loads_real_artifact_bundle_and_indexes_companions(self):
        artifacts = load_sfg_artifacts(ARTIFACTS)
        self.assertEqual(
            dict(artifacts.source_schema_versions),
            {"annotations": 1, "flows": 1, "functions": 2, "sfg": 1},
        )
        self.assertEqual(len(artifacts.functions), 4)
        self.assertEqual(len(artifacts.annotations), 4)
        self.assertEqual(len(artifacts.flows), 4)
        self.assertEqual(artifacts.files, ("include/parser.h", "src/parser.c"))
        self.assertEqual([item["name"] for item in artifacts.structs], ["Node", "Parser"])
        self.assertEqual(artifacts.function_warnings, ())
        self.assertEqual(artifacts.graph.null_node_id, "(null)")
        function_id = "src/parser.c:3:parser_from_memory"
        self.assertEqual(artifacts.functions_by_id[function_id]["name"], "parser_from_memory")
        self.assertEqual(artifacts.annotations_by_id[function_id]["labels"], ["ISF", "HPF"])
        self.assertEqual(artifacts.flows_by_id[function_id]["output_structs"], ["Parser"])
        self.assertEqual(artifacts.graph.ancestors("Node"), ("(null)", "Parser"))
        self.assertEqual(artifacts.graph.descendants("Parser"), ("(null)", "Node"))

    def test_null_spellings_and_kind_are_normalized_in_one_place(self):
        aliases = (None, "null", "NULL", "(null)", "**NULL**", "None", "__NULL__")
        for alias in aliases:
            with self.subTest(alias=alias):
                self.assertTrue(is_null_node(alias))
                self.assertEqual(normalize_null_node(alias), CANONICAL_NULL_NODE)
        self.assertTrue(is_null_node("project-sentinel", kind="null"))
        self.assertFalse(is_null_node("NullableContext"))
        self.assertEqual(normalize_null_node(" Context "), "Context")

    def test_parallel_edges_are_preserved_and_traversal_is_stable(self):
        document = {
            "schema_version": 1,
            "nodes": [
                {"id": "Context", "kind": "struct"},
                {"id": "Result", "kind": "struct"},
                {"id": "**NULL**", "kind": "null"},
            ],
            "edges": [
                edge("foo", "src/example.c:10:foo"),
                edge("bar", "src/example.c:11:bar"),
                edge("finish", "src/example.c:12:finish", "Result", None),
            ],
            "functions": [],
            "warnings": [],
        }
        graph = adapt_sfg_document(document)
        self.assertEqual(
            [item.function for item in graph.outgoing("Context")],
            ["foo", "bar"],
        )
        self.assertEqual(len(graph.outgoing("Context")), 2)
        self.assertEqual(graph.outgoing("Result")[0].target, CANONICAL_NULL_NODE)
        self.assertEqual(graph.descendants("Context"), ("(null)", "Result"))
        self.assertEqual(graph.ancestors(None), ())

    def test_null_sentinel_is_reachable_but_never_propagates(self):
        document = {
            "schema_version": 1,
            "nodes": [
                {"id": "A", "kind": "struct"},
                {"id": "B", "kind": "struct"},
                {"id": "C", "kind": "struct"},
                {"id": "(null)", "kind": "null"},
            ],
            "edges": [
                edge("finish_a", "finish-a", "A", "(null)"),
                edge("finish_b", "finish-b", "B", "(null)"),
                edge("start_c", "start-c", "(null)", "C"),
            ],
            "functions": [],
            "warnings": [],
        }
        graph = adapt_sfg_document(document)
        self.assertEqual(graph.descendants("A"), ("(null)",))
        self.assertEqual(graph.descendants("B"), ("(null)",))
        self.assertEqual(graph.ancestors("C"), ("(null)",))
        self.assertEqual(graph.descendants("(null)"), ())
        self.assertEqual(graph.ancestors("(null)"), ())

    def test_predicate_filters_edges_without_changing_graph(self):
        document = {
            "schema_version": 1,
            "nodes": [
                {"id": "A", "kind": "struct"},
                {"id": "B", "kind": "struct"},
            ],
            "edges": [
                edge("parse", "parse-id", "A", "B", ["ISF"]),
                edge("process", "process-id", "A", "B", ["PRF"]),
            ],
            "functions": [],
            "warnings": [],
        }
        graph = adapt_sfg_document(document)
        only_prf = lambda item: "PRF" in item.labels
        self.assertEqual([item.function for item in graph.outgoing("A", predicate=only_prf)],
                         ["process"])
        self.assertEqual(len(graph.outgoing("A")), 2)

    def test_invalid_schema_is_rejected(self):
        with self.assertRaises(SFGLoadError):
            adapt_sfg_document({"schema_version": 2, "nodes": [], "edges": []})


if __name__ == "__main__":
    unittest.main()
