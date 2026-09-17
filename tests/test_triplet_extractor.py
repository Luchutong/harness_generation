from pathlib import Path
import unittest

from harness_generation.sfg_adapter import (SFGArtifacts, adapt_sfg_document,
                                             load_sfg_artifacts)
from harness_generation.triplet import triplets_document
from harness_generation.triplet_extractor import FunctionTripletExtractor


REAL_ARTIFACTS = Path(__file__).resolve().parents[1] / "artifacts" / "simple"


def make_artifacts(specs):
    """Build a schema-v1 artifact bundle from (name, roles, src, dst) records."""
    functions = []
    annotations = []
    flows = []
    edges = []
    node_names = set()
    for line, spec in enumerate(specs, 1):
        name, roles, source, target = spec[:4]
        file = spec[4] if len(spec) > 4 else "src/fixture.c"
        signature = spec[5] if len(spec) > 5 else f"void {name}(void)"
        function_id = f"{file}:{line}:{name}"
        function_record = {
            "id": function_id,
            "name": name,
            "file": file,
            "start_line": line,
            "signature": signature,
        }
        if len(spec) > 6:
            function_record.update(spec[6])
        functions.append(function_record)
        annotations.append({
            "function_id": function_id,
            "function": name,
            "file": file,
            "line": line,
            "labels": list(roles),
        })
        flow = {
            "function_id": function_id,
            "function": name,
            "labels": list(roles),
        }
        flows.append(flow)
        edges.append({
            "source": source,
            "target": target,
            "function": name,
            "function_id": function_id,
            "labels": list(roles),
            "file": file,
            "line": line,
            "inferred": False,
            "inference_reason": None,
        })
        node_names.update((source, target))
    nodes = [
        {"id": node, "kind": "null" if str(node).lower() == "(null)" else "struct"}
        for node in node_names
    ]
    graph = adapt_sfg_document({
        "schema_version": 1,
        "nodes": nodes,
        "edges": edges,
        "functions": flows,
        "warnings": [],
    })
    return SFGArtifacts(
        graph=graph,
        project="synthetic",
        files=("src/fixture.c",),
        structs=tuple(
            {"name": node} for node in node_names if str(node).lower() != "(null)"
        ),
        function_warnings=(),
        functions=tuple(functions),
        annotations=tuple(annotations),
        flows=tuple(flows),
        embedded_flows=tuple(flows),
        source_schema_versions={"functions": 1, "annotations": 1, "flows": 1, "sfg": 1},
    )


def names(functions):
    return [function.function for function in functions]


class FunctionTripletExtractorTests(unittest.TestCase):
    def setUp(self):
        self.extractor = FunctionTripletExtractor()

    def test_case_a_simple_chain(self):
        artifacts = make_artifacts([
            ("parse", ("ISF",), "ByteStream", "Context"),
            ("process", ("PRF",), "Context", "Result"),
            ("consume", ("PRF",), "Result", "(null)"),
            ("destroy", ("HPF",), "Context", "(null)"),
        ])
        triplets = self.extractor.extract(artifacts)
        self.assertEqual(len(triplets), 1)
        self.assertEqual(triplets[0].isf.function, "parse")
        self.assertEqual(names(triplets[0].prfs), ["process", "consume"])
        self.assertEqual(names(triplets[0].hpfs), ["destroy"])

    def test_bypass_semantics_are_sidecar_and_do_not_rewrite_sfg(self):
        artifacts = make_artifacts([
            (
                "parse", ("ISF",), "(null)", "Context", "src/fixture.c",
                "int parse(Context *ctx, const uint8_t *data, size_t size)",
                {
                    "return_type": "int",
                    "return_base_type": "int",
                    "return_is_struct_like": False,
                    "return_pointer_depth": 0,
                    "parameters": [
                        {
                            "name": "ctx", "type": "Context *",
                            "declaration": "Context *ctx",
                            "base_type": "Context", "is_pointer": True,
                            "pointer_depth": 1, "is_const": False,
                            "is_struct_like": True,
                        },
                        {
                            "name": "data", "type": "const uint8_t *",
                            "declaration": "const uint8_t *data",
                            "base_type": "uint8_t", "is_pointer": True,
                            "pointer_depth": 1, "is_const": True,
                            "is_struct_like": False,
                        },
                        {
                            "name": "size", "type": "size_t",
                            "declaration": "size_t size",
                            "base_type": "size_t", "is_pointer": False,
                            "pointer_depth": 0, "is_const": False,
                            "is_struct_like": False,
                        },
                    ],
                    "access_hints": [
                        {
                            "parameter": "ctx",
                            "reads": False,
                            "writes": True,
                            "evidence": ["write: ctx->state"],
                        }
                    ],
                    "body": "{ if (size < MP_HEADER_SIZE) return -1; ctx->state = data[0]; return 0; }",
                },
            ),
        ])
        triplet = self.extractor.extract(artifacts)[0]

        self.assertEqual(
            [(edge.src, edge.function, edge.dst) for edge in triplet.edges],
            [("(null)", "parse", "Context")],
        )
        kinds = {semantic.kind for semantic in triplet.bypass_semantics}
        self.assertIn("fuzzer_input_binding", kinds)
        self.assertIn("byte_stream_parameter", kinds)
        self.assertIn("scalar_parameter", kinds)
        self.assertIn("return_status", kinds)
        self.assertIn("struct_access_hint", kinds)
        self.assertIn("guard_condition", kinds)
        self.assertIn("constant_reference", kinds)
        self.assertEqual(
            triplet.metadata["bypass_semantics_version"],
            "function-triplet-bypass-v1",
        )

    def test_case_b_other_isfs_are_role_aware_and_each_ft_has_one_isf(self):
        artifacts = make_artifacts([
            ("parse_memory", ("ISF",), "(null)", "Context"),
            ("parse_file", ("ISF",), "(null)", "Context"),
            ("process", ("PRF",), "Context", "Result"),
            ("destroy", ("HPF",), "Context", "(null)"),
        ])
        triplets = self.extractor.extract(artifacts)
        ids = [triplet.id for triplet in triplets]
        self.assertEqual(len(set(ids)), 2)
        self.assertTrue(all(item.startswith("ft_parse_") for item in ids))
        self.assertEqual(
            [triplet.id for triplet in self.extractor.extract(artifacts)],
            ids,
        )
        self.assertEqual({triplet.isf.function for triplet in triplets},
                         {"parse_memory", "parse_file"})
        for triplet in triplets:
            self.assertEqual(
                sum("ISF" in function.roles for function in triplet.functions), 1
            )
            self.assertIn("process", names(triplet.prfs))

    def test_other_isf_non_isf_role_is_retained_inside_selected_subgraph(self):
        artifacts = make_artifacts([
            ("parse_memory", ("ISF",), "(null)", "Context"),
            ("parse_file", ("ISF", "HPF"), "(null)", "Context"),
            ("process", ("PRF",), "Context", "Result"),
        ])
        memory = next(
            item for item in self.extractor.extract(artifacts)
            if item.isf.function == "parse_memory"
        )
        masked_file = next(
            item for item in memory.functions if item.function == "parse_file"
        )
        self.assertEqual(masked_file.roles, ("HPF",))
        self.assertIn("parse_file", names(memory.hpfs))

    def test_case_c_multi_role_keeps_roles_and_prf_wins_over_hpf(self):
        artifacts = make_artifacts([
            ("parse", ("ISF", "HPF"), "(null)", "Context"),
            ("transform", ("PRF", "HPF"), "Context", "Result"),
        ])
        triplet = self.extractor.extract(artifacts)[0]
        self.assertEqual(triplet.isf.roles, ("ISF", "HPF"))
        self.assertEqual(names(triplet.prfs), ["transform"])
        self.assertEqual(names(triplet.hpfs), ["parse"])
        self.assertEqual(
            next(item for item in triplet.prfs if item.function == "transform").roles,
            ("PRF", "HPF"),
        )

    def test_other_multi_role_isf_cannot_expand_anchor_subgraph(self):
        artifacts = make_artifacts([
            ("parse_a", ("ISF",), "InputA", "ContextA"),
            ("parse_b", ("ISF", "HPF"), "InputB", "ContextB"),
            ("process_a", ("PRF",), "ContextA", "ResultA"),
            ("process_b", ("PRF",), "ContextB", "ResultB"),
        ])
        triplets = self.extractor.extract(artifacts)
        triplet_a = next(item for item in triplets if item.isf.function == "parse_a")
        self.assertEqual(names(triplet_a.prfs), ["process_a"])
        self.assertNotIn("parse_b", names(triplet_a.functions))
        self.assertNotIn("ContextB", triplet_a.structures)

    def test_case_d_parallel_edges_are_both_retained(self):
        artifacts = make_artifacts([
            ("parse", ("ISF",), "(null)", "Context"),
            ("foo", ("PRF",), "Context", "Result"),
            ("bar", ("PRF",), "Context", "Result"),
        ])
        triplet = self.extractor.extract(artifacts)[0]
        self.assertEqual(set(names(triplet.prfs)), {"foo", "bar"})
        parallel = [edge for edge in triplet.edges
                    if edge.src == "Context" and edge.dst == "Result"]
        self.assertEqual({edge.function for edge in parallel}, {"foo", "bar"})

    def test_case_e_empty_prf_and_hpf_is_valid(self):
        artifacts = make_artifacts([
            ("parse", ("ISF",), "(null)", "Context"),
        ])
        triplet = self.extractor.extract(artifacts)[0]
        self.assertEqual(triplet.prfs, ())
        self.assertEqual(triplet.hpfs, ())

    def test_case_f_cycle_is_finite_and_deterministic(self):
        artifacts = make_artifacts([
            ("parse", ("ISF",), "(null)", "A"),
            ("forward", ("PRF",), "A", "B"),
            ("back", ("PRF",), "B", "A"),
        ])
        first = self.extractor.extract(artifacts)
        second = self.extractor.extract(artifacts)
        self.assertEqual(triplets_document(first), triplets_document(second))
        self.assertEqual(set(names(first[0].prfs)), {"forward", "back"})

    def test_shared_null_does_not_pull_unrelated_terminal_components(self):
        artifacts = make_artifacts([
            ("parse", ("ISF",), "ByteStream", "Parser"),
            ("next", ("PRF",), "Parser", "Node"),
            ("parser_free", ("HPF",), "Parser", "(null)"),
            ("image_free", ("HPF",), "Image", "(null)"),
        ])
        triplet = self.extractor.extract(artifacts)[0]
        self.assertEqual(names(triplet.prfs), ["next"])
        self.assertEqual(names(triplet.hpfs), ["parser_free"])
        self.assertNotIn("Image", triplet.structures)
        self.assertNotIn("image_free", names(triplet.functions))

    def test_multiple_terminal_components_remain_isolated(self):
        artifacts = make_artifacts([
            ("parse_a", ("ISF",), "Input", "A"),
            ("finish_a", ("HPF",), "A", "(null)"),
            ("finish_b", ("HPF",), "B", "(null)"),
            ("finish_c", ("HPF",), "C", "(null)"),
        ])
        triplet = self.extractor.extract(artifacts)[0]
        self.assertEqual(names(triplet.hpfs), ["finish_a"])
        self.assertEqual(set(triplet.structures), {"A", "Input"})

    def test_shared_null_source_does_not_merge_entries(self):
        artifacts = make_artifacts([
            ("parse_a", ("ISF",), "(null)", "A"),
            ("process_a", ("PRF",), "A", "ResultA"),
            ("start_b", ("PRF",), "(null)", "B"),
            ("process_b", ("PRF",), "B", "ResultB"),
        ])
        triplet = self.extractor.extract(artifacts)[0]
        self.assertEqual(names(triplet.prfs), ["process_a"])
        self.assertNotIn("B", triplet.structures)

    def test_cycle_with_null_is_finite_stable_and_keeps_terminal_edge(self):
        artifacts = make_artifacts([
            ("parse", ("ISF",), "Input", "A"),
            ("forward", ("PRF",), "A", "B"),
            ("back", ("PRF",), "B", "A"),
            ("finish", ("HPF",), "B", "(null)"),
            ("unrelated", ("HPF",), "C", "(null)"),
        ])
        first = self.extractor.extract(artifacts)
        second = self.extractor.extract(artifacts)
        self.assertEqual(triplets_document(first), triplets_document(second))
        self.assertEqual(set(names(first[0].prfs)), {"forward", "back"})
        self.assertEqual(names(first[0].hpfs), ["finish"])

    def test_stable_ids_survive_insertion_of_an_earlier_isf(self):
        original = make_artifacts([
            ("b_parse", ("ISF",), "InputB", "B"),
            ("c_parse", ("ISF",), "InputC", "C"),
        ])
        expanded = make_artifacts([
            ("a_parse", ("ISF",), "InputA", "A"),
            ("b_parse", ("ISF",), "InputB", "B"),
            ("c_parse", ("ISF",), "InputC", "C"),
        ])
        before = {
            item.isf.function: item.id for item in self.extractor.extract(original)
        }
        after = {
            item.isf.function: item.id for item in self.extractor.extract(expanded)
        }
        self.assertEqual(after["b_parse"], before["b_parse"])
        self.assertEqual(after["c_parse"], before["c_parse"])

    def test_stable_ids_distinguish_paths_and_signature_changes(self):
        different_paths = make_artifacts([
            ("parse", ("ISF",), "InputA", "A", "src/a.c", "A parse(void)"),
            ("parse", ("ISF",), "InputB", "B", "src/b.c", "A parse(void)"),
        ])
        path_ids = [item.id for item in self.extractor.extract(different_paths)]
        self.assertEqual(len(set(path_ids)), 2)

        old = make_artifacts([
            ("parse", ("ISF",), "Input", "A", "src/a.c", "A parse(void)"),
        ])
        changed = make_artifacts([
            ("parse", ("ISF",), "Input", "A", "src/a.c", "A parse(int flags)"),
        ])
        self.assertNotEqual(
            self.extractor.extract(old)[0].id,
            self.extractor.extract(changed)[0].id,
        )

    def test_real_simple_artifacts_produce_serializable_ft(self):
        triplets = self.extractor.extract(load_sfg_artifacts(REAL_ARTIFACTS))
        self.assertEqual(len(triplets), 1)
        triplet = triplets[0]
        self.assertTrue(triplet.id.startswith("ft_parser_from_memory_"))
        self.assertEqual(triplet.isf.function, "parser_from_memory")
        self.assertEqual(names(triplet.prfs), ["parser_next", "node_process"])
        self.assertEqual(names(triplet.hpfs), ["parser_from_memory", "parser_free"])
        self.assertEqual(
            triplet.metadata["data_chain"]["structures"], ["Parser", "Node"]
        )
        semantic_kinds = {semantic.kind for semantic in triplet.bypass_semantics}
        self.assertIn("fuzzer_input_binding", semantic_kinds)
        self.assertIn("return_status", semantic_kinds)
        self.assertIn("struct_access_hint", semantic_kinds)
        self.assertEqual(
            triplet.metadata["bypass_semantics_count"],
            len(triplet.bypass_semantics),
        )
        self.assertEqual(len(triplets_document(triplets)["triplets"]), 1)


if __name__ == "__main__":
    unittest.main()
