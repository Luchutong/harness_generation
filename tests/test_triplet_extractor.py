from dataclasses import replace
from pathlib import Path
import unittest

from harness_generation.sfg_adapter import (SFGArtifacts, adapt_sfg_document,
                                             load_sfg_artifacts)
from harness_generation.triplet import TripletFunction, triplets_document
from harness_generation.triplet_extractor import (
    FunctionTripletExtractor,
    _bypass_semantics,
    _ownership_relations,
)


REAL_ARTIFACTS = Path(__file__).resolve().parents[1] / "artifacts" / "simple"

# A consumer only owns a resource its own signature can name. These fixtures
# mirror the shape of a real one: the parser arrives as a typed parameter.
PARSER_CONSUMER_METADATA = {
    "return_type": "int",
    "return_base_type": "int",
    "return_pointer_depth": 0,
    "parameters": [
        {"name": "parser", "type": "Parser *", "base_type": "Parser",
         "pointer_depth": 1, "is_pointer": True, "is_struct_like": True},
        {"name": "data", "type": "const char *", "base_type": "char",
         "pointer_depth": 1, "is_pointer": True, "is_struct_like": False},
        {"name": "size", "type": "unsigned", "base_type": "unsigned",
         "pointer_depth": 0, "is_pointer": False, "is_struct_like": False},
    ],
}


def make_artifacts(specs, *, ownership=(), usage_patterns=()):
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
        ownership=tuple(ownership),
        usage_patterns=tuple(usage_patterns),
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

    def test_same_graph_endpoints_need_delegation_to_be_alternatives(self):
        artifacts = make_artifacts([
            ("parse", ("ISF",), "(null)", "Context", "src/api.c",
             "Context *parse(const char *data)",
             {"body": "{ return parse_ex(data, 0); }"}),
            ("parse_ex", ("PRF",), "(null)", "Context", "src/api.c",
             "Context *parse_ex(const char *data, int mode)",
             {"body": "{ return 0; }"}),
            ("configure", ("PRF",), "(null)", "Context", "src/api.c",
             "void configure(Context *ctx)",
             {"body": "{ ctx->state = 1; }"}),
        ])
        triplet = self.extractor.extract(artifacts)[0]
        steps = [step.functions for step in triplet.structural_steps()]
        self.assertIn(("parse", "parse_ex"), steps)
        self.assertIn(("configure",), steps)
        self.assertEqual(triplet.missing_structural_steps(("parse",)), ("configure",))

    def test_function_name_in_comment_does_not_create_alternative_step(self):
        artifacts = make_artifacts([
            ("parse", ("ISF",), "(null)", "Context", "src/api.c",
             "Context *parse(const char *data)",
             {"body": "{ /* parse_ex(data) */ return 0; }"}),
            ("parse_ex", ("PRF",), "(null)", "Context", "src/api.c",
             "Context *parse_ex(const char *data)",
             {"body": "{ return 0; }"}),
        ])
        triplet = self.extractor.extract(artifacts)[0]
        self.assertEqual(triplet.metadata["structural_alternatives"], [])

    def test_setup_call_before_delegation_is_not_an_alternative_step(self):
        artifacts = make_artifacts([
            ("parse", ("ISF",), "(null)", "Context", "src/api.c",
             "Context *parse(const char *data)",
             {"body": "{ record_parse(); return parse_ex(data); }"}),
            ("parse_ex", ("PRF",), "(null)", "Context", "src/api.c",
             "Context *parse_ex(const char *data)",
             {"body": "{ return 0; }"}),
        ])
        triplet = self.extractor.extract(artifacts)[0]
        self.assertEqual(triplet.metadata["structural_alternatives"], [])

    def test_conditional_delegation_is_not_an_alternative_step(self):
        artifacts = make_artifacts([
            ("parse", ("ISF",), "(null)", "Context", "src/api.c",
             "Context *parse(const char *data)",
             {"body": "{ if (data) return parse_ex(data); return 0; }"}),
            ("parse_ex", ("PRF",), "(null)", "Context", "src/api.c",
             "Context *parse_ex(const char *data)",
             {"body": "{ return 0; }"}),
        ])
        triplet = self.extractor.extract(artifacts)[0]
        self.assertEqual(triplet.metadata["structural_alternatives"], [])

    def test_opaque_handle_consumer_closes_over_create_and_free(self):
        artifacts = make_artifacts([
            (
                "ParserCreate", (), "OtherA", "OtherB", "src/fixture.c",
                "Parser ParserCreate(void)",
                {
                    "return_type": "Parser",
                    "return_base_type": "Parser",
                    "return_pointer_depth": 1,
                    "return_is_struct_like": True,
                    "return_is_opaque_handle": True,
                    "parameters": [],
                },
            ),
            (
                "ParserParse", ("ISF",), "(null)", "(null)", "src/fixture.c",
                "int ParserParse(Parser parser, const char *data, int size)",
                {
                    "return_type": "int",
                    "return_base_type": "int",
                    "return_pointer_depth": 0,
                    "return_is_struct_like": False,
                    "parameters": [{
                        "name": "parser", "type": "Parser",
                        "declaration": "Parser parser", "base_type": "Parser",
                        "is_pointer": True, "pointer_depth": 1,
                        "is_const": False, "is_struct_like": True,
                        "is_opaque_handle": True,
                    }],
                },
            ),
            (
                "ParserFree", (), "OtherC", "OtherD", "src/fixture.c",
                "void ParserFree(Parser parser)",
                {
                    "return_type": "void",
                    "return_base_type": "void",
                    "return_pointer_depth": 0,
                    "return_is_struct_like": False,
                    "parameters": [{
                        "name": "parser", "type": "Parser",
                        "declaration": "Parser parser", "base_type": "Parser",
                        "is_pointer": True, "pointer_depth": 1,
                        "is_const": False, "is_struct_like": True,
                        "is_opaque_handle": True,
                    }],
                },
            ),
        ], ownership=({
            "id": "own_parser",
            "producer_function_id": "src/fixture.c:1:ParserCreate",
            "producer_function": "ParserCreate",
            "resource_type": "Parser",
            "cleanup_function_id": "src/fixture.c:3:ParserFree",
            "cleanup_function": "ParserFree",
            "cleanup_argument": "return_value",
            "consumers": [],
            "nullable": True,
            "evidence": ["opaque handle typedef: Parser"],
            "confidence": 0.95,
            "source": "opaque_handle_static_inference",
        },))

        triplet = self.extractor.extract(artifacts)[0]
        self.assertEqual(
            {function.function for function in triplet.functions},
            {"ParserCreate", "ParserParse", "ParserFree"},
        )
        self.assertIn("ParserCreate", names(triplet.prfs))
        self.assertIn("ParserFree", names(triplet.hpfs))
        self.assertIn("Parser", triplet.structures)
        self.assertEqual(len(triplet.ownership_relations), 1)
        self.assertEqual(triplet.ownership_relations[0].consumers, ("ParserParse",))
        self.assertEqual(
            triplet.metadata["lifecycle_closure"][0]["resource_type"], "Parser"
        )

    def test_a_release_function_is_not_a_consumer_of_the_resource(self):
        """`ParserFreeEx` releases the handle; it never consumes it.

        Counting it as a consumer orders one destructor after the other, so a
        plan that realizes the release step with `ParserFree` could never
        satisfy the ordering it would be handed.
        """
        handle_parameter = {
            "name": "parser", "type": "Parser", "declaration": "Parser parser",
            "base_type": "Parser", "is_pointer": True, "pointer_depth": 1,
            "is_const": False, "is_struct_like": True, "is_opaque_handle": False,
        }
        void_handle = {
            "return_type": "void", "return_base_type": "void",
            "return_pointer_depth": 0, "return_is_struct_like": False,
            "parameters": [dict(handle_parameter)],
        }
        artifacts = make_artifacts([
            ("ParserCreate", (), "(null)", "Parser", "src/fixture.c",
             "Parser ParserCreate(void)",
             {"return_type": "Parser", "return_base_type": "Parser",
              "return_pointer_depth": 1, "return_is_struct_like": True,
              "parameters": []}),
            ("ParserParse", ("ISF",), "Parser", "(null)", "src/fixture.c",
             "void ParserParse(Parser parser)", void_handle),
            ("ParserFree", ("HPF",), "Parser", "(null)", "src/fixture.c",
             "void ParserFree(Parser parser)", void_handle),
            ("ParserFreeEx", ("HPF",), "Parser", "(null)", "src/fixture.c",
             "void ParserFreeEx(int mode, Parser parser)", void_handle),
        ], ownership=({
            "id": "own_parser",
            "producer_function_id": "src/fixture.c:1:ParserCreate",
            "producer_function": "ParserCreate",
            "resource_type": "Parser",
            "cleanup_function_id": "src/fixture.c:3:ParserFree",
            "cleanup_function": "ParserFree",
            "cleanup_argument": "return_value",
            "consumers": [],
            "nullable": True,
            "evidence": ["complete struct type: Parser"],
            "confidence": 0.95,
            "source": "opaque_handle_static_inference",
        },))
        functions = tuple(
            TripletFunction(f"src/fixture.c:{line}:{name}", name, roles,
                            "src/fixture.c", line)
            for line, (name, roles) in enumerate((
                ("ParserCreate", ("PRF",)),
                ("ParserParse", ("ISF", "PRF")),
                ("ParserFree", ("HPF",)),
                ("ParserFreeEx", ("HPF",)),
            ), 1)
        )

        relations = _ownership_relations(artifacts, functions)

        self.assertEqual(relations[0].consumers, ("ParserParse",))

    def test_usage_patterns_create_separate_ft_variants_with_support(self):
        specs = [
            ("ParserCreate", (), "(null)", "Parser"),
            ("ParserCreateNS", (), "(null)", "Parser"),
            ("ParserParse", ("ISF",), "Parser", "(null)", "src/fixture.c",
             "int ParserParse(Parser *parser, const char *data, unsigned size)",
             PARSER_CONSUMER_METADATA),
            ("ParserFree", (), "Parser", "(null)"),
        ]
        ids = {name: f"src/fixture.c:{line}:{name}"
               for line, (name, *_rest) in enumerate(specs, 1)}
        def pattern(pattern_id, producer, support):
            return {
                "id": pattern_id,
                "lifecycle_kind": "owned_resource",
                "resource_type": "Parser",
                "producer_function_id": ids[producer],
                "producer_function": producer,
                "producer_binding": "return_value",
                "producer_argument_index": None,
                "consumers": ["ParserParse"],
                "consumer_function_ids": [ids["ParserParse"]],
                "consumer_argument_indices": [0],
                "cleanup_function_id": ids["ParserFree"],
                "cleanup_function": "ParserFree",
                "cleanup_argument_index": 0,
                "cleanup_argument": "resource",
                "sequence": [producer, "ParserParse", "ParserFree"],
                "conditions": ["parser != NULL"],
                "path_kind": "conditional",
                "support_total": support,
                "support_by_source": {"test": support},
                "evidence": [f"tests/{producer}.c:10 (caller)"],
            }
        artifacts = make_artifacts(specs, usage_patterns=(
            pattern("up_create", "ParserCreate", 4),
            pattern("up_create_ns", "ParserCreateNS", 2),
        ))
        triplets = self.extractor.extract(artifacts)
        self.assertEqual(len(triplets), 2)
        paper_triplets = self.extractor.extract(artifacts, paper_minimal=True)
        self.assertEqual(len(paper_triplets), 1)
        self.assertEqual(paper_triplets[0].isf.function, "ParserParse")
        self.assertIsNone(paper_triplets[0].metadata["usage_pattern"])
        self.assertEqual(len({item.id for item in triplets}), 2)
        self.assertEqual(
            {item.metadata["usage_pattern"]["id"] for item in triplets},
            {"up_create", "up_create_ns"},
        )
        self.assertEqual(
            {item.ownership_relations[0].support_total for item in triplets},
            {2, 4},
        )
        for triplet in triplets:
            producer = triplet.metadata["usage_pattern"]["producer_function"]
            self.assertEqual(
                {item.function for item in triplet.functions},
                {producer, "ParserParse", "ParserFree"},
            )
            self.assertEqual(
                sum("ISF" in item.roles for item in triplet.functions), 1
            )

    def test_void_userdata_does_not_import_callers_resource_lifecycle(self):
        # The real md_parse shape: a caller may thread its own WBuf through the
        # void* userdata slot, but md_parse's own signature cannot name a WBuf,
        # so the resource lifecycle is not part of md_parse's API.
        specs = [
            ("WBufInit", (), "(null)", "WBuf"),
            ("md_parse", ("ISF",), "MD_PARSER", "(null)", "src/fixture.c",
             "int md_parse(const char *text, unsigned size, void *userdata)",
             {"return_type": "int", "return_base_type": "int",
              "return_pointer_depth": 0, "parameters": [
                  {"name": "text", "type": "const char *", "base_type": "char",
                   "pointer_depth": 1, "is_pointer": True, "is_struct_like": False},
                  {"name": "size", "type": "unsigned", "base_type": "unsigned",
                   "pointer_depth": 0, "is_pointer": False, "is_struct_like": False},
                  {"name": "userdata", "type": "void *", "base_type": "void",
                   "pointer_depth": 1, "is_pointer": True, "is_struct_like": False},
              ]}),
            ("WBufFree", (), "WBuf", "(null)"),
        ]
        pattern = {
            "id": "up_userdata", "resource_type": "WBuf",
            "producer_function_id": "src/fixture.c:1:WBufInit",
            "producer_function": "WBufInit",
            "consumer_function_ids": ["src/fixture.c:2:md_parse"],
            "consumers": ["md_parse"], "consumer_argument_indices": [3],
            "cleanup_function_id": "src/fixture.c:3:WBufFree",
            "cleanup_function": "WBufFree",
        }
        triplet = self.extractor.extract(
            make_artifacts(specs, usage_patterns=(pattern,))
        )[0]
        self.assertEqual([item.function for item in triplet.functions], ["md_parse"])
        self.assertEqual(triplet.metadata["lifecycle_closure"], [])

    def test_negative_stream_vote_is_not_reintroduced_as_bypass_evidence(self):
        artifacts = make_artifacts([
            ("md_parse", ("ISF",), "MD_PARSER", "(null)", "src/fixture.c",
             "int md_parse(const char *text, unsigned size, void *userdata)",
             {"parameters": [
                 {"name": "text", "type": "const char *", "base_type": "char",
                  "is_pointer": True, "is_struct_like": False},
                 {"name": "size", "type": "unsigned", "base_type": "unsigned",
                  "is_pointer": False, "is_struct_like": False},
                 {"name": "userdata", "type": "void *", "base_type": "void",
                  "is_pointer": True, "is_struct_like": False},
             ]}),
        ])
        annotation = {**artifacts.annotations[0], "stream_parameters": [
            {"parameter": "text", "is_byte_stream": True},
            {"parameter": "userdata", "is_byte_stream": False},
        ]}
        artifacts = replace(artifacts, annotations=(annotation,))
        function = TripletFunction(
            "src/fixture.c:1:md_parse", "md_parse", ("ISF",), "src/fixture.c", 1
        )
        semantics = _bypass_semantics(artifacts, (function,))
        streams = [item.metadata["parameter"] for item in semantics
                   if item.kind == "byte_stream_parameter"]
        self.assertEqual(streams, ["text"])

    def test_usage_out_parameter_and_refcount_fields_reach_ft_contract(self):
        specs = [
            ("ParserOpen", (), "(null)", "Parser"),
            ("ParserParse", ("ISF",), "Parser", "(null)", "src/fixture.c",
             "int ParserParse(Parser *parser, const char *data, unsigned size)",
             PARSER_CONSUMER_METADATA),
            ("ParserClose", (), "Parser", "(null)"),
        ]
        pattern = {
            "id": "up_out", "lifecycle_kind": "owned_resource",
            "resource_type": "Parser",
            "producer_function_id": "src/fixture.c:1:ParserOpen",
            "producer_function": "ParserOpen", "producer_binding": "out_parameter",
            "producer_argument_index": 1, "consumers": ["ParserParse"],
            "consumer_function_ids": ["src/fixture.c:2:ParserParse"],
            "consumer_argument_indices": [0],
            "cleanup_function_id": "src/fixture.c:3:ParserClose",
            "cleanup_function": "ParserClose", "cleanup_argument_index": 0,
            "cleanup_argument": "resource", "sequence": ["ParserOpen", "ParserParse", "ParserClose"],
            "conditions": ["rc != 0"], "path_kind": "error", "support_total": 3,
            "support_by_source": {"production": 3}, "evidence": ["src/client.c:7 (open)"],
        }
        relation = self.extractor.extract(
            make_artifacts(specs, usage_patterns=(pattern,))
        )[0].ownership_relations[0]
        self.assertEqual(relation.producer_binding, "out_parameter")
        self.assertEqual(relation.producer_argument_index, 1)
        self.assertEqual(relation.path_kind, "error")
        self.assertEqual(relation.conditions, ("rc != 0",))
        self.assertEqual(relation.support_by_source, {"production": 3})

        ref_specs = [
            ("ParserRef", (), "Parser", "Parser"),
            ("ParserParse", ("ISF",), "Parser", "(null)", "src/fixture.c",
             "int ParserParse(Parser *parser, const char *data, unsigned size)",
             PARSER_CONSUMER_METADATA),
            ("ParserUnref", (), "Parser", "(null)"),
        ]
        ref_pattern = {
            **pattern,
            "id": "up_ref", "lifecycle_kind": "reference_count",
            "producer_function_id": "src/fixture.c:1:ParserRef",
            "producer_function": "ParserRef", "producer_binding": "existing_argument",
            "producer_argument_index": 0,
            "cleanup_function_id": "src/fixture.c:3:ParserUnref",
            "cleanup_function": "ParserUnref", "conditions": [],
            "path_kind": "normal", "sequence": ["ParserRef", "ParserParse", "ParserUnref"],
        }
        ref_relation = self.extractor.extract(
            make_artifacts(ref_specs, usage_patterns=(ref_pattern,))
        )[0].ownership_relations[0]
        self.assertEqual(ref_relation.lifecycle_kind, "reference_count")
        self.assertEqual(ref_relation.producer_binding, "existing_argument")

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
            "function-triplet-bypass-v2",
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
