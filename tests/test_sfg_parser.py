import json
from pathlib import Path
import tempfile
import unittest

from sfg_builder.candidates import CandidateDetector
from sfg_builder.parser import CProjectParser, DEFAULT_IGNORES, write_functions_json


PROJECT = Path(__file__).parent / "fixtures/simple_project"


class ProjectParserTests(unittest.TestCase):
    def setUp(self):
        self.result = CProjectParser().parse(PROJECT)

    def test_extracts_functions_structs_and_ignores_vendor(self):
        self.assertEqual({function.name for function in self.result.functions}, {
            "parser_from_memory", "parser_next", "node_process", "parser_free",
        })
        self.assertEqual({struct.name for struct in self.result.structs}, {"Parser", "Node"})
        self.assertNotIn("vendor/ignored.c", self.result.files)
        self.assertTrue(all(function.defined for function in self.result.functions))

    def test_resolves_types_and_ast_access_hints(self):
        functions = {function.name: function for function in self.result.functions}
        parse = functions["parser_from_memory"]
        self.assertEqual(parse.parameters[0].base_type, "Parser")
        self.assertTrue(parse.parameters[0].is_struct_like)
        self.assertEqual(parse.parameters[1].base_type, "unsigned char")
        self.assertTrue(parse.parameters[1].is_const)
        self.assertTrue(parse.access_hints[0].writes)
        self.assertFalse(parse.access_hints[0].reads)
        process = functions["node_process"]
        self.assertTrue(process.access_hints[0].reads)
        self.assertTrue(process.access_hints[0].writes)

    def test_candidate_discovery(self):
        candidates = {candidate.function: candidate for candidate in
                      CandidateDetector().detect(self.result.functions)}
        self.assertTrue(candidates["parser_from_memory"].isf_candidate)
        self.assertEqual(candidates["parser_from_memory"].stream_parameters[0].name, "data")
        self.assertTrue(candidates["parser_next"].struct_related_candidate)
        self.assertTrue(candidates["parser_next"].prf_candidate)
        self.assertTrue(candidates["parser_next"].hpf_candidate)
        self.assertEqual(candidates["parser_next"].return_struct, "Node")
        self.assertFalse(candidates["parser_free"].isf_candidate)

    def test_common_pointer_and_typedef_forms(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / "types.h").write_text('''
typedef struct Thing Thing;
struct Thing { int value; };
typedef struct internal_name { int field; } foo_t;
const foo_t *forms(struct Thing *a, Thing **b, const foo_t *item,
           void *memory, char *text, const char *constant_text,
           uint8_t *bytes, const uint8_t *constant_bytes,
           unsigned char *octets, float *values);
''')
            parsed = CProjectParser().parse(project)
        function = parsed.functions[0]
        parameters = {parameter.name: parameter for parameter in function.parameters}
        self.assertEqual(function.return_type, "const foo_t *")
        self.assertEqual(function.return_base_type, "foo_t")
        self.assertTrue(function.return_is_struct_like)
        self.assertEqual(parameters["a"].base_type, "Thing")
        self.assertTrue(parameters["a"].is_struct_like)
        self.assertEqual(parameters["b"].pointer_depth, 2)
        self.assertEqual(parameters["b"].type, "Thing **")
        self.assertEqual(parameters["item"].type, "const foo_t *")
        self.assertTrue(parameters["item"].is_const)
        self.assertTrue(parameters["item"].is_struct_like)
        self.assertEqual(parameters["memory"].base_type, "void")
        self.assertEqual(parameters["text"].type, "char *")
        self.assertTrue(parameters["constant_text"].is_const)
        self.assertEqual(parameters["bytes"].base_type, "uint8_t")
        self.assertTrue(parameters["constant_bytes"].is_const)
        self.assertEqual(parameters["octets"].base_type, "unsigned char")
        candidates = CandidateDetector().detect(parsed.functions)
        self.assertEqual({item.name for item in candidates[0].stream_parameters},
                         {"memory", "text", "constant_text", "bytes",
                          "constant_bytes", "octets"})
        thing = next(info for info in parsed.structs if info.name == "Thing")
        self.assertIn("{ int value; }", thing.declaration)

    def test_forward_typedef_and_definition_are_one_struct_type(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / "types.h").write_text('''
typedef struct internal_type public_type;
struct internal_type { int value; };
void use(public_type *public_value, struct internal_type *tag_value);
''')
            parsed = CProjectParser().parse(project)
        self.assertEqual(len(parsed.structs), 1)
        self.assertEqual(parsed.structs[0].name, "public_type")
        self.assertIn("{ int value; }", parsed.structs[0].declaration)
        parameters = parsed.functions[0].parameters
        self.assertTrue(all(parameter.is_struct_like for parameter in parameters))
        self.assertEqual({parameter.base_type for parameter in parameters}, {"public_type"})

    def test_custom_ignore_pattern(self):
        result = CProjectParser(DEFAULT_IGNORES + ("src",)).parse(PROJECT)
        self.assertTrue(all(not function.defined for function in result.functions))
        self.assertEqual({struct.name for struct in result.structs}, {"Parser", "Node"})

    def test_default_ignore_patterns_and_custom_pattern(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            (project / "keep").mkdir()
            (project / "keep" / "visible.c").write_text("void visible(void) {}\n")
            for directory in DEFAULT_IGNORES:
                name = "cmake-build-debug" if directory == "cmake-build*" else directory
                ignored = project / name
                ignored.mkdir()
                (ignored / "hidden.c").write_text("void hidden(void) {}\n")
            (project / "generated").mkdir()
            (project / "generated" / "custom.c").write_text("void custom(void) {}\n")
            parsed = CProjectParser(DEFAULT_IGNORES + ("generated",)).parse(project)
        self.assertEqual([function.name for function in parsed.functions], ["visible"])
        self.assertEqual(parsed.files, ("keep/visible.c",))

    def test_function_metadata_and_functions_json(self):
        functions = {function.name: function for function in self.result.functions}
        function = functions["parser_from_memory"]
        self.assertEqual(function.file, "src/parser.c")
        self.assertGreater(function.end_line, function.start_line)
        self.assertEqual(function.return_type, "int")
        self.assertIn("parser->state = data[0]", function.body)
        self.assertEqual(function.labels, ())
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "metadata" / "functions.json"
            written = write_functions_json(self.result, path, project=PROJECT)
            payload = json.loads(path.read_text())
        self.assertEqual(written, path)
        self.assertEqual(payload["schema_version"], 2)
        self.assertFalse(Path(payload["project"]).is_absolute())
        self.assertEqual(
            (path.parent / payload["project"]).resolve(), PROJECT.resolve()
        )
        self.assertEqual(payload["source_path_base"], "project")
        self.assertEqual(len(payload["functions"]), 4)
        serialized = next(item for item in payload["functions"]
                          if item["name"] == "parser_from_memory")
        self.assertEqual(serialized["labels"], [])
        self.assertEqual(serialized["parameters"][1]["type"], "const unsigned char *")


if __name__ == "__main__":
    unittest.main()
