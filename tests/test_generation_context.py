import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.generation_context import project_type_context


class GenerationContextTests(unittest.TestCase):
    def test_api_corpus_json_is_loaded_next_to_functions_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            functions_path = Path(temporary) / "functions.json"
            functions_path.write_text("{}", encoding="utf-8")
            (Path(temporary) / "api_corpus.json").write_text(json.dumps({
                "items": [
                    {
                        "title": "xmlReadMemory lifecycle",
                        "text": "xmlReadMemory returns xmlDocPtr; release it with xmlFreeDoc.",
                    }
                ]
            }), encoding="utf-8")
            context = project_type_context(
                {"schema_version": 3, "project": "", "files": [], "structs": []},
                functions_path=functions_path,
            )

        self.assertEqual(context["api_corpus"][0]["title"], "xmlReadMemory lifecycle")
        self.assertIn("xmlFreeDoc", context["api_corpus"][0]["text"])

    def test_headers_follow_selected_source_include_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            (root / "entry.c").write_text(
                '#include "common.h"\n'
                '#include "renderer.h"\n'
                "int parse(const char *data, unsigned size) { return 0; }\n",
                encoding="utf-8",
            )
            (root / "common.h").write_text(
                "#include <stdint.h>\n"
                "typedef uint8_t bool;\n"
                "typedef unsigned u32;\n"
                '#include "buffer.h"\n',
                encoding="utf-8",
            )
            (root / "buffer.h").write_text(
                "typedef struct Buffer { u32 len; } Buffer;\n",
                encoding="utf-8",
            )
            (root / "renderer.h").write_text(
                "typedef struct Renderer { Buffer *buffer; } Renderer;\n",
                encoding="utf-8",
            )
            functions_path = Path(temporary) / "functions.json"
            document = {
                "schema_version": 3,
                "project": "project",
                "files": ["entry.c", "common.h", "buffer.h", "renderer.h"],
                "functions": [],
                "structs": [
                    {
                        "name": "Buffer",
                        "file": "buffer.h",
                        "declaration": "typedef struct Buffer { u32 len; } Buffer;",
                    },
                    {
                        "name": "Renderer",
                        "file": "renderer.h",
                        "declaration": (
                            "typedef struct Renderer { Buffer *buffer; } Renderer;"
                        ),
                    },
                ],
            }
            functions_path.write_text(json.dumps(document), encoding="utf-8")

            context = project_type_context(
                document,
                functions_path=functions_path,
                source_files=("entry.c",),
                functions=(
                    {
                        "name": "parseUTF8",
                        "signature": (
                            "export size_t parseUTF8(const char* inbufptr, "
                            "u32 inbuflen, OutputFlags outflags, "
                            "JSTextFilterFun onCodeBlock);"
                        ),
                        "parameters": [
                            {
                                "name": "inbufptr",
                                "type": "const char *",
                                "base_type": "char",
                                "pointer_depth": 1,
                                "is_const": True,
                            },
                            {
                                "name": "inbuflen",
                                "type": "u32",
                                "base_type": "uint32_t",
                                "pointer_depth": 0,
                                "is_const": False,
                            },
                            {
                                "name": "outflags",
                                "type": "OutputFlags",
                                "base_type": "OutputFlags",
                                "pointer_depth": 0,
                                "is_const": False,
                            },
                            {
                                "name": "onCodeBlock",
                                "type": "JSTextFilterFun",
                                "base_type": "JSTextFilterFun",
                                "pointer_depth": 0,
                                "is_const": False,
                            },
                        ],
                    },
                ),
            )

        self.assertEqual(
            [item["include"] for item in context["headers"]],
            ["common.h", "buffer.h", "renderer.h"],
        )
        self.assertEqual(
            context["cplusplus_unsafe_headers"],
            ["buffer.h", "common.h", "renderer.h"],
        )
        self.assertEqual(
            context["portable_abi_declarations"],
            [{
                "function": "parseUTF8",
                "declaration": (
                    'extern "C" size_t parseUTF8(const char * inbufptr, '
                    "uint32_t inbuflen, int outflags, void * onCodeBlock);"
                ),
                "callback_parameters": [
                    {"parameter": "onCodeBlock", "typedef": "JSTextFilterFun"},
                ],
            }],
        )

    def test_callback_members_separate_required_from_optional(self):
        # The optionality comment sits after the member's own semicolon and can
        # contain one of its own, which is what makes a fixed lookback window
        # misclassify debug_log as required.
        declaration = (
            "typedef struct MD_PARSER {\n"
            "    /* Reserved. Set to zero. */ unsigned abi_version;\n"
            "    int (*enter_block)(int /*type*/, void* /*detail*/,"
            " void* /*userdata*/);\n"
            "    /* Debug callback. Optional (may be NULL).\n"
            "     * If provided and something goes wrong, this function gets\n"
            "     * called. This is intended for debugging and problem diagnosis\n"
            "     * for developers; it is not intended to provide any errors\n"
            "     * suitable for displaying to an end user. */\n"
            "    void (*debug_log)(const char* /*msg*/, void* /*userdata*/);\n"
            "    /* Reserved. Set to NULL. */ void (*syntax)(void);\n"
            "} MD_PARSER;"
        )
        document = {
            "schema_version": 3,
            "project": "",
            "files": [],
            "functions": [],
            "structs": [{
                "name": "MD_PARSER",
                "file": "md4c.h",
                "declaration": declaration,
            }],
        }
        context = project_type_context(document)

        tables = {item["type"]: item["fields"] for item in context["callback_tables"]}
        self.assertEqual(
            {field["name"]: field["required"] for field in tables["MD_PARSER"]},
            {"enter_block": True, "debug_log": False, "syntax": False},
        )
        # The parameter names inside the declarator comments must not leak into
        # the declared types the harness has to match.
        enter_block = tables["MD_PARSER"][0]
        self.assertEqual(enter_block["parameter_types"], ["int", "void*", "void*"])
        self.assertEqual(enter_block["return_type"], "int")

    def test_portable_declaration_matches_the_header_it_shadows(self):
        # The harness includes md4c.h, which declares md_parse with MD_PARSER*,
        # MD_CHAR* and MD_SIZE. A portable declaration that spells those const
        # void*, char* and int is a conflicting redeclaration in C++.
        document = {
            "schema_version": 3,
            "project": "",
            "files": [],
            "functions": [],
            "structs": [],
        }
        context = project_type_context(document, functions=(
            {
                "name": "md_parse",
                "signature": ("int md_parse(const MD_CHAR* text, MD_SIZE size, "
                              "const MD_PARSER* parser, void* userdata);"),
                "parameters": [
                    {"name": "text", "type": "const MD_CHAR *", "base_type": "char",
                     "pointer_depth": 1, "is_const": True},
                    {"name": "size", "type": "MD_SIZE", "base_type": "unsigned",
                     "pointer_depth": 0, "is_const": False},
                    {"name": "parser", "type": "const MD_PARSER *",
                     "base_type": "MD_PARSER", "pointer_depth": 1, "is_const": True},
                    {"name": "userdata", "type": "void *", "base_type": "void",
                     "pointer_depth": 1, "is_const": False},
                ],
            },
        ))
        self.assertEqual(
            context["portable_abi_declarations"][0]["declaration"],
            'extern "C" int md_parse(const char * text, unsigned size, '
            "const MD_PARSER * parser, void * userdata);",
        )

    def test_safe_headers_do_not_get_erased_portable_callback_abi(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            (root / "entry.c").write_text(
                '#include "api.h"\n'
                "int parse_with_cb(Callback cb) { return cb ? cb(1) : 0; }\n"
                "static int local_helper(int value) { return value; }\n",
                encoding="utf-8",
            )
            (root / "api.h").write_text(
                "typedef int (*Callback)(int value);\n"
                "int parse_with_cb(Callback cb);\n",
                encoding="utf-8",
            )
            functions_path = Path(temporary) / "functions.json"
            document = {
                "schema_version": 3,
                "project": "project",
                "files": ["entry.c", "api.h"],
                "functions": [],
                "structs": [],
            }
            functions_path.write_text(json.dumps(document), encoding="utf-8")

            context = project_type_context(
                document,
                functions_path=functions_path,
                source_files=("entry.c",),
                functions=(
                    {
                        "name": "parse_with_cb",
                        "signature": "int parse_with_cb(Callback cb);",
                        "storage": [],
                        "parameters": [{
                            "name": "cb",
                            "type": "Callback",
                            "base_type": "Callback",
                            "pointer_depth": 0,
                            "is_const": False,
                        }],
                    },
                    {
                        "name": "local_helper",
                        "signature": "int local_helper(int value);",
                        "storage": ["static"],
                        "parameters": [{
                            "name": "value",
                            "type": "int",
                            "base_type": "int",
                            "pointer_depth": 0,
                            "is_const": False,
                        }],
                    },
                ),
            )

        self.assertEqual(context["cplusplus_unsafe_headers"], [])
        self.assertEqual(
            [item["function"] for item in context["portable_abi_declarations"]],
            ["local_helper"],
        )

    def test_callback_typedefs_are_read_from_the_include_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            (root / "entry.c").write_text('#include "common.h"\n', encoding="utf-8")
            (root / "common.h").write_text(
                "typedef unsigned u32;\n"
                "typedef int(*JSTextFilterFun)( const char* metaptr, u32 metalen,\n"
                "                              const char* inptr, u32 inlen,\n"
                "                              const char** outptrp);\n",
                encoding="utf-8",
            )
            functions_path = Path(temporary) / "functions.json"
            document = {
                "schema_version": 3,
                "project": "project",
                "files": ["entry.c", "common.h"],
                "functions": [],
                "structs": [],
            }
            functions_path.write_text(json.dumps(document), encoding="utf-8")
            context = project_type_context(
                document,
                functions_path=functions_path,
                source_files=("entry.c",),
            )

        self.assertEqual(
            context["callback_typedefs"],
            [{
                "name": "JSTextFilterFun",
                "file": "common.h",
                "declaration": (
                    "typedef int(*JSTextFilterFun)( const char* metaptr, u32 metalen, "
                    "const char* inptr, u32 inlen, const char** outptrp);"
                ),
                "return_type": "int",
                "parameter_types": [
                    "const char*", "u32", "const char*", "u32", "const char**",
                ],
            }],
        )


if __name__ == "__main__":
    unittest.main()
