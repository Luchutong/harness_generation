import json
from pathlib import Path
import tempfile

from sfg_builder.ownership import derive_ownership_relations, load_ownership_json, write_ownership_json
from sfg_builder.parser import CProjectParser


CJSON_DECLARATIONS = '''
typedef struct cJSON cJSON;
#define CJSON_PUBLIC(type) type
// The parser accepts these no-op source annotations as explicit contract facts.
#define returns_owned(x)
#define cleanup_for(x)
__attribute__((returns_owned(cJSON_Delete))) CJSON_PUBLIC(cJSON *) cJSON_ParseWithLengthOpts(
    const char *value, size_t buffer_length, const char **return_parse_end);
__attribute__((cleanup_for(cJSON *))) CJSON_PUBLIC(void) cJSON_Delete(cJSON *item) { (void)item; }
cJSON *cJSON_GetObjectItem(const cJSON *object, const char *string);
'''


def parse_source(source: str):
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory)
        (project / "cjson.h").write_text(source, encoding="utf-8")
        return CProjectParser().parse(project)


def test_comment_prose_can_propose_generic_cleanup_contract():
    parsed = parse_source('''
    typedef struct widget widget;
    // The returned widget is owned by the caller and must be freed with widget_release.
    widget *widget_parse(const char *text);
    // Releases a widget passed by the caller.
    void widget_release(widget *value) { (void)value; }
    ''')
    functions = {function.name: function for function in parsed.functions}
    assert functions["widget_parse"].return_ownership is not None
    assert functions["widget_parse"].return_ownership.cleanup_function == "widget_release"
    relations = derive_ownership_relations(parsed.functions)
    assert len(relations) == 1
    assert relations[0].cleanup_function == "widget_release"


def test_header_family_contract_survives_definition_deduplication():
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory)
        (project / "widget.h").write_text('''
            typedef struct widget widget;
            /* Memory Management: the caller is responsible to free results
               from all variants of widget_parse (with widget_release). */
            widget *widget_parse(const char *text);
            widget *widget_parse_n(const char *text, unsigned long size);
            /* Returns a borrowed widget; do not free it. */
            widget *widget_parse_borrowed(const char *text);
            widget *widget_borrow(widget *item);
            /* Release a widget. */
            void widget_release(widget *item);
        ''', encoding="utf-8")
        (project / "widget.c").write_text('''
            #include "widget.h"
            widget *widget_parse(const char *text) { (void)text; return 0; }
            widget *widget_parse_n(const char *text, unsigned long size) {
                (void)text; (void)size; return 0;
            }
            widget *widget_borrow(widget *item) { return item; }
            widget *widget_parse_borrowed(const char *text) {
                (void)text; return 0;
            }
            /* Release a widget. */
            void widget_release(widget *item) { (void)item; }
        ''', encoding="utf-8")
        parsed = CProjectParser().parse(project)
    functions = {function.name: function for function in parsed.functions}
    assert functions["widget_parse_n"].return_ownership is not None
    assert functions["widget_borrow"].return_ownership is None
    assert functions["widget_parse_borrowed"].return_ownership is None
    assert {relation.producer_function for relation in derive_ownership_relations(parsed.functions)} == {
        "widget_parse", "widget_parse_n",
    }


    parsed = parse_source(CJSON_DECLARATIONS)
    functions = {function.name: function for function in parsed.functions}
    producer = functions["cJSON_ParseWithLengthOpts"]
    cleanup = functions["cJSON_Delete"]

    assert producer.return_type == "cJSON *"
    assert producer.return_base_type == "cJSON"
    assert producer.return_pointer_depth == 1
    assert producer.return_is_struct_like is True
    assert producer.return_type_annotations == ("CJSON_PUBLIC",)
    assert producer.return_ownership is not None
    assert producer.return_ownership.kind == "owned_pointer"
    assert producer.return_ownership.cleanup_function == "cJSON_Delete"
    assert cleanup.return_type == "void"
    assert cleanup.parameters[0].base_type == "cJSON"
    assert cleanup.parameters[0].pointer_depth == 1

    relations = derive_ownership_relations(parsed.functions)
    assert len(relations) == 1
    assert relations[0].producer_function == "cJSON_ParseWithLengthOpts"
    assert relations[0].cleanup_function == "cJSON_Delete"
    assert relations[0].consumers == ()


def test_borrowed_cjson_return_and_object_item_do_not_authorize_cleanup():
    parsed = parse_source('''
typedef struct cJSON cJSON;
CJSON_PUBLIC(cJSON *) cJSON_GetObjectItem(const cJSON *object, const char *string);
CJSON_PUBLIC(void) cJSON_Delete(cJSON *item) { (void)item; }
''')
    functions = {function.name: function for function in parsed.functions}
    assert functions["cJSON_GetObjectItem"].return_ownership is None
    assert derive_ownership_relations(parsed.functions) == ()


def test_static_cleanup_definition_does_not_authorize_external_harness_call():
    parsed = parse_source('''
    typedef struct cJSON cJSON;
    CJSON_PUBLIC(cJSON *) cJSON_ParseWithLengthOpts(
        const char *value, size_t buffer_length, const char **return_parse_end);
    static void cJSON_Delete(cJSON *item) { (void)item; }
    ''')
    assert derive_ownership_relations(parsed.functions) == ()


def test_cjson_print_returns_require_cjson_free_contract():
    parsed = parse_source('''
    __attribute__((returns_owned(cJSON_free))) char *cJSON_Print(const cJSON *item);
    __attribute__((returns_owned(cJSON_free))) char *cJSON_PrintUnformatted(const cJSON *item);
    cJSON_bool cJSON_PrintPreallocated(cJSON *item, char *buffer, int length,
                                       const cJSON_bool format);
    __attribute__((cleanup_for(char *))) void cJSON_free(char *object) { (void)object; }
    ''')
    functions = {function.name: function for function in parsed.functions}
    assert functions["cJSON_Print"].return_ownership is not None
    assert functions["cJSON_Print"].return_ownership.resource_type == "char"
    assert functions["cJSON_PrintUnformatted"].return_ownership is not None
    assert functions["cJSON_PrintPreallocated"].return_ownership is None
    relations = derive_ownership_relations(parsed.functions)
    assert {relation.producer_function for relation in relations} == {
        "cJSON_Print", "cJSON_PrintUnformatted",
    }
    assert {relation.cleanup_function for relation in relations} == {"cJSON_free"}


    parsed = parse_source(CJSON_DECLARATIONS)
    relations = derive_ownership_relations(parsed.functions)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "ownership.json"
        write_ownership_json(relations, path)
        loaded = load_ownership_json(path)
        assert loaded[0]["cleanup_function"] == "cJSON_Delete"
        assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 1
        assert load_ownership_json(Path(directory) / "missing.json") == ()
