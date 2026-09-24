import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.prompts import (
    PROMPT_TEMPLATES,
    PromptTemplate,
    get_prompt_template,
    protocol_convention_refinement,
    stage1_function_doc,
    stage2_structure_snippet,
    stage3_rough_assembly,
    stage4_harness_plan,
    stage4_harness_transform,
)


# Pinned deliberately: a silent prompt edit must show up as a failing test.
STAGE4_PLAN_VERSION = "stage4-harness-plan-v11"
STAGE4_TRANSFORM_VERSION = "stage4-harness-transform-v10"


class GenerationPromptTests(unittest.TestCase):
    def test_all_required_prompts_are_independent_and_versioned(self):
        prompts = (
            stage1_function_doc(
                function_signature="int parse(Parser *p)",
                function_source="int parse(Parser *p) { return p != 0; }",
                usage_context={"role": "ISF"},
            ),
            stage2_structure_snippet(
                input_structure="Parser",
                output_structure="Node",
                functions=["parser_next"],
                dependencies={"Parser": ["Node"]},
                documentation="Returns the next node.",
            ),
            stage3_rough_assembly(
                snippets=["Node n = parser_next(p);"],
                structural_dependencies=["Parser -> Node"],
                function_metadata={"parser_next": {"roles": ["PRF"]}},
            ),
            protocol_convention_refinement(
                entry_function="mp_parse",
                protocol_facts={"fields": [{"name": "opcode", "offset": 3}]},
                source_context="case MP_STORE: ctx->saved = payload;",
            ),
            stage4_harness_plan(
                triplet_id="ft_parser_from_memory_a5265df23ba0",
                rough_code="Parser p; parse(&p);",
                unique_isf={
                    "id": "src/parser.c:3:parser_from_memory",
                    "name": "parser_from_memory",
                },
                function_metadata={"parser_from_memory": {"roles": ["ISF"]}},
                bypass_semantics=[
                    {"kind": "scalar_parameter", "summary": "size controls input"}
                ],
                protocol_contract={
                    "contract": {
                        "command_loop": {"max_steps": 32},
                        "frame": {"fields": [{"name": "payload_length", "offset": 4}]},
                    }
                },
            ),
            stage4_harness_transform(
                harness_plan={"call_sequence": [{"function": "parser_from_memory"}]},
                rough_code="Parser p; parse(&p);",
                unique_isf="parser_from_memory",
                function_metadata={"parser_from_memory": {"roles": ["ISF"]}},
                protocol_contract={"requirements": ["multi-frame command loop"]},
            ),
        )

        self.assertEqual(
            set(PROMPT_TEMPLATES),
            {
                "stage1_function_doc",
                "stage2_structure_snippet",
                "stage3_rough_assembly",
                "protocol_convention_refinement",
                "stage4_harness_plan",
                "stage4_harness_transform",
            },
        )
        self.assertEqual(len({prompt.prompt_version for prompt in prompts}), 6)
        self.assertEqual(
            [prompt.prompt_version for prompt in prompts],
            [
                "stage1-function-doc-v3",
                "stage2-structure-snippet-v3",
                "stage3-rough-assembly-v3",
                "protocol-convention-refinement-v1",
                STAGE4_PLAN_VERSION,
                STAGE4_TRANSFORM_VERSION,
            ],
        )
        self.assertIn("int parse(Parser *p)", str(prompts[0]))
        self.assertIn("direct call expression", prompts[0].content)
        self.assertIn('"role": "ISF"', prompts[0].content)
        self.assertIn("parser_next", prompts[1].content)
        self.assertIn("Parser -> Node", prompts[2].content)
        self.assertIn("strict JSON object", prompts[3].content)
        self.assertIn("MP_STORE", prompts[3].content)
        self.assertIn("parser_from_memory", prompts[4].content)
        self.assertIn("ft_parser_from_memory_a5265df23ba0", prompts[4].content)
        self.assertIn('"triplet_id":"ft_parser_from_memory_a5265df23ba0"', prompts[4].content)
        self.assertIn("Do not use a function id", prompts[4].content)
        self.assertIn("size controls input", prompts[4].content)
        self.assertIn("multi-frame command loop", prompts[4].content)
        self.assertIn("payload_length", prompts[4].content)
        self.assertIn("HarnessPlan JSON", prompts[5].content)
        self.assertIn("aggressive control prefix", prompts[5].content)
        self.assertIn("non-null local encoder", prompts[5].content)
        self.assertIn("xmlBufferCreate", prompts[5].content)
        self.assertIn("std::tmpfile", prompts[5].content)
        self.assertIn("C++ libFuzzer harness", prompts[5].content)
        self.assertIn("#include <stdint.h>", prompts[5].content)
        self.assertIn('extern "C" int LLVMFuzzerTestOneInput', prompts[5].content)
        self.assertIn("std::vector", prompts[5].content)
        self.assertIn("do not use lambdas", prompts[5].content)
        self.assertIn("multi-frame command loop", prompts[5].content)

    def test_rendered_prompt_is_printable_and_savable(self):
        prompt = stage1_function_doc(
            function_signature="void f(void)",
            function_source="void f(void) {}",
            usage_context="test context",
        )
        self.assertEqual(str(prompt), prompt.content)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "nested" / "stage1_prompt.json"
            prompt.save(path)
            document = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(document["name"], "stage1_function_doc")
        self.assertEqual(document["prompt_version"], "stage1-function-doc-v3")
        self.assertEqual(document["parameters"]["usage_context"], "test context")
        self.assertEqual(document["content"], prompt.content)

    def test_template_rejects_missing_and_unexpected_parameters(self):
        template = PromptTemplate("sample", "sample-v1", "Hello {name}")
        with self.assertRaisesRegex(ValueError, "missing prompt parameters"):
            template.render()
        with self.assertRaisesRegex(ValueError, "unexpected prompt parameters"):
            template.render(name="world", extra="unused")
        with self.assertRaisesRegex(ValueError, "JSON-serializable"):
            template.render(name=object())

    def test_registry_lookup_is_explicit(self):
        template = get_prompt_template("stage4_harness_transform")
        self.assertEqual(template.version, STAGE4_TRANSFORM_VERSION)
        self.assertEqual(
            get_prompt_template("stage4_harness_plan").version,
            STAGE4_PLAN_VERSION,
        )
        self.assertEqual(
            get_prompt_template("protocol_convention_refinement").version,
            "protocol-convention-refinement-v1",
        )
        with self.assertRaisesRegex(KeyError, "unknown prompt template"):
            get_prompt_template("missing")

    def test_stage4_prompts_require_callback_tables_to_be_filled(self):
        # md4c dereferences its rendering callbacks unconditionally, and
        # fmt_html calls onCodeBlock through its typedef, so both stages must
        # say so rather than let a zeroed table or a wrong-arity helper through.
        plan = get_prompt_template("stage4_harness_plan").template
        transform = get_prompt_template("stage4_harness_transform").template
        for template in (plan, transform):
            self.assertIn("callback_tables", template)
            self.assertIn("required", template)
            self.assertIn("iowrite", template)
            self.assertIn("ioclose", template)
            self.assertIn("escaping", template)
            self.assertIn("nullptr", template)
            self.assertIn("ft_functions", template)
            with self.subTest(template=template[:40]):
                self.assertIn("callback_typedefs", template)
        self.assertIn("empty relation_id", plan)
        self.assertIn("sentinel fd", plan)


if __name__ == "__main__":
    unittest.main()
