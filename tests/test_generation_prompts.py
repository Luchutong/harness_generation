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
                "stage1-function-doc-v1",
                "stage2-structure-snippet-v2",
                "stage3-rough-assembly-v2",
                "protocol-convention-refinement-v1",
                "stage4-harness-plan-v7",
                "stage4-harness-transform-v6",
            ],
        )
        self.assertIn("int parse(Parser *p)", str(prompts[0]))
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
        self.assertIn("C++ libFuzzer harness", prompts[5].content)
        self.assertIn("#include <stdint.h>", prompts[5].content)
        self.assertIn('extern "C" int LLVMFuzzerTestOneInput', prompts[5].content)
        self.assertIn("std::vector", prompts[5].content)
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
        self.assertEqual(document["prompt_version"], "stage1-function-doc-v1")
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
        self.assertEqual(template.version, "stage4-harness-transform-v6")
        self.assertEqual(
            get_prompt_template("stage4_harness_plan").version,
            "stage4-harness-plan-v7",
        )
        self.assertEqual(
            get_prompt_template("protocol_convention_refinement").version,
            "protocol-convention-refinement-v1",
        )
        with self.assertRaisesRegex(KeyError, "unknown prompt template"):
            get_prompt_template("missing")


if __name__ == "__main__":
    unittest.main()
