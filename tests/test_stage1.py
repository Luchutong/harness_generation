import json
from pathlib import Path
import tempfile
import unittest

from harness_generation.llm import MockLLM
from harness_generation.stage1 import (
    Stage1Error,
    Stage1Generator,
    generate_stage1_documentation,
)
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.triplet_extractor import extract_function_triplets
from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.semantic import MockSemanticAnalyzer


REPOSITORY = Path(__file__).resolve().parents[1]
SIMPLE_PROJECT = REPOSITORY / "tests" / "fixtures" / "simple_project"


class Stage1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.phase1_artifacts = Path(cls.temporary.name) / "phase1"
        SFGPipeline(
            MockSemanticAnalyzer(), ignored_directories=DEFAULT_IGNORES
        ).run(SIMPLE_PROJECT, cls.phase1_artifacts)
        cls.triplet = extract_function_triplets(
            load_sfg_artifacts(cls.phase1_artifacts)
        )[0]
        cls.functions_document = json.loads(
            (cls.phase1_artifacts / "functions.json").read_text(encoding="utf-8")
        )
        cls.functions_by_id = {
            function["id"]: function
            for function in cls.functions_document["functions"]
        }

    def responses(self):
        return [
            json.dumps({
                "function": function.function,
                "signature": self.functions_by_id[function.function_id]["signature"],
                "functionality": f"Documents {function.function} behavior.",
                "application_scenario": "Use it in the FT structural data flow.",
                "example_code": f"{function.function}(...);",
                "parameter_notes": ["Pass arguments matching the signature."],
                "return_semantics": None,
                "resource_lifecycle_notes": ["Follow the observed FT lifecycle."],
                "notes": ["Derived only from supplied source."],
            }, sort_keys=True)
            for function in self.triplet.functions
        ]

    def test_stage1_generates_structured_docs_and_raw_responses(self):
        responses = self.responses()
        llm = MockLLM(responses)
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts" / "project"
            result = generate_stage1_documentation(
                self.triplet,
                llm,
                functions_json=self.phase1_artifacts / "functions.json",
                artifacts=artifacts,
            )
            output = json.loads(result.output_path.read_text(encoding="utf-8"))
            scoped_output = json.loads((
                artifacts / "generation" / self.triplet.id / "stage1"
                / "stage1_docs.json"
            ).read_text(encoding="utf-8"))
            raw = {
                path.name: path.read_text(encoding="utf-8")
                for path in result.raw_directory.iterdir()
            }
            audits = {}
            for function in self.triplet.functions:
                stem = f"stage1_{function.function}"
                prompt = (
                    artifacts / "generation" / self.triplet.id / "prompts"
                    / f"{stem}.json"
                )
                scoped_prompt = (
                    artifacts / "generation" / self.triplet.id / "stage1"
                    / "prompts" / f"{stem}.json"
                )
                parsed = result.raw_directory / f"{stem}.parsed.json"
                metadata = result.raw_directory / f"{stem}.metadata.json"
                audits[function.function] = {
                    "prompt": json.loads(prompt.read_text(encoding="utf-8")),
                    "scoped_prompt": json.loads(
                        scoped_prompt.read_text(encoding="utf-8")
                    ),
                    "scoped_raw": (
                        artifacts / "generation" / self.triplet.id / "stage1"
                        / "raw" / f"stage1_{function.function}.txt"
                    ).read_text(encoding="utf-8"),
                    "parsed": json.loads(parsed.read_text(encoding="utf-8")),
                    "metadata": json.loads(metadata.read_text(encoding="utf-8")),
                }

        self.assertEqual(result.output_path,
                         artifacts / "generation" / self.triplet.id / "stage1_docs.json")
        self.assertEqual(output["schema_version"], 1)
        self.assertEqual(scoped_output, output)
        self.assertEqual(output["stage"], "stage1_function_doc")
        self.assertEqual(output["triplet_id"], self.triplet.id)
        self.assertEqual(
            [document["function"] for document in output["documents"]],
            [function.function for function in self.triplet.functions],
        )
        for document in output["documents"]:
            self.assertIn("signature", document)
            self.assertIn("functionality", document)
            self.assertIn("application_scenario", document)
            self.assertIn("example_code", document)
            self.assertIn("notes", document)
            self.assertIn("return_semantics", document)
            self.assertIn("resource_lifecycle_notes", document)
            self.assertEqual(
                document["generation_metadata"]["prompt_version"],
                "stage1-function-doc-v1",
            )
        for function, response in zip(self.triplet.functions, responses):
            self.assertEqual(raw[f"stage1_{function.function}.txt"], response)
            audit = audits[function.function]
            metadata = audit["metadata"]
            self.assertEqual(
                audit["prompt"]["prompt_version"], "stage1-function-doc-v1"
            )
            self.assertEqual(audit["scoped_prompt"], audit["prompt"])
            self.assertEqual(audit["scoped_raw"], response)
            self.assertEqual(audit["parsed"]["function"], function.function)
            self.assertEqual(metadata["provider"], "mock")
            self.assertEqual(metadata["model"], "mock-model")
            self.assertEqual(metadata["prompt_version"], "stage1-function-doc-v1")
            self.assertEqual(metadata["attempt"], 1)
            self.assertIn("timestamp", metadata)
            self.assertIsNone(metadata["rollback_source"])
            self.assertIsNone(metadata["retry_reason"])

    def test_prompts_include_only_current_ft_source(self):
        functions_document = json.loads(json.dumps(self.functions_document))
        functions_document["functions"].append({
            "id": "src/unrelated.c:1:unrelated_secret",
            "name": "unrelated_secret",
            "file": "src/unrelated.c",
            "start_line": 1,
            "end_line": 1,
            "signature": "void unrelated_secret(void);",
            "body": "{ TOP_SECRET_UNRELATED_BODY(); }",
            "defined": True,
        })
        llm = MockLLM(self.responses())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            functions_path = root / "functions.json"
            functions_path.write_text(json.dumps(functions_document), encoding="utf-8")
            Stage1Generator(llm).run(
                self.triplet,
                functions_json=functions_path,
                artifacts=root / "output",
            )

        self.assertEqual(len(llm.calls), len(self.triplet.functions))
        prompts = [call["prompt"] for call in llm.calls]
        self.assertTrue(all("TOP_SECRET_UNRELATED_BODY" not in prompt for prompt in prompts))
        self.assertTrue(all("unrelated_secret" not in prompt for prompt in prompts))
        for reference, prompt in zip(self.triplet.functions, prompts):
            source = self.functions_by_id[reference.function_id]["body"]
            self.assertIn(source, prompt)

    def test_invalid_json_is_rejected_after_raw_response_is_saved(self):
        llm = MockLLM(["```json\n{}\n```"])
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            with self.assertRaisesRegex(Stage1Error, "invalid JSON"):
                Stage1Generator(llm).run(
                    self.triplet,
                    functions_json=self.phase1_artifacts / "functions.json",
                    artifacts=artifacts,
                )
            raw_path = (
                artifacts / "generation" / self.triplet.id / "raw"
                / f"stage1_{self.triplet.functions[0].function}.txt"
            )
            self.assertEqual(raw_path.read_text(encoding="utf-8"), "```json\n{}\n```")
            self.assertFalse(
                (artifacts / "generation" / self.triplet.id / "stage1_docs.json").exists()
            )

    def test_example_must_call_the_documented_function(self):
        response = json.loads(self.responses()[0])
        response["example_code"] = "some_other_function();"
        llm = MockLLM([json.dumps(response)])
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(Stage1Error, "does not call documented function"):
                Stage1Generator(llm).run(
                    self.triplet,
                    functions_json=self.phase1_artifacts / "functions.json",
                    artifacts=Path(temporary),
                )

    def test_equivalent_signature_formatting_is_accepted(self):
        responses = self.responses()
        response = json.loads(responses[0])
        expected = response["signature"]
        response["signature"] = expected.replace("( ", "(").removesuffix(";")
        responses[0] = json.dumps(response)
        with tempfile.TemporaryDirectory() as temporary:
            result = Stage1Generator(MockLLM(responses)).run(
                self.triplet,
                functions_json=self.phase1_artifacts / "functions.json",
                artifacts=Path(temporary),
            )

        self.assertEqual(result.documents[0].signature, expected)

    def test_semantically_different_signature_is_rejected(self):
        response = json.loads(self.responses()[0])
        response["signature"] = response["signature"].replace(
            "const unsigned char *data", "unsigned char *data"
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(Stage1Error, "signature mismatch"):
                Stage1Generator(MockLLM([json.dumps(response)])).run(
                    self.triplet,
                    functions_json=self.phase1_artifacts / "functions.json",
                    artifacts=Path(temporary),
                )


if __name__ == "__main__":
    unittest.main()
