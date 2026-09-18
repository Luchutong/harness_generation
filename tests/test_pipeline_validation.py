import json
from pathlib import Path
import shutil
import tempfile
import unittest

from harness_generation.artifacts import ArtifactStore
from harness_generation.llm import MockLLM
from harness_generation.pipeline_validation import (
    PipelineStageValidator,
    PipelineValidationConfig,
)
from harness_generation.stage1 import Stage1Result
from harness_generation.stage2 import Stage2Result, required_processing_units
from harness_generation.stage3 import Stage3Metadata, Stage3Result
from harness_generation.stage4 import (
    Stage4Generator,
    Stage4Result,
    declared_contract_helpers,
)
from harness_generation.triplet import load_triplets_json
from harness_generation.validation import IntermediateValidator, ValidationResult

from tests.test_stage4_protocol_ir import Stage4ProjectTests
from tests.test_stage4_structured_input import recorded_ir


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ARTIFACTS = ROOT / "artifacts" / "simple"
SIMPLE_PROJECT = ROOT / "tests" / "fixtures" / "simple_project"


class PipelineStageValidatorTests(unittest.TestCase):
    def test_existing_but_incomplete_stage1_artifact_is_failed(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copy2(SOURCE_ARTIFACTS / name, artifacts / name)
            triplet = load_triplets_json(artifacts / "triplets.json")[0]
            output = artifacts / "generation" / triplet.id / "stage1_docs.json"
            output.parent.mkdir(parents=True)
            output.write_text(json.dumps({
                "schema_version": 1,
                "triplet_id": triplet.id,
                "documents": [],
            }), encoding="utf-8")
            result = PipelineStageValidator(
                triplet,
                artifacts=artifacts,
                functions_json=artifacts / "functions.json",
                project_root=SIMPLE_PROJECT,
            ).validate_stage1(Stage1Result(
                triplet_id=triplet.id,
                documents=(),
                output_path=output,
                raw_directory=output.parent / "raw",
            ))

        self.assertFalse(result.success)
        self.assertEqual(result.status, "failed")
        self.assertIn("does not match the FT", result.errors[0])

    def test_stage2_enforces_units_calls_known_apis_and_parseable_c(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copy2(SOURCE_ARTIFACTS / name, artifacts / name)
            triplet = load_triplets_json(artifacts / "triplets.json")[0]
            units = [dict(unit) for unit in required_processing_units(triplet)]
            snippets = {
                "parser_from_memory": "(void)0;",
                "node_process": "node_process(&node); invented_api();",
                "parser_free": "parser_free(parser",
                "parser_next": "Node node = parser_next(parser);",
            }
            for unit in units:
                unit["generated_code"] = snippets[unit["functions"][0]]
            units.pop()

            output = artifacts / "generation" / triplet.id / "stage2_snippets.json"
            output.parent.mkdir(parents=True)
            output.write_text(json.dumps({
                "schema_version": 1,
                "triplet_id": triplet.id,
                "units": units,
            }), encoding="utf-8")
            result = PipelineStageValidator(
                triplet,
                artifacts=artifacts,
                functions_json=artifacts / "functions.json",
                project_root=SIMPLE_PROJECT,
            ).validate_stage2(Stage2Result(
                triplet_id=triplet.id,
                snippets=(),
                output_path=output,
                snippets_directory=output.parent / "snippets",
                raw_directory=output.parent / "raw",
                prompts_directory=output.parent / "prompts",
            ))

        self.assertEqual(result.status, "failed")
        diagnostics = "\n".join(result.errors)
        self.assertIn("omits declared functions", diagnostics)
        self.assertIn("unknown APIs", diagnostics)
        self.assertIn("not valid C syntax", diagnostics)
        self.assertIn("omits required processing units", diagnostics)

    def test_stage3_reports_missing_unexpected_and_target_redefinition(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copy2(SOURCE_ARTIFACTS / name, artifacts / name)
            functions_path = artifacts / "functions.json"
            functions = json.loads(functions_path.read_text(encoding="utf-8"))
            functions["functions"].append({
                "id": "src/extra.c:1:other_target",
                "name": "other_target",
            })
            functions_path.write_text(json.dumps(functions), encoding="utf-8")
            triplet = load_triplets_json(artifacts / "triplets.json")[0]
            generation = artifacts / "generation" / triplet.id
            attempt = generation / "stage3" / "attempt_001"
            attempt.mkdir(parents=True)
            rough = generation / "stage3_rough.c"
            rough.write_text("""#include "parser.h"
void parser_free(Parser *parser) { (void)parser; }
void rough_sequence(Parser *parser, const unsigned char *data) {
    parser_from_memory(parser, data, 1);
    other_target();
    parser_free(parser);
}
""", encoding="utf-8")
            metadata = Stage3Metadata(
                triplet_id=triplet.id,
                invoked_functions=(),
                missing_functions=(),
                unexpected_functions=(),
                involved_structures=(),
                assembly_order=(),
                dependency_warnings=(),
                generation_metadata={},
            )
            result = PipelineStageValidator(
                triplet,
                artifacts=artifacts,
                functions_json=functions_path,
                project_root=SIMPLE_PROJECT,
            ).validate_stage3(Stage3Result(
                triplet_id=triplet.id,
                rough_code=rough.read_text(encoding="utf-8"),
                metadata=metadata,
                rough_code_path=rough,
                metadata_path=generation / "stage3_metadata.json",
                attempt_directory=attempt,
            ))

        self.assertEqual(result.status, "failed")
        self.assertIn("node_process", result.metadata["missing_expected_functions"])
        self.assertIn("other_target", result.metadata["unexpected_function_calls"])
        self.assertEqual(
            result.metadata["redefined_target_functions"], ["parser_free"]
        )

    def test_stage4_intermediate_failure_prevents_real_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary) / "artifacts"
            artifacts.mkdir()
            for name in ("functions.json", "triplets.json"):
                shutil.copy2(SOURCE_ARTIFACTS / name, artifacts / name)
            triplet = load_triplets_json(artifacts / "triplets.json")[0]
            generation = artifacts / "generation" / triplet.id
            attempt = generation / "stage4" / "attempt_001"
            attempt.mkdir(parents=True)
            harness = generation / "stage4_harness.c"
            harness.write_text(
                "int LLVMFuzzerTestOneInput(const unsigned char *data, "
                "unsigned long size) { (void)data; (void)size; return 0; }\n",
                encoding="utf-8",
            )

            result = PipelineStageValidator(
                triplet,
                artifacts=artifacts,
                functions_json=artifacts / "functions.json",
                project_root=SIMPLE_PROJECT,
            ).validate_stage4(Stage4Result(
                triplet_id=triplet.id,
                harness_code=harness.read_text(encoding="utf-8"),
                harness_path=harness,
                stable_path=None,
                generation_metadata={},
                attempt_directory=attempt,
            ))

            self.assertEqual(result.status, "failed")
            self.assertEqual(
                result.metadata["failure_type"], "intermediate_validation"
            )
            self.assertFalse((artifacts / "build" / triplet.id).exists())
            self.assertFalse((
                attempt / "validation" / "compiler.json"
            ).exists())


class ContractHelperAllowanceTests(Stage4ProjectTests):
    """This validator has to allow what Stage 4's audit allowed.

    Stage 4 publishes a harness and the pipeline then validates that same file
    again.  Both checks ask "may this harness call this project function?", and
    for a contracted harness the answer comes from the mined IR: the lifecycle
    and checksum helpers the ISF really calls sit outside the FT, because an FT
    is built from shared-structure edges and not from a call closure.

    When only the audit knew that, a real run published
    ``harnesses/ft_mp_parse_787468773c9f.c`` and still reported ``FAILED``:
    three of its six stage-4 attempts were refused here, with
    ``unexpected target function calls: mp_init, mp_checksum``, for code the
    stage that produced them had already accepted.
    """

    #: The shape a contracted harness takes: it calls the contract's lifecycle
    #: and checksum helpers, repairs the envelope, and hands the ISF a frame it
    #: assembled.  Accepted by the audit -- see HelperRelaxationTests in
    #: tests/test_stage4_protocol_ir_audit.py, which pins that half.
    HARNESS = """#include <stddef.h>
#include <stdint.h>
extern "C" {
#include "target.c"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < MP_HEADER_SIZE) return 0;
    mp_context ctx = {0};
    mp_init(&ctx);

    uint8_t frame[MP_HEADER_SIZE + MP_MAX_PAYLOAD] = {0};
    size_t payload_len = size - MP_HEADER_SIZE;
    if (payload_len > MP_MAX_PAYLOAD) payload_len = MP_MAX_PAYLOAD;

    memcpy(frame + MP_HEADER_SIZE, data + MP_HEADER_SIZE, payload_len);
    frame[2] = 1;
    frame[3] = 1;
    uint16_t sum = mp_checksum(frame + MP_HEADER_SIZE, payload_len);
    frame[6] = (uint8_t)(sum & 0xff);
    frame[7] = (uint8_t)(sum >> 8);

    mp_parse(&ctx, frame, MP_HEADER_SIZE + payload_len);
    mp_destroy(&ctx);
    return 0;
}"""

    def project_functions(self) -> frozenset[str]:
        document = json.loads(
            (self.phase1 / "functions.json").read_text(encoding="utf-8")
        )
        return frozenset(record["name"] for record in document["functions"])

    def with_ir(self, name: str) -> Path:
        root = self.artifact_root(name)
        ArtifactStore(root).write_protocol_ir(recorded_ir())
        return root

    def validator(self, root: Path) -> PipelineStageValidator:
        return PipelineStageValidator(
            self.triplet,
            artifacts=root,
            functions_json=root / "functions.json",
            project_root=self.phase1.parent / "project",
            # The intermediate verdict is what is under test; building and
            # fuzzing the published harness is a separate, later step.
            config=PipelineValidationConfig(build_enabled=False, fuzz_smoke=None),
        )

    def intermediate(self, root: Path, *, allow: bool) -> ValidationResult:
        (root / "harness.c").write_text(self.HARNESS, encoding="utf-8")
        return IntermediateValidator().validate_triplet(
            root / "harness.c",
            self.triplet,
            functions_json=root / "functions.json",
            artifacts=root,
            stage="stage4_harness",
            allowed_functions=(
                declared_contract_helpers(root, self.project_functions())
                if allow else ()
            ),
        )

    # -- the names themselves -------------------------------------------------

    def test_the_allowance_is_the_contracts_declared_helpers(self):
        root = self.with_ir("revalidation_names")
        # ``mp_parse`` is the ISF and already expected, so its presence here
        # changes no decision -- it is in the set because the IR's provenance
        # names it too, and the two validators get the same names either way.
        self.assertEqual(
            declared_contract_helpers(root, self.project_functions()),
            frozenset({"le16", "mp_checksum", "mp_destroy", "mp_init", "mp_parse"}),
        )
        # And the validator's own accessor agrees with the free function, or
        # the two call sites could drift apart the way the first pair did.
        self.assertEqual(self.validator(root).contract_helpers(),
                         declared_contract_helpers(root, self.project_functions()))

    def test_without_an_ir_the_allowance_is_empty(self):
        root = self.artifact_root("revalidation_no_ir_names")
        self.assertEqual(declared_contract_helpers(root, self.project_functions()),
                         frozenset())
        self.assertEqual(self.validator(root).contract_helpers(), frozenset())

    def test_a_name_the_project_does_not_define_is_not_an_allowance(self):
        """The IR's evidence quotes real source; a ghost name is not a licence."""

        root = self.with_ir("revalidation_ghost")
        self.assertNotIn(
            "invented_checksum",
            declared_contract_helpers(root, self.project_functions() | {"invented_checksum"}),
        )

    # -- the decision ---------------------------------------------------------

    def test_the_contracts_helpers_are_refused_without_them(self):
        """The pre-existing behaviour, on the harness that motivated the fix."""

        result = self.intermediate(self.with_ir("revalidation_off"), allow=False)
        self.assertFalse(result.success)
        self.assertIn("unexpected target function calls", result.errors[0])
        self.assertIn("mp_init", result.errors[0])
        self.assertIn("mp_checksum", result.errors[0])

    def test_and_accepted_with_them(self):
        result = self.intermediate(self.with_ir("revalidation_on"), allow=True)
        self.assertTrue(result.success, result.errors)
        self.assertIn("mp_checksum", result.metadata["observed_function_calls"])

    def test_a_project_function_the_contract_never_declared_stays_refused(self):
        """This widening is a list of names, not a licence to call the project.

        ``mp_parse`` is in the FT and ``mp_destroy`` is declared; ``mp_reset``
        is neither, so adding the contract's helpers must not have turned the
        check into "any target function is fine".
        """

        root = self.with_ir("revalidation_undeclared")
        (root / "harness.c").write_text(
            self.HARNESS.replace("mp_init(&ctx);", "mp_reset(&ctx);"),
            encoding="utf-8",
        )
        result = IntermediateValidator().validate_triplet(
            root / "harness.c",
            self.triplet,
            functions_json=root / "functions.json",
            artifacts=root,
            stage="stage4_harness",
            allowed_functions=declared_contract_helpers(
                root, self.project_functions()
            ),
        )
        self.assertFalse(result.success)
        self.assertIn("mp_reset", result.errors[0])

    # -- end to end, through the pipeline entry point -------------------------

    def test_a_contracted_publish_survives_the_pipelines_revalidation(self):
        """The bug, stated as the whole path: publish, then validate the publish.

        The harness comes from a formal Stage 4 publish -- not from a text this
        test wrote -- and the validator is the one ``generate`` calls.
        """

        root = self.with_ir("revalidation_published")
        published = Stage4Generator(MockLLM([self.plan_for(root), self.HARNESS])).run(
            self.triplet,
            rough_code=self.rough_code(),
            functions_json=root / "functions.json",
            artifacts=root,
        )
        self.assertTrue(ArtifactStore(root).for_triplet(self.triplet.id).harness.is_file())

        result = self.validator(root).validate_stage4(published)
        self.assertTrue(result.success, result.errors)
        self.assertEqual(result.metadata["component_statuses"], ("passed",))

    def test_the_revalidated_file_is_the_harness_that_was_audited(self):
        """This validator judges ``harness_path``, so that is what has to match.

        Stage 4 writes the harness twice -- once as its own output and once as
        the stable copy later stages compile -- and the pipeline re-validates
        the first.  If the two ever disagreed, the check would be about a file
        nobody builds.
        """

        root = self.with_ir("revalidation_same_file")
        published = Stage4Generator(MockLLM([self.plan_for(root), self.HARNESS])).run(
            self.triplet,
            rough_code=self.rough_code(),
            functions_json=root / "functions.json",
            artifacts=root,
        )
        layout = ArtifactStore(root).for_triplet(self.triplet.id)
        self.assertEqual(published.harness_path,
                         layout.generation / "stage4_harness.c")
        self.assertEqual(
            published.harness_path.read_text(encoding="utf-8").rstrip("\n"),
            self.HARNESS,
        )
        self.assertEqual(published.harness_path.read_bytes(), layout.harness.read_bytes())


if __name__ == "__main__":
    unittest.main()
