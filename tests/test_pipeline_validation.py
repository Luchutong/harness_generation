from dataclasses import replace
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import unittest.mock

from harness_generation.artifacts import ArtifactStore
from harness_generation.compiler_validation import CompilerConfig
from harness_generation.llm import MockLLM
from harness_generation.pipeline_validation import (
    PipelineStageValidator,
    PipelineValidationConfig,
)
from harness_generation.stage1 import Stage1Result
from harness_generation.stage2 import Stage2Result, required_processing_units
from harness_generation.stage3 import Stage3Metadata, Stage3Result
from harness_generation.stage4 import (
    Stage4Error,
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

    def callable_helpers(self, root: Path) -> frozenset[str]:
        return declared_contract_helpers(root, self.triplet, self.functions)

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
            allowed_functions=self.callable_helpers(root) if allow else (),
        )

    # -- the names themselves -------------------------------------------------

    def test_the_allowance_is_the_contracts_declared_helpers(self):
        root = self.with_ir("revalidation_names")
        # ``mp_parse`` is the ISF and already expected, so its presence here
        # changes no decision -- it is in the set because the IR's provenance
        # names it too, and the two validators get the same names either way.
        # ``le16`` is not: it is ``static`` in target.c, so the IR may cite it
        # as the algorithm behind the checksum but no harness can call it.
        self.assertEqual(
            self.callable_helpers(root),
            frozenset({"mp_checksum", "mp_destroy", "mp_init", "mp_parse"}),
        )
        # And the validator's own accessor agrees with the free function, or
        # the two call sites could drift apart the way the first pair did.
        self.assertEqual(self.validator(root).contract_helpers(),
                         self.callable_helpers(root))

    def test_without_an_ir_the_allowance_is_empty(self):
        root = self.artifact_root("revalidation_no_ir_names")
        self.assertEqual(self.callable_helpers(root), frozenset())
        self.assertEqual(self.validator(root).contract_helpers(), frozenset())

    def test_a_name_the_project_does_not_define_is_not_an_allowance(self):
        """The IR's evidence quotes real source; a ghost name is not a licence."""

        root = self.with_ir("revalidation_ghost")
        self.assertNotIn("invented_checksum", self.callable_helpers(root))

    def test_an_ir_replaced_after_the_attempt_hands_out_nothing(self):
        """The file is re-read; nothing says it is the file Stage 4 accepted.

        ``protocol_ir.json`` is an artifact on disk, so the document the
        re-validation reads is not guaranteed to be the one the attempt
        reconciled -- and an allowance computed from an IR about a *different*
        function is the whole failure this layer exists to catch.  "The stage
        that published the harness checked this already" is a fact about a
        moment, not about this document, so a failed reconciliation fails here
        too rather than returning the half of it that resolved.
        """

        root = self.with_ir("revalidation_replaced")
        self.assertTrue(self.callable_helpers(root))  # as published
        ArtifactStore(root).write_protocol_ir(
            replace(recorded_ir(), entry_function="mp_destroy")
        )
        with self.assertRaisesRegex(
            Stage4Error, r"protocol_ir\.json no longer reconciles with the FT"
        ):
            self.callable_helpers(root)
        with self.assertRaisesRegex(
            Stage4Error, r"protocol_ir\.json no longer reconciles with the FT"
        ):
            self.validator(root).contract_helpers()

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
                root, self.triplet, self.functions
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


class AttemptOutcomeTests(ContractHelperAllowanceTests):
    """The attempt's own record has to survive the stages after the parse.

    ``parsed.json`` is written while Stage 4 is still parsing, and the build runs
    after it.  So a harness that parsed cleanly and then failed to compile left an
    attempt whose ``parsed.json`` said ``passed`` and whose failure lived only in
    ``validation/compiler.json`` -- a reader had to know which of four files to
    distrust.  ``outcome.json`` is written once provisionally and again by
    :meth:`PipelineStageValidator.validate_stage4`, so the attempt's own record
    carries the build's verdict.
    """

    def published_attempt(self, name: str) -> tuple[Path, Stage4Result]:
        root = self.with_ir(name)
        published = Stage4Generator(MockLLM([self.plan_for(root), self.HARNESS])).run(
            self.triplet,
            rough_code=self.rough_code(),
            functions_json=root / "functions.json",
            artifacts=root,
        )
        return root, published

    def building_validator(
        self,
        root: Path,
        compiler: CompilerConfig | None = None,
    ) -> PipelineStageValidator:
        """A validator that really builds.

        ``compiler=None`` leaves the pipeline's own compiler configuration in
        place -- the one ``generate`` uses -- so the success case is a real
        build of the published harness rather than a second configuration that
        happens to agree with it.
        """

        return PipelineStageValidator(
            self.triplet,
            artifacts=root,
            functions_json=root / "functions.json",
            project_root=self.phase1.parent / "project",
            config=PipelineValidationConfig(compiler=compiler, fuzz_smoke=None),
        )

    def outcome_in(self, published: Stage4Result) -> dict:
        return json.loads(
            (published.attempt_directory / "outcome.json").read_text(encoding="utf-8")
        )

    def test_a_clean_parse_is_recorded_as_pending_until_validation_runs(self):
        """The provisional record, and the reason it is not simply absent.

        ``Stage4Generator.run`` does not validate -- ``generate`` calls the
        validator afterwards -- so the attempt must say "not decided yet" rather
        than claim a verdict it has not been given.
        """

        _root, published = self.published_attempt("outcome_pending")

        outcome = self.outcome_in(published)
        self.assertEqual(outcome["status"], "pending_validation")
        self.assertEqual(outcome["phase"], "awaiting_validation")
        self.assertIsNone(outcome["failure_type"])
        self.assertEqual(outcome["parsed_status"], "passed")
        self.assertEqual(outcome["parsed_artifact"], "parsed.json")
        self.assertTrue((published.attempt_directory / "parsed.json").is_file())

    def test_a_build_failure_is_the_attempts_outcome_not_just_a_side_file(self):
        """The case the record exists for: parsed ``passed``, built nothing.

        ``/bin/false`` is the compiler, so the intermediate audit passes and the
        build is what fails.  The assertion that matters is the pair: the parse
        says ``passed`` and the outcome says ``failed``, in the same directory,
        so the disagreement is visible in the attempt's own record.
        """

        root, published = self.published_attempt("outcome_build_failure")

        result = self.building_validator(
            root, CompilerConfig(compiler="/bin/false")
        ).validate_stage4(published)

        self.assertEqual(result.status, "failed", result.errors)
        outcome = self.outcome_in(published)
        self.assertEqual(outcome["status"], "failed")
        self.assertEqual(outcome["parsed_status"], "passed")
        self.assertNotEqual(outcome["phase"], "validated")
        self.assertTrue(outcome["failure_type"], outcome)
        self.assertTrue(outcome["error"], outcome)
        self.assertIn("compiler", outcome["validation_artifacts"])
        self.assertEqual(
            outcome["validation_result"]["status"], result.status,
        )

    def test_unavailable_compiler_keeps_toolchain_reason_in_attempt(self):
        root, published = self.published_attempt("outcome_compiler_unavailable")

        result = self.building_validator(
            root, CompilerConfig(compiler="missing-harness-compiler-p3")
        ).validate_stage4(published)

        self.assertEqual(result.status, "unavailable")
        self.assertFalse(result.accepted)
        self.assertEqual(result.metadata["failure_type"],
                         "required_validation_incomplete")
        self.assertIn("missing-harness-compiler-p3", result.warnings[0])
        self.assertIn("compiler validation unavailable", result.warnings[0])
        outcome = self.outcome_in(published)
        self.assertEqual(outcome["status"], "unavailable")
        self.assertIn("missing-harness-compiler-p3", outcome["error"])

    def test_a_successful_validation_is_recorded_as_validated(self):
        root, published = self.published_attempt("outcome_validated")

        result = self.building_validator(root).validate_stage4(published)

        self.assertTrue(result.accepted, result.errors)
        outcome = self.outcome_in(published)
        self.assertEqual(outcome["status"], result.status)
        self.assertEqual(outcome["phase"], "validated")
        self.assertIsNone(outcome["failure_type"])
        self.assertIsNone(outcome["error"])

    def test_a_validator_that_raises_still_leaves_an_outcome(self):
        """The exception is the case most likely to leave no record at all.

        Nothing wrote a failure, because the thing that would have written one
        is the thing that broke.  The wrapper records first and re-raises, so
        the attempt is not left looking pending.
        """

        root, published = self.published_attempt("outcome_exception")

        def explode(_self, _result):
            raise RuntimeError("validator fell over")

        with unittest.mock.patch.object(
            PipelineStageValidator, "_validate_stage4", explode
        ):
            with self.assertRaisesRegex(RuntimeError, "fell over"):
                self.building_validator(root).validate_stage4(published)

        outcome = self.outcome_in(published)
        self.assertEqual(outcome["status"], "failed")
        self.assertEqual(outcome["phase"], "validation_exception")
        self.assertEqual(outcome["failure_type"], "validation_exception")
        self.assertEqual(outcome["error_type"], "RuntimeError")
        self.assertEqual(outcome["parsed_status"], "passed")


if __name__ == "__main__":
    unittest.main()
