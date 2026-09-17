"""Stage 4 must plan from the mined protocol IR, and fall back cleanly without it.

The load-bearing tests here are:

``MinedContractEndToEndTests``
    mines ``protocol_ir.json`` from ``benchmarks/mini_parser/target.c`` with the
    real miner and a mock convention vote, writes it through
    :meth:`ArtifactStore.write_protocol_ir`, and checks the *mined* field names
    reach the Stage 4 plan prompt.  The hand-written
    ``benchmarks/mini_parser/protocol.json`` is never read on that path, and one
    test proves it by mining a source the hand-written file does not describe.

``FallbackTests``
    pins the other half of the contract: with no ``protocol_ir.json`` the plan
    prompt renders an empty contract object and the plan artifact gains no new
    key, so a run without a mined protocol behaves exactly as it did before the
    IR was wired in.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from harness_generation.artifacts import ArtifactStore
from harness_generation.llm import MockLLM
from harness_generation.protocol_conventions import (
    ContextModel,
    ProtocolConventions,
    SequenceModel,
    StatefulOperation,
    infer_protocol_conventions,
)
from harness_generation.protocol_ir import (
    FrameField,
    FrameModel,
    ProtocolEvidence,
    ProtocolIR,
    ProtocolIRError,
)
from harness_generation.protocol_miner import (
    Evidence,
    FieldFact,
    ProtocolFacts,
    mine_protocol_facts,
)
from harness_generation.prompts import stage4_harness_plan
from harness_generation.sfg_adapter import load_sfg_artifacts
from harness_generation.stage4 import (
    Stage4Error,
    Stage4Generator,
    load_protocol_contract,
)
from harness_generation.triplet_extractor import extract_function_triplets
from sfg_builder.parser import DEFAULT_IGNORES
from sfg_builder.pipeline import SFGPipeline
from sfg_builder.semantic import MockSemanticAnalyzer


ROOT = Path(__file__).resolve().parents[1]
MINI_PARSER = ROOT / "benchmarks" / "mini_parser"
SOURCE = MINI_PARSER / "target.c"
HAND_WRITTEN_PROTOCOL = MINI_PARSER / "protocol.json"

#: Field names the miner recovers from ``mini_parser/target.c``.  They are
#: declared here rather than read from ``protocol.json`` on purpose: the point
#: of these tests is that Stage 4 is driven by measurement, so the expectation
#: has to come from somewhere other than the hand-written contract.
MINED_FIELD_NAMES = (
    "magic0", "magic1", "version", "opcode",
    "payload_length", "checksum", "payload",
)

#: One valid C-block sample for ``mp_parse``, voted three times.  The vote makes
#: every field unanimous, so the mined IR's confidence is 1.0.
CONVENTION_SAMPLE = json.dumps({
    "schema_version": 1,
    "sequence_model": {
        "multi_frame": True,
        "reason": (
            "mp_parse parses one frame per call and the context carries state "
            "across frames"
        ),
        "evidence": ["MP_STORE saves state in ctx and MP_USE reads it"],
        "max_steps": {
            "value": 32,
            "source": "engineering_choice",
            "evidence": ["the command-loop cap is a harness policy"],
        },
    },
    "context": {
        "type": "mp_context",
        "init": "mp_init(&ctx)",
        "destroy": "mp_destroy(&ctx)",
        "lifetime": "one context per libFuzzer iteration",
        "evidence": ["mp_init/mp_destroy are the declared lifecycle helpers"],
    },
    "stateful_operations": [
        {
            "opcode": "MP_STORE",
            "reason": "stores the payload pointer in the context",
            "evidence": ["case MP_STORE writes ctx->saved"],
        },
        {
            "opcode": "MP_USE",
            "reason": "reads state stored by an earlier frame",
            "evidence": ["case MP_USE reads ctx->saved"],
        },
        {
            "opcode": "MP_RELEASE",
            "reason": "clears the stored state",
            "evidence": ["case MP_RELEASE clears ctx->saved"],
        },
    ],
    "requirements": [
        "repair the frame envelope and keep the payload fuzz-controlled",
    ],
    "notes": ["keep one mp_context alive across frames"],
})


def mined_ir(source: bytes | None = None, *, filename: str = "target.c",
             samples: int = 3) -> ProtocolIR:
    """Mine the A/B facts and vote the C block, exactly as the pipeline does."""

    text = SOURCE.read_text(encoding="utf-8") if source is None else source.decode("utf-8")
    facts = mine_protocol_facts(
        SOURCE.read_bytes() if source is None else source, "mp_parse", filename=filename
    )
    result = infer_protocol_conventions(
        facts, text, MockLLM([CONVENTION_SAMPLE] * samples), samples=samples
    )
    return ProtocolIR.from_facts_and_conventions(facts, result.conventions)


def contract_block(ir: ProtocolIR) -> str:
    """The contract exactly as the prompt renders it (``_printable``'s format)."""

    return json.dumps(
        ir.to_protocol_contract(), ensure_ascii=False, indent=2, sort_keys=True,
        allow_nan=False,
    )


def contract_section(prompt: str) -> str:
    """The rendered ``Protocol contract, if supplied:`` slot of a prompt."""

    return prompt.split("Protocol contract, if supplied:")[1].split(
        "Previous validation feedback"
    )[0]


class Stage4ProjectTests(unittest.TestCase):
    """Shared mini_parser artifacts: a real FT with a real target next to it."""

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        project = Path(cls.temporary.name) / "project"
        project.mkdir()
        shutil.copy2(SOURCE, project / "target.c")
        cls.phase1 = Path(cls.temporary.name) / "phase1"
        SFGPipeline(
            MockSemanticAnalyzer(), ignored_directories=DEFAULT_IGNORES
        ).run(project, cls.phase1)
        cls.triplet = next(
            triplet
            for triplet in extract_function_triplets(load_sfg_artifacts(cls.phase1))
            if triplet.isf.function == "mp_parse"
        )

    def artifact_root(self, name: str) -> Path:
        """A fresh artifact root holding the FT's functions.json, and nothing else."""

        root = Path(self.temporary.name) / name
        root.mkdir()
        shutil.copy2(self.phase1 / "functions.json", root / "functions.json")
        return root

    @staticmethod
    def rough_code() -> str:
        return """void rough_sequence(
    mp_context *ctx,
    const unsigned char *data,
    unsigned long size)
{
    mp_parse(ctx, data, size);
    mp_destroy(ctx);
}"""

    def harness_plan(self, *, bounded_steps: int = 32) -> str:
        return json.dumps({
            "schema_version": 1,
            "triplet_id": self.triplet.id,
            "entrypoint": "LLVMFuzzerTestOneInput",
            "input_strategy": {
                "description": "Decode fuzzer bytes as mini_parser frames.",
                "data_identifier": "data",
                "size_identifier": "size",
                "bounded_steps": bounded_steps,
                "notes": [],
            },
            "state_objects": [
                {
                    "name": "ctx",
                    "type": "mp_context",
                    "initialization": "zero initialize before the command loop",
                }
            ],
            "call_sequence": [
                {
                    "function": "mp_parse",
                    "roles": ["ISF", "PRF"],
                    "purpose": "parse one frame from fuzzer bytes",
                    "arguments": ["&ctx", "data", "size"],
                    "uses_fuzzer_data": True,
                    "uses_fuzzer_size": True,
                    "outputs": [],
                    "conditions": [],
                }
            ],
            "cleanup_sequence": [
                {
                    "function": "mp_destroy",
                    "purpose": "release the context after the loop",
                    "arguments": ["&ctx"],
                    "after": ["mp_parse"],
                }
            ],
            "constraints": ["repair length and checksum before mp_parse"],
            "notes": ["keep one mp_context alive across frames"],
        })

    @staticmethod
    def harness_code() -> str:
        return """#include <stddef.h>
#include <stdint.h>
extern "C" {
#include "target.c"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mp_context ctx = {0};
    int status = mp_parse(&ctx, data, size);
    (void)status;
    mp_destroy(&ctx);
    return 0;
}"""

    def generate(self, root: Path):
        """Run Stage 4 against ``root`` and hand back the client and the result."""

        llm = MockLLM([self.harness_plan(), self.harness_code()])
        result = Stage4Generator(llm).run(
            self.triplet,
            rough_code=self.rough_code(),
            functions_json=root / "functions.json",
            artifacts=root,
        )
        return llm, result

    def plan_artifact(self, root: Path) -> dict:
        path = (
            root / "generation" / self.triplet.id / "stage4" / "attempt_001"
            / "plan.json"
        )
        return json.loads(path.read_text(encoding="utf-8"))


class RoundTripTests(unittest.TestCase):
    """``from_json`` must be the inverse of ``to_json``, or nothing else holds."""

    @classmethod
    def setUpClass(cls):
        cls.mined = mined_ir()

    def assert_round_trips(self, ir: ProtocolIR) -> None:
        restored = ProtocolIR.from_json(json.loads(json.dumps(ir.to_json())))
        self.assertEqual(restored, ir)

    def test_the_mined_ir_round_trips(self):
        self.assert_round_trips(self.mined)

    def test_the_a_b_only_ir_round_trips(self):
        """No convention block: sequence, context and the opcode set are empty."""

        facts = mine_protocol_facts(
            SOURCE.read_bytes(), "mp_parse", filename="target.c"
        )
        ir = ProtocolIR.from_facts_and_conventions(facts, None)
        self.assertIsNone(ir.sequence)
        self.assertIsNone(ir.context)
        self.assertEqual(ir.stateful_operations, ())
        self.assert_round_trips(ir)

    def test_an_empty_c_block_round_trips_without_being_normalised(self):
        """An empty ``max_steps`` block must not come back as an explicit null.

        ``SequenceModel`` defaults ``max_steps`` to ``{}``, and "no bound was
        stated" is a different claim from "the bound is null"; normalising the
        block on load would quietly turn one into the other.
        """

        facts = mine_protocol_facts(
            SOURCE.read_bytes(), "mp_parse", filename="target.c"
        )
        conventions = ProtocolConventions(
            entry_function="mp_parse",
            sequence_model=SequenceModel(multi_frame=True),
            context=ContextModel(),
        )
        ir = ProtocolIR.from_facts_and_conventions(facts, conventions)
        self.assertEqual(ir.sequence.max_steps, {})
        self.assertEqual(ProtocolIR.from_json(ir.to_json()).sequence.max_steps, {})

    def test_a_fully_populated_ir_round_trips(self):
        facts = ProtocolFacts(entry_function="f", filename="bare.c")
        facts.fields.append(FieldFact(
            name="field_0", offset=0, width=1, role="magic", value="'M'",
            evidence=[Evidence(
                kind="literal_guard", line=3, column=9,
                snippet="data[0] != 'M'", detail="byte at offset 0 compared",
            )],
        ))
        facts.fields.append(FieldFact(
            name="field_1", offset=1, width=-1, role="payload",
            value="fuzzer-controlled bytes",
        ))
        ir = ProtocolIR(
            entry_function="f",
            frame=FrameModel(
                fields=(
                    FrameField(
                        name="magic", offset=0, width=1, role="magic", value="'M'",
                        endianness="little_endian",
                        evidence=(ProtocolEvidence.from_miner_evidence(
                            Evidence(kind="literal_guard", line=3, column=9,
                                     snippet="data[0] != 'M'", detail="compared"),
                            "bare.c",
                        ),),
                    ),
                    FrameField(
                        name="payload", offset=1, width="payload_length",
                        role="payload", value="fuzzer-controlled bytes",
                        source="unknown", confidence=0.0,
                    ),
                ),
                header_size=1,
                payload_offset=1,
                max_payload=64,
                max_payload_symbol="MAX_BODY",
                evidence=(ProtocolEvidence.unresolved("no header guard seen"),),
            ),
            sequence=SequenceModel(
                multi_frame=True,
                reason="stateful opcodes",
                evidence=("ctx outlives one frame",),
                max_steps={"value": 32, "source": "engineering_choice",
                           "evidence": ["policy"]},
            ),
            context=ContextModel(
                type="ctx_t", init="ctx_new()", destroy="ctx_free()",
                lifetime="one per iteration", evidence=("ctx_t is heap allocated",),
            ),
            stateful_operations=(
                StatefulOperation(opcode="OP_STORE", reason="saves",
                                  evidence=("case OP_STORE",)),
            ),
            requirements=("repair the envelope",),
            notes=("keep the context alive",),
            limitations=("no endianness helper was recognised",),
            source_name="bare.c",
            llm_confidence=0.75,
            metadata={"samples_requested": 4, "valid_samples": 3},
        )
        self.assert_round_trips(ir)

    # -- refusal -----------------------------------------------------------

    def document(self) -> dict:
        return json.loads(json.dumps(self.mined.to_json()))

    def test_a_wrong_schema_version_is_refused(self):
        document = self.document()
        document["schema_version"] = 99
        with self.assertRaisesRegex(ProtocolIRError, "schema_version must be 1"):
            ProtocolIR.from_json(document)

    def test_a_missing_top_level_key_names_itself(self):
        document = self.document()
        del document["stateful_operations"]
        with self.assertRaisesRegex(ProtocolIRError, "stateful_operations"):
            ProtocolIR.from_json(document)

    def test_a_bad_field_offset_names_the_field(self):
        document = self.document()
        document["frame"]["fields"][0]["offset"] = "zero"
        with self.assertRaisesRegex(ProtocolIRError, r"frame\.fields\[0\]\.offset"):
            ProtocolIR.from_json(document)

    def test_a_bad_field_width_names_the_field(self):
        document = self.document()
        document["frame"]["fields"][0]["width"] = [1]
        with self.assertRaisesRegex(ProtocolIRError, r"frame\.fields\[0\]\.width"):
            ProtocolIR.from_json(document)

    def test_an_unknown_provenance_names_the_field(self):
        document = self.document()
        document["frame"]["fields"][0]["source"] = "vibes"
        with self.assertRaisesRegex(ProtocolIRError, r"frame\.fields\[0\]\.source"):
            ProtocolIR.from_json(document)

    def test_a_field_without_provenance_is_refused_rather_than_assumed_static(self):
        """Loading must not invent a measurement the document never claimed."""

        document = self.document()
        del document["frame"]["fields"][0]["source"]
        with self.assertRaisesRegex(
            ProtocolIRError, r"frame\.fields\[0\] is missing 'source'"
        ):
            ProtocolIR.from_json(document)

    def test_a_bad_sequence_field_names_it(self):
        document = self.document()
        del document["sequence_model"]["multi_frame"]
        with self.assertRaisesRegex(ProtocolIRError, "sequence_model"):
            ProtocolIR.from_json(document)

    def test_a_nested_evidence_error_names_its_path(self):
        document = self.document()
        document["frame"]["fields"][0]["evidence"][0]["line"] = "three"
        with self.assertRaisesRegex(
            ProtocolIRError, r"frame\.fields\[0\]\.evidence\[0\]\.line"
        ):
            ProtocolIR.from_json(document)

    def test_an_out_of_range_confidence_is_refused(self):
        document = self.document()
        document["confidence"] = 1.5
        with self.assertRaisesRegex(ProtocolIRError, "confidence must be between"):
            ProtocolIR.from_json(document)

    def test_a_json_array_is_not_an_ir_document(self):
        with self.assertRaisesRegex(ProtocolIRError, "must be a JSON object"):
            ProtocolIR.from_json([])


class MinedContractEndToEndTests(Stage4ProjectTests):
    """The strongest evidence: Stage 4 planning off a mined, persisted IR."""

    def test_stage4_consumes_a_written_protocol_ir(self):
        root = self.artifact_root("mined")
        ir = mined_ir()
        written = ArtifactStore(root).write_protocol_ir(ir)
        self.assertEqual(written, root / "protocol_ir.json")

        llm, result = self.generate(root)
        plan_prompt = llm.calls[0]["prompt"]
        transform_prompt = llm.calls[1]["prompt"]

        # The IR is mined, not read from the hand-written benchmark contract.
        self.assertEqual(
            tuple(field.name for field in ir.frame.fields), MINED_FIELD_NAMES
        )
        self.assertEqual(ir.frame.payload_offset, 8)
        self.assertEqual(ir.frame.max_payload_symbol, "MP_MAX_PAYLOAD")
        self.assertEqual(ir.llm_confidence, 1.0)

        contract = contract_block(ir)
        self.assertIn(contract, plan_prompt)
        self.assertIn(contract, transform_prompt)

        for name in MINED_FIELD_NAMES:
            with self.subTest(field=name):
                self.assertIn(f'"name": "{name}"', plan_prompt)
        self.assertIn('"payload_offset": 8', plan_prompt)
        self.assertIn('"max_payload": "MP_MAX_PAYLOAD"', plan_prompt)
        self.assertIn('"endianness": "little_endian"', plan_prompt)
        # context lifetime, the loop bound and the stateful opcodes
        self.assertIn('"type": "mp_context"', plan_prompt)
        self.assertIn('"init": "mp_init(&ctx)"', plan_prompt)
        self.assertIn('"destroy": "mp_destroy(&ctx)"', plan_prompt)
        self.assertIn('"max_steps": 32', plan_prompt)
        for opcode in ("MP_STORE", "MP_USE", "MP_RELEASE"):
            with self.subTest(opcode=opcode):
                self.assertIn(opcode, plan_prompt)

        self.assertEqual(
            result.harness_plan["generation_metadata"]["protocol_ir"],
            {
                "path": str(root / "protocol_ir.json"),
                "entry_function": "mp_parse",
                "llm_confidence": 1.0,
            },
        )
        self.assertEqual(
            self.plan_artifact(root)["generation_metadata"]["protocol_ir"],
            result.harness_plan["generation_metadata"]["protocol_ir"],
        )

    def test_the_plan_follows_the_mined_source_not_the_hand_written_file(self):
        """Rename the payload cap in the source and watch the prompt follow.

        ``protocol.json`` names ``MP_MAX_PAYLOAD``; this source names
        ``MP_LIMIT``.  If the prompt's contract section still said
        ``MP_MAX_PAYLOAD`` it could only have come from the hand-written file,
        which is the dependency this path exists to remove.

        The assertion is scoped to the contract section because the FT's own
        bypass semantics quote the unmodified source's guard conditions, and
        those legitimately still name ``MP_MAX_PAYLOAD``.
        """

        modified = SOURCE.read_bytes().replace(b"MP_MAX_PAYLOAD", b"MP_LIMIT")
        self.assertIn(b"MP_LIMIT = 64", modified)
        ir = mined_ir(modified, filename="target.c")
        self.assertEqual(ir.frame.max_payload_symbol, "MP_LIMIT")

        root = self.artifact_root("mined_renamed")
        ArtifactStore(root).write_protocol_ir(ir)
        llm, _ = self.generate(root)

        section = contract_section(llm.calls[0]["prompt"])
        self.assertIn('"max_payload": "MP_LIMIT"', section)
        self.assertNotIn("MP_MAX_PAYLOAD", section)
        # The rest of the frame is still the miner's, unchanged by the rename.
        self.assertIn('"name": "payload_length"', section)
        self.assertIn('"payload_offset": 8', section)
        self.assertIn("MP_LIMIT", contract_section(llm.calls[1]["prompt"]))

    def test_the_loader_returns_the_same_contract_stage4_prompted_with(self):
        root = self.artifact_root("loader")
        ir = mined_ir()
        ArtifactStore(root).write_protocol_ir(ir)

        loaded = load_protocol_contract(root)
        self.assertIsNotNone(loaded)
        contract, provenance = loaded
        self.assertEqual(contract, ir.to_protocol_contract())
        self.assertEqual(provenance["entry_function"], "mp_parse")
        self.assertEqual(provenance["llm_confidence"], 1.0)

    def test_an_ir_without_a_convention_block_still_reaches_the_prompt(self):
        """A/B-only mining is a supported run; the frame block must still arrive."""

        facts = mine_protocol_facts(
            SOURCE.read_bytes(), "mp_parse", filename="target.c"
        )
        ir = ProtocolIR.from_facts_and_conventions(facts, None)
        root = self.artifact_root("ab_only")
        ArtifactStore(root).write_protocol_ir(ir)

        llm, _ = self.generate(root)
        plan_prompt = llm.calls[0]["prompt"]
        self.assertIn('"name": "magic0"', plan_prompt)
        self.assertIn('"payload_offset": 8', plan_prompt)
        # No C block was voted, so the contract says nothing about stateful
        # opcodes rather than saying there are none.
        self.assertNotIn("stateful_operations", contract_section(plan_prompt))
        self.assertNotIn("command_loop", contract_section(plan_prompt))

    def test_an_ir_written_as_a_raw_document_is_read_the_same_way(self):
        root = self.artifact_root("raw_document")
        ir = mined_ir()
        ArtifactStore(root).write_protocol_ir(ir.to_json())

        llm, _ = self.generate(root)
        self.assertIn(contract_block(ir), llm.calls[0]["prompt"])


class SixConcernsTests(Stage4ProjectTests):
    """The six protocol concerns are scoped to a supplied contract."""

    CONCERNS = (
        "1. bounded multi-frame command loop:",
        "2. context lifetime across frames:",
        "3. exact frame fields:",
        "4. length/checksum repair:",
        "5. payload remains fuzzer-controlled:",
        "6. stateful opcodes and cleanup:",
    )
    CONDITION = "If a protocol contract is supplied,"
    FALLBACK = (
        "If no protocol contract is supplied, fall back to FT-only harness planning"
    )

    def test_the_concerns_are_stated_when_a_contract_is_supplied(self):
        root = self.artifact_root("concerns_with_ir")
        ArtifactStore(root).write_protocol_ir(mined_ir())
        llm, _ = self.generate(root)

        plan_prompt = llm.calls[0]["prompt"]
        self.assertIn(self.CONDITION, plan_prompt)
        for concern in self.CONCERNS:
            with self.subTest(concern=concern):
                self.assertIn(concern, plan_prompt)
        # The specifics the concerns exist to force, so that a rewrite that
        # keeps the headings but drops the requirement fails here.
        self.assertIn("offset, width and endianness", plan_prompt)
        self.assertIn("checksum fields must be filled in by", plan_prompt)
        self.assertIn(
            "set input_strategy.bounded_steps to a positive cap", plan_prompt
        )
        self.assertIn("frame.payload_offset up to frame.max_payload", plan_prompt)

    def test_without_a_contract_the_prompt_falls_back_to_ft_only(self):
        root = self.artifact_root("concerns_without_ir")
        llm, _ = self.generate(root)

        plan_prompt = llm.calls[0]["prompt"]
        self.assertIn(self.FALLBACK, plan_prompt)
        self.assertIn("Do not invent a framed protocol.", plan_prompt)

        # Being in the text is not enough: the six concerns must sit *inside*
        # the supplied-contract branch.  An FT-only run that still reads a
        # standing demand for frame offset/width/endianness is exactly the
        # hallucination risk this scoping removes, and it would pass a test
        # that only checked for the six headings.
        self.assertLess(
            plan_prompt.index(self.CONDITION), plan_prompt.index(self.CONCERNS[0])
        )
        self.assertLess(
            plan_prompt.index(self.CONCERNS[-1]), plan_prompt.index(self.FALLBACK)
        )
        self.assertNotIn(
            "Whether or not a protocol contract appears below", plan_prompt
        )

    def test_the_plan_prompt_version_records_the_rewrite(self):
        root = self.artifact_root("version")
        llm, _ = self.generate(root)
        self.assertEqual(llm.calls[0]["prompt_version"], "stage4-harness-plan-v6")
        self.assertEqual(
            llm.calls[1]["prompt_version"], "stage4-harness-transform-v6"
        )


class FallbackTests(Stage4ProjectTests):
    """No ``protocol_ir.json`` must reproduce the pre-IR behaviour exactly."""

    EMPTY_SECTION = "Protocol contract, if supplied:\n{}"

    def test_a_missing_ir_renders_an_empty_contract_section(self):
        root = self.artifact_root("fallback")
        self.assertIsNone(load_protocol_contract(root))

        llm, result = self.generate(root)
        self.assertIn(self.EMPTY_SECTION, llm.calls[0]["prompt"])
        self.assertIn(self.EMPTY_SECTION, llm.calls[1]["prompt"])
        self.assertEqual(result.harness_code, self.harness_code())

    def test_a_missing_ir_adds_no_key_to_the_plan_artifact(self):
        root = self.artifact_root("fallback_plan")
        _, result = self.generate(root)

        metadata = result.harness_plan["generation_metadata"]
        self.assertEqual(
            sorted(metadata), ["model", "prompt_version", "provider", "usage"]
        )
        self.assertNotIn("protocol_ir", self.plan_artifact(root)["generation_metadata"])
        stable = json.loads((
            root / "generation" / self.triplet.id / "stage4_harness_plan.json"
        ).read_text(encoding="utf-8"))
        self.assertNotIn("protocol_ir", stable["generation_metadata"])

    def test_omitting_the_contract_and_passing_none_render_the_same_prompt(self):
        """The fallback depends on this equivalence, so it is pinned here."""

        parameters = {
            "triplet_id": "ft_mp_parse_deadbeef",
            "rough_code": "mp_parse(&ctx, data, size);",
            "unique_isf": {"id": "target.c:57:mp_parse", "name": "mp_parse"},
            "function_metadata": {"mp_parse": {"roles": ["ISF"]}},
        }
        omitted = stage4_harness_plan(**parameters).content
        explicit = stage4_harness_plan(**parameters, protocol_contract=None).content

        self.assertEqual(omitted, explicit)
        self.assertIn(self.EMPTY_SECTION, omitted)


class CorruptContractTests(Stage4ProjectTests):
    """A protocol IR that is there but unreadable is a hard stop, not a fallback."""

    def assert_refused(self, root: Path, text: str, message: str):
        (root / "protocol_ir.json").write_text(text, encoding="utf-8")
        llm = MockLLM([self.harness_plan(), self.harness_code()])
        with self.assertRaisesRegex(Stage4Error, message):
            Stage4Generator(llm).run(
                self.triplet,
                rough_code=self.rough_code(),
                functions_json=root / "functions.json",
                artifacts=root,
            )
        # The run stops before the prompt is rendered and before any attempt is
        # written, so a rejected protocol IR cannot leave a half-built harness
        # behind that looks like it was planned from the contract.
        self.assertEqual(llm.calls, [])
        self.assertFalse((root / "generation").exists())

    def test_unparseable_json_is_refused(self):
        self.assert_refused(self.artifact_root("corrupt_json"), "{not json",
                            "cannot read protocol IR")

    def test_a_json_array_is_refused(self):
        self.assert_refused(self.artifact_root("corrupt_array"), "[]",
                            "invalid protocol IR")

    def test_a_valid_json_document_of_the_wrong_shape_is_refused(self):
        self.assert_refused(
            self.artifact_root("corrupt_shape"),
            json.dumps({"schema_version": 1, "entry_function": "mp_parse"}),
            "invalid protocol IR",
        )

    def test_the_hand_written_contract_is_not_an_ir_document(self):
        """``protocol.json`` is LLM-facing; it must not be loadable as the IR.

        If it were, a stage pointed at the wrong file would silently prompt with
        an unversioned contract that carries no provenance at all.
        """

        self.assert_refused(
            self.artifact_root("hand_written"),
            HAND_WRITTEN_PROTOCOL.read_text(encoding="utf-8"),
            "invalid protocol IR",
        )

    def test_a_corrupted_field_is_refused_with_the_field_named(self):
        document = json.loads(json.dumps(mined_ir().to_json()))
        document["frame"]["fields"][3]["offset"] = "four"
        self.assert_refused(
            self.artifact_root("corrupt_field"),
            json.dumps(document),
            r"frame\.fields\[3\]\.offset",
        )


if __name__ == "__main__":
    unittest.main()
