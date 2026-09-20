"""The IR must merge both halves without losing where anything came from.

Two tests carry most of the weight here:

``test_frame_block_matches_the_hand_written_contract``
    differentially compares the IR's A/B output against the human-authored
    ``protocol.json``, so the merge is measured against ground truth rather than
    against itself.

``test_every_element_can_be_traced_back_to_its_half``
    checks that every element the IR exposes declares a provenance from the
    agreed vocabulary, and that the static half really points at source lines.
"""

import json
from pathlib import Path
import unittest

from harness_generation.llm import MockLLM
from harness_generation.protocol_conventions import (
    ContextModel,
    ProtocolConventions,
    SequenceModel,
    StatefulOperation,
    infer_protocol_conventions,
)
from harness_generation.protocol_ir import (
    DEFAULT_LLM_CONFIDENCE,
    PROTOCOL_IR_SCHEMA_VERSION,
    SOURCES,
    SOURCE_ENGINEERING,
    SOURCE_LLM,
    SOURCE_STATIC,
    SOURCE_UNKNOWN,
    VARIABLE_WIDTH,
    FrameField,
    FrameModel,
    ProtocolEvidence,
    ProtocolIR,
    ProtocolIRError,
    _llm_confidence,
)
from harness_generation.protocol_miner import (
    ROLE_MAGIC,
    Evidence,
    FieldFact,
    ProtocolFacts,
    mine_protocol_facts,
)
from harness_generation.protocol_spec import load_protocol_spec


ROOT = Path(__file__).resolve().parents[1]
MINI_PARSER = ROOT / "benchmarks" / "mini_parser"


def _conventions(entry_function="mp_parse", **metadata):
    return ProtocolConventions(
        entry_function=entry_function,
        sequence_model=SequenceModel(
            multi_frame=True,
            reason="decode the byte stream as zero or more command frames",
            evidence=("mp_parse is called per frame inside a loop",),
            max_steps={"value": 32, "source": "llm_inference", "evidence": []},
        ),
        context=ContextModel(
            type="mp_context",
            init="mp_init(&ctx)",
            destroy="mp_destroy(&ctx)",
            lifetime="one context per iteration",
            evidence=("mp_context outlives a single frame",),
        ),
        stateful_operations=(
            StatefulOperation(
                opcode="MP_STORE",
                reason="stores the payload pointer in the context",
                evidence=("case MP_STORE writes ctx",),
            ),
        ),
        requirements=("Use a bounded multi-frame command loop.",),
        notes=("Stateful opcodes need a context across frames.",),
        metadata={
            "prompt_version": "v1",
            "model": "mock-model",
            "provider": "mock",
            "samples_requested": 4,
            "valid_samples": 3,
            "vote_threshold": 2,
            **metadata,
        },
    )


class MiniParserIRTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_text = (MINI_PARSER / "target.c").read_text(encoding="utf-8")
        cls.facts = mine_protocol_facts(
            (MINI_PARSER / "target.c").read_bytes(), "mp_parse", filename="target.c"
        )
        cls.ir = ProtocolIR.from_facts_and_conventions(cls.facts, _conventions())
        cls.declared = json.loads(
            (MINI_PARSER / "protocol.json").read_text(encoding="utf-8")
        )

    # -- the differential oracle ------------------------------------------

    def test_frame_block_matches_the_hand_written_contract(self):
        declared = self.declared["contract"]["frame"]
        mined = self.ir.to_protocol_contract()["contract"]["frame"]

        self.assertEqual(mined["header_size"], declared["header_size"])
        self.assertEqual(mined["payload_offset"], declared["payload_offset"])
        self.assertEqual(mined["max_payload"], declared["max_payload"])

        by_name = {item["name"]: item for item in mined["fields"]}
        self.assertEqual(set(by_name), {item["name"] for item in declared["fields"]})
        for field in declared["fields"]:
            with self.subTest(field=field["name"]):
                recovered = by_name[field["name"]]
                self.assertEqual(recovered["offset"], field["offset"])
                self.assertEqual(recovered["width"], field["width"])
                if "endianness" in field:
                    self.assertEqual(recovered["endianness"], field["endianness"])

    def test_variable_width_field_is_tied_to_the_length_field(self):
        payload = self.ir.field_by_name("payload")
        self.assertTrue(payload.is_variable_width)
        self.assertEqual(payload.width, "payload_length")
        self.assertEqual(
            payload.width, self.ir.field_by_name("payload_length").name
        )

    def test_max_payload_keeps_both_the_symbol_and_the_resolved_value(self):
        declared = self.declared["contract"]["frame"]["max_payload"]
        self.assertEqual(self.ir.frame.max_payload_symbol, declared)  # "MP_MAX_PAYLOAD"
        self.assertEqual(self.ir.frame.max_payload, 64)
        self.assertEqual(self.ir.frame.to_contract_block()["max_payload"], declared)

    def test_contract_round_trips_through_the_loader(self):
        document = self.ir.to_protocol_contract()
        self.assertEqual(document["schema_version"], 1)
        path = ROOT / "tests" / "_tmp_protocol_ir_contract.json"
        try:
            path.write_text(json.dumps(document), encoding="utf-8")
            loaded = load_protocol_spec(path, function="mp_parse")
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(loaded["entry_function"], "mp_parse")
        self.assertEqual(
            loaded["contract"]["frame"]["header_size"],
            self.declared["contract"]["frame"]["header_size"],
        )
        self.assertEqual(loaded["requirements"], list(self.ir.requirements))


class PayloadOffsetPassthroughTests(unittest.TestCase):
    """The IR must carry the measured payload base, not re-derive it.

    Before the miner exposed ``payload_offset`` the IR set it equal to the
    header size, which is only correct for the header+payload layout that
    `mini_parser` happens to use.
    """

    WIDE = b"""
static unsigned short le16(const unsigned char *p) {
    return (unsigned short)((unsigned short)p[0] | ((unsigned short)p[1] << 8));
}

static unsigned short chk(const unsigned char *p, size_t n) {
    (void)p;
    return (unsigned short)n;
}

int parse_wide(const unsigned char *data, size_t size) {
    if (size < 8) return -1;
    size_t len = le16(data + 4);
    if (len != size - 12) return -2;
    if (chk(data + 12, len) != le16(data + 10)) return -3;
    return 0;
}
"""

    @classmethod
    def setUpClass(cls):
        cls.facts = mine_protocol_facts(cls.WIDE, "parse_wide", filename="wide.c")
        cls.ir = ProtocolIR.from_facts_and_conventions(cls.facts, None)

    def test_ir_carries_the_measured_payload_offset(self):
        self.assertEqual(self.ir.frame.header_size, 8)
        self.assertEqual(self.ir.frame.payload_offset, 12)

    def test_contract_block_keeps_header_and_payload_distinct(self):
        frame = self.ir.to_protocol_contract()["contract"]["frame"]
        self.assertEqual(frame["header_size"], 8)
        self.assertEqual(frame["payload_offset"], 12)

    def test_ir_json_reports_the_payload_offset(self):
        self.assertEqual(self.ir.to_json()["frame"]["payload_offset"], 12)

    def test_old_facts_without_a_payload_offset_fall_back_to_the_header(self):
        facts = ProtocolFacts(entry_function="f", filename="x.c", header_size=8)
        ir = ProtocolIR.from_facts_and_conventions(facts, None)
        self.assertEqual(ir.frame.payload_offset, 8)

    def test_a_payload_base_inside_the_header_is_resolved_and_reported(self):
        """The miner can see only header loads; the IR must not publish a
        payload base that overlaps the header."""

        facts = ProtocolFacts(
            entry_function="f", filename="x.c", header_size=8, payload_offset=6
        )
        ir = ProtocolIR.from_facts_and_conventions(facts, None)
        self.assertEqual(ir.frame.payload_offset, 8)
        self.assertTrue(
            any("falls inside the 8-byte header" in item for item in ir.limitations)
        )

    def test_conflicting_facts_do_not_make_the_ir_raise(self):
        """Real miner output must merge, even when it is self-contradictory."""

        facts = mine_protocol_facts(
            b"""
static unsigned short le16(const unsigned char *p) {
    return (unsigned short)((unsigned short)p[0] | ((unsigned short)p[1] << 8));
}
int parse_conflict(const unsigned char *data, size_t size) {
    if (size < 8) return -1;
    size_t len = le16(data + 4);
    if (len != size - 8) return -2;
    if (le16(data + 6) != 0) return -3;
    return 0;
}
""",
            "parse_conflict",
            filename="conflict.c",
        )
        ir = ProtocolIR.from_facts_and_conventions(facts, None)
        offsets = [item.offset for item in ir.frame.fields]
        self.assertEqual(sorted(offsets), sorted(set(offsets)))


class ProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_text = (MINI_PARSER / "target.c").read_text(encoding="utf-8")
        cls.facts = mine_protocol_facts(
            (MINI_PARSER / "target.c").read_bytes(), "mp_parse", filename="target.c"
        )
        cls.ir = ProtocolIR.from_facts_and_conventions(cls.facts, _conventions())

    def test_every_element_can_be_traced_back_to_its_half(self):
        document = self.ir.to_json()

        for field in document["frame"]["fields"]:
            with self.subTest(field=field["name"]):
                self.assertIn(field["source"], SOURCES)
                self.assertIsInstance(field["confidence"], float)
                self.assertTrue(field["evidence"], "static field lost its evidence")
                for item in field["evidence"]:
                    self.assertEqual(item["source"], SOURCE_STATIC)

        for key in ("sequence_model", "context"):
            with self.subTest(section=key):
                self.assertEqual(document[key]["source"], SOURCE_LLM)
                self.assertEqual(
                    document[key]["confidence"], document["confidence"]
                )
        for operation in document["stateful_operations"]:
            self.assertEqual(operation["source"], SOURCE_LLM)

    def test_static_evidence_still_points_at_real_source_lines(self):
        lines = self.source_text.splitlines()
        for field in self.ir.to_json()["frame"]["fields"]:
            for item in field["evidence"]:
                with self.subTest(field=field["name"], kind=item.get("kind")):
                    path, line, column = item["location"].rsplit(":", 2)
                    self.assertEqual(path, "target.c")
                    line = int(line)
                    self.assertTrue(1 <= line <= len(lines))
                    self.assertGreaterEqual(int(column), 1)
                    snippet = item["snippet"]
                    if snippet.endswith(" ..."):
                        snippet = snippet[: -len(" ...")]
                    if snippet:
                        self.assertIn(snippet, lines[line - 1])

    def test_static_and_inferred_facts_carry_different_confidence(self):
        payload = self.ir.field_by_name("payload_length")
        self.assertEqual(payload.source, SOURCE_STATIC)
        self.assertEqual(payload.confidence, 1.0)
        self.assertLess(self.ir.llm_confidence, 1.0)

    def test_llm_confidence_falls_back_to_the_parsed_sample_ratio(self):
        """These conventions are hand-built, so there is no vote summary to read.

        ``_conventions()`` writes the sample-level metadata directly and never
        ran a vote, so the recorded agreement does not exist.  The number is then
        the fallback it was scored with before the summary existed: 3 of the 4
        requested samples parsed and voted, so 0.75.
        """

        self.assertEqual(self.ir.llm_confidence, 0.75)

    def test_evidence_index_covers_both_halves(self):
        index = self.ir.evidence_index()
        sources = {item.source for item in index}
        self.assertIn(SOURCE_STATIC, sources)
        self.assertIn(SOURCE_LLM, sources)
        self.assertTrue(any(item.line for item in index if item.source == SOURCE_STATIC))

    def test_missing_evidence_degrades_to_unknown_rather_than_static(self):
        """A field the miner could not justify must not look measured.

        The miner's strict mode refuses such fields, but ``strict=False`` is a
        supported inspection path, so the IR has to downgrade them instead of
        handing the prompt a fact with nothing behind it.
        """

        facts = ProtocolFacts(entry_function="f", filename="bare.c")
        facts.fields.append(FieldFact(
            name="field_0", offset=0, width=1, role=ROLE_MAGIC, value="'M'",
        ))
        self.assertEqual(facts.fields_without_evidence(), ["field_0"])

        ir = ProtocolIR.from_facts_and_conventions(facts, None)
        field = ir.frame.fields[0]
        self.assertEqual(field.source, SOURCE_UNKNOWN)
        self.assertEqual(field.confidence, 0.0)
        self.assertEqual(field.evidence, ())
        self.assertEqual(ir.unresolved_fields(), ("field_0",))

    def test_justified_field_stays_static_with_full_confidence(self):
        facts = ProtocolFacts(entry_function="f", filename="bare.c")
        facts.fields.append(FieldFact(
            name="field_0", offset=0, width=1, role=ROLE_MAGIC, value="'M'",
            evidence=[Evidence(
                kind="literal_guard", line=3, column=9,
                snippet="data[0] != 'M'", detail="byte at offset 0 compared",
            )],
        ))
        ir = ProtocolIR.from_facts_and_conventions(facts, None)
        field = ir.frame.fields[0]
        self.assertEqual(field.source, SOURCE_STATIC)
        self.assertEqual(field.confidence, 1.0)
        self.assertEqual(field.evidence[0].location, "bare.c:3:9")
        self.assertEqual(field.evidence[0].snippet, "data[0] != 'M'")
        self.assertEqual(ir.unresolved_fields(), ())

    def test_evidence_constructors_agree_with_the_vocabulary(self):
        for item in (
            ProtocolEvidence.from_convention_text("x"),
            ProtocolEvidence.from_engineering_choice("x"),
            ProtocolEvidence.unresolved("x"),
        ):
            self.assertIn(item.source, SOURCES)


class MergeContractTests(unittest.TestCase):
    SOURCE = b"""
#define HEADER 8
#define MAX_BODY 64
enum op { OP_READ = 1, OP_STORE = 2 };
typedef struct { unsigned char *saved; } ctx_t;
ctx_t *ctx_new(void);
void ctx_free(ctx_t *);
unsigned short read_u16le(const unsigned char *p);
unsigned short checksum(const unsigned char *payload, unsigned short len);

int parse_frame(ctx_t *ctx, const unsigned char *data, unsigned long size) {
    if (size < HEADER) return -1;
    unsigned short len = read_u16le(data + 4);
    if (len > MAX_BODY || len != size - HEADER) return -2;
    if (checksum(data + HEADER, len) != read_u16le(data + 6)) return -3;
    switch (data[3]) {
        case OP_READ: return 0;
        case OP_STORE: ctx->saved = (unsigned char *)(data + HEADER); return 1;
    }
    return 0;
}
"""

    def test_entry_function_mismatch_is_rejected(self):
        facts = mine_protocol_facts(self.SOURCE, "parse_frame", filename="f.c")
        with self.assertRaisesRegex(ProtocolIRError, "conventions describe"):
            ProtocolIR.from_facts_and_conventions(
                facts, _conventions(entry_function="something_else")
            )

    def test_absent_conventions_are_reported_not_invented(self):
        facts = mine_protocol_facts(self.SOURCE, "parse_frame", filename="f.c")
        ir = ProtocolIR.from_facts_and_conventions(facts, None)

        self.assertIsNone(ir.sequence)
        self.assertIsNone(ir.context)
        self.assertEqual(ir.stateful_operations, ())
        self.assertTrue(any("convention block is absent" in item for item in ir.limitations))
        # The A/B half still works without an LLM.
        self.assertEqual(ir.frame.header_size, 8)
        self.assertIn("checksum", {item.name for item in ir.frame.fields})

    def test_default_max_steps_is_recorded_as_an_engineering_choice(self):
        facts = mine_protocol_facts(self.SOURCE, "parse_frame", filename="f.c")
        conventions = ProtocolConventions(
            entry_function="parse_frame",
            sequence_model=SequenceModel(
                multi_frame=True,
                reason="multi frame",
                max_steps={"value": None, "source": "", "evidence": []},
            ),
            context=ContextModel(type="ctx_t"),
            metadata={"samples_requested": 2, "valid_samples": 2},
        )
        ir = ProtocolIR.from_facts_and_conventions(
            facts, conventions, default_max_steps=32
        )
        self.assertEqual(ir.sequence.max_steps["value"], 32)
        self.assertEqual(ir.sequence.max_steps["source"], SOURCE_ENGINEERING)
        # A measured bound must never be overwritten by the fallback.
        conventions_measured = _conventions(entry_function="parse_frame")
        measured = ProtocolIR.from_facts_and_conventions(
            facts, conventions_measured, default_max_steps=99
        )
        self.assertEqual(measured.sequence.max_steps["value"], 32)

    def test_duplicate_offsets_are_rejected(self):
        with self.assertRaisesRegex(ProtocolIRError, "share an offset"):
            FrameModel(fields=(
                FrameField(name="a", offset=1, width=1, role="magic"),
                FrameField(name="b", offset=1, width=1, role="version"),
            ))

    def test_payload_inside_the_header_is_rejected(self):
        with self.assertRaisesRegex(ProtocolIRError, "falls inside"):
            FrameModel(
                fields=(FrameField(name="a", offset=0, width=1, role="magic"),),
                header_size=8,
                payload_offset=4,
            )

    def test_unknown_provenance_is_rejected(self):
        with self.assertRaisesRegex(ProtocolIRError, "unknown provenance"):
            FrameField(name="a", offset=0, width=1, role="magic", source="vibes")


class EndToEndInferenceTests(unittest.TestCase):
    """The IR must accept what the real inference pipeline produces."""

    SOURCE = MergeContractTests.SOURCE

    def test_ir_built_from_a_voted_inference_result(self):
        from tests.test_protocol_conventions import _sample

        samples = [_sample(include_release=True) for _ in range(3)]
        facts = mine_protocol_facts(self.SOURCE, "parse_frame", filename="f.c")
        result = infer_protocol_conventions(
            facts,
            "int parse_frame(...)",
            MockLLM(samples),
            samples=3,
        )
        ir = ProtocolIR.from_facts_and_conventions(facts, result.conventions)

        self.assertEqual(ir.entry_function, "parse_frame")
        # 3 of 3 parsed *and* all eight fields unanimous: 1.0 x 1.0.  Validity
        # alone is not enough to reach 1.0 -- three samples that contradicted
        # each other would parse just as well and score lower.
        self.assertEqual(ir.llm_confidence, 1.0)
        self.assertEqual(
            ir.metadata["vote_summary"]["confidence"]["mean_field_agreement"], 1.0
        )
        self.assertEqual(ir.metadata["valid_samples"], 3)
        self.assertTrue(ir.stateful_operations)
        self.assertEqual(ir.sequence.max_steps["value"], 32)

        document = ir.to_protocol_contract()
        self.assertEqual(document["contract"]["context"]["type"], "parser_ctx")
        self.assertTrue(document["contract"]["command_loop"]["preferred"])

    def test_unparseable_samples_lower_the_confidence(self):
        from tests.test_protocol_conventions import _sample

        samples = [_sample()] + ["not json at all"] * 3
        facts = mine_protocol_facts(self.SOURCE, "parse_frame", filename="f.c")
        result = infer_protocol_conventions(
            facts, "int parse_frame(...)", MockLLM(samples), samples=4
        )
        ir = ProtocolIR.from_facts_and_conventions(facts, result.conventions)
        # 1 of 4 requested samples parsed (0.25); the one that did had nothing to
        # disagree with, so it agreed with itself on every field (1.0) and the
        # product stays at the validity.  The failure here is validity, not
        # agreement -- see ConfidenceTracksDisagreementTests for the other half.
        self.assertEqual(ir.llm_confidence, 0.25)
        self.assertGreater(ir.llm_confidence, 0.0)
        self.assertEqual(
            ir.metadata["vote_summary"]["confidence"]["mean_field_agreement"], 1.0
        )


class ConfidenceTracksDisagreementTests(unittest.TestCase):
    """Samples that parse but contradict each other must not score like agreement.

    This is the defect the vote summary exists to close.  Under the old
    confidence -- the share of requested samples that parsed -- every run in this
    class scored 1.0, because every sample in every run parsed.  Measured on
    these fixtures, with eight fields voted on:

    ==========================================  =======
    three samples, byte-identical              1.0
    three samples, one field answered 3 ways   0.9167
    three samples, four fields answered 3 ways 0.6666
    ==========================================  =======

    So one contested semantic field costs 0.0833 out of 1.0.  The product form
    is deliberately conservative about trusting a stable inference; it is *not*
    sensitive enough to make a coin flip look alarming on its own, which is why
    the per-field evidence is persisted alongside it.
    """

    SOURCE = MergeContractTests.SOURCE

    def _confidence(self, responses):
        from tests.test_protocol_conventions import _sample  # noqa: F401

        facts = mine_protocol_facts(self.SOURCE, "parse_frame", filename="f.c")
        result = infer_protocol_conventions(
            facts,
            "int parse_frame(...)",
            MockLLM(responses),
            samples=len(responses),
        )
        ir = ProtocolIR.from_facts_and_conventions(facts, result.conventions)
        return ir, result.conventions.metadata["vote_summary"]

    def test_contradicting_samples_score_below_unanimous_ones(self):
        """The headline repro: same samples, one field answered three ways."""

        from tests.test_protocol_conventions import _sample, _variant

        unanimous, unanimous_summary = self._confidence([_sample()] * 3)
        contradictory, summary = self._confidence([
            _variant(lifetime="one per fuzz iteration"),
            _variant(lifetime="process lifetime"),
            _variant(lifetime="unknown"),
        ])

        self.assertEqual(unanimous.llm_confidence, 1.0)
        self.assertEqual(
            unanimous_summary["confidence"]["mean_field_agreement"], 1.0
        )
        # Strictly greater: a contradiction must cost something.
        self.assertGreater(unanimous.llm_confidence, contradictory.llm_confidence)
        self.assertEqual(contradictory.llm_confidence, 0.9167)
        self.assertEqual(summary["confidence"]["sample_validity"], 1.0)
        self.assertEqual(summary["confidence"]["mean_field_agreement"], 0.9167)
        self.assertEqual(len(summary["confidence"]["fields_counted"]), 8)

    def test_the_contested_field_is_visible_in_the_summary(self):
        """A reader has to be able to see *which* field cost the confidence."""

        from tests.test_protocol_conventions import _variant

        _, summary = self._confidence([
            _variant(lifetime="one per fuzz iteration"),
            _variant(lifetime="process lifetime"),
            _variant(lifetime="unknown"),
        ])
        entry = summary["fields"]["context.lifetime"]

        self.assertEqual(entry["selected"], "one per fuzz iteration")
        self.assertEqual(entry["votes"], 1)
        self.assertEqual(entry["valid_samples"], 3)
        self.assertEqual(entry["agreement"], 0.3333)
        self.assertEqual(
            entry["alternatives"],
            {"one per fuzz iteration": 1, "process lifetime": 1, "unknown": 1},
        )
        # Every other field agreed, so the low mean is explained by this one.
        others = {
            key: value["agreement"]
            for key, value in summary["fields"].items()
            if key != "context.lifetime"
        }
        self.assertEqual(set(others.values()), {1.0})

    def test_a_run_that_lost_a_sample_scores_lower_than_a_unanimous_one(self):
        """Validity and agreement are two halves of the same number."""

        from tests.test_protocol_conventions import _sample

        unanimous, _ = self._confidence([_sample()] * 3)
        degraded, summary = self._confidence([_sample(), _sample(), "not json"])

        self.assertEqual(summary["confidence"]["sample_validity"], 0.6667)
        self.assertEqual(summary["confidence"]["mean_field_agreement"], 1.0)
        self.assertEqual(summary["confidence"]["value"], 0.6667)
        self.assertLess(degraded.llm_confidence, unanimous.llm_confidence)
        self.assertEqual(degraded.llm_confidence, 0.6667)

    def test_a_unanimous_vote_records_all_eight_fields(self):
        from tests.test_protocol_conventions import _sample

        ir, summary = self._confidence([_sample()] * 3)
        confidence = summary["confidence"]

        self.assertEqual(ir.llm_confidence, 1.0)
        self.assertEqual(confidence["sample_validity"], 1.0)
        self.assertEqual(confidence["mean_field_agreement"], 1.0)
        self.assertEqual(confidence["fields_counted"], sorted(summary["fields"]))
        self.assertEqual(
            confidence["fields_counted"],
            [
                "context.destroy",
                "context.init",
                "context.lifetime",
                "context.type",
                "sequence_model.max_steps.source",
                "sequence_model.max_steps.value",
                "sequence_model.multi_frame",
                "stateful_operations",
            ],
        )


class ConfidenceFallbackTests(unittest.TestCase):
    """The read must degrade to the old behaviour, never crash on a bad document.

    Old artifacts carry no ``vote_summary`` and hand-built conventions in tests
    never had one, so the fallback order has to keep scoring those exactly as
    they were scored before.
    """

    SOURCE = MergeContractTests.SOURCE

    def _conventions(self, metadata):
        return ProtocolConventions(
            entry_function="parse_frame",
            sequence_model=SequenceModel(multi_frame=True),
            context=ContextModel(type="parser_ctx"),
            metadata=metadata,
        )

    def _confidence(self, conventions):
        return _llm_confidence(conventions)

    def test_absent_conventions_keep_the_default(self):
        self.assertEqual(_llm_confidence(None), DEFAULT_LLM_CONFIDENCE)

    def test_a_conventions_block_without_a_summary_keeps_the_sample_ratio(self):
        conventions = self._conventions({"samples_requested": 4, "valid_samples": 3})
        self.assertEqual(self._confidence(conventions), 0.75)

    def test_empty_or_missing_metadata_keeps_the_default(self):
        self.assertEqual(self._confidence(self._conventions({})), DEFAULT_LLM_CONFIDENCE)
        self.assertEqual(self._confidence(self._conventions(None)), DEFAULT_LLM_CONFIDENCE)

    def test_a_malformed_recorded_value_falls_through_to_the_ratio(self):
        """A bad number must be ignored, not propagated into the IR.

        These documents are written by a pipeline and can be edited by hand, so
        the read rejects anything that is not a finite float in ``[0, 1]`` --
        ``True`` included, since a bool is an int in Python and would otherwise
        read as 1.0.
        """

        for value in ("high", float("nan"), float("inf"), -0.5, 1.5, True, None, [0.5]):
            with self.subTest(value=value):
                conventions = self._conventions({
                    "samples_requested": 4,
                    "valid_samples": 3,
                    "vote_summary": {"confidence": {"value": value}},
                })
                self.assertEqual(self._confidence(conventions), 0.75)

    def test_a_malformed_summary_shape_falls_through_to_the_ratio(self):
        for summary in ("a string", [], {"confidence": None}, {"confidence": "0.5"}, {}):
            with self.subTest(summary=summary):
                conventions = self._conventions({
                    "samples_requested": 4,
                    "valid_samples": 3,
                    "vote_summary": summary,
                })
                self.assertEqual(self._confidence(conventions), 0.75)

    def test_a_recorded_value_wins_over_the_sample_ratio(self):
        conventions = self._conventions({
            "samples_requested": 4,
            "valid_samples": 4,
            "vote_summary": {"confidence": {"value": 0.4}},
        })
        self.assertEqual(self._confidence(conventions), 0.4)

    def test_the_boundary_values_are_accepted(self):
        for value in (0.0, 1.0, 0, 1):
            with self.subTest(value=value):
                conventions = self._conventions({
                    "samples_requested": 4,
                    "valid_samples": 4,
                    "vote_summary": {"confidence": {"value": value}},
                })
                self.assertEqual(self._confidence(conventions), float(value))

    def test_the_ir_reads_the_recorded_value_rather_than_recomputing_it(self):
        """A summary that contradicts the sample counts still wins.

        The recorded value is authoritative by design: it is the number the vote
        computed, and a fallback that quietly disagreed with the persisted
        ``vote_summary`` would be worse than either number alone.
        """

        facts = mine_protocol_facts(self.SOURCE, "parse_frame", filename="f.c")
        conventions = self._conventions({
            "samples_requested": 4,
            "valid_samples": 4,
            "vote_summary": {"confidence": {"value": 0.3}},
        })
        ir = ProtocolIR.from_facts_and_conventions(facts, conventions)
        self.assertEqual(ir.llm_confidence, 0.3)


class ContractStaysCleanTests(unittest.TestCase):
    """The contract is what the LLM sees; inference metadata must not reach it."""

    SOURCE = MergeContractTests.SOURCE

    # The contract this same input produced *before* the vote summary existed,
    # captured from the pre-change tree.  The vote records a lot more now, and
    # none of it may move the contract: the summary is for reading, not for
    # conditioning on.
    CONTRACT_BEFORE_VOTE_SUMMARY = """\
{
    "contract": {
        "command_loop": {
            "max_steps": 32,
            "preferred": true,
            "reason": "stateful opcodes need multiple frames sharing one context"
        },
        "context": {
            "destroy": "parser_destroy",
            "init": "parser_init",
            "lifetime": "one per fuzz iteration",
            "type": "parser_ctx"
        },
        "frame": {
            "fields": [
                {
                    "name": "opcode",
                    "offset": 3,
                    "value": "dispatch selector over 2 cases, values 1..2",
                    "width": 1
                },
                {
                    "endianness": "little_endian",
                    "name": "payload_length",
                    "offset": 4,
                    "value": "read_u16le() load",
                    "width": 2
                },
                {
                    "endianness": "little_endian",
                    "name": "checksum",
                    "offset": 6,
                    "value": "read_u16le() load",
                    "width": 2
                },
                {
                    "name": "payload",
                    "offset": 8,
                    "relation": {
                        "direction": "parse",
                        "kind": "size_of",
                        "target": "payload"
                    },
                    "value": "fuzzer-controlled bytes",
                    "width": "payload_length"
                }
            ],
            "header_size": 8,
            "max_payload": "MAX_BODY",
            "payload_offset": 8
        },
        "input_model": "stateful opcodes need multiple frames sharing one context",
        "stateful_operations": [
            {
                "opcode": "OP_RELEASE",
                "reason": "clears saved parser state"
            },
            {
                "opcode": "OP_STORE",
                "reason": "stores payload pointer and length in parser_ctx"
            },
            {
                "opcode": "OP_USE",
                "reason": "reads previously stored parser_ctx state"
            }
        ]
    },
    "entry_function": "parse_frame",
    "limitations": [
        "no little/big-endian load helper was recognised; multi-byte field widths and endianness remain unknown",
        "field_8 has a variable width; it must be tied to the length field by a later stage",
        "convention block (command loop, context lifetime, requirements, notes) is out of scope for static mining: it is not present in the parser body"
    ],
    "notes": [
        "keep one parser_ctx alive across generated frames"
    ],
    "requirements": [
        "preserve payload bytes as fuzzer-controlled data",
        "repair magic/length/checksum envelope fields before parse_frame"
    ],
    "schema_version": 1
}
"""

    def _inferred(self):
        from tests.test_protocol_conventions import _sample

        facts = mine_protocol_facts(self.SOURCE, "parse_frame", filename="f.c")
        result = infer_protocol_conventions(
            facts,
            "int parse_frame(...)",
            MockLLM([_sample(include_release=True)] * 3),
            samples=3,
        )
        return facts, result

    def test_the_convention_block_carries_no_metadata_at_all(self):
        _, result = self._inferred()
        block = result.conventions.to_contract_block()

        self.assertNotIn("vote_summary", json.dumps(block))
        self.assertNotIn("metadata", block)
        # And it is not merely renamed: the block is the C block, key for key.
        self.assertEqual(
            sorted(block),
            [
                "context",
                "notes",
                "requirements",
                "sequence_model",
                "stateful_operations",
            ],
        )

    def test_the_contract_is_unchanged_by_the_vote_summary(self):
        facts, result = self._inferred()
        self.assertIn("vote_summary", result.conventions.metadata)

        ir = ProtocolIR.from_facts_and_conventions(facts, result.conventions)

        self.assertEqual(
            json.dumps(ir.to_protocol_contract(), indent=4, sort_keys=True),
            self.CONTRACT_BEFORE_VOTE_SUMMARY.strip(),
        )
        self.assertNotIn("vote_summary", json.dumps(ir.to_protocol_contract()))


class SerialisationShapeTests(unittest.TestCase):
    def test_ir_json_is_versioned_separately_from_the_contract(self):
        facts = mine_protocol_facts(
            MergeContractTests.SOURCE, "parse_frame", filename="f.c"
        )
        ir = ProtocolIR.from_facts_and_conventions(facts, None)
        self.assertEqual(ir.to_json()["schema_version"], PROTOCOL_IR_SCHEMA_VERSION)
        # The contract reuses the loader's version so it can round-trip.
        self.assertEqual(ir.to_protocol_contract()["schema_version"], 1)

    def test_contract_omits_provenance_but_ir_keeps_it(self):
        facts = mine_protocol_facts(
            MergeContractTests.SOURCE, "parse_frame", filename="f.c"
        )
        ir = ProtocolIR.from_facts_and_conventions(facts, _conventions("parse_frame"))

        contract = ir.to_protocol_contract()
        for field in contract["contract"]["frame"]["fields"]:
            self.assertNotIn("evidence", field)
            self.assertNotIn("source", field)
        self.assertNotIn("evidence", contract["contract"]["context"])

        for field in ir.to_json()["frame"]["fields"]:
            self.assertIn("evidence", field)
            self.assertIn("source", field)

    def test_unresolved_fields_are_reported(self):
        facts = mine_protocol_facts(
            MergeContractTests.SOURCE, "parse_frame", filename="f.c"
        )
        ir = ProtocolIR.from_facts_and_conventions(facts, None)
        self.assertEqual(ir.unresolved_fields(), ())

    def test_variable_width_constant_is_exported(self):
        self.assertEqual(VARIABLE_WIDTH, "variable")
        self.assertEqual(SOURCE_UNKNOWN, "unknown")
        self.assertEqual(DEFAULT_LLM_CONFIDENCE, 0.6)


if __name__ == "__main__":
    unittest.main()
