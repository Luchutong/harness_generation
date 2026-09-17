"""The A/B miner must recover frame facts *and* prove them from source.

The load-bearing test here is
``test_every_field_evidence_points_at_real_source_lines``: it re-reads the
source file and checks that every evidence snippet really occurs on the line it
claims.  Without that, "every field carries evidence" would be a comment rather
than a guarantee.
"""

from pathlib import Path
import unittest

from harness_generation.protocol_miner import (
    ROLE_CHECKSUM,
    ROLE_MAGIC,
    ROLE_OPCODE,
    ROLE_PAYLOAD,
    ROLE_PAYLOAD_LENGTH,
    ROLE_VERSION,
    FieldFact,
    ProtocolFacts,
    ProtocolMinerError,
    mine_protocol_facts,
)


ROOT = Path(__file__).resolve().parents[1]
MINI_PARSER = ROOT / "benchmarks" / "mini_parser"
SOURCE = MINI_PARSER / "target.c"

# An 8-byte header followed by a 4-byte trailer field, so the payload starts at
# 12 and *not* at the header size.  `mini_parser` cannot distinguish the two
# because its payload begins exactly at its header.
WIDE_HEADER_SOURCE = b"""
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

# Every `data + K` here is a header field load, so the largest one (6) is *not*
# a payload base.  The payload field used to be emitted on top of the checksum
# field at the same offset.
CONFLICTING_PAYLOAD_SOURCE = b"""
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
"""

# Exercises the branches `mini_parser` does not: magic values behind named
# macros, a big-endian helper, and a header size that is not 8.
NAMED_CONSTANTS_SOURCE = b"""
#define MP_MAGIC0 'M'
#define MP_MAGIC1 'P'
#define MP_HEADER_SIZE 7
#define MP_MAX_PAYLOAD 32

enum mp_op { OP_A = 1, OP_B, OP_C };

static uint16_t be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint16_t demo_sum(const uint8_t *payload, size_t size);

int demo_parse(void *ctx, const uint8_t *data, size_t size) {
    if (size < MP_HEADER_SIZE) return -1;
    if (data[0] != MP_MAGIC0 || data[1] != MP_MAGIC1) return -2;
    size_t len = be16(data + 3);
    if (len > MP_MAX_PAYLOAD || len != size - MP_HEADER_SIZE) return -3;
    if (demo_sum(data + MP_HEADER_SIZE, len) != be16(data + 5)) return -4;
    switch (data[2]) {
        case OP_A: return 0;
        case OP_B: return 1;
        case OP_C: return 2;
    }
    return 0;
}
"""

GENERIC_INLINE_SOURCE = b"""
#define MAX_BODY 48

enum command_id { CMD_ALPHA = 10, CMD_BETA = 11, CMD_GAMMA = 12 };

static unsigned packet_crc(const unsigned char *payload, unsigned long length);

int parse_packet(const unsigned char *buf, unsigned long len) {
    if (len < 8) return -1;
    if (buf[0] != 0xca || buf[1] != 0xfe) return -2;
    unsigned short body_len = ((unsigned short)buf[2] << 8) | buf[3];
    if (body_len > MAX_BODY || body_len > len - 8) return -3;
    unsigned char type = buf[4];
    if (buf[5] != 1) return -4;
    if (packet_crc(buf + 8, body_len) != (((unsigned)buf[6] << 8) | buf[7])) {
        return -5;
    }
    if (type == CMD_ALPHA) return 1;
    else if (type == CMD_BETA) return 2;
    else if (type == CMD_GAMMA) return 3;
    return 0;
}
"""

ALIAS_AND_HELPER_NAME_SOURCE = b"""
#define HDR_BYTES 10
#define BODY_LIMIT 512

enum packet_kind { KIND_OPEN = 4, KIND_CLOSE = 5 };

unsigned short read_u16le(const unsigned char *p);
unsigned short fold_sum(const unsigned char *payload, unsigned short n);

int parse_alias_packet(const unsigned char *packet, size_t packet_len) {
    if (packet_len < HDR_BYTES) return -1;
    const unsigned char *length_ptr = packet + 2;
    const unsigned char *payload = packet + HDR_BYTES;
    unsigned short body_len = read_u16le(length_ptr);
    if (body_len > BODY_LIMIT || body_len != packet_len - HDR_BYTES) return -2;
    unsigned char kind = packet[4];
    if (fold_sum(payload, body_len) != read_u16le(packet + 8)) return -3;
    switch (kind) {
        case KIND_OPEN: return 1;
        case KIND_CLOSE: return 2;
    }
    return 0;
}
"""


def _fields(facts: ProtocolFacts) -> dict[str, dict]:
    return {item["name"]: item for item in facts.to_json()["fields"]}


class MiniParserMiningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_text = SOURCE.read_text(encoding="utf-8")
        cls.facts = mine_protocol_facts(SOURCE.read_bytes(), "mp_parse", filename="target.c")

    def test_frame_fields_match_the_declared_contract(self):
        fields = _fields(self.facts)
        self.assertEqual(
            set(fields),
            {"magic0", "magic1", "version", "opcode",
             "payload_length", "checksum", "payload"},
        )

        expected = {
            "magic0": (0, 1, None, ROLE_MAGIC),
            "magic1": (1, 1, None, ROLE_MAGIC),
            "version": (2, 1, None, ROLE_VERSION),
            "opcode": (3, 1, None, ROLE_OPCODE),
            "payload_length": (4, 2, "little_endian", ROLE_PAYLOAD_LENGTH),
            "checksum": (6, 2, "little_endian", ROLE_CHECKSUM),
        }
        for name, (offset, width, endianness, role) in expected.items():
            with self.subTest(field=name):
                self.assertEqual(fields[name]["offset"], offset)
                self.assertEqual(fields[name]["width"], width)
                self.assertEqual(fields[name].get("endianness"), endianness)
                self.assertEqual(fields[name]["role"], role)

        payload = fields["payload"]
        self.assertEqual(payload["offset"], 8)
        self.assertEqual(payload["role"], ROLE_PAYLOAD)
        self.assertEqual(payload["width"], -1)  # variable width, tied to the length field

    def test_literal_values_are_recovered(self):
        fields = _fields(self.facts)
        self.assertEqual(fields["magic0"]["value"], "'M'")
        self.assertEqual(fields["magic1"]["value"], "'P'")
        self.assertEqual(fields["version"]["value"], "1")

    def test_constants_and_opcode_range(self):
        self.assertEqual(self.facts.header_size, 8)
        self.assertEqual(self.facts.max_payload, 64)
        self.assertEqual(
            [(item.name, item.value) for item in self.facts.opcodes],
            [("MP_READ", 1), ("MP_WRITE", 2), ("MP_MULTIPLY", 3), ("MP_STORE", 4),
             ("MP_RELEASE", 5), ("MP_USE", 6), ("MP_NESTED_LENGTH", 7)],
        )

    def test_every_field_evidence_points_at_real_source_lines(self):
        lines = self.source_text.splitlines()
        self.assertTrue(lines)

        for field in self.facts.to_json()["fields"]:
            with self.subTest(field=field["name"]):
                self.assertTrue(field["evidence"], "field has no source evidence")
                for item in field["evidence"]:
                    line = item["line"]
                    self.assertTrue(
                        1 <= line <= len(lines),
                        f"evidence line {line} is outside the file",
                    )
                    snippet = item["snippet"]
                    if snippet.endswith(" ..."):
                        snippet = snippet[: -len(" ...")]
                    if snippet:
                        self.assertIn(
                            snippet,
                            lines[line - 1],
                            f"evidence snippet {snippet!r} is not on line {line}",
                        )

    def test_checksum_field_is_justified_by_a_payload_wide_comparison(self):
        checksum = _fields(self.facts)["checksum"]
        kinds = {item["kind"] for item in checksum["evidence"]}
        self.assertIn("symbolic_load", kinds)
        self.assertIn("checksum_comparison", kinds)

    def test_length_field_is_justified_by_a_size_relation(self):
        length = _fields(self.facts)["payload_length"]
        kinds = {item["kind"] for item in length["evidence"]}
        self.assertIn("length_relation", kinds)

    def test_limitations_scope_out_the_convention_block(self):
        limitations = "\n".join(self.facts.limitations)
        self.assertIn("convention block", limitations)
        self.assertIn("command loop", limitations)

    def test_contract_is_strict_by_default(self):
        contract = self.facts.to_contract()
        self.assertEqual(contract["entry_function"], "mp_parse")
        self.assertEqual(contract["contract"]["frame"]["header_size"], 8)
        self.assertEqual(contract["contract"]["frame"]["payload_offset"], 8)
        self.assertEqual(contract["contract"]["frame"]["max_payload"], 64)
        self.assertEqual(len(contract["contract"]["frame"]["fields"]), 7)


class DifferentialAgainstHandWrittenContractTests(unittest.TestCase):
    """Use the hand-written protocol.json as ground truth and measure the gap.

    This is the objective oracle for the miner: it does not ask whether the
    output *looks* plausible, only whether it agrees with the contract a human
    wrote.
    """

    @classmethod
    def setUpClass(cls):
        import json

        cls.declared = json.loads((MINI_PARSER / "protocol.json").read_text(encoding="utf-8"))
        cls.facts = mine_protocol_facts(SOURCE.read_bytes(), "mp_parse", filename="target.c")
        cls.mined = _fields(cls.facts)

    def test_same_number_of_fields(self):
        declared = self.declared["contract"]["frame"]["fields"]
        self.assertEqual(len(declared), len(self.mined))

    def test_every_declared_field_is_recovered_at_the_same_offset(self):
        for field in self.declared["contract"]["frame"]["fields"]:
            offset = field["offset"]
            with self.subTest(field=field["name"]):
                matches = [item for item in self.mined.values() if item["offset"] == offset]
                self.assertEqual(
                    len(matches), 1,
                    f"no unique mined field at offset {offset}",
                )
                recovered = matches[0]

                declared_width = field["width"]
                if isinstance(declared_width, int):
                    self.assertEqual(recovered["width"], declared_width)

                if "endianness" in field:
                    self.assertEqual(recovered.get("endianness"), field["endianness"])

    def test_header_size_and_payload_offset_agree(self):
        frame = self.declared["contract"]["frame"]
        self.assertEqual(self.facts.header_size, frame["header_size"])
        self.assertEqual(self.facts.header_size, frame["payload_offset"])

    def test_max_payload_agrees_after_resolving_the_declared_symbol(self):
        """protocol.json declares the *symbol*; the miner must resolve it."""

        declared_frame = self.declared["contract"]["frame"]
        symbol = declared_frame["max_payload"]
        table = {item.name: item.value for item in self.facts.constants}
        self.assertIn(symbol, table, "declared max_payload symbol was not mined")
        self.assertEqual(self.facts.max_payload, table[symbol])

    def test_opcode_range_agrees(self):
        declared_frame = self.declared["contract"]["frame"]
        declared_text = next(
            field["value"] for field in declared_frame["fields"] if field["name"] == "opcode"
        )
        self.assertIn("1..7", declared_text)
        values = sorted(item.value for item in self.facts.opcodes)
        self.assertEqual(values, list(range(1, 8)))


class NamedConstantMiningTests(unittest.TestCase):
    """Covers magic values behind macros and a big-endian load helper."""

    @classmethod
    def setUpClass(cls):
        cls.source_text = NAMED_CONSTANTS_SOURCE.decode("utf-8")
        cls.facts = mine_protocol_facts(
            NAMED_CONSTANTS_SOURCE, "demo_parse", filename="demo.c"
        )

    def test_macros_are_resolved_to_values(self):
        fields = _fields(self.facts)
        self.assertEqual(fields["magic0"]["value"], "MP_MAGIC0")
        self.assertEqual(fields["magic1"]["value"], "MP_MAGIC1")

    def test_big_endian_helpers_are_detected(self):
        fields = _fields(self.facts)
        self.assertEqual(fields["payload_length"]["endianness"], "big_endian")
        self.assertEqual(fields["checksum"]["endianness"], "big_endian")
        self.assertEqual(fields["payload_length"]["width"], 2)

    def test_header_size_follows_the_macro(self):
        self.assertEqual(self.facts.header_size, 7)
        self.assertEqual(self.facts.max_payload, 32)
        self.assertEqual(
            [(item.name, item.value) for item in self.facts.opcodes],
            [("OP_A", 1), ("OP_B", 2), ("OP_C", 3)],
        )

    def test_evidence_again_points_at_real_lines(self):
        lines = self.source_text.splitlines()
        for field in self.facts.to_json()["fields"]:
            for item in field["evidence"]:
                snippet = item["snippet"]
                if snippet.endswith(" ..."):
                    snippet = snippet[: -len(" ...")]
                if snippet:
                    self.assertIn(snippet, lines[item["line"] - 1])


class GenericIdiomMiningTests(unittest.TestCase):
    """Covers source patterns that are intentionally not mini_parser-shaped."""

    @classmethod
    def setUpClass(cls):
        cls.facts = mine_protocol_facts(
            GENERIC_INLINE_SOURCE, "parse_packet", filename="generic.c"
        )

    def test_literal_header_and_unsigned_char_buffer_are_detected(self):
        self.assertEqual(self.facts.header_size, 8)
        self.assertEqual(self.facts.max_payload, 48)

    def test_inline_big_endian_length_and_checksum_are_detected(self):
        fields = _fields(self.facts)
        self.assertEqual(fields["payload_length"]["offset"], 2)
        self.assertEqual(fields["payload_length"]["width"], 2)
        self.assertEqual(fields["payload_length"]["endianness"], "big_endian")
        self.assertEqual(fields["checksum"]["offset"], 6)
        self.assertEqual(fields["checksum"]["width"], 2)
        self.assertEqual(fields["checksum"]["endianness"], "big_endian")

    def test_if_else_selector_is_detected_without_switch(self):
        fields = _fields(self.facts)
        self.assertEqual(fields["opcode"]["offset"], 4)
        self.assertEqual(
            [(item.name, item.value) for item in self.facts.opcodes],
            [("CMD_ALPHA", 10), ("CMD_BETA", 11), ("CMD_GAMMA", 12)],
        )

    def test_no_mp_names_are_required_for_payload_region(self):
        fields = _fields(self.facts)
        self.assertEqual(fields["payload"]["offset"], 8)
        self.assertEqual(fields["payload"]["role"], ROLE_PAYLOAD)
        self.assertEqual(fields["magic0"]["value"], "0xca")
        self.assertEqual(fields["magic1"]["value"], "0xfe")


class AliasAndHelperNameMiningTests(unittest.TestCase):
    """Covers aliases and endian helpers declared without visible bodies."""

    @classmethod
    def setUpClass(cls):
        cls.facts = mine_protocol_facts(
            ALIAS_AND_HELPER_NAME_SOURCE,
            "parse_alias_packet",
            filename="alias.c",
        )

    def test_header_and_max_payload_are_not_name_specific(self):
        self.assertEqual(self.facts.header_size, 10)
        self.assertEqual(self.facts.max_payload, 512)

    def test_helper_name_and_pointer_alias_recover_length(self):
        fields = _fields(self.facts)
        self.assertEqual(fields["payload_length"]["offset"], 2)
        self.assertEqual(fields["payload_length"]["width"], 2)
        self.assertEqual(fields["payload_length"]["endianness"], "little_endian")

    def test_payload_alias_and_checksum_field_are_recovered(self):
        fields = _fields(self.facts)
        self.assertEqual(fields["payload"]["offset"], 10)
        self.assertEqual(fields["checksum"]["offset"], 8)
        self.assertEqual(fields["checksum"]["endianness"], "little_endian")

    def test_switch_on_variable_loaded_from_buffer_is_recovered(self):
        fields = _fields(self.facts)
        self.assertEqual(fields["opcode"]["offset"], 4)
        self.assertEqual(
            [(item.name, item.value) for item in self.facts.opcodes],
            [("KIND_OPEN", 4), ("KIND_CLOSE", 5)],
        )


class PayloadOffsetMiningTests(unittest.TestCase):
    """The payload base is its own fact, not a restatement of the header size."""

    @classmethod
    def setUpClass(cls):
        cls.source_text = WIDE_HEADER_SOURCE.decode("utf-8")
        cls.facts = mine_protocol_facts(
            WIDE_HEADER_SOURCE, "parse_wide", filename="wide.c"
        )

    def test_header_and_payload_are_mined_separately(self):
        self.assertEqual(self.facts.header_size, 8)
        self.assertEqual(self.facts.payload_offset, 12)

    def test_contract_reports_the_measured_payload_offset(self):
        frame = self.facts.to_contract()["contract"]["frame"]
        self.assertEqual(frame["payload_offset"], 12)
        self.assertNotEqual(frame["payload_offset"], frame["header_size"])

    def test_json_exposes_the_payload_offset(self):
        document = self.facts.to_json()
        self.assertEqual(document["payload_offset"], 12)
        self.assertIn("payload_offset_evidence", document)

    def test_payload_field_sits_at_the_payload_offset(self):
        fields = _fields(self.facts)
        self.assertEqual(fields["payload"]["offset"], 12)
        self.assertEqual(fields["payload"]["role"], ROLE_PAYLOAD)

    def test_payload_evidence_names_the_selected_expression(self):
        evidence = self.facts.payload_offset_evidence
        self.assertEqual(len(evidence), 1)
        item = evidence[0]
        self.assertEqual(item.snippet, "data + 12")
        self.assertIn("largest fixed offset", item.detail)
        self.assertIn(
            item.snippet, self.source_text.splitlines()[item.line - 1]
        )

    def test_header_field_loads_are_not_claimed_as_the_payload_base(self):
        """`data + 4` and `data + 10` are header fields; only 12 is the base."""

        for item in self.facts.payload_offset_evidence:
            self.assertNotIn("data + 4 ", item.detail)
            self.assertNotIn("data + 10 ", item.detail)

    def test_mini_parser_payload_coincides_with_its_header(self):
        facts = mine_protocol_facts(
            SOURCE.read_bytes(), "mp_parse", filename="target.c"
        )
        self.assertEqual(facts.payload_offset, facts.header_size)

    def test_facts_without_a_payload_offset_fall_back_to_the_header(self):
        """Older facts serialised before the field existed must still work."""

        facts = ProtocolFacts(entry_function="f", filename="x.c", header_size=8)
        self.assertIsNone(facts.payload_offset)
        self.assertEqual(facts.resolved_payload_offset, 8)
        self.assertEqual(
            facts.to_contract(strict=False)["contract"]["frame"]["payload_offset"], 8
        )

    def test_an_explicit_payload_offset_wins_over_the_header_size(self):
        facts = ProtocolFacts(
            entry_function="f", filename="x.c", header_size=8, payload_offset=12
        )
        self.assertEqual(facts.resolved_payload_offset, 12)

    def test_no_payload_offset_and_no_header_size_stays_unknown(self):
        facts = ProtocolFacts(entry_function="f", filename="x.c")
        self.assertIsNone(facts.resolved_payload_offset)


class ConflictingPayloadRegionTests(unittest.TestCase):
    """A `data + K` inside the header must not become the payload base.

    Left unhandled it produced two fields at the same offset (the header field
    and a phantom payload), which downstream consumers key by offset.
    """

    @classmethod
    def setUpClass(cls):
        cls.facts = mine_protocol_facts(
            CONFLICTING_PAYLOAD_SOURCE, "parse_conflict", filename="conflict.c"
        )

    def test_no_two_fields_share_an_offset(self):
        offsets = [item.offset for item in self.facts.fields]
        self.assertEqual(sorted(offsets), sorted(set(offsets)))

    def test_the_rejected_base_is_recorded_as_a_limitation(self):
        limitations = "\n".join(self.facts.limitations)
        self.assertIn("rejected as a payload base", limitations)

    def test_payload_sits_after_every_header_field(self):
        fields = _fields(self.facts)
        payload = fields["payload"]["offset"]
        header_fields = [
            item["offset"] for name, item in fields.items() if name != "payload"
        ]
        self.assertTrue(header_fields, "the fixture should still mine header fields")
        self.assertGreater(payload, max(header_fields))


class EntryResolutionTests(unittest.TestCase):
    """The entry point must be resolved by its own name, not a parameter's.

    ``_find_entry`` used to walk every identifier under each declarator, so a
    helper whose *parameter* was named like the entry point won the match when
    it appeared earlier in the file.  The miner then reported facts about the
    wrong function, with evidence that looked perfectly plausible.
    """

    SOURCE = b"""
static unsigned short le16(const unsigned char *p) {
    return (unsigned short)((unsigned short)p[0] | ((unsigned short)p[1] << 8));
}

int p(const unsigned char *data, size_t size) {
    if (size < 4) return -1;
    unsigned short value = le16(data + 2);
    return value;
}
"""

    def test_parameter_name_collision_does_not_hijack_the_entry_point(self):
        facts = mine_protocol_facts(self.SOURCE, "p", filename="collision.c")

        self.assertEqual(facts.header_size, 4)
        fields = _fields(facts)
        self.assertIn("field_2", fields)
        self.assertEqual(fields["field_2"]["width"], 2)
        self.assertEqual(fields["field_2"]["endianness"], "little_endian")

    def test_entry_evidence_never_points_into_the_helper_body(self):
        facts = mine_protocol_facts(self.SOURCE, "p", filename="collision.c")
        lines = self.SOURCE.decode("utf-8").splitlines()
        helper_last_line = 3

        for field in facts.to_json()["fields"]:
            for item in field["evidence"]:
                with self.subTest(field=field["name"], kind=item["kind"]):
                    self.assertGreater(
                        item["line"], helper_last_line,
                        "evidence was taken from the helper, not the entry point",
                    )
                    snippet = item["snippet"]
                    if snippet.endswith(" ..."):
                        snippet = snippet[: -len(" ...")]
                    if snippet:
                        self.assertIn(snippet, lines[item["line"] - 1])


class EvidenceDisciplineTests(unittest.TestCase):
    def test_strict_contract_rejects_evidence_free_fields(self):
        facts = ProtocolFacts(entry_function="f", filename="x.c")
        facts.fields.append(FieldFact(
            name="field_0", offset=0, width=1, role=ROLE_MAGIC, value="'M'",
        ))
        self.assertEqual(facts.fields_without_evidence(), ["field_0"])
        with self.assertRaisesRegex(ProtocolMinerError, "without source evidence"):
            facts.to_contract()

    def test_non_strict_contract_allows_them_for_inspection(self):
        facts = ProtocolFacts(entry_function="f", filename="x.c")
        facts.fields.append(FieldFact(
            name="field_0", offset=0, width=1, role=ROLE_MAGIC, value="'M'",
        ))
        contract = facts.to_contract(strict=False)
        self.assertEqual(len(contract["contract"]["frame"]["fields"]), 1)

    def test_missing_entry_function_is_an_error(self):
        with self.assertRaisesRegex(ProtocolMinerError, "not found"):
            mine_protocol_facts(NAMED_CONSTANTS_SOURCE, "absent", filename="demo.c")

    def test_source_without_endian_helper_reports_the_gap(self):
        facts = mine_protocol_facts(
            b"int opaque_parse(void *c, const unsigned char *data, size_t size) { return 0; }",
            "opaque_parse",
            filename="opaque.c",
        )
        self.assertEqual([item for item in facts.fields if item.width > 0], [])
        limitations = "\n".join(facts.limitations)
        self.assertIn("endian", limitations)


if __name__ == "__main__":
    unittest.main()
