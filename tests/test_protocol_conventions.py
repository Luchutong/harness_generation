import json
import unittest

from harness_generation.llm import MockLLM
from harness_generation.protocol_conventions import (
    PROTOCOL_CONVENTION_SCHEMA_VERSION,
    ProtocolConventionError,
    infer_protocol_conventions,
    parse_convention_response,
)
from harness_generation.protocol_miner import mine_protocol_facts


SOURCE = b"""
#define HEADER 8
#define MAX_BODY 64

enum op { OP_READ = 1, OP_STORE = 2, OP_USE = 3, OP_RELEASE = 4 };

typedef struct {
    unsigned char *saved;
    unsigned saved_len;
} parser_ctx;

void parser_init(parser_ctx *ctx);
void parser_destroy(parser_ctx *ctx);
unsigned short read_u16le(const unsigned char *p);
unsigned short checksum(const unsigned char *payload, unsigned short len);

int parse_frame(parser_ctx *ctx, const unsigned char *data, unsigned long size) {
    if (size < HEADER) return -1;
    unsigned short len = read_u16le(data + 4);
    if (len > MAX_BODY || len != size - HEADER) return -2;
    if (checksum(data + HEADER, len) != read_u16le(data + 6)) return -3;
    switch (data[3]) {
        case OP_READ: return 0;
        case OP_STORE: ctx->saved = (unsigned char *)(data + HEADER); ctx->saved_len = len; return 1;
        case OP_USE: return ctx->saved != 0;
        case OP_RELEASE: ctx->saved = 0; ctx->saved_len = 0; return 2;
    }
    return 0;
}
"""


def _sample(max_steps=32, include_release=False):
    operations = [
        {
            "opcode": "OP_STORE",
            "reason": "stores payload pointer and length in parser_ctx",
            "evidence": ["case OP_STORE writes ctx->saved and ctx->saved_len"],
        },
        {
            "opcode": "OP_USE",
            "reason": "reads previously stored parser_ctx state",
            "evidence": ["case OP_USE reads ctx->saved"],
        },
    ]
    if include_release:
        operations.append({
            "opcode": "OP_RELEASE",
            "reason": "clears saved parser state",
            "evidence": ["case OP_RELEASE clears ctx->saved and ctx->saved_len"],
        })
    return json.dumps({
        "schema_version": 1,
        "sequence_model": {
            "multi_frame": True,
            "reason": "stateful opcodes need multiple frames sharing one context",
            "evidence": ["OP_STORE saves state and OP_USE reads it"],
            "max_steps": {
                "value": max_steps,
                "source": "engineering_choice",
                "evidence": ["bounded loop cap is a harness policy"],
            },
        },
        "context": {
            "type": "parser_ctx",
            "init": "parser_init",
            "destroy": "parser_destroy",
            "lifetime": "one per fuzz iteration",
            "evidence": [
                "parser_init/parser_destroy are available lifecycle helpers",
            ],
        },
        "stateful_operations": operations,
        "requirements": [
            "repair magic/length/checksum envelope fields before parse_frame",
            "preserve payload bytes as fuzzer-controlled data",
        ],
        "notes": [
            "keep one parser_ctx alive across generated frames",
        ],
    })


class ProtocolConventionTests(unittest.TestCase):
    def test_parse_rejects_non_json_and_missing_evidence(self):
        with self.assertRaisesRegex(ProtocolConventionError, "valid JSON"):
            parse_convention_response("not json")
        invalid = json.loads(_sample())
        invalid["stateful_operations"][0]["evidence"] = []
        with self.assertRaisesRegex(ProtocolConventionError, "evidence is required"):
            parse_convention_response(json.dumps(invalid))

    def test_llm_samples_are_voted_with_evidence(self):
        facts = mine_protocol_facts(SOURCE, "parse_frame", filename="proto.c")
        llm = MockLLM([
            _sample(32),
            "this is not json",
            _sample(32, include_release=True),
            _sample(16),
        ])
        result = infer_protocol_conventions(
            facts,
            SOURCE.decode("utf-8"),
            llm,
            samples=4,
        )
        document = result.conventions.to_json()

        self.assertEqual(document["schema_version"], PROTOCOL_CONVENTION_SCHEMA_VERSION)
        self.assertEqual(document["entry_function"], "parse_frame")
        self.assertEqual(document["sequence_model"]["multi_frame"], True)
        self.assertEqual(document["sequence_model"]["max_steps"]["value"], 32)
        self.assertEqual(
            document["sequence_model"]["max_steps"]["source"],
            "engineering_choice",
        )
        self.assertEqual(document["context"]["type"], "parser_ctx")
        self.assertEqual(document["context"]["init"], "parser_init")
        self.assertEqual(document["context"]["destroy"], "parser_destroy")
        self.assertEqual(
            [item["opcode"] for item in document["stateful_operations"]],
            ["OP_STORE", "OP_USE"],
        )
        self.assertTrue(document["stateful_operations"][0]["evidence"])
        self.assertIn(
            "repair magic/length/checksum envelope fields before parse_frame",
            document["requirements"],
        )
        self.assertEqual(document["metadata"]["valid_samples"], 3)
        self.assertEqual(len(document["metadata"]["rejected_samples"]), 1)
        self.assertEqual(len(llm.calls), 4)
        self.assertEqual(
            {call["prompt_name"] for call in llm.calls},
            {"protocol_convention_refinement"},
        )
        self.assertIn("command_loop", llm.calls[0]["prompt"])
        self.assertIn("Static protocol facts", llm.calls[0]["prompt"])

    def test_all_invalid_samples_raise(self):
        facts = mine_protocol_facts(SOURCE, "parse_frame", filename="proto.c")
        llm = MockLLM(["nope", "{\"schema_version\": 1}"])
        with self.assertRaisesRegex(ProtocolConventionError, "no valid"):
            infer_protocol_conventions(
                facts,
                SOURCE.decode("utf-8"),
                llm,
                samples=2,
            )


if __name__ == "__main__":
    unittest.main()
