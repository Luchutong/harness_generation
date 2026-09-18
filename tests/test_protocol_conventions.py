import json
import unittest

from harness_generation.llm import LLMError, MockLLM
from harness_generation.protocol_conventions import (
    PROTOCOL_CONVENTION_SCHEMA_VERSION,
    ProtocolConventionError,
    _clean_string,
    _identity,
    _majority_from,
    _majority_mode,
    _majority_or_mode_from,
    _majority_or_mode_string,
    _mode,
    _mode_from,
    _mode_string,
    _tally,
    _voted_strings,
    _voted_strings_from,
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


def _variant(**overrides):
    """One sample, byte-identical to ``_sample()`` apart from the named fields.

    Contesting a value means changing *only* that value, so a test that says
    "one field disagreed" is measuring the field it named and nothing else.
    """

    document = json.loads(_sample())
    for name, value in overrides.items():
        if name == "multi_frame":
            document["sequence_model"]["multi_frame"] = value
        elif name == "max_steps_value":
            document["sequence_model"]["max_steps"]["value"] = value
        elif name == "max_steps_source":
            document["sequence_model"]["max_steps"]["source"] = value
        else:
            document["context"][name] = value
    return json.dumps(document)


VOTED_FIELDS = (
    "context.destroy",
    "context.init",
    "context.lifetime",
    "context.type",
    "sequence_model.max_steps.source",
    "sequence_model.max_steps.value",
    "sequence_model.multi_frame",
    "stateful_operations",
)


class VoteSummaryTests(unittest.TestCase):
    """The vote summary has to describe the vote that actually happened.

    ``_vote_conventions`` used to reduce each field to one value and drop the
    counter, so a run where three samples agreed and a run where three samples
    contradicted each other produced the same persisted result.  These tests pin
    the two properties that fix makes: the recorded tally is the one the value
    was selected from, and a field nobody answered is not counted as agreement.
    """

    def _infer(self, responses):
        facts = mine_protocol_facts(SOURCE, "parse_frame", filename="proto.c")
        return infer_protocol_conventions(
            facts, SOURCE.decode("utf-8"), MockLLM(responses), samples=len(responses)
        )

    def _summary(self, responses):
        return self._infer(responses).conventions.metadata["vote_summary"]

    def _fields(self, responses):
        return self._summary(responses)["fields"]

    # -- one implementation of each rule -----------------------------------

    def test_the_wrappers_and_the_counter_rules_agree(self):
        """Each old entry point is a wrapper, so it must agree with its rule.

        The tally is taken here with the normaliser each wrapper documents --
        identity for the boolean and integer fields, ``_clean_string`` for the
        stripped strings, whitespace normalising for the voted-string lists --
        because the pairing is the part that could drift: a wrapper that counted
        whitespace-normalised text while its rule was documented against stripped
        text would select from one counter and report another.
        """

        cases = [
            [],
            [""],
            ["   "],
            ["only"],
            [None, None],
            [True, False, True],
            [1, 2, 3],
            ["a", "b", "a"],
            ["a", "a", "b", "b"],  # a tie, broken by the candidate's string form
            ["b", "b", "a", "a"],  # the same tie, in the other order
            ["", "a", "  a  ", "a", "b"],
            [["x", "y"], ["x"], ["x", "x", "y"], [], "x"],
        ]
        for values in cases:
            with self.subTest(values=values):
                identity_counter, _ = _tally(values, normalize=_identity)
                self.assertEqual(
                    _mode(values, default=None), _mode_from(identity_counter, default=None)
                )
                self.assertEqual(
                    _majority_mode(values, 2), _majority_from(identity_counter, 2)
                )

                text_counter, _ = _tally(values, normalize=_clean_string)
                self.assertEqual(
                    _majority_or_mode_string(values, 2),
                    _majority_or_mode_from(text_counter, 2),
                )
                self.assertEqual(_mode_string(values), _mode_from(text_counter, default=""))

                word_counter, _ = _tally(values)
                self.assertEqual(
                    _voted_strings(values, 2), _voted_strings_from(word_counter, 2)
                )

    def test_an_empty_field_returns_the_default_rather_than_a_candidate(self):
        self.assertEqual(_mode([], default="fallback"), "fallback")
        self.assertIsNone(_majority_mode([], 2))
        self.assertIsNone(_majority_from(_tally([], normalize=_identity)[0], 2))
        self.assertEqual(_mode_string(["", "  "]), "")
        self.assertEqual(_majority_or_mode_string([], 2), "")
        self.assertEqual(_voted_strings([], 2), ())

    def test_the_tally_counts_samples_and_not_offers(self):
        """``valid_samples`` counts samples that answered, not values offered.

        A sample that names the same opcode twice, or repeats a requirement, is
        still one sample: counting its offers would let a duplicated line push a
        candidate over the vote threshold on its own.
        """

        counter, valid = _tally([["x", "x", "x"], [], "x", None], normalize=_identity)
        self.assertEqual(counter, {"x": 2})
        self.assertEqual(valid, 2)

    # -- the recorded value is the selected value --------------------------

    def test_the_summary_records_the_values_the_vote_selected(self):
        """Field by field, `selected` is what the built block actually carries.

        This is what makes the tally and the selection the same pass: if either
        were computed twice, this is where the two would part company.
        """

        conventions = self._infer([
            _variant(lifetime="process lifetime", init="other_init"),
            _sample(),
            _variant(max_steps_value=16),
        ]).conventions
        fields = conventions.metadata["vote_summary"]["fields"]

        self.assertEqual(sorted(fields), list(VOTED_FIELDS))
        self.assertEqual(
            fields["sequence_model.multi_frame"]["selected"],
            conventions.sequence_model.multi_frame,
        )
        self.assertEqual(
            fields["sequence_model.max_steps.value"]["selected"],
            conventions.sequence_model.max_steps["value"],
        )
        self.assertEqual(
            fields["sequence_model.max_steps.source"]["selected"],
            conventions.sequence_model.max_steps["source"],
        )
        for name in ("type", "init", "destroy", "lifetime"):
            with self.subTest(field=name):
                self.assertEqual(
                    fields[f"context.{name}"]["selected"],
                    getattr(conventions.context, name),
                )
        self.assertEqual(
            fields["stateful_operations"]["selected"],
            [item.opcode for item in conventions.stateful_operations],
        )

    def test_a_contested_field_carries_its_alternatives(self):
        fields = self._fields([
            _variant(lifetime="one per fuzz iteration"),
            _variant(lifetime="process lifetime"),
            _variant(lifetime="unknown"),
        ])
        entry = fields["context.lifetime"]

        self.assertEqual(entry["selected"], "one per fuzz iteration")
        self.assertEqual(entry["votes"], 1)
        self.assertEqual(entry["valid_samples"], 3)
        self.assertEqual(entry["agreement"], 0.3333)
        # The three losing answers are the whole point: they are how a reader
        # sees *why* the agreement is low without re-running the vote.
        self.assertEqual(
            entry["alternatives"],
            {"one per fuzz iteration": 1, "process lifetime": 1, "unknown": 1},
        )

    def test_an_unanimous_field_carries_no_alternatives(self):
        """A single candidate would make the map say nothing new."""

        fields = self._fields([_sample(), _sample(), _sample()])

        self.assertEqual(fields["context.lifetime"]["agreement"], 1.0)
        self.assertNotIn("alternatives", fields["context.lifetime"])
        self.assertNotIn("alternatives", fields["sequence_model.multi_frame"])

    def test_a_value_the_vote_could_not_settle_is_recorded_as_null(self):
        """Three different bounds: candidates exist, none reaches the threshold.

        ``null`` is the real answer here, and it must not be silently dropped --
        nor scored as if the samples had agreed on it.
        """

        fields = self._fields([
            _variant(max_steps_value=32),
            _variant(max_steps_value=64),
            _variant(max_steps_value=128),
        ])
        entry = fields["sequence_model.max_steps.value"]

        self.assertIsNone(entry["selected"])
        self.assertEqual(entry["votes"], 0)
        self.assertEqual(entry["valid_samples"], 3)
        self.assertEqual(entry["agreement"], 0.0)
        self.assertEqual(entry["alternatives"], {"32": 1, "64": 1, "128": 1})

    def test_a_field_no_sample_answered_is_left_out_of_the_summary(self):
        """An unasked field must not score as a unanimous one.

        Every sample returned ``max_steps.value: null``, so no candidate was
        offered for it.  Recording it with ``agreement: 1.0`` would let a field
        nobody answered raise the confidence.
        """

        summary = self._summary([_sample(max_steps=None) for _ in range(3)])

        self.assertNotIn("sequence_model.max_steps.value", summary["fields"])
        self.assertNotIn(
            "sequence_model.max_steps.value", summary["confidence"]["fields_counted"]
        )
        self.assertEqual(len(summary["confidence"]["fields_counted"]), 7)
        self.assertEqual(summary["confidence"]["mean_field_agreement"], 1.0)

    def test_the_bool_field_names_its_alternatives_the_way_json_does(self):
        """``str(True)`` is ``"True"``; a JSON key for it is ``"true"``."""

        fields = self._fields([_variant(multi_frame=True)] * 2 + [_variant(multi_frame=False)])

        self.assertIs(fields["sequence_model.multi_frame"]["selected"], True)
        self.assertEqual(
            fields["sequence_model.multi_frame"]["alternatives"],
            {"true": 2, "false": 1},
        )

    def test_the_set_field_has_alternatives_and_no_votes(self):
        """The two shapes, side by side, so the missing key is not a surprise.

        ``votes`` is ill-defined once the selection is a union, and any single
        number chosen for it would not satisfy ``votes / valid_samples ==
        agreement``.  ``alternatives`` is always present for the set field --
        here it holds the opcode only one sample voted for, which the threshold
        rejected.
        """

        fields = self._fields([
            _variant(),
            _variant(),
            json.dumps({
                **json.loads(_variant()),
                "stateful_operations": json.loads(_variant())["stateful_operations"] + [{
                    "opcode": "OP_LATE",
                    "reason": "added by one sample only",
                    "evidence": ["case OP_LATE"],
                }],
            }),
        ])
        entry = fields["stateful_operations"]

        self.assertEqual(entry["selected"], ["OP_STORE", "OP_USE"])
        self.assertNotIn("votes", entry)
        self.assertEqual(entry["valid_samples"], 3)
        # (3 + 3 + 1) / (3 samples x 3 opcodes in the union) = 0.7778
        self.assertEqual(entry["agreement"], 0.7778)
        self.assertEqual(
            entry["alternatives"], {"OP_STORE": 3, "OP_USE": 3, "OP_LATE": 1}
        )

    def test_the_confidence_block_shows_how_the_value_was_reached(self):
        """Every number in the product is in the document, so it can be checked."""

        summary = self._summary([
            _variant(lifetime="process lifetime"),
            _sample(),
            _variant(max_steps_value=16),
        ])
        fields = summary["fields"]
        confidence = summary["confidence"]

        agreements = [entry["agreement"] for entry in fields.values()]
        self.assertEqual(confidence["sample_validity"], 1.0)
        self.assertEqual(
            confidence["mean_field_agreement"],
            round(sum(agreements) / len(agreements), 4),
        )
        self.assertEqual(confidence["fields_counted"], sorted(fields))
        self.assertEqual(
            confidence["value"],
            round(
                confidence["sample_validity"] * confidence["mean_field_agreement"], 4
            ),
        )

    def test_rejected_samples_lower_the_validity_not_the_agreement(self):
        """A sample that never parsed voted on nothing, so it cannot disagree.

        The two halves of the product measure different failures: an unparseable
        sample lowers ``sample_validity``, a parseable sample that contradicts
        the others lowers ``mean_field_agreement``.
        """

        summary = self._summary([_sample(), _sample(), "not json at all"])
        confidence = summary["confidence"]

        self.assertEqual(confidence["sample_validity"], 0.6667)
        self.assertEqual(confidence["mean_field_agreement"], 1.0)
        self.assertEqual(confidence["value"], 0.6667)
        # The sample that failed is still visible, and it did not vote.
        self.assertEqual(self._fields([_sample(), _sample(), "not json at all"])
                         ["context.lifetime"]["valid_samples"], 2)


class _FailingLLM:
    """A client that records its calls and then fails every one of them.

    ``MockLLM`` answers from a queue, so it can only fail the way its own
    bookkeeping fails (an exhausted sequence).  A provider failure and a
    timeout both arrive as ``LLMError`` with a message the transport wrote, and
    that message is part of what these tests check survives, so it is supplied
    here instead of borrowed.
    """

    def __init__(self, error: Exception, *, model: str = "failing-model") -> None:
        self._error = error
        self.model = model
        self.provider = "failing"
        self.calls: list[dict[str, str]] = []

    def generate(self, prompt, *, prompt_version=None):
        self.calls.append({"prompt": str(prompt)})
        raise self._error


class FailFastTests(unittest.TestCase):
    """``fail_fast_on_llm_error`` stops on a failed sample, not on a vote.

    The two properties that have to hold at once are easy to confuse: a sample
    that could not be used at all ends the run early when the flag is set, while
    samples that are perfectly valid and merely disagree must still reach the
    vote with the flag set.  Failing one of those for the other would turn a
    decision about time into a decision about evidence.
    """

    def _facts(self):
        return mine_protocol_facts(SOURCE, "parse_frame", filename="proto.c")

    def _infer(self, llm, *, samples, fail_fast):
        return infer_protocol_conventions(
            self._facts(),
            SOURCE.decode("utf-8"),
            llm,
            samples=samples,
            fail_fast_on_llm_error=fail_fast,
        )

    def test_a_failed_sample_is_voted_around_by_default(self):
        llm = MockLLM(["not json at all", _sample(), _sample()])

        result = self._infer(llm, samples=3, fail_fast=False)

        self.assertEqual(len(llm.calls), 3)
        self.assertEqual(result.conventions.metadata["valid_samples"], 2)
        self.assertEqual(len(result.rejected_samples), 1)

    def test_fail_fast_stops_at_the_first_failed_sample(self):
        llm = MockLLM(["not json at all", _sample(), _sample()])

        with self.assertRaisesRegex(
            ProtocolConventionError, "sample 1 of 3 failed"
        ) as caught:
            self._infer(llm, samples=3, fail_fast=True)

        # The remaining samples were never requested: the point of the flag is
        # not to rewrite the outcome but to stop paying for the rest of it.
        self.assertEqual(len(llm.calls), 1)
        # The reason is still the reason, in the original words.
        self.assertIn("not valid JSON", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__, ProtocolConventionError)

    def test_fail_fast_keeps_the_type_of_a_provider_failure(self):
        # A timeout is reported as an LLMError by the transport, and it stays
        # one here: a caller that catches LLMError to mean "the provider is
        # unusable" must not have to also catch a schema error to find that out.
        llm = _FailingLLM(
            LLMError("OpenAI-compatible request timed out after 10s")
        )

        with self.assertRaisesRegex(LLMError, "sample 1 of 2 failed") as caught:
            self._infer(llm, samples=2, fail_fast=True)

        self.assertIn("timed out after 10s", str(caught.exception))
        self.assertEqual(len(llm.calls), 1)

    def test_valid_samples_that_disagree_still_reach_the_vote(self):
        llm = MockLLM([_sample(32), _variant(max_steps_value=16), _sample(16)])

        result = self._infer(llm, samples=3, fail_fast=True)

        # Every sample was used, none was rejected, and the disagreement shows
        # up where it belongs: in the vote summary.
        self.assertEqual(len(llm.calls), 3)
        self.assertEqual(result.conventions.metadata["valid_samples"], 3)
        self.assertEqual(result.rejected_samples, ())
        fields = result.conventions.metadata["vote_summary"]["fields"]
        self.assertIn("sequence_model.max_steps.value", fields)

    def test_fail_fast_does_not_change_the_default_path(self):
        # The kwarg is additive, so a caller that never mentions it gets the
        # tolerant loop it always got -- including the all-samples-failed error.
        facts = self._facts()
        llm = MockLLM(["nope", "nope"])

        with self.assertRaisesRegex(ProtocolConventionError, "no valid"):
            infer_protocol_conventions(
                facts, SOURCE.decode("utf-8"), llm, samples=2
            )

        self.assertEqual(len(llm.calls), 2)


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
