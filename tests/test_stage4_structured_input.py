"""The structured-input execution model, replayed against a real recorded run.

A real DeepSeek run generated 17 Stage 4 attempts for ``ft_mp_parse_787468773c9f``
against a mined ``protocol_ir.json`` and published nothing.  Every attempt is
committed here verbatim, with the failure the run recorded for it, so the audit's
behaviour is measured against what a model actually wrote rather than against
shapes invented to fit the rules.

The run's own buckets (``<attempt>/parsed.json``, copied into the manifest):

===============================  =====  =============================
recorded phase / error            count  attempts
===============================  =====  =============================
``harness_plan`` / ``mp_init``        3  001 002 004
``harness_code`` / redefines          3  003 008 011
``harness_code`` / not connected      7  005 007 009 013 012 016 017
``harness_code`` / invalid C syntax   4  006 010 014 015
===============================  =====  =============================

What each bucket needs, and what these tests pin:

* the three plan-stage attempts are **already fixed** -- ``parse_harness_plan``
  now accepts the very plan texts that were fatal, and the contract gate passes
  them too.  Their plans are committed, so this is measured, not asserted.
* the seven connection attempts are B2's evidence.  Six of them are really
  assembles-a-frame-then-parses-it harnesses and are now published; the seventh
  (013) calls ``le16``, which is ``static`` in the target, so B1 refuses it on
  purpose -- see ``test_the_static_helper_attempt_is_refused_rather_than_linked``.
* the four syntax attempts are C++ harnesses (``std::``, ``constexpr``,
  anonymous namespaces) that used to be read with the C grammar, which filed
  them under a parse failure that was never true of them.  They are now parsed
  as the C++ they are: three assemble no frame, one redefines project APIs, and
  none is any longer a syntax verdict.  See
  ``test_the_syntax_attempts_are_now_audited_as_cpp``.

The table above is the **run's** buckets and stays as recorded -- read it as
history, not as today's behaviour.  Where the two differ is the whole point of
the four syntax attempts.

The negatives are the load-bearing half.  ``StructuredFrameNegativeTests`` and
``HelperCallabilityTests`` each state a rule the relaxation must *not* have
moved, and every one of them is a harness that would otherwise pass.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

from harness_generation.artifacts import ArtifactStore
from harness_generation.llm import MockLLM
from harness_generation.protocol_ir import ProtocolIR
from harness_generation.protocol_plan_validation import (
    protocol_contract_projection,
    validate_plan_contract,
)
from harness_generation.protocol_reconciliation import reconcile_protocol_ir
from harness_generation.stage4 import (
    Stage4Error,
    Stage4Generator,
    _analyze_c,
    _load_function_metadata,
    _validate_harness,
    parse_harness_plan,
)

from tests.test_stage4_protocol_ir import Stage4ProjectTests


#: The recorded run, committed as fixtures.  ``protocol_ir.json`` here is the
#: IR the run itself loaded -- mined conventions voted by three real DeepSeek
#: samples -- and not the mock-convention IR the other Stage 4 tests mine.
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "stage4_recorded_attempts"

#: Every attempt that has a ``harness.c``, keyed by the recorded failure.
CONNECTION_ATTEMPTS = (
    "attempt_005", "attempt_007", "attempt_009", "attempt_012",
    "attempt_016", "attempt_017",
)
PLAN_ATTEMPTS = ("attempt_001", "attempt_002", "attempt_004")
REDEFINITION_ATTEMPTS = ("attempt_003", "attempt_008", "attempt_011")
SYNTAX_ATTEMPTS = ("attempt_006", "attempt_010", "attempt_014", "attempt_015")

#: The copy each attempt writes, as the connection record has to quote it back.
#: Three spell the payload into the frame byte by byte, three call ``memcpy``.
RECORDED_COPIES = {
    "attempt_005": "frame[MP_HEADER_SIZE + i] = data[offset + i]",
    "attempt_007": ("memcpy(frame_buf + MP_HEADER_SIZE, data + payload_src, "
                    "payload_len)"),
    "attempt_009": "frame_buf[MP_HEADER_SIZE + i] = data[offset + i]",
    "attempt_012": ("memcpy(frame_buf + MP_HEADER_SIZE, data + offset + "
                    "MP_HEADER_SIZE, payload_length)"),
    "attempt_016": ("frame_buf[MP_HEADER_SIZE + i] = data[offset + "
                    "MP_HEADER_SIZE + i]"),
    "attempt_017": ("frame_buf[MP_HEADER_SIZE + i] = data[offset + "
                    "MP_HEADER_SIZE + i]"),
}


def recorded_ir() -> ProtocolIR:
    """The IR this run was driven by, read back through the public loader."""

    document = json.loads((FIXTURES / "protocol_ir.json").read_text(encoding="utf-8"))
    return ProtocolIR.from_json(document)


def recorded_attempts() -> list[dict]:
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    return manifest["attempts"]


def harness_source(attempt: str) -> str:
    return (FIXTURES / f"{attempt}.c").read_text(encoding="utf-8")


class RecordedRunReplayTests(Stage4ProjectTests):
    """All 17 attempts of the recorded run, replayed through today's audit."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.function_metadata, cls.functions, _context = _load_function_metadata(
            cls.phase1 / "functions.json", cls.triplet
        )
        cls.isf_metadata = cls.function_metadata[cls.triplet.isf.function_id]
        cls.reconciliation = reconcile_protocol_ir(
            recorded_ir(), cls.triplet, cls.functions
        )
        cls.declared_helpers = cls.reconciliation.callable_helpers

    def audit(self, attempt: str, *, structured_frame: bool):
        """Run the C audit over a recorded harness, returning its connection."""

        analysis = _analyze_c(harness_source(attempt))
        return _validate_harness(
            analysis,
            self.triplet,
            self.isf_metadata,
            self.functions,
            reconciliation=self.reconciliation,
            structured_frame=structured_frame,
        )

    def refusal(self, attempt: str, *, structured_frame: bool = True) -> str:
        with self.assertRaises(Stage4Error) as caught:
            self.audit(attempt, structured_frame=structured_frame)
        return str(caught.exception)

    def test_the_recorded_buckets_are_the_ones_this_docstring_claims(self):
        """The failure table above is data, not prose.

        If the fixture is ever regenerated from a different run, this is what
        says so -- the counts below are the run's own verdicts, not today's.
        """

        # Every attempt the run made, under the failure it recorded.  The
        # ``le16`` redefinition is its own string and so its own key; it is the
        # same *bucket* as the two ``mp_checksum`` ones, which is exactly the
        # distinction the table above draws and a count alone would blur.
        buckets: dict[str, list[str]] = {}
        for entry in recorded_attempts():
            buckets.setdefault(entry["recorded_error"], []).append(entry["attempt"])
        self.assertEqual(len(buckets), 5)

        # The four families below have to partition the run: an attempt that
        # matched none of them is a failure mode this module does not know
        # about, and one that matched two is a table that no longer describes
        # the data.
        covered: list[str] = []
        for pattern, expected in (
            (r"HarnessPlan references functions outside the FT: mp_init$", PLAN_ATTEMPTS),
            (r"Stage 4 redefines project APIs: ", REDEFINITION_ATTEMPTS),
            (r"Stage 4 ISF call is not connected",
             CONNECTION_ATTEMPTS + ("attempt_013",)),
            (r"LLM returned invalid C syntax$", SYNTAX_ATTEMPTS),
        ):
            with self.subTest(error=pattern):
                matched = [
                    attempt
                    for error, names in buckets.items()
                    if re.match(pattern, error)
                    for attempt in names
                ]
                self.assertEqual(sorted(matched), sorted(expected))
                covered += matched
        self.assertEqual(
            sorted(covered),
            sorted(entry["attempt"] for entry in recorded_attempts()),
        )

    # -- the plan stage: already fixed, and measured on the real plans --------

    def test_the_recorded_plan_responses_now_clear_the_membership_gate(self):
        """The three ``mp_init`` attempts, on the plan text the model wrote.

        ``mp_init`` is a real project function the contract declares and the FT
        cannot contain, so the membership rule had to admit it (Fix A).  The
        committed responses are the only end-to-end evidence that the
        relaxation reaches a real attempt.
        """

        for attempt in PLAN_ATTEMPTS:
            with self.subTest(attempt=attempt):
                plan = parse_harness_plan(
                    (FIXTURES / f"{attempt}.plan.txt").read_text(encoding="utf-8"),
                    triplet=self.triplet,
                    isf_metadata=self.isf_metadata,
                    declared_helpers=self.declared_helpers,
                )
                self.assertIn(
                    "mp_init", [step["function"] for step in plan.call_sequence]
                )

    def test_those_plans_are_refused_by_the_contract_gate_on_one_name(self):
        """The other half of the same response, and why refusing it is not a loss.

        The model bound ``helpers: [le16, mp_checksum, mp_destroy, mp_init,
        mp_parse]`` because the IR's evidence names ``le16`` -- it really is the
        algorithm behind ``payload_length``.  It is also ``static`` in
        ``target.c``, so the harness built from this plan could not have linked;
        the audit says exactly that at attempt_013, one layer later and on the
        same name.  With the plan gate reading the reconciled set, the response
        is refused here instead, before any C exists.
        """

        projection = protocol_contract_projection(
            recorded_ir(), callable_helpers=self.declared_helpers
        )
        for attempt in PLAN_ATTEMPTS:
            with self.subTest(attempt=attempt):
                plan = parse_harness_plan(
                    (FIXTURES / f"{attempt}.plan.txt").read_text(encoding="utf-8"),
                    triplet=self.triplet,
                    isf_metadata=self.isf_metadata,
                    declared_helpers=self.declared_helpers,
                )
                conformance = validate_plan_contract(
                    plan.protocol_contract_bindings,
                    projection=projection,
                    input_strategy=plan.input_strategy,
                )
                self.assertFalse(conformance.ok)
                # One name, and it is the one the audit also refused: the two
                # layers do not merely agree on the allow-set, they disagree
                # with the same plan for the same reason.
                self.assertEqual(conformance.violations, (
                    "the plan binds helpers the contract does not make callable "
                    "in this project: le16",
                ))

    def test_dropping_that_one_name_is_all_it_takes_to_clear_the_gate(self):
        """Fix B still holds for a plan that binds only callable helpers.

        The recorded response, minimally corrected rather than rewritten: the
        same ``mp_init`` call sequence, the same context, the same frame
        bindings, with ``le16`` removed.  That it clears is what says the
        refusal above is about linkage and not about the shape of the plan.
        """

        projection = protocol_contract_projection(
            recorded_ir(), callable_helpers=self.declared_helpers
        )
        for attempt in PLAN_ATTEMPTS:
            with self.subTest(attempt=attempt):
                document = json.loads(
                    (FIXTURES / f"{attempt}.plan.txt").read_text(encoding="utf-8")
                )
                bindings = document["protocol_contract_bindings"]
                bindings["helpers"] = [
                    name for name in bindings["helpers"] if name != "le16"
                ]
                plan = parse_harness_plan(
                    json.dumps(document),
                    triplet=self.triplet,
                    isf_metadata=self.isf_metadata,
                    declared_helpers=self.declared_helpers,
                )
                conformance = validate_plan_contract(
                    plan.protocol_contract_bindings,
                    projection=projection,
                    input_strategy=plan.input_strategy,
                )
                self.assertTrue(conformance.ok, conformance.violations)

    def test_those_attempts_never_reached_the_harness_stage(self):
        """They have no ``harness.c``, so nothing here can judge their C."""

        recorded = {entry["attempt"]: entry for entry in recorded_attempts()}
        for attempt in PLAN_ATTEMPTS:
            with self.subTest(attempt=attempt):
                self.assertIsNone(recorded[attempt]["harness"])
                self.assertFalse((FIXTURES / f"{attempt}.c").exists())

    # -- the seven connection attempts ---------------------------------------

    def test_six_of_the_seven_connection_attempts_now_publish(self):
        """The frames the model actually built, accepted on their real shape."""

        for attempt in CONNECTION_ATTEMPTS:
            with self.subTest(attempt=attempt):
                connection = self.audit(attempt, structured_frame=True)
                self.assertEqual(connection.kind, "repaired_frame")
                self.assertEqual(connection.isf, "mp_parse")
                self.assertTrue(connection.buffer_argument.startswith("frame"))
                self.assertIn(RECORDED_COPIES[attempt], connection.evidence[0])
                # Every one assembles the envelope around the payload, which is
                # the repair the record has to name.
                self.assertIn(
                    "frame length/checksum repaired before mp_parse",
                    connection.evidence,
                )

    def test_those_six_are_refused_without_the_protocol_ir(self):
        """The widening is the IR's, not the harness's.

        The same harness, the same helper set, one flag apart: this is B3's
        "without a ProtocolIR the repaired-frame widening must not take effect",
        stated as a pair rather than as two separate expectations.
        """

        for attempt in CONNECTION_ATTEMPTS:
            with self.subTest(attempt=attempt):
                self.assertIsNotNone(self.audit(attempt, structured_frame=True))
                self.assertEqual(
                    self.refusal(attempt, structured_frame=False),
                    "Stage 4 ISF call is not connected to external data/size",
                )

    def test_the_static_helper_attempt_is_refused_rather_than_linked(self):
        """013 is the one connection attempt that must *not* be published.

        Its frame is assembled exactly like the other six -- B2 recognises it --
        but it also calls ``le16``, which ``functions.json`` records as
        ``static``.  Under this pipeline's build recipe the harness is a separate
        object linked against the target's, so that call cannot resolve; the
        audit has to say so at the gate, with the way out, instead of publishing
        something the linker will reject later.
        """

        source = harness_source("attempt_013")
        self.assertIn("uint16_t raw_len = le16(hdr + 4);", source)
        message = self.refusal("attempt_013")
        self.assertEqual(
            message,
            "Stage 4 harness calls static project helpers it cannot link: le16 "
            "(the contract evidences them for their algorithm: reimplement it "
            "under a local name that is not a project API)",
        )
        # The guidance has to be actionable: a differently named local helper is
        # what 012 did, and 012 publishes.
        self.assertIn("harness_le16", harness_source("attempt_012"))
        self.assertIsNotNone(self.audit("attempt_012", structured_frame=True))

    # -- the two buckets this task does not move ------------------------------

    def test_the_redefinition_attempts_are_still_refused(self):
        for attempt, name, hint in (
            ("attempt_003", "mp_checksum", "call it instead of redefining it"),
            ("attempt_008", "mp_checksum", "call it instead of redefining it"),
            # le16 is evidence-only, so there is no callable alternative to
            # offer and the message must not pretend otherwise.
            ("attempt_011", "le16", None),
        ):
            with self.subTest(attempt=attempt):
                message = self.refusal(attempt)
                self.assertIn(f"Stage 4 redefines project APIs: {name}", message)
                if hint is None:
                    self.assertNotIn("callable from the harness", message)
                else:
                    self.assertIn(hint, message)

    def test_the_syntax_attempts_are_now_audited_as_cpp(self):
        """Four harnesses filed under a parse failure, re-measured.

        ``std::``, ``constexpr`` and anonymous namespaces are legal in the C++
        translation unit the harness is really compiled as, so the run's
        ``invalid C syntax`` was a statement about the parser and not about the
        harness.  Parsed as what it is, every one of the four reads cleanly.

        None of them becomes publishable, and that is the honest result: three
        assemble no frame and one redefines project APIs.  What changed is what
        the refusal *says* -- a fact about the harness rather than a fact about
        the tool.  A verdict of "invalid syntax" here would mean the grammar
        switch had silently stopped reaching these attempts.
        """

        for attempt, marker, expected in (
            ("attempt_006", "std::memset", r"Stage 4 ISF call is not connected"),
            ("attempt_010", "std::vector", r"Stage 4 ISF call is not connected"),
            ("attempt_014", "std::vector", r"Stage 4 ISF call is not connected"),
            ("attempt_015", "constexpr",
             r"Stage 4 redefines project APIs: le16, mp_checksum"),
        ):
            with self.subTest(attempt=attempt):
                self.assertIn(marker, harness_source(attempt))
                message = self.refusal(attempt)
                self.assertRegex(message, expected)
                self.assertNotIn("syntax", message)


class StructuredFrameNegativeTests(Stage4ProjectTests):
    """Harnesses that must stay refused, each one only a line away from passing.

    ``loop_harness`` is the shape the recorded run kept producing, reduced to
    what the rule is about: a bounded loop copies the payload into a frame, the
    frame's envelope is written by the harness, and the frame is handed to the
    ISF at its own length.  Every variant below changes exactly one thing.
    """

    #: Substituted into the harness to make each negative case.
    COPY = ("for (size_t i = 0; i < payload_len; ++i) {\n"
            "        frame_buf[MP_HEADER_SIZE + i] = data[MP_HEADER_SIZE + i];\n"
            "    }")
    LENGTH = "size_t frame_len = MP_HEADER_SIZE + payload_len;"

    def loop_harness(self, *, copy: str | None = None,
                     before_parse: str = "", after_parse: str = "") -> str:
        body = self.COPY if copy is None else copy
        return f"""#include <stddef.h>
#include <stdint.h>
extern "C" {{
#include "target.c"
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{{
    if (size < MP_HEADER_SIZE) return 0;
    mp_context ctx = {{0}};
    mp_init(&ctx);

    uint8_t frame_buf[MP_HEADER_SIZE + MP_MAX_PAYLOAD] = {{0}};
    size_t payload_len = size - MP_HEADER_SIZE;
    if (payload_len > MP_MAX_PAYLOAD) payload_len = MP_MAX_PAYLOAD;

    frame_buf[0] = 'M';
    frame_buf[1] = 'P';
    frame_buf[2] = 1;
    frame_buf[3] = 1;
    frame_buf[4] = (uint8_t)(payload_len & 0xff);
    frame_buf[5] = (uint8_t)(payload_len >> 8);

    {body}

    uint16_t sum = mp_checksum(frame_buf + MP_HEADER_SIZE, payload_len);
    frame_buf[6] = (uint8_t)(sum & 0xff);
    frame_buf[7] = (uint8_t)(sum >> 8);

    {self.LENGTH}
    {before_parse}
    mp_parse(&ctx, frame_buf, frame_len);
    {after_parse}
    mp_destroy(&ctx);
    return 0;
}}"""

    # -- helpers -------------------------------------------------------------

    def with_ir(self, name: str) -> Path:
        root = self.artifact_root(name)
        ArtifactStore(root).write_protocol_ir(recorded_ir())
        return root

    def publish(self, root: Path, harness: str):
        return Stage4Generator(MockLLM([self.plan_for(root), harness])).run(
            self.triplet,
            rough_code=self.rough_code(),
            functions_json=root / "functions.json",
            artifacts=root,
        )

    def published(self, root: Path) -> Path:
        return ArtifactStore(root).for_triplet(self.triplet.id).harness

    def refused(self, root: Path, harness: str, pattern: str) -> str:
        with self.assertRaises(Stage4Error) as caught:
            self.publish(root, harness)
        message = str(caught.exception)
        self.assertRegex(message, pattern)
        self.assertFalse(
            self.published(root).exists(),
            "a refused harness must not be published",
        )
        return message

    # -- the shape that passes, so each negative is a real delta -------------

    def test_the_loop_harness_itself_publishes(self):
        root = self.with_ir("loop_baseline")
        self.publish(root, self.loop_harness())
        self.assertTrue(self.published(root).is_file())

    def test_the_same_loop_harness_is_refused_without_the_ir(self):
        """The full pipeline, no ``protocol_ir.json``, the same harness.

        Nothing else in this harness reaches outside the FT -- it calls only
        ``mp_parse``/``mp_destroy``/``mp_init``... and ``mp_checksum``, which
        is why the no-IR case here is run through the audit with the helper set
        the IR would have supplied: that is the only way to hold everything
        constant but the widening under test.  See
        ``RecordedRunReplayTests.test_those_six_are_refused_without_the_protocol_ir``.
        """

        root = self.artifact_root("loop_without_ir")
        self.refused(
            root,
            self.loop_harness(),
            r"Stage 4 harness calls project APIs outside the FT: mp_checksum",
        )

    def test_a_loop_filling_the_frame_from_a_local_table_is_not_a_connection(self):
        """``data`` is read, and the frame still does not come from it.

        The stored byte is taken from a table *at an index read from the input*,
        which keeps the harness a genuine consumer of ``data`` -- so the refusal
        is the connection rule's and not the earlier "must use both external
        data and size" one, which is what a plain local-table loop would trip.
        """

        harness = self.loop_harness(copy=(
            "for (size_t i = 0; i < payload_len; ++i) {\n"
            "        frame_buf[MP_HEADER_SIZE + i] = canned[data[0]];\n"
            "    }"
        )).replace(
            "uint8_t frame_buf[MP_HEADER_SIZE + MP_MAX_PAYLOAD] = {0};",
            "static const uint8_t canned[256] = {0};\n"
            "    uint8_t frame_buf[MP_HEADER_SIZE + MP_MAX_PAYLOAD] = {0};",
        )
        self.refused(
            self.with_ir("loop_from_table"),
            harness,
            r"Stage 4 ISF call is not connected to external data/size",
        )

    def test_a_loop_that_writes_one_input_byte_everywhere_is_not_a_connection(self):
        """``frame[i] = data[0]`` reads ``data`` but copies no frame.

        The stored byte has to be *this* iteration's byte, so the read from
        ``data`` is indexed by the loop's own counter.  Without that, a harness
        that fills the frame with a single input byte would be read as a copy.
        """

        self.refused(
            self.with_ir("loop_one_byte"),
            self.loop_harness(copy=(
                "for (size_t i = 0; i < payload_len; ++i) {\n"
                "        frame_buf[MP_HEADER_SIZE + i] = data[0];\n"
                "    }"
            )),
            r"Stage 4 ISF call is not connected to external data/size",
        )

    def test_a_length_that_is_reassigned_before_the_call_is_not_resolved(self):
        """A clamp makes the initialiser stop describing the call site.

        ``frame_len`` is written twice, so expanding it to
        ``MP_HEADER_SIZE + payload_len`` would claim a length the ISF is not
        actually given.
        """

        self.refused(
            self.with_ir("loop_clamped_length"),
            self.loop_harness(
                before_parse="if (frame_len > sizeof(frame_buf)) "
                             "frame_len = sizeof(frame_buf);"
            ),
            r"Stage 4 ISF call is not connected to external data/size",
        )

    def test_a_length_computed_by_a_call_is_not_resolved(self):
        """``x = f(...)`` mentions ``f``, but ``x`` is not ``f``'s arguments."""

        self.refused(
            self.with_ir("loop_call_length"),
            self.loop_harness(
                copy=self.COPY,
                before_parse="",
            ).replace(
                self.LENGTH,
                "size_t frame_len = (size_t)mp_checksum(frame_buf, "
                "MP_HEADER_SIZE);",
            ),
            r"Stage 4 ISF call is not connected to external data/size",
        )

    def test_a_copy_after_the_isf_call_is_not_a_connection(self):
        """Text order stands in for dynamic order, and it is all there is."""

        harness = self.loop_harness()
        loop = self.COPY
        harness = harness.replace(f"    {loop}\n\n", "")
        harness = harness.replace(
            "    mp_destroy(&ctx);",
            f"    {loop}\n    mp_destroy(&ctx);",
        )
        self.refused(
            self.with_ir("loop_late_copy"),
            harness,
            r"Stage 4 ISF call is not connected to external data/size",
        )


class HelperCallabilityTests(Stage4ProjectTests):
    """A contract-declared helper is callable only if the project exports it.

    ``functions.json`` has always recorded which functions are ``static``; Stage
    4 used to drop the field, so the audit could promise a call that the build
    recipe cannot resolve.  These tests pin the three outcomes the policy has to
    distinguish, all on the one harness that otherwise publishes.
    """

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

    uint8_t frame_buf[MP_HEADER_SIZE + MP_MAX_PAYLOAD] = {0};
    size_t payload_len = size - MP_HEADER_SIZE;
    if (payload_len > MP_MAX_PAYLOAD) payload_len = MP_MAX_PAYLOAD;

    frame_buf[0] = 'M';
    frame_buf[1] = 'P';
    frame_buf[2] = 1;
    frame_buf[3] = 1;
    frame_buf[4] = (uint8_t)(payload_len & 0xff);
    frame_buf[5] = (uint8_t)(payload_len >> 8);
    for (size_t i = 0; i < payload_len; ++i) {
        frame_buf[MP_HEADER_SIZE + i] = data[MP_HEADER_SIZE + i];
    }

    __EXTRA__

    uint16_t sum = mp_checksum(frame_buf + MP_HEADER_SIZE, payload_len);
    frame_buf[6] = (uint8_t)(sum & 0xff);
    frame_buf[7] = (uint8_t)(sum >> 8);

    size_t frame_len = MP_HEADER_SIZE + payload_len;
    mp_parse(&ctx, frame_buf, frame_len);
    mp_destroy(&ctx);
    return 0;
}"""

    def harness(self, extra: str = "") -> str:
        return self.HARNESS.replace("    __EXTRA__\n", extra)

    def with_ir(self, name: str) -> Path:
        root = self.artifact_root(name)
        ArtifactStore(root).write_protocol_ir(recorded_ir())
        return root

    def publish(self, root: Path, harness: str):
        return Stage4Generator(MockLLM([self.plan_for(root), harness])).run(
            self.triplet,
            rough_code=self.rough_code(),
            functions_json=root / "functions.json",
            artifacts=root,
        )

    def refused(self, root: Path, harness: str, pattern: str) -> str:
        with self.assertRaises(Stage4Error) as caught:
            self.publish(root, harness)
        message = str(caught.exception)
        self.assertRegex(message, pattern)
        self.assertFalse(ArtifactStore(root).for_triplet(self.triplet.id).harness.exists())
        return message

    def test_the_baseline_harness_publishes(self):
        root = self.with_ir("callability_baseline")
        self.publish(root, self.harness())
        self.assertTrue(ArtifactStore(root).for_triplet(self.triplet.id).harness.is_file())

    def test_calling_a_static_project_helper_is_refused(self):
        """``le16`` is real, declared by the contract, and out of reach.

        Nothing about the call looks wrong, which is the point: the name is a
        project API the IR's evidence names.  It is only the linkage that makes
        it unusable, and the message has to carry the way out.
        """

        message = self.refused(
            self.with_ir("callability_static_call"),
            self.harness("uint16_t raw = le16(frame_buf + 4);\n    (void)raw;"),
            r"Stage 4 harness calls static project helpers it cannot link: le16",
        )
        self.assertIn("reimplement it under a local name", message)

    def test_redefining_that_static_helper_is_still_refused(self):
        """The same name may not be taken either, and no false advice is given.

        A local ``le16`` cannot call the project's, so the refusal must not
        suggest calling it -- there is nothing to call.
        """

        message = self.refused(
            self.with_ir("callability_static_define"),
            self.harness("static uint16_t le16(const uint8_t *p) { return p[0]; }\n"
                         "    uint16_t raw = le16(frame_buf + 4);\n    (void)raw;"),
            r"Stage 4 redefines project APIs: le16",
        )
        self.assertNotIn("callable from the harness", message)

    def test_a_differently_named_local_helper_is_allowed(self):
        """The algorithm is free to be reimplemented; the API name is not."""

        root = self.with_ir("callability_local_helper")
        self.publish(root, self.harness(
            "static uint16_t harness_le16(const uint8_t *p) "
            "{ return (uint16_t)(p[0] | (p[1] << 8)); }\n"
            "    uint16_t raw = harness_le16(frame_buf + 4);\n    (void)raw;"
        ))
        self.assertTrue(ArtifactStore(root).for_triplet(self.triplet.id).harness.is_file())

    def test_calling_a_non_static_helper_is_allowed(self):
        """``mp_checksum`` is exported, so the audit was never the problem."""

        root = self.with_ir("callability_exported_call")
        self.publish(root, self.harness(
            "uint16_t twice = mp_checksum(frame_buf + MP_HEADER_SIZE, payload_len);\n"
            "    (void)twice;"
        ))
        self.assertTrue(ArtifactStore(root).for_triplet(self.triplet.id).harness.is_file())

    def test_redefining_an_exported_helper_says_it_could_have_been_called(self):
        """The refusal is the only channel the model has for that fact."""

        message = self.refused(
            self.with_ir("callability_exported_define"),
            self.harness("static uint16_t mp_checksum(const uint8_t *p, size_t n) "
                         "{ (void)p; (void)n; return 0; }\n    (void)mp_checksum;"),
            r"Stage 4 redefines project APIs: mp_checksum",
        )
        self.assertIn(
            "callable from the harness: mp_checksum; call it instead of "
            "redefining it",
            message,
        )


class AnalyzerFactTests(unittest.TestCase):
    """The two facts the audit reads, on sources small enough to read too.

    ``_analyze_c`` computes them once per function because the AST body is not
    kept; these are the shapes it has to get right, including the ones that must
    produce nothing.
    """

    def facts(self, body: str):
        source = f"void f(const uint8_t *data, size_t size) {{\n{body}\n}}\n"
        return _analyze_c(source).functions[0]

    def aliases(self, body: str) -> dict[str, tuple[str, ...]]:
        return dict(self.facts(body).local_aliases)

    def regions(self, body: str) -> list:
        return list(self.facts(body).copy_regions)

    def test_a_single_initialiser_is_an_alias(self):
        self.assertEqual(self.aliases("size_t a = b + c;"), {"a": ("b", "c")})

    def test_a_name_written_twice_is_not_an_alias(self):
        self.assertEqual(self.aliases("size_t a = b;\na = c;"), {})
        self.assertEqual(self.aliases("size_t a = b;\na += c;"), {})
        self.assertEqual(self.aliases("size_t a = b;\na++;"), {})

    def test_a_declared_then_assigned_name_is_not_an_alias(self):
        # Its one write is not the declaration, so the declaration says nothing
        # about the value the call site sees.
        self.assertEqual(self.aliases("size_t a;\na = b;"), {})

    def test_an_initialiser_that_calls_something_is_not_an_alias(self):
        self.assertEqual(self.aliases("size_t a = g(b);"), {})
        self.assertEqual(self.aliases("size_t a = b[i];"), {})
        self.assertEqual(self.aliases("size_t a = c->len;"), {})

    def test_a_store_loop_indexed_by_its_counter_is_a_region(self):
        regions = self.regions(
            "for (size_t i = 0; i < n; ++i) frame[8 + i] = data[i];"
        )
        self.assertEqual(len(regions), 1)
        self.assertEqual(regions[0].kind, "loop")
        self.assertEqual(regions[0].destination_identifiers, ("frame",))
        self.assertEqual(regions[0].length.identifiers, ("n",))

    def test_a_store_at_a_constant_index_is_not_a_region(self):
        # The header repair every one of the real harnesses writes, and the
        # reason the counter has to appear in the index.
        self.assertEqual(self.regions("for (size_t i = 0; i < n; ++i) "
                                      "frame[3] = data[i];"), [])
        self.assertEqual(self.regions("frame[3] = data[offset + 3];"), [])

    def test_a_compound_loop_condition_has_no_counter_to_bind_to(self):
        self.assertEqual(
            self.regions("for (size_t s = 0; s < max_steps && offset < size; ++s) "
                         "frame[8 + s] = data[s];"),
            [],
        )

    def test_a_nested_loop_belongs_to_its_own_counter(self):
        regions = self.regions(
            "for (size_t i = 0; i < n; ++i) {\n"
            "  for (size_t j = 0; j < m; ++j) frame[j] = data[j];\n"
            "}"
        )
        self.assertEqual(len(regions), 1)
        self.assertEqual(regions[0].length.identifiers, ("m",))

    def test_a_memcpy_from_data_is_a_region_of_kind_call(self):
        regions = self.regions("memcpy(frame + 8, data + 8, n);")
        self.assertEqual(len(regions), 1)
        self.assertEqual(regions[0].kind, "call")
        # Only identifiers, so the offset literal in ``frame + 8`` is not part
        # of the destination's name -- matching is by buffer, not by address.
        self.assertEqual(regions[0].destination_identifiers, ("frame",))
        self.assertEqual(regions[0].source.identifiers, ("data",))
        self.assertEqual(regions[0].length.identifiers, ("n",))

    def test_a_copy_is_recorded_whoever_its_source_is(self):
        """Extraction records the copy; the *connection* rule judges the source.

        Keeping those apart is what lets one rule serve both the harness that
        fills its frame from ``data`` and the one that fills it from a local
        table -- the latter still has a region, and is refused later for the
        region's source rather than for its absence.
        """

        regions = self.regions("memcpy(frame, canned, n);")
        self.assertEqual(len(regions), 1)
        self.assertEqual(regions[0].source.identifiers, ("canned",))

    def test_regions_come_back_in_source_order(self):
        regions = self.regions(
            "memcpy(frame + 8, data + 8, n);\n"
            "for (size_t i = 0; i < n; ++i) tail[i] = data[i];"
        )
        self.assertEqual([region.kind for region in regions], ["call", "loop"])


if __name__ == "__main__":
    unittest.main()
