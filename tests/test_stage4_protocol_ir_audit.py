"""Stage 4's audit, relaxed exactly where the mined protocol justifies it.

Stage 4 refuses a *structured* harness for ``mp_parse`` for two reasons that
have nothing to do with the harness being wrong:

1. ``mp_checksum`` and ``mp_init`` are functions the protocol's own provenance
   names -- the checksum comparison and the context lifecycle -- but they are
   not FT members.  An FT is built from the structural edges its ISF shares with
   other functions, not from its call closure, so a callee the ISF shares no
   struct with never joins it.
2. ``mp_parse(&ctx, frame, frame_len)`` hands the ISF a buffer the harness
   assembled, because ``data`` is ``const`` and the frame envelope has to be
   repaired in place.  The old ISF rule looked for the literal identifier
   ``data`` in the call's arguments, which an assembled frame never has.

Both relaxations are conditioned on the ``protocol_ir.json`` that ``protocol-mine``
wrote: with no IR the audit is the FT-only one it always was, and the tests here
prove that by running the *same* harness down both paths.

Every assertion is made against the published artifact -- the file under
``<artifacts>/harnesses/<ft_id>.c`` that a later stage actually compiles -- and
not against the in-memory string the generator happened to return.
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import unittest

from harness_generation.artifacts import ArtifactStore
from harness_generation.llm import MockLLM
from harness_generation.protocol_ir_helpers import (
    ProtocolHelper,
    ProtocolHelperSet,
    collect_protocol_helpers,
)
from harness_generation.stage4 import Stage4Error, Stage4Generator
from tests.test_stage4_protocol_ir import Stage4ProjectTests, mined_ir


#: The helpers the mined mini_parser IR's own provenance names.
DECLARED_HELPERS = frozenset({"le16", "mp_checksum", "mp_init", "mp_destroy"})

#: The copy that assembles the frame, and the ISF call it feeds.  These are the
#: exact texts the connection record has to quote back.
FRAME_COPY = "memcpy(frame + MP_HEADER_SIZE, data + MP_HEADER_SIZE, payload_len)"
FRAME_LENGTH = "MP_HEADER_SIZE + payload_len"


class HelperRelaxationTests(Stage4ProjectTests):
    """The outside-FT allow-set follows the IR, and only the IR."""

    def structured_harness(self) -> str:
        """A harness that repairs the envelope and then parses it.

        It calls two helpers the FT does not contain (``mp_init``,
        ``mp_checksum``) and hands ``mp_parse`` a frame it assembled itself.
        """

        return """#include <stddef.h>
#include <stdint.h>
extern "C" {
#include "target.c"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < MP_HEADER_SIZE) return 0;
    mp_context ctx = {0};
    mp_init(&ctx);

    uint8_t frame[MP_HEADER_SIZE + MP_MAX_PAYLOAD];
    memset(frame, 0, sizeof(frame));
    size_t payload_len = size - MP_HEADER_SIZE;
    if (payload_len > MP_MAX_PAYLOAD) payload_len = MP_MAX_PAYLOAD;

    memcpy(frame + MP_HEADER_SIZE, data + MP_HEADER_SIZE, payload_len);
    frame[0] = 'M';
    frame[1] = 'P';
    frame[2] = 1;
    frame[3] = 1;
    frame[4] = (uint8_t)(payload_len & 0xff);
    frame[5] = (uint8_t)(payload_len >> 8);
    uint16_t sum = mp_checksum(frame + MP_HEADER_SIZE, payload_len);
    frame[6] = (uint8_t)(sum & 0xff);
    frame[7] = (uint8_t)(sum >> 8);

    mp_parse(&ctx, frame, MP_HEADER_SIZE + payload_len);
    mp_destroy(&ctx);
    return 0;
}"""

    def constant_frame_harness(self) -> str:
        """The same shape, but the frame never comes from ``data``.

        A literal byte-at-a-time copy loop would be missed by the
        approximation entirely; this is the sharper case, a ``memcpy`` whose
        *source* is a local constant array.  The connection rule must not
        accept it just because a copy into the frame is written down.
        """

        return """#include <stddef.h>
#include <stdint.h>
extern "C" {
#include "target.c"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint8_t canned[MP_HEADER_SIZE + 4] = {
        'M', 'P', 1, 1, 4, 0, 0, 0, 1, 2, 3, 4,
    };
    mp_context ctx = {0};
    mp_init(&ctx);

    uint8_t frame[MP_HEADER_SIZE + MP_MAX_PAYLOAD] = {0};
    size_t frame_len = sizeof(canned);
    memcpy(frame, canned, frame_len);

    frame[6] = 10;
    frame[7] = 0;
    (void)data;
    (void)size;
    mp_parse(&ctx, frame, frame_len);
    mp_destroy(&ctx);
    return 0;
}"""

    # -- helpers -----------------------------------------------------------

    def publish(self, root: Path, harness: str):
        """Run Stage 4 against ``root`` and return the result."""

        llm = MockLLM([self.plan_for(root), harness])
        return Stage4Generator(llm).run(
            self.triplet,
            rough_code=self.rough_code(),
            functions_json=root / "functions.json",
            artifacts=root,
        )

    def published_harness(self, root: Path) -> Path:
        """The stable artifact a later stage compiles, from the real layout."""

        return ArtifactStore(root).for_triplet(self.triplet.id).harness

    def passed_attempt(self, root: Path) -> dict:
        path = (
            root / "generation" / self.triplet.id / "stage4" / "attempt_001"
            / "parsed.json"
        )
        document = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(document["status"], "passed")
        return document

    def refused(self, root: Path, harness: str, pattern: str) -> str:
        """Run Stage 4 and insist it refuses, returning the error message."""

        harness_path = self.published_harness(root)
        with self.assertRaises(Stage4Error) as caught:
            self.publish(root, harness)
        message = str(caught.exception)
        self.assertRegex(message, pattern)
        self.assertFalse(
            harness_path.exists(),
            "a refused harness must not be published",
        )
        return message

    def with_protocol_ir(self, root: Path, ir=None):
        ArtifactStore(root).write_protocol_ir(mined_ir() if ir is None else ir)
        return root

    # -- 1. a declared helper is allowed -----------------------------------

    def test_helpers_the_protocol_declares_publish_the_structured_harness(self):
        root = self.with_protocol_ir(self.artifact_root("audit_declared"))
        result = self.publish(root, self.structured_harness())

        published = self.published_harness(root)
        self.assertEqual(published, root / "harnesses" / f"{self.triplet.id}.c")
        self.assertTrue(published.is_file())
        # The published file *is* the structured harness: the same text the
        # generator validated, written where the build stage reads it.
        self.assertEqual(published.read_text(encoding="utf-8"),
                         result.harness_code + "\n")
        for call in ("mp_init(&ctx)", "mp_checksum(frame + MP_HEADER_SIZE, payload_len)",
                     "mp_parse(&ctx, frame, MP_HEADER_SIZE + payload_len)",
                     "mp_destroy(&ctx)"):
            with self.subTest(call=call):
                self.assertIn(call, published.read_text(encoding="utf-8"))

    def test_the_undeclared_part_of_that_harness_is_unaffected(self):
        """The relaxation is a list of names, not a blanket permission.

        ``memcpy``/``memset`` are standard C and were always allowed; the point
        of this test is that allowing two project helpers did not turn the
        allow-set into "anything goes" for the rest of the harness.
        """

        root = self.with_protocol_ir(self.artifact_root("audit_other_calls"))
        self.publish(root, self.structured_harness())
        published = self.published_harness(root).read_text(encoding="utf-8")
        self.assertNotIn("invented_", published)
        self.assertIn("memcpy(frame + MP_HEADER_SIZE", published)

    # -- 2. without the IR, nothing changed --------------------------------

    def test_the_same_harness_without_an_ir_is_still_refused(self):
        root = self.artifact_root("audit_without_ir")
        message = self.refused(
            root,
            self.structured_harness(),
            r"Stage 4 harness calls project APIs outside the FT: ",
        )
        # Exactly the calls the FT does not contain, and nothing weaker: this is
        # the pre-existing message, byte for byte, from the pre-existing rule.
        self.assertIn("mp_checksum", message)
        self.assertIn("mp_init", message)
        self.assertNotIn("mp_parse", message)
        self.assertNotIn("mp_destroy", message)

    def test_a_helper_call_is_only_allowed_because_the_ir_declared_it(self):
        """Same harness, same code shape, IR the only difference."""

        with_ir = self.with_protocol_ir(self.artifact_root("audit_only_ir"))
        without_ir = self.artifact_root("audit_only_no_ir")

        self.publish(with_ir, self.structured_harness())
        with self.assertRaises(Stage4Error):
            self.publish(without_ir, self.structured_harness())

        self.assertTrue(self.published_harness(with_ir).is_file())
        self.assertFalse(self.published_harness(without_ir).exists())

    # -- 3. an invented helper stays forbidden -----------------------------

    def invented_ir(self):
        """The mined IR plus a *mention* of a helper that does not exist.

        The mention is in ``requirements``, which is prose.  A sentence hoping
        the harness will "repair the envelope with invented_checksum(...)" is
        collected into ``ProtocolHelperSet.weak`` and must never be able to
        authorise the call.
        """

        return replace(
            mined_ir(),
            requirements=(
                "repair the frame envelope with invented_checksum(frame, len)",
            ),
        )

    def invented_harness(self) -> str:
        harness = self.structured_harness()
        return harness.replace(
            "uint16_t sum = mp_checksum(frame + MP_HEADER_SIZE, payload_len);",
            "uint16_t sum = invented_checksum(frame + MP_HEADER_SIZE, payload_len);",
        )

    def test_an_invented_helper_is_refused_even_with_the_ir(self):
        root = self.artifact_root("audit_invented")
        # The name has to be a *project* API for the outside-FT rule to be the
        # rule under test, so functions.json is told about it and nothing else.
        document = json.loads(
            (root / "functions.json").read_text(encoding="utf-8")
        )
        document["functions"].append({
            "id": "target.c:99:invented_checksum",
            "name": "invented_checksum",
            "parameters": [
                {"name": "payload", "base_type": "uint8_t", "is_pointer": True,
                 "is_struct_like": False, "pointer_depth": 1},
                {"name": "size", "base_type": "size_t", "is_pointer": False,
                 "is_struct_like": False, "pointer_depth": 0},
            ],
        })
        (root / "functions.json").write_text(
            json.dumps(document), encoding="utf-8"
        )

        ir = self.invented_ir()
        helpers = collect_protocol_helpers(ir)
        self.assertIn("invented_checksum", helpers.weak)
        self.assertNotIn("invented_checksum", helpers.allowed)
        self.with_protocol_ir(root, ir)

        message = self.refused(
            root,
            self.invented_harness(),
            r"Stage 4 harness calls project APIs outside the FT: ",
        )
        self.assertIn("invented_checksum", message)

    def ghost_ir(self):
        """The mined IR declaring a lifecycle helper the project never defines.

        ``context.init`` is a *strong* provenance source -- a convention
        expression, not prose -- so this name does reach
        ``ProtocolHelperSet.allowed``.  It must be refused anyway: the IR's
        evidence quotes real source, so a name with no definition behind it is a
        broken claim rather than a licence.  Allowing it would additionally stop
        the unknown-API check firing for that name, which is weaker than the
        audit this relaxation has to leave otherwise intact.
        """

        return replace(
            mined_ir(), context=replace(mined_ir().context, init="invented_init(&ctx)")
        )

    def ghost_harness(self) -> str:
        return self.structured_harness().replace(
            "mp_init(&ctx);", "invented_init(&ctx);"
        )

    def test_a_declared_helper_the_project_does_not_define_is_still_refused(self):
        root = self.artifact_root("audit_ghost")
        ir = self.ghost_ir()
        helpers = collect_protocol_helpers(ir)
        # The name really is declared -- so this test exercises the intersection
        # against the project, not the weak-prose path the previous test covers.
        self.assertIn("invented_init", helpers.allowed)
        self.with_protocol_ir(root, ir)

        message = self.refused(
            root, self.ghost_harness(), r"Stage 4 harness calls unknown APIs: "
        )
        self.assertIn("invented_init", message)
        self.assertFalse(self.published_harness(root).exists())

    # -- 4. the repaired frame is accepted, and recorded -------------------

    def test_a_repaired_frame_is_accepted_and_recorded(self):
        root = self.with_protocol_ir(self.artifact_root("audit_repaired"))
        result = self.publish(root, self.structured_harness())

        self.assertTrue(self.published_harness(root).is_file())
        connection = self.passed_attempt(root)["input_connection"]
        self.assertEqual(connection, {
            "kind": "repaired_frame",
            "isf": "mp_parse",
            "buffer_argument": "frame",
            "size_argument": FRAME_LENGTH,
            "evidence": [
                FRAME_COPY,
                "frame length/checksum repaired before mp_parse",
            ],
        })
        # The result and the artifact carry the same record, or one of them is
        # a second opinion about what the audit decided.
        self.assertEqual(dict(result.input_connection), connection)

    def test_a_frame_filled_from_a_local_constant_is_not_connected(self):
        root = self.with_protocol_ir(self.artifact_root("audit_constant"))

        self.refused(
            root,
            self.constant_frame_harness(),
            r"Stage 4 ISF call is not connected to external data/size",
        )

    def test_a_copy_that_happens_after_the_isf_is_not_a_connection(self):
        """The frame must be filled *before* it is parsed.

        A copy written after the call cannot be what the ISF read, and the
        connection rule says so by comparing source positions rather than by
        looking for a copy anywhere in the function.
        """

        root = self.with_protocol_ir(self.artifact_root("audit_late_copy"))
        harness = """#include <stddef.h>
#include <stdint.h>
extern "C" {
#include "target.c"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    mp_context ctx = {0};
    mp_init(&ctx);
    uint8_t frame[MP_HEADER_SIZE + MP_MAX_PAYLOAD] = {0};
    size_t payload_len = size < MP_MAX_PAYLOAD ? size : MP_MAX_PAYLOAD;

    mp_parse(&ctx, frame, MP_HEADER_SIZE + payload_len);
    memcpy(frame + MP_HEADER_SIZE, data, payload_len);
    mp_destroy(&ctx);
    return 0;
}"""

        self.refused(
            root,
            harness,
            r"Stage 4 ISF call is not connected to external data/size",
        )

    # -- 5. the direct connection is untouched -----------------------------

    def test_a_direct_connection_is_still_accepted_and_now_recorded(self):
        root = self.with_protocol_ir(self.artifact_root("audit_direct"))
        result = self.publish(root, self.harness_code())

        self.assertTrue(self.published_harness(root).is_file())
        connection = self.passed_attempt(root)["input_connection"]
        self.assertEqual(connection["kind"], "direct")
        self.assertEqual(connection["isf"], "mp_parse")
        self.assertEqual(connection["buffer_argument"], "data")
        self.assertEqual(connection["size_argument"], "size")
        self.assertEqual(connection["evidence"], ["data", "size"])
        self.assertEqual(dict(result.input_connection), connection)

    def test_a_direct_connection_is_recorded_without_an_ir_too(self):
        """The FT-only run gains a record, not a different decision."""

        root = self.artifact_root("audit_direct_no_ir")
        self.publish(root, self.harness_code())
        self.assertTrue(self.published_harness(root).is_file())
        self.assertEqual(
            self.passed_attempt(root)["input_connection"]["kind"], "direct"
        )


class HelperProvenanceTests(Stage4ProjectTests):
    """The allow-set is evidence-backed, or it is empty."""

    def test_the_declared_helpers_are_the_mined_ones(self):
        helpers = collect_protocol_helpers(mined_ir())
        self.assertEqual(helpers.allowed, DECLARED_HELPERS)

    def test_every_declared_helper_carries_its_justification(self):
        helpers = collect_protocol_helpers(mined_ir())
        self.assertEqual(len(helpers.helpers), len(DECLARED_HELPERS))
        for helper in helpers.helpers:
            with self.subTest(helper=helper.name):
                self.assertTrue(helper.origin, "a helper without an origin is a guess")
                self.assertTrue(helper.evidence, "a helper without evidence is a guess")
                self.assertEqual(
                    helpers.evidence_for(helper.name), (helper.evidence,)
                )

    def test_without_an_ir_the_set_is_empty(self):
        helpers = collect_protocol_helpers(None)
        self.assertEqual(helpers.allowed, frozenset())
        self.assertEqual(helpers.weak, ())
        self.assertEqual(helpers.to_dict(), {"helpers": [], "weak": []})
        self.assertEqual(helpers, ProtocolHelperSet())

    def test_the_empty_set_is_not_a_licence_to_call_anything(self):
        """``ProtocolHelperSet()`` must authorise nothing at all."""

        empty = ProtocolHelperSet()
        self.assertFalse(empty.allowed)
        self.assertEqual(
            empty.allowed | frozenset({"mp_parse", "mp_destroy"}),
            frozenset({"mp_parse", "mp_destroy"}),
        )
        # A weak-only set -- names mentioned in prose -- is the same shape.
        weak_only = ProtocolHelperSet(
            weak=("mp_checksum",),
            helpers=(ProtocolHelper("le16", "frame.fields[payload_length].value",
                                    "le16() load"),),
        )
        self.assertEqual(weak_only.allowed, frozenset({"le16"}))
        self.assertNotIn("mp_checksum", weak_only.allowed)


if __name__ == "__main__":
    unittest.main()
