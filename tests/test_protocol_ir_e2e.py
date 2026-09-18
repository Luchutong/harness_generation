"""mini_parser, end to end: source -> mined IR -> published harness -> a real run.

The chain under test is the one the product claims to have:

    target.c
      -> protocol-miner (A/B facts) + protocol_conventions (C block, MockLLM)
      -> protocol_ir.json
      -> Stage 4, which validates and publishes
      -> <artifacts>/harnesses/<ft_id>.c
      -> clang++ -fsanitize=fuzzer,address,undefined
      -> a running libFuzzer process

Two things about the shape of this file are deliberate.

**The published artifact is the subject.**  Every structural assertion reads
``harnesses/<ft_id>.c`` back off disk -- the file a later stage compiles --
rather than the string the generator returned.  A harness that validated but
was never written is not a harness.

**Stage 4's audit is not adjusted anywhere in this file.**  The relaxation that
lets a structured harness through was frozen as its own checkpoint; this file
verifies the loop that checkpoint unblocked.  If a harness here is refused, the
refusal is the finding, not an obstacle to widen away.

The mock LLM plays the generator, as elsewhere in the suite: it is handed the
prompt Stage 4 would send and answers with the plan and the harness.  The
harness it returns is *built from the mined IR* -- the field offsets, the magic
and version bytes, the payload cap, the lifecycle expressions, the loop bound
and the checksum helper are all read out of ``protocol_ir.json`` -- so a
regression in mining shows up here as a harness that no longer matches its own
contract.

``benchmarks/mini_parser/protocol.json`` is never read on this path.  One test
proves that rather than asserting it: the loader that would discover it is
patched to fail.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import subprocess
import unittest
from unittest import mock

from harness_generation.artifacts import ArtifactStore
from harness_generation.fuzzer_build import (
    DEFAULT_FUZZER_LINK_FLAGS,
    DEFAULT_HARNESS_COMPILE_FLAGS,
)
from harness_generation.llm import MockLLM
from harness_generation.protocol_cli import main as protocol_mine
from harness_generation.protocol_ir import FrameField, ProtocolIR
from harness_generation.stage4 import Stage4Error, Stage4Generator
from tests.test_stage4_protocol_ir import (
    CONVENTION_SAMPLE,
    SOURCE,
    Stage4ProjectTests,
)
from tests.toolchain_probe import LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON


#: The eight structural elements a structured harness has to have.  The needles
#: for each are built per-test out of the mined IR, because the point is that
#: they come from there and not from this file.
ELEMENTS = (
    "bounded loop",
    "context init/destroy",
    "frame buffer",
    "magic/version",
    "opcode",
    "length repair",
    "checksum repair",
    "payload copy/fuzz control",
)

#: ``values 1..7`` in the opcode field's contract text.  The opcode's *range* is
#: the one thing the miner describes in prose -- the field's value line -- and
#: :func:`opcode_range` refuses to guess if that changes.
_OPCODE_RANGE = re.compile(r"values\s+(\d+)\.\.(\d+)")

#: A C call at the head of an evidence snippet, e.g. ``mp_checksum(...)``.
_CALL_HEAD = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


# -- reading the mined contract -------------------------------------------


def mine_protocol_ir(root: Path, *, source: Path = SOURCE,
                     samples: int = 3) -> ProtocolIR:
    """Run the real ``protocol-mine`` CLI over ``source`` into ``root``.

    The C block is voted by a mock, and the same sample comes back every time so
    the vote is unanimous; what is exercised is the miner, the merge and the
    write, not the model's opinion.
    """

    code = protocol_mine(
        [
            "--source", str(source),
            "--function", "mp_parse",
            "--output", str(root),
            "--with-llm",
            "--samples", str(samples),
        ],
        llm=MockLLM([CONVENTION_SAMPLE] * samples),
    )
    if code != 0:
        raise AssertionError(f"protocol-mining failed with exit code {code}")
    written = root / "protocol_ir.json"
    if not written.is_file():
        raise AssertionError(f"protocol-mining wrote no {written.name}")
    return ProtocolIR.from_json(json.loads(written.read_text(encoding="utf-8")))


def fields_with_role(ir: ProtocolIR, role: str) -> list[FrameField]:
    return [field for field in ir.frame.fields if field.role == role]


def field_by_role(ir: ProtocolIR, role: str) -> FrameField:
    matches = fields_with_role(ir, role)
    if len(matches) != 1:
        raise AssertionError(
            f"the mined IR has {len(matches)} fields with role {role!r}, want 1"
        )
    return matches[0]


def checksum_helper(ir: ProtocolIR) -> str:
    """The checksum function, read out of the checksum field's own evidence.

    This is the same provenance Stage 4's audit consults to decide the call is
    legitimate, so the harness and the audit agree by construction rather than
    by both hard-coding ``mp_checksum``.
    """

    for evidence in field_by_role(ir, "checksum").evidence:
        if evidence.kind != "checksum_comparison":
            continue
        match = _CALL_HEAD.search(evidence.snippet)
        if match:
            return match.group(1)
    raise AssertionError(
        "the mined checksum field carries no checksum_comparison evidence naming "
        "a helper, so the harness cannot be told which function repairs it"
    )


def opcode_range(ir: ProtocolIR) -> tuple[int, int]:
    """``(low, high)`` for the opcode field, from the contract's own value line."""

    field = field_by_role(ir, "opcode")
    match = _OPCODE_RANGE.search(str(field.value))
    if match is None:
        raise AssertionError(
            f"the mined opcode field describes {field.value!r}, which names no "
            "opcode range for the harness to draw from"
        )
    low, high = int(match.group(1)), int(match.group(2))
    if not 0 < low <= high < 256:
        raise AssertionError(f"mined opcode range {low}..{high} is not a byte range")
    return low, high


# -- building the harness the mock returns ---------------------------------


def structured_harness(ir: ProtocolIR) -> str:
    """A harness whose every structural element is read out of ``ir``.

    The offsets, the magic and version bytes, the payload cap, the lifecycle
    expressions and the loop bound all come from the mined contract, so a mining
    regression cannot leave a stale literal behind here.
    """

    if ir.context is None or ir.sequence is None:
        raise AssertionError("the mined IR carries no context or sequence block")
    magic = fields_with_role(ir, "magic")
    version = field_by_role(ir, "version")
    opcode = field_by_role(ir, "opcode")
    length = field_by_role(ir, "payload_length")
    checksum = field_by_role(ir, "checksum")

    header = ir.frame.header_size
    payload = ir.frame.payload_offset
    cap = ir.frame.max_payload_symbol
    steps = ir.sequence.max_steps["value"]
    low, high = opcode_range(ir)
    helper = checksum_helper(ir)

    return f"""#include <stddef.h>
#include <stdint.h>
#include <string.h>
extern "C" {{
#include "target.c"
}}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{{
    {ir.context.type} ctx = {{0}};
    {ir.context.init};

    size_t pos = 0;
    for (unsigned step = 0; step < {steps} && size - pos >= 2; ++step) {{
        uint8_t op = (uint8_t)({low} + (data[pos++] % {high - low + 1}));
        size_t requested = (size_t)(data[pos++] % ({cap} + 1u));
        size_t payload_len = requested < size - pos ? requested : size - pos;

        uint8_t frame[{header} + {cap}] = {{0}};
        frame[{magic[0].offset}] = {magic[0].value};
        frame[{magic[1].offset}] = {magic[1].value};
        frame[{version.offset}] = {version.value};
        frame[{opcode.offset}] = op;
        frame[{length.offset}] = (uint8_t)(payload_len & 0xff);
        frame[{length.offset + 1}] = (uint8_t)(payload_len >> 8);
        memcpy(frame + {payload}, data + pos, payload_len);
        uint16_t sum = {helper}(frame + {payload}, payload_len);
        frame[{checksum.offset}] = (uint8_t)(sum & 0xff);
        frame[{checksum.offset + 1}] = (uint8_t)(sum >> 8);

        volatile int status = mp_parse(&ctx, frame, {header} + payload_len);
        (void)status;
        pos += payload_len;
    }}

    {ir.context.destroy};
    return 0;
}}"""


def elements_of(ir: ProtocolIR) -> dict[str, tuple[str, ...]]:
    """``element -> the published text that has to show it``."""

    magic = fields_with_role(ir, "magic")
    version = field_by_role(ir, "version")
    opcode = field_by_role(ir, "opcode")
    length = field_by_role(ir, "payload_length")
    checksum = field_by_role(ir, "checksum")
    payload = ir.frame.payload_offset
    cap = ir.frame.max_payload_symbol
    steps = ir.sequence.max_steps["value"]

    return {
        "bounded loop": (f"for (unsigned step = 0; step < {steps} &&",),
        "context init/destroy": (f"{ir.context.init};", f"{ir.context.destroy};"),
        "frame buffer": (f"uint8_t frame[{ir.frame.header_size} + {cap}]",),
        "magic/version": (
            f"frame[{magic[0].offset}] = {magic[0].value};",
            f"frame[{magic[1].offset}] = {magic[1].value};",
            f"frame[{version.offset}] = {version.value};",
        ),
        "opcode": (f"frame[{opcode.offset}] = op;",),
        "length repair": (
            f"frame[{length.offset}] = (uint8_t)(payload_len & 0xff);",
            f"frame[{length.offset + 1}] = (uint8_t)(payload_len >> 8);",
        ),
        "checksum repair": (
            f"uint16_t sum = {checksum_helper(ir)}(frame + {payload}, payload_len);",
            f"frame[{checksum.offset}] = (uint8_t)(sum & 0xff);",
        ),
        # The payload is copied through, and both the opcode and the length the
        # frame is built with are drawn from the fuzzer's own bytes -- so the
        # structure is the contract's and the content is the input's.
        "payload copy/fuzz control": (
            f"memcpy(frame + {payload}, data + pos, payload_len);",
            "size_t requested = (size_t)(data[pos++] % (",
            "size_t payload_len = requested < size - pos ? requested : size - pos;",
        ),
    }


def target_crash_seed(ir: ProtocolIR) -> bytes:
    """A fuzzer input the *target's own* defects make crash, deterministically.

    The harness consumes ``data[0]`` as the opcode and ``data[1]`` as the
    payload length, so the seed is written the way the harness reads it: the top
    of the mined opcode range selects the last handler (``mp_parse``'s
    nested-length case), a two-byte payload is the smallest the target's length
    check admits, and those two bytes hold an inner length of 1 -- which the
    handler compares against its destination capacity instead of against the
    payload it actually has, then reads.  Every constant here comes from the
    contract the harness itself was built from.
    """

    low, high = opcode_range(ir)
    payload = b"\x01\x00"
    return bytes([high - low, len(payload)]) + payload


# -- tests -----------------------------------------------------------------


class MinedProtocolEndToEndTests(Stage4ProjectTests):
    """From ``target.c`` to a published harness, with nothing hand-supplied."""

    def e2e_root(self, name: str) -> Path:
        """An artifact root holding the FT's functions.json and the mined IR."""

        root = self.artifact_root(name)
        self.ir = mine_protocol_ir(root)
        return root

    def publish(self, root: Path, harness: str):
        """Stage 4 over ``root``, planned for the mined loop bound."""

        llm = MockLLM([
            self.harness_plan(bounded_steps=self.ir.sequence.max_steps["value"]),
            harness,
        ])
        return llm, Stage4Generator(llm).run(
            self.triplet,
            rough_code=self.rough_code(),
            functions_json=root / "functions.json",
            artifacts=root,
        )

    def published(self, root: Path) -> Path:
        """The stable artifact a later stage compiles, from the real layout."""

        return ArtifactStore(root).for_triplet(self.triplet.id).harness

    # -- 1. mining ---------------------------------------------------------

    def test_mining_target_c_writes_the_ir_stage4_reads(self):
        root = self.artifact_root("e2e_mine")
        ir = mine_protocol_ir(root)

        self.assertEqual(
            sorted(path.name for path in root.glob("protocol_*.json")),
            ["protocol_candidates.json", "protocol_conventions.json",
             "protocol_ir.json"],
        )
        self.assertEqual(
            tuple(field.name for field in ir.frame.fields),
            ("magic0", "magic1", "version", "opcode", "payload_length",
             "checksum", "payload"),
        )
        self.assertEqual(ir.frame.header_size, 8)
        self.assertEqual(ir.frame.payload_offset, 8)
        self.assertEqual(ir.frame.max_payload_symbol, "MP_MAX_PAYLOAD")
        self.assertEqual(ir.context.type, "mp_context")
        self.assertEqual(ir.sequence.max_steps["value"], 32)
        # The two facts the harness builder needs that the frame offsets alone
        # do not carry, both recovered from the miner's provenance.
        self.assertEqual(checksum_helper(ir), "mp_checksum")
        self.assertEqual(opcode_range(ir), (1, 7))

    def test_the_hand_written_contract_is_never_discovered(self):
        """The benchmark's own ``protocol.json`` is not on this path.

        Proven rather than asserted: the only function that would find it is
        patched to explode, so a run that still publishes can only have got its
        contract from the miner.
        """

        root = self.artifact_root("e2e_no_hand_written")
        with mock.patch(
            "harness_generation.candidate.discover_protocol_spec",
            side_effect=AssertionError("the hand-written contract was read"),
        ):
            self.ir = mine_protocol_ir(root)
            self.publish(root, structured_harness(self.ir))

        self.assertTrue(self.published(root).is_file())

    # -- 2. publication ----------------------------------------------------

    def test_stage4_publishes_the_structured_harness(self):
        root = self.e2e_root("e2e_publish")
        _, result = self.publish(root, structured_harness(self.ir))

        published = self.published(root)
        self.assertEqual(published, root / "harnesses" / f"{self.triplet.id}.c")
        self.assertTrue(published.is_file(), "the harness was validated but not written")
        self.assertEqual(published.read_text(encoding="utf-8"),
                         result.harness_code + "\n")

        # The audit recorded how the ISF was fed, and it is the harness's own
        # assembled frame rather than the fuzzer's buffer.
        attempt = json.loads((
            root / "generation" / self.triplet.id / "stage4" / "attempt_001"
            / "parsed.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(attempt["status"], "passed")
        self.assertEqual(attempt["input_connection"]["kind"], "repaired_frame")
        self.assertEqual(attempt["input_connection"]["isf"], "mp_parse")
        self.assertEqual(attempt["input_connection"]["buffer_argument"], "frame")

    def test_every_structural_element_is_in_the_published_artifact(self):
        """The eight elements, read back off the file a later stage compiles."""

        root = self.e2e_root("e2e_elements")
        self.publish(root, structured_harness(self.ir))
        text = self.published(root).read_text(encoding="utf-8")

        elements = elements_of(self.ir)
        self.assertEqual(tuple(elements), ELEMENTS)
        for element, needles in elements.items():
            for needle in needles:
                with self.subTest(element=element, needle=needle):
                    self.assertIn(needle, text)

    def test_the_published_harness_follows_the_contract_not_a_literal(self):
        """Renaming the payload cap in the source renames it in the artifact.

        Nothing on this path may carry ``MP_MAX_PAYLOAD`` as a string: the cap
        is whatever the miner measured.  The source it measures is a renamed
        copy, so the module-level ``SOURCE`` is left alone.
        """

        renamed = SOURCE.read_bytes().replace(b"MP_MAX_PAYLOAD", b"MP_LIMIT")
        self.assertIn(b"MP_LIMIT = 64", renamed)
        variant = Path(self.temporary.name) / "renamed_target.c"
        variant.write_bytes(renamed)

        root = self.artifact_root("e2e_renamed")
        self.ir = mine_protocol_ir(root, source=variant)
        self.assertEqual(self.ir.frame.max_payload_symbol, "MP_LIMIT")

        self.publish(root, structured_harness(self.ir))
        text = self.published(root).read_text(encoding="utf-8")
        self.assertIn("uint8_t frame[8 + MP_LIMIT]", text)
        self.assertNotIn("MP_MAX_PAYLOAD", text)

    # -- 3. and the same harness without the IR is still refused -----------

    def test_without_the_mined_ir_the_same_harness_is_refused(self):
        """The relaxation is conditional on the IR, and this is the condition.

        Same harness, same project, IR the only difference -- so a change that
        made the audit permissive in general would fail here.
        """

        with_ir = self.e2e_root("e2e_conditional")
        without_ir = self.artifact_root("e2e_conditional_none")
        harness = structured_harness(self.ir)

        self.publish(with_ir, harness)
        with self.assertRaises(Stage4Error) as caught:
            self.publish(without_ir, harness)

        self.assertIn("outside the FT", str(caught.exception))
        self.assertTrue(self.published(with_ir).is_file())
        self.assertFalse(self.published(without_ir).exists())


@unittest.skipUnless(LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON)
class PublishedHarnessBuildTests(Stage4ProjectTests):
    """The published artifact is a program, not a document."""

    @classmethod
    def setUpClass(cls):
        """Mine, publish once, and let both tests build the same artifact."""

        super().setUpClass()
        cls.root = Path(cls.temporary.name) / "e2e_build"
        cls.root.mkdir()
        shutil.copy2(cls.phase1 / "functions.json", cls.root / "functions.json")
        cls.ir = mine_protocol_ir(cls.root)
        Stage4Generator(MockLLM([
            cls.harness_plan(cls, bounded_steps=cls.ir.sequence.max_steps["value"]),
            structured_harness(cls.ir),
        ])).run(
            cls.triplet,
            rough_code=cls.rough_code(),
            functions_json=cls.root / "functions.json",
            artifacts=cls.root,
        )
        cls.published = ArtifactStore(cls.root).for_triplet(cls.triplet.id).harness
        if not cls.published.is_file():
            raise AssertionError("Stage 4 published nothing to build")

    def build(self) -> Path:
        """Compile and link the published artifact, with the repo's own flags."""

        executable = self.root / "fuzzer"
        command = [
            "clang++",
            *DEFAULT_HARNESS_COMPILE_FLAGS,
            *DEFAULT_FUZZER_LINK_FLAGS,
            "-I", str(Path(self.temporary.name) / "project"),
            "-o", str(executable),
            str(self.published),
        ]
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=300, check=False
        )
        self.assertEqual(
            completed.returncode, 0,
            f"clang++ failed for the published harness:\n{completed.stderr[-4000:]}",
        )
        self.assertTrue(executable.is_file())
        return executable

    def test_the_published_artifact_compiles_and_links(self):
        self.build()

    def test_running_it_reaches_the_target_defect_and_not_a_harness_one(self):
        """A crash here is the *target's*, and it is recorded as one.

        This is the assertion that keeps the two failure modes apart.  The
        harness is expected to reach ``mp_parse``'s own bugs -- that is what it
        is for -- so a sanitizer report naming ``target.c`` passes and is kept
        as evidence.  A report naming the harness file would mean the generated
        code is broken, and that fails.
        """

        executable = self.build()
        corpus = self.root / "seed"
        corpus.mkdir()
        (corpus / "nested_length").write_bytes(target_crash_seed(self.ir))

        # Both the working directory and the artifact prefix are redirected into
        # the test's own temporary root: libFuzzer drops a ``crash-<sha1>`` file
        # next to whatever it is pointed at, and inheriting the repository root
        # would leave one there on every run.
        crashes = self.root / "crashes"
        crashes.mkdir()
        completed = subprocess.run(
            [str(executable), "-runs=16", f"-artifact_prefix={crashes}/",
             str(corpus)],
            capture_output=True, text=True, timeout=300, check=False,
            cwd=self.root,
        )
        report = completed.stdout + completed.stderr
        (self.root / "fuzz_report.txt").write_text(report, encoding="utf-8")

        crashed = "ERROR: AddressSanitizer" in report or "runtime error:" in report
        self.assertTrue(
            crashed,
            "the seeded input reached no sanitizer report; the published harness "
            "may no longer read its input the way it was built to\n"
            f"{report[-4000:]}",
        )

        # Whatever the sanitizer stopped on, the frame that stopped it has to be
        # the target's own source.  ``#0`` is the top of the stack.
        frames = [
            line.strip() for line in report.splitlines()
            if line.strip().startswith("#0 ")
        ]
        self.assertTrue(frames, f"no stack frame in the report\n{report[-2000:]}")
        top = frames[0]
        self.assertIn("target.c:", top, f"the top frame is not target code: {top}")
        self.assertNotIn(self.published.name, top)

        # And the crash is attributed, not treated as a harness failure: Stage 4
        # published before any of this ran, and nothing here rolls it back.
        self.assertEqual(
            json.loads((
                self.root / "generation" / self.triplet.id / "stage4"
                / "attempt_001" / "parsed.json"
            ).read_text(encoding="utf-8"))["status"],
            "passed",
        )
        self.assertTrue(self.published.is_file())


if __name__ == "__main__":
    unittest.main()
