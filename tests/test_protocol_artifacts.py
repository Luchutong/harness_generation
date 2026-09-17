"""Persisting the protocol artifacts must be additive and lossless.

Three things carry most of the weight here:

``test_writing_leaves_preexisting_artifacts_byte_identical``
    compares every pre-existing file's *contents* before and after a write, so
    "additive" is measured rather than assumed.

``test_absent_conventions_are_recorded_as_not_inferred``
    pins the difference between "no inference was run" and "the vote produced
    nothing", which an empty document would blur.

Every test works on a copy of the checked-in fixture, never on the fixture
itself: ``artifacts/simple`` is committed to git and other tests read it.
"""

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from harness_generation.artifacts import (
    PROTOCOL_CONVENTIONS_NOT_INFERRED,
    PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY,
    ArtifactStore,
)
from harness_generation.llm import MockLLM
from harness_generation.protocol_conventions import infer_protocol_conventions
from harness_generation.protocol_ir import (
    PROTOCOL_IR_SCHEMA_VERSION,
    SOURCE_ENGINEERING,
    ProtocolIR,
)
from harness_generation.protocol_miner import (
    PROTOCOL_MINER_SCHEMA_VERSION,
    ROLE_PAYLOAD_LENGTH,
    mine_protocol_facts,
)


ROOT = Path(__file__).resolve().parents[1]
MINI_PARSER = ROOT / "benchmarks" / "mini_parser"
SIMPLE_ARTIFACTS = ROOT / "artifacts" / "simple"


def _sample(max_steps=32):
    """One plausible convention sample for ``mp_parse``, as the LLM returns it."""

    return json.dumps({
        "schema_version": 1,
        "sequence_model": {
            "multi_frame": True,
            "reason": "stateful opcodes need several frames sharing one context",
            "evidence": ["MP_STORE saves state and MP_USE reads it"],
            "max_steps": {
                "value": max_steps,
                "source": "engineering_choice",
                "evidence": ["a bounded command loop is a harness policy"],
            },
        },
        "context": {
            "type": "mp_context",
            "init": "mp_init",
            "destroy": "mp_destroy",
            "lifetime": "one context per fuzz iteration",
            "evidence": ["mp_init/mp_destroy are the lifecycle helpers"],
        },
        "stateful_operations": [
            {
                "opcode": "MP_STORE",
                "reason": "stores the payload pointer in mp_context",
                "evidence": ["case MP_STORE sets ctx->saved and ctx->saved_len"],
            },
            {
                "opcode": "MP_USE",
                "reason": "reads previously stored mp_context state",
                "evidence": ["case MP_USE reads ctx->saved"],
            },
        ],
        "requirements": [
            "repair magic/length/checksum envelope fields before mp_parse",
            "preserve payload bytes as fuzzer-controlled data",
        ],
        "notes": ["keep one mp_context alive across generated frames"],
    })


def _contested_sample(lifetime: str) -> str:
    """``_sample()`` with one field answered differently, nothing else touched."""

    document = json.loads(_sample())
    document["context"]["lifetime"] = lifetime
    return json.dumps(document)


def _artifact_copy(parent: Path, name: str = "simple") -> Path:
    """A writable copy of the checked-in fixture, in a temporary directory."""

    destination = parent / name
    shutil.copytree(SIMPLE_ARTIFACTS, destination)
    return destination


def _snapshot(root: Path) -> dict[str, bytes]:
    """Every file under ``root``, keyed by relative path, by content."""

    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class ProtocolArtifactPersistenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source_text = (MINI_PARSER / "target.c").read_text(encoding="utf-8")
        cls.facts = mine_protocol_facts(
            (MINI_PARSER / "target.c").read_bytes(), "mp_parse", filename="target.c"
        )

    def _infer(self, responses: list[str]):
        return infer_protocol_conventions(
            self.facts,
            self.source_text,
            MockLLM(responses),
            samples=len(responses),
        )

    def _run_conventions(self):
        """A realistic inference result: two valid samples and one rejection."""

        return self._infer([_sample(), _sample(), "this is not json"])

    def _store(self, temporary: str, name: str = "simple") -> ArtifactStore:
        return ArtifactStore(_artifact_copy(Path(temporary), name))

    # -- paths and round-trips ---------------------------------------------

    def test_three_artifacts_land_at_the_documented_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            written = store.write_protocol(self.facts, self._run_conventions())

            self.assertEqual(
                written,
                (
                    store.protocol_candidates,
                    store.protocol_conventions,
                    store.protocol_ir,
                ),
            )
            self.assertEqual(
                [path.name for path in written],
                [
                    "protocol_candidates.json",
                    "protocol_conventions.json",
                    "protocol_ir.json",
                ],
            )
            for path in written:
                self.assertTrue(path.is_file(), path)
                self.assertEqual(path.parent, store.root)
                # Every document is JSON with a trailing newline, as write_json
                # writes it; a truncated write would fail here.
                self.assertTrue(path.read_text(encoding="utf-8").endswith("\n"))

    def test_store_root_is_created_without_other_catalogs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "artifacts" / "fresh"
            store = ArtifactStore(root)
            self.assertFalse(root.exists())

            store.write_protocol(self.facts)

            self.assertTrue(store.protocol_ir.is_file())
            # The three files live at the root, which is all this stage owns:
            # no Phase 2 subdirectory is conjured up on the way.
            self.assertEqual(
                sorted(path.name for path in root.iterdir()),
                [
                    "protocol_candidates.json",
                    "protocol_conventions.json",
                    "protocol_ir.json",
                ],
            )

    def test_candidates_round_trip_to_the_same_facts(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            store.write_protocol(self.facts, self._run_conventions())
            document = json.loads(
                store.protocol_candidates.read_text(encoding="utf-8")
            )

            self.assertEqual(document, self.facts.to_json())
            self.assertEqual(
                document["schema_version"], PROTOCOL_MINER_SCHEMA_VERSION
            )
            self.assertEqual(document["entry_function"], "mp_parse")
            self.assertEqual(document["source"], "target.c")
            self.assertEqual(document["header_size"], 8)
            # Evidence travels with the facts; a facts file that kept only the
            # shape would round-trip empty.
            by_name = {item["name"]: item for item in document["fields"]}
            self.assertTrue(by_name["magic0"]["evidence"])
            self.assertIn("line", by_name["payload_length"]["evidence"][0])
            self.assertEqual(
                by_name["payload_length"]["role"], ROLE_PAYLOAD_LENGTH
            )

    def test_conventions_round_trip_preserves_samples_and_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            result = self._run_conventions()
            store.write_protocol(self.facts, result)
            document = json.loads(
                store.protocol_conventions.read_text(encoding="utf-8")
            )

            self.assertEqual(document, result.to_json())
            self.assertEqual(
                document["accepted_samples"],
                [dict(item) for item in result.accepted_samples],
            )
            self.assertEqual(
                document["rejected_samples"],
                [dict(item) for item in result.rejected_samples],
            )
            # Every sample that came back is kept, including the one that failed
            # to parse: the raw responses are how a bad vote gets audited.
            self.assertEqual(len(document["generations"]), 3)
            self.assertEqual(len(document["accepted_samples"]), 2)
            metadata = document["conventions"]["metadata"]
            self.assertEqual(metadata["model"], "mock-model")
            self.assertEqual(metadata["provider"], "mock")
            self.assertEqual(metadata["samples_requested"], 3)
            self.assertEqual(metadata["valid_samples"], 2)
            self.assertEqual(len(metadata["rejected_samples"]), 1)
            self.assertEqual(
                document["conventions"]["sequence_model"]["max_steps"]["value"], 32
            )
            # ``vote_summary`` is what the vote tallied field by field: the value
            # it selected, the count that value reached, how many samples
            # answered, and the losing candidates when there were any.  It is
            # written by the vote itself, in the same pass that selected the
            # value, so a reader can trust it as a description of this run rather
            # than a count taken afterwards by the writer.
            self.assertEqual(
                sorted(metadata),
                [
                    "model",
                    "prompt_version",
                    "provider",
                    "rejected_samples",
                    "samples_requested",
                    "valid_samples",
                    "vote_summary",
                    "vote_threshold",
                ],
            )
            self.assertIn("vote_summary", document["conventions"]["metadata"])

    def test_ir_round_trip_matches_to_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            result = self._run_conventions()
            store.write_protocol(self.facts, result)
            document = json.loads(store.protocol_ir.read_text(encoding="utf-8"))

            expected = ProtocolIR.from_facts_and_conventions(
                self.facts, result.conventions
            )
            self.assertEqual(document, expected.to_json())
            self.assertEqual(document["schema_version"], PROTOCOL_IR_SCHEMA_VERSION)
            # 2 of 3 requested samples parsed (0.6667) and the two that parsed
            # were byte-identical, so every field agreed (1.0) and the product
            # stays at the validity.  The number is unchanged from the old
            # parsed-sample ratio because this run has nothing to disagree about;
            # `test_the_persisted_vote_explains_a_low_confidence` is the case
            # where the two forms part company.
            self.assertEqual(document["confidence"], 0.6667)
            self.assertEqual(
                document["metadata"]["vote_summary"]["confidence"],
                {
                    "sample_validity": 0.6667,
                    "mean_field_agreement": 1.0,
                    "fields_counted": sorted(
                        document["metadata"]["vote_summary"]["fields"]
                    ),
                    "value": 0.6667,
                },
            )
            self.assertEqual(document["context"]["type"], "mp_context")
            self.assertEqual(
                [item["opcode"] for item in document["stateful_operations"]],
                ["MP_STORE", "MP_USE"],
            )

    def test_the_persisted_vote_explains_a_low_confidence(self):
        """The repro, read off the two files the way a consumer reads them.

        Three samples that all parse but give three different context lifetimes
        used to produce the same ``confidence`` as three identical ones.  A
        reader must now be able to see *why* this run's number is lower without
        re-running the vote: the IR's confidence is the vote's own value, and the
        field that cost it names the answers that lost.
        """

        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            store.write_protocol(self.facts, self._infer([
                _contested_sample("one context per fuzz iteration"),
                _contested_sample("one context for the whole process"),
                _contested_sample("unknown"),
            ]))

            conventions = json.loads(
                store.protocol_conventions.read_text(encoding="utf-8")
            )
            ir = json.loads(store.protocol_ir.read_text(encoding="utf-8"))
            metadata = conventions["conventions"]["metadata"]
            summary = metadata["vote_summary"]
            entry = summary["fields"]["context.lifetime"]

            # The three answers are all there, each with a single vote, and the
            # one that won is the value the C block carries.
            self.assertEqual(
                entry["alternatives"],
                {
                    "one context per fuzz iteration": 1,
                    "one context for the whole process": 1,
                    "unknown": 1,
                },
            )
            # A three-way tie is broken by the candidate's string form, which is
            # how the vote has always broken ties; on a tie the C block gets the
            # first answer alphabetically rather than the first one returned.
            self.assertEqual(entry["selected"], "one context for the whole process")
            self.assertEqual(entry["votes"], 1)
            self.assertEqual(entry["valid_samples"], 3)
            self.assertEqual(entry["agreement"], 0.3333)
            self.assertEqual(
                conventions["conventions"]["context"]["lifetime"],
                entry["selected"],
            )
            # The lost vote is what the confidence is made of: eight fields, one
            # of them at 1/3, gives 0.9167 -- and 0.0833 is the whole difference
            # between a stable inference and this one.
            self.assertEqual(summary["confidence"]["sample_validity"], 1.0)
            self.assertEqual(summary["confidence"]["mean_field_agreement"], 0.9167)
            self.assertEqual(summary["confidence"]["value"], 0.9167)
            self.assertIn("context.lifetime", summary["confidence"]["fields_counted"])
            # The IR makes the same claim as the file it was built from; the two
            # are not two computations of one number.
            self.assertEqual(ir["confidence"], summary["confidence"]["value"])

    def test_default_max_steps_fills_a_bound_the_vote_left_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            result = self._infer([_sample(max_steps=None), _sample(max_steps=None)])
            self.assertIsNone(
                result.conventions.sequence_model.max_steps["value"]
            )

            # No sample measured a bound, so the default fills it -- and is
            # labelled as an engineering choice rather than a finding.
            store.write_protocol(self.facts, result, default_max_steps=8)
            document = json.loads(store.protocol_ir.read_text(encoding="utf-8"))
            max_steps = document["sequence_model"]["max_steps"]
            self.assertEqual(max_steps["value"], 8)
            self.assertEqual(max_steps["source"], SOURCE_ENGINEERING)

    # -- additivity --------------------------------------------------------

    def test_writing_leaves_preexisting_artifacts_byte_identical(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            before = _snapshot(store.root)
            fixture_before = _snapshot(SIMPLE_ARTIFACTS)

            store.write_protocol(self.facts, self._run_conventions())

            after = _snapshot(store.root)
            added = set(after) - set(before)
            self.assertEqual(
                added,
                {
                    "protocol_candidates.json",
                    "protocol_conventions.json",
                    "protocol_ir.json",
                },
            )
            self.assertEqual(set(before) - set(after), set())
            for name, content in before.items():
                with self.subTest(artifact=name):
                    self.assertEqual(after[name], content)
            # The copy is what gets written to; the committed fixture is read-only.
            self.assertEqual(_snapshot(SIMPLE_ARTIFACTS), fixture_before)

    def test_no_temporary_file_survives_a_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            store.write_protocol(self.facts, self._run_conventions())
            self.assertEqual([path.name for path in store.root.rglob("*.tmp")], [])

            # Rewriting an existing artifact replaces it atomically too.
            store.write_protocol(self.facts, self._run_conventions())
            self.assertEqual([path.name for path in store.root.rglob("*.tmp")], [])

    # -- an absent C block is a result, not an empty vote ------------------

    def test_absent_conventions_are_recorded_as_not_inferred(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            store.write_protocol(self.facts)
            document = json.loads(
                store.protocol_conventions.read_text(encoding="utf-8")
            )

            self.assertIs(document["conventions"], None)
            self.assertIs(document[PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY], True)
            self.assertEqual(document["entry_function"], "mp_parse")
            self.assertEqual(document["reason"], PROTOCOL_CONVENTIONS_NOT_INFERRED)
            self.assertIn("not inferred", document["reason"])
            # Nothing here may read as a vote that found no conventions.
            self.assertNotIn("metadata", document)
            self.assertEqual(document["accepted_samples"], [])
            self.assertEqual(document["rejected_samples"], [])
            self.assertEqual(document["generations"], [])

    def test_the_not_inferred_marker_fails_safe_for_a_successful_inference(self):
        """A missing marker must mean the C block is there, never the reverse.

        The inferred document is written verbatim as ``to_json()`` produces it,
        so a *positive* ``inferred`` key would have to be absent from it -- and
        ``document.get("inferred")`` would then read ``None``, i.e. false, for a
        run that inferred perfectly well.  Any consumer testing the flag the
        obvious way would drop a valid C block.  Spelling the marker in the
        negative makes the same check fail toward "the block is present".
        """

        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            store.write_protocol(self.facts, self._run_conventions())
            inferred = json.loads(store.protocol_conventions.read_text(encoding="utf-8"))

            self.assertNotIn(PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY, inferred)
            self.assertIsNone(inferred.get(PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY))
            self.assertIsNotNone(inferred["conventions"])

            # And the marker is not merely renamed: it must be asserted the
            # other way, or the flag would be true for both documents.
            store.write_protocol(self.facts)
            absent = json.loads(store.protocol_conventions.read_text(encoding="utf-8"))

            self.assertIs(absent[PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY], True)
            self.assertIsNone(absent["conventions"])

    def test_absent_conventions_are_visible_in_the_ir(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            store.write_protocol(self.facts)
            document = json.loads(store.protocol_ir.read_text(encoding="utf-8"))

            self.assertNotIn("sequence_model", document)
            self.assertNotIn("context", document)
            self.assertEqual(document["stateful_operations"], [])
            self.assertTrue(
                any(
                    "convention block is absent" in item
                    for item in document["limitations"]
                ),
                document["limitations"],
            )
            self.assertEqual(document["confidence"], 0.6)

    def test_write_protocol_conventions_accepts_no_inference_at_all(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            path = store.write_protocol_conventions()

            self.assertEqual(path, store.protocol_conventions)
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document["entry_function"], "")
            self.assertIs(document[PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY], True)

    # -- already-serialised documents --------------------------------------

    def test_serialised_documents_are_written_verbatim(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            result = self._run_conventions()
            candidates = self.facts.to_json()
            conventions = result.to_json()
            ir = ProtocolIR.from_facts_and_conventions(
                self.facts, result.conventions
            ).to_json()

            store.write_protocol(candidates, conventions, ir)

            for path, expected in (
                (store.protocol_candidates, candidates),
                (store.protocol_conventions, conventions),
                (store.protocol_ir, ir),
            ):
                with self.subTest(artifact=path.name):
                    self.assertEqual(
                        json.loads(path.read_text(encoding="utf-8")), expected
                    )

    def test_merging_a_serialised_half_is_refused_rather_than_guessed(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)
            candidates = self.facts.to_json()
            conventions = self._run_conventions().to_json()

            with self.assertRaisesRegex(ValueError, "pass ir explicitly"):
                store.write_protocol(candidates, conventions)
            with self.assertRaisesRegex(ValueError, "pass ir explicitly"):
                store.write_protocol(candidates)
            with self.assertRaisesRegex(ValueError, "ConventionInferenceResult"):
                # Facts are the dataclass, but the C block is only a document.
                store.write_protocol(self.facts, conventions)

            # The merge runs before the first write, so a refusal leaves the
            # root exactly as it was.
            self.assertEqual(
                sorted(path.name for path in store.root.glob("protocol_*.json")),
                [],
            )

    def test_unknown_document_kinds_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = self._store(temporary)

            with self.assertRaisesRegex(ValueError, "ProtocolFacts"):
                store.write_protocol_candidates(["not", "facts"])
            with self.assertRaisesRegex(ValueError, "ConventionInferenceResult"):
                store.write_protocol_conventions("not conventions")
            with self.assertRaisesRegex(ValueError, "ProtocolIR"):
                store.write_protocol_ir("not an ir")


if __name__ == "__main__":
    unittest.main()
