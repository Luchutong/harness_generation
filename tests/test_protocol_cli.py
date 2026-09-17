"""The ``protocol-mine`` subcommand: two modes, one persistence path.

The property that carries most of the weight is the one that is *absent* from a
successful run: without a usable LLM configuration, ``--with-llm`` fails and
leaves nothing behind.  A mock, an empty C block, or a ``not_inferred`` marker
would all look plausible to a downstream stage and would all be fabrications, so
``test_missing_llm_configuration_fails_loudly_and_writes_nothing`` pins the
output root itself rather than only the exit code.

Every test writes into a temporary directory.  Nothing here touches the
checked-in ``artifacts/`` fixtures, which other tests read.
"""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from harness_generation.artifacts import (
    PROTOCOL_CONVENTIONS_NOT_INFERRED,
    PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY,
)
from harness_generation.cli import main
from harness_generation.llm import MockLLM
from harness_generation.protocol_cli import _print_limitations
from harness_generation.protocol_conventions import (
    ContextModel,
    ProtocolConventions,
    SequenceModel,
)
from harness_generation.protocol_ir import ProtocolIR
from harness_generation.protocol_miner import ProtocolFacts, mine_protocol_facts


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "benchmarks" / "mini_parser" / "target.c"
FUNCTION = "mp_parse"
ARTIFACTS = (
    "protocol_candidates.json",
    "protocol_conventions.json",
    "protocol_ir.json",
)


def _sample(*, max_steps=32, stateful=True):
    """One plausible convention sample for ``mp_parse``, as the LLM returns it."""

    operations = []
    if stateful:
        operations = [
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
        ]
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
        "stateful_operations": operations,
        "requirements": [
            "repair magic/length/checksum envelope fields before mp_parse",
        ],
        "notes": ["keep one mp_context alive across generated frames"],
    })


class ProtocolMineCLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temporary = Path(temporary.name)
        self.output = self.temporary / "artifacts" / "mini_parser"

    def _run(self, *extra, llm=None, source=SOURCE):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(
                [
                    "protocol-mine",
                    "--source", str(source),
                    "--function", FUNCTION,
                    "--output", str(self.output),
                    *extra,
                ],
                llm=llm,
            )
        return code, stdout.getvalue(), stderr.getvalue()

    def _usage_error(self, *extra, function=FUNCTION, source=SOURCE):
        stderr = io.StringIO()
        # The environment is cleared so a usage error is decided by the
        # arguments alone, whatever the developer's shell has configured.
        with patch.dict(os.environ, {}, clear=True), redirect_stdout(
            io.StringIO()
        ), redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            main([
                "protocol-mine",
                "--source", str(source),
                "--function", function,
                "--output", str(self.output),
                *extra,
            ])
        self.assertEqual(caught.exception.code, 2)
        # A usage error is decided before anything is mined or written.
        self.assertFalse(self.output.exists())
        return stderr.getvalue()

    def _read(self, name: str) -> dict:
        return json.loads((self.output / name).read_text(encoding="utf-8"))

    # -- the two modes -----------------------------------------------------

    def test_default_mode_mines_the_facts_without_an_llm(self):
        code, stdout, stderr = self._run()

        self.assertEqual(code, 0, stderr)
        self.assertEqual(stderr, "")
        facts = mine_protocol_facts(
            SOURCE.read_bytes(), FUNCTION, filename=SOURCE.name
        )
        self.assertEqual(
            json.loads(
                (self.output / "protocol_candidates.json").read_text(encoding="utf-8")
            ),
            facts.to_json(),
        )

        # The C block is absent *as a statement*: the file exists so a reader
        # need not handle a missing path, and says plainly that nothing was
        # inferred rather than looking like a vote that found no conventions.
        conventions = self._read("protocol_conventions.json")
        self.assertIs(conventions[PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY], True)
        self.assertIsNone(conventions["conventions"])
        self.assertEqual(conventions["reason"], PROTOCOL_CONVENTIONS_NOT_INFERRED)
        self.assertEqual(conventions["entry_function"], FUNCTION)
        self.assertNotIn("metadata", conventions)
        self.assertEqual(conventions["accepted_samples"], [])
        self.assertEqual(conventions["generations"], [])

        # The IR is merged from the A/B half alone.
        ir = self._read("protocol_ir.json")
        self.assertNotIn("context", ir)
        self.assertNotIn("sequence_model", ir)
        self.assertEqual(ir["stateful_operations"], [])
        self.assertEqual(ir["entry_function"], FUNCTION)
        self.assertTrue(any("convention block is absent" in item
                            for item in ir["limitations"]))

        self.assertIn(f"Protocol mining: {FUNCTION}", stdout)
        self.assertIn(f"Fields: {len(facts.fields)}", stdout)
        self.assertIn(f"Opcodes: {len(facts.opcodes)}", stdout)
        self.assertIn(
            "Context: not inferred (run with --with-llm to infer the C block)", stdout
        )
        self.assertIn("Stateful ops: not inferred", stdout)
        self.assertIn("Limitations: ", stdout)
        for name in ARTIFACTS:
            self.assertIn(str(self.output / name), stdout)

    def test_with_llm_infers_the_c_block_and_merges_it(self):
        llm = MockLLM([_sample(), _sample(), _sample()])
        code, stdout, stderr = self._run("--with-llm", "--samples", "3", llm=llm)

        self.assertEqual(code, 0, stderr)
        # Three samples were asked for, and all three were voted on.
        self.assertEqual(len(llm.calls), 3)
        self.assertEqual(
            {call["prompt_name"] for call in llm.calls},
            {"protocol_convention_refinement"},
        )

        conventions = self._read("protocol_conventions.json")
        self.assertNotIn(PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY, conventions)
        self.assertEqual(conventions["conventions"]["entry_function"], FUNCTION)
        self.assertEqual(
            conventions["conventions"]["metadata"]["samples_requested"], 3
        )
        self.assertEqual(conventions["conventions"]["metadata"]["valid_samples"], 3)
        self.assertEqual(
            conventions["conventions"]["sequence_model"]["max_steps"]["value"], 32
        )

        ir = self._read("protocol_ir.json")
        self.assertEqual(ir["entry_function"], FUNCTION)
        self.assertEqual(ir["context"]["type"], "mp_context")
        self.assertEqual(ir["sequence_model"]["multi_frame"], True)
        self.assertEqual(
            [item["opcode"] for item in ir["stateful_operations"]],
            ["MP_STORE", "MP_USE"],
        )

        self.assertIn(
            "Context: mp_context (init=mp_init, destroy=mp_destroy, "
            "lifetime=one context per fuzz iteration)",
            stdout,
        )
        self.assertIn("Stateful ops: 2 (MP_STORE, MP_USE)", stdout)
        self.assertNotIn("not inferred", stdout)

    def test_no_limitations_is_reported_plainly(self):
        # The miner always appends its own scope limitation today, so this line
        # has no input that reaches it yet.  It is exercised directly because a
        # summary that silently prints nothing, or an empty list, would read as
        # "there is nothing left open" without ever saying so.
        facts = ProtocolFacts(entry_function=FUNCTION, filename="target.c")
        ir = ProtocolIR.from_facts_and_conventions(
            facts,
            ProtocolConventions(
                entry_function=FUNCTION,
                sequence_model=SequenceModel(multi_frame=False),
                context=ContextModel(),
            ),
        )
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            _print_limitations(facts, ir)

        self.assertEqual(stdout.getvalue(), "Limitations: none\n")

    def test_a_vote_that_finds_no_stateful_opcode_is_not_the_same_as_no_llm(self):
        llm = MockLLM([_sample(stateful=False) for _ in range(3)])
        code, stdout, stderr = self._run("--with-llm", llm=llm)

        self.assertEqual(code, 0, stderr)
        self.assertEqual(self._read("protocol_ir.json")["stateful_operations"], [])
        self.assertIn("Stateful ops: none", stdout)
        self.assertNotIn("Stateful ops: not inferred", stdout)

    # -- no silent fallback ------------------------------------------------

    def test_missing_llm_configuration_fails_loudly_and_writes_nothing(self):
        stderr = io.StringIO()
        stdout = io.StringIO()
        # Nothing is injected and no LLM_* variable is visible: the only honest
        # answer is to fail.  clear=True makes this independent of the shell the
        # tests happen to run in.
        with patch.dict(os.environ, {}, clear=True), redirect_stdout(
            stdout
        ), redirect_stderr(stderr):
            code = main([
                "protocol-mine",
                "--source", str(SOURCE),
                "--function", FUNCTION,
                "--output", str(self.output),
                "--with-llm",
            ])

        self.assertNotEqual(code, 0)
        self.assertIn("missing LLM configuration", stderr.getvalue())
        for name in ("LLM_BASE_URL", "LLM_API_KEY", "LLM_MODEL"):
            self.assertIn(name, stderr.getvalue())
        # Nothing was written -- not a mock C block, not an empty one, not even
        # the two files that needed no LLM.  The root was not created on the way
        # either, so a reader cannot find a partial artifact tree.
        self.assertFalse(self.output.exists())
        self.assertFalse(self.output.parent.exists())
        self.assertEqual(sorted(self.temporary.iterdir()), [])
        self.assertNotIn("Protocol mining:", stdout.getvalue())

    def test_an_unusable_vote_fails_before_writing(self):
        # Every sample is rejected, so there is no C block to merge.  Inferring
        # "nothing" from unusable responses would be a silent fallback by
        # another name.
        code, _, stderr = self._run("--with-llm", llm=MockLLM(["not json"]))

        self.assertEqual(code, 1)
        self.assertIn("no valid protocol convention samples", stderr)
        self.assertFalse(self.output.exists())

    def test_a_missing_source_fails_cleanly(self):
        code, _, stderr = self._run(source=self.temporary / "missing.c")

        self.assertEqual(code, 1)
        self.assertIn("Protocol mining failed", stderr)
        self.assertFalse(self.output.exists())

    # -- usage errors ------------------------------------------------------

    def test_usage_errors_are_rejected_by_the_parser(self):
        self.assertIn(
            "--function must be a C identifier", self._usage_error(function="1bad")
        )
        self.assertIn(
            "--source must be a .c file",
            self._usage_error(source=self.temporary / "target.txt"),
        )
        self.assertIn(
            "--samples requires --with-llm", self._usage_error("--samples", "2")
        )
        self.assertIn(
            "--samples must be positive",
            self._usage_error("--with-llm", "--samples", "0"),
        )
        self.assertIn(
            "--model, --mock-responses and --recorded-responses require --with-llm",
            self._usage_error("--mock-responses", str(self.temporary / "mock.json")),
        )

    # -- re-running --------------------------------------------------------

    def test_rerunning_over_an_existing_root_is_safe(self):
        self.output.mkdir(parents=True)
        for _ in range(2):
            code, _, stderr = self._run()
            self.assertEqual(code, 0, stderr)
        code, _, stderr = self._run(
            "--with-llm", llm=MockLLM([_sample()] * 3)
        )
        self.assertEqual(code, 0, stderr)

        self.assertEqual(
            sorted(path.name for path in self.output.iterdir()), sorted(ARTIFACTS)
        )
        # Derived artifacts are rewritten atomically: no partial file survives.
        self.assertEqual([path.name for path in self.output.rglob("*.tmp")], [])
        self.assertNotIn(PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY,
                         self._read("protocol_conventions.json"))

    def test_module_cli_reaches_the_subcommand(self):
        completed = subprocess.run(
            [
                sys.executable, "-m", "harness_generation", "protocol-mine",
                "--source", str(SOURCE),
                "--function", FUNCTION,
                "--output", str(self.output),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn(f"Protocol mining: {FUNCTION}", completed.stdout)
        self.assertEqual(
            sorted(path.name for path in self.output.iterdir()), sorted(ARTIFACTS)
        )


if __name__ == "__main__":
    unittest.main()
