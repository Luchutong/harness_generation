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

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from harness_generation.artifacts import (
    PROTOCOL_CONVENTIONS_NOT_INFERRED,
    PROTOCOL_CONVENTIONS_NOT_INFERRED_KEY,
)
from harness_generation.cli import main
from harness_generation.llm import LLMConfig, LLMError, MockLLM, OpenAICompatibleLLM
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


def _provider_environment(base_url="https://llm.example.test/v1"):
    """A complete LLM_* configuration pointing nowhere a test can reach."""

    return {
        "LLM_BASE_URL": base_url,
        "LLM_API_KEY": "unit-test-only",
        "LLM_MODEL": "configured-model",
    }


def _chat_completions_response(content):
    return {
        "id": "chatcmpl-unit-test",
        "model": "configured-model",
        "choices": [{"finish_reason": "stop", "message": {"content": content}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }


@contextmanager
def _silent_endpoint():
    """A local TCP port that accepts connections and then never answers.

    This is the failure the timeout flag exists to bound.  It is deliberately a
    localhost socket rather than a mock: a mock cannot be slow, and being able
    to be slow is the entire property under test.  Nothing here leaves the
    machine.
    """

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    accepted = []

    def accept_forever():
        while True:
            try:
                connection, _ = server.accept()
            except OSError:
                return
            # Accepted and then deliberately ignored: the client blocks reading
            # the response until its own timeout expires.
            accepted.append(connection)

    threading.Thread(target=accept_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.getsockname()[1]}/v1"
    finally:
        server.close()
        for connection in accepted:
            connection.close()


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

    # -- bounding the wait -------------------------------------------------

    def test_llm_timeout_bounds_the_wait_against_a_silent_endpoint(self):
        # The behavioural proof for --llm-timeout.  Three samples against a
        # reachable but silent endpoint, with per-sample timeouts that add up
        # because the sample loop asks for them one after another.  With the
        # 120s LLMConfig default this exact invocation is allowed up to
        # 3 x 120 = 360s; the flag has to turn that into a wait a person would
        # sit through, which is why this test must pass a short timeout rather
        # than accept the default.
        with _silent_endpoint() as base_url:
            started = time.monotonic()
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.dict(
                os.environ, _provider_environment(base_url), clear=True
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                code = main([
                    "protocol-mine",
                    "--source", str(SOURCE),
                    "--function", FUNCTION,
                    "--output", str(self.output),
                    "--with-llm",
                    "--samples", "3",
                    "--llm-timeout", "1",
                ])
            elapsed = time.monotonic() - started

        self.assertEqual(code, 1, stderr.getvalue())
        # Deliberately generous: the claim under test is that the wait is
        # bounded, not that it is bounded to the millisecond.
        self.assertLess(elapsed, 20.0)
        # And a floor, so a run that gave up early for an unrelated reason --
        # a refused connection, a rejected argument -- cannot pass this test.
        self.assertGreater(elapsed, 1.0)
        self.assertIn("Protocol mining failed", stderr.getvalue())
        # The wait expired before any sample was usable, so nothing was mined
        # and no artifact root was created.
        self.assertFalse(self.output.exists())

    def test_a_silent_endpoint_reads_as_a_timeout_not_as_a_bad_response(self):
        # A timeout is a statement about the clock.  Reporting it as an invalid
        # response sends the reader hunting for a malformed body that does not
        # exist, which is the misdiagnosis a short --llm-timeout is most likely
        # to produce, so the wording is pinned here.
        with _silent_endpoint() as base_url:
            client = OpenAICompatibleLLM(
                LLMConfig(
                    model="configured-model",
                    base_url=base_url,
                    api_key_env_name="LLM_API_KEY",
                    timeout=1.0,
                ),
                environ={"LLM_API_KEY": "unit-test-only"},
            )
            with self.assertRaises(LLMError) as caught:
                client.generate("unit-test prompt", prompt_version="unit-test-v1")

        message = str(caught.exception)
        self.assertIn("timed out", message)
        self.assertNotIn("invalid OpenAI-compatible response", message)
        # What actually arrives at the error handler is builtins.TimeoutError,
        # not a bespoke socket class: socket.timeout is an alias of it on this
        # Python, and http.client raises it out of the blocking read.  Pinning
        # the class keeps the handler catching the exception that really occurs
        # rather than one that merely looks like it should.
        self.assertIs(socket.timeout, TimeoutError)
        self.assertIsInstance(caught.exception.__cause__, TimeoutError)

    def test_the_requested_timeout_reaches_the_provider(self):
        captured = {}
        responses = [_sample() for _ in range(3)]

        def fake_provider(config, **_kwargs):
            captured["config"] = config
            return MockLLM(responses)

        with patch(
            "harness_generation.llm_config.OpenAICompatibleLLM",
            new=fake_provider,
        ), patch.dict(
            os.environ, _provider_environment(), clear=True
        ):
            code, _, stderr = self._run(
                "--with-llm", "--samples", "3", "--llm-timeout", "1.5"
            )

        self.assertEqual(code, 0, stderr)
        self.assertEqual(captured["config"].timeout, 1.5)

    def test_an_absent_timeout_leaves_the_provider_default_in_place(self):
        captured = {}
        responses = [_sample() for _ in range(3)]

        def fake_provider(config, **_kwargs):
            captured["config"] = config
            return MockLLM(responses)

        with patch(
            "harness_generation.llm_config.OpenAICompatibleLLM",
            new=fake_provider,
        ), patch.dict(
            os.environ, _provider_environment(), clear=True
        ):
            code, _, stderr = self._run("--with-llm", "--samples", "3")

        self.assertEqual(code, 0, stderr)
        # Read from LLMConfig rather than written out, so this test cannot
        # become a second copy of the number it is checking is not duplicated.
        declared = LLMConfig(
            model="configured-model",
            base_url="https://llm.example.test/v1",
            api_key_env_name="LLM_API_KEY",
        ).timeout
        self.assertEqual(captured["config"].timeout, declared)

    def test_the_summary_states_the_worst_case_for_the_real_provider(self):
        # The transport is replaced, not the client, so the summary still reads
        # the effective timeout off a real provider object and no request is
        # made.
        with patch.dict(
            os.environ, _provider_environment(), clear=True
        ), patch(
            "harness_generation.llm._post_json",
            lambda *_args: _chat_completions_response(_sample()),
        ):
            code, stdout, stderr = self._run(
                "--with-llm", "--samples", "3", "--llm-timeout", "1"
            )

        self.assertEqual(code, 0, stderr)
        # 3 samples x 1s, added rather than guessed: the loop is sequential.
        self.assertIn("samples=3 timeout=1s worst_case=3s", stdout)

    def test_the_summary_reports_no_timeout_for_a_mock(self):
        mock_path = self.temporary / "mock.json"
        mock_path.write_text(
            json.dumps({"responses": [_sample() for _ in range(3)]}),
            encoding="utf-8",
        )
        code, stdout, stderr = self._run(
            "--with-llm", "--samples", "3", "--llm-timeout", "7",
            "--mock-responses", str(mock_path),
        )

        self.assertEqual(code, 0, stderr)
        # A mock does not wait, so it has no wall-clock bound to quote: naming
        # one would be a number with no referent.
        self.assertIn("timeout=n/a worst_case=n/a", stdout)
        self.assertNotIn("timeout=7s", stdout)

    def test_the_summary_says_nothing_about_time_without_an_llm(self):
        code, stdout, stderr = self._run()

        self.assertEqual(code, 0, stderr)
        # No samples are requested and no provider is resolved in this mode, so
        # there is no exposure to report and no line pretending otherwise.
        self.assertNotIn("worst_case", stdout)
        self.assertNotIn("samples=", stdout)

    def test_injected_llm_with_a_timeout_is_refused_loudly(self):
        # The injected client was built by the caller, timeout included.  Doing
        # nothing with the flag would leave a user who asked for a 10-second
        # bound with no bound and no notice, so the run fails instead.
        code, stdout, stderr = self._run(
            "--with-llm", "--llm-timeout", "5", llm=MockLLM([_sample()])
        )

        self.assertEqual(code, 1)
        self.assertIn("cannot combine an injected LLM with provider options", stderr)
        self.assertIn("--llm-timeout", stderr)
        self.assertFalse(self.output.exists())
        self.assertNotIn("Protocol mining:", stdout)

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

    def test_llm_timeout_usage_errors_are_rejected_by_the_parser(self):
        self.assertIn(
            "--llm-timeout requires --with-llm",
            self._usage_error("--llm-timeout", "1"),
        )
        # inf and nan both parse as floats, so each has to be rejected on its
        # own: `inf > 0` is True, and `nan` compares False against everything.
        for value in ("0", "-1", "inf", "nan"):
            with self.subTest(value=value):
                self.assertIn(
                    "--llm-timeout must be a positive number of seconds",
                    self._usage_error("--with-llm", "--llm-timeout", value),
                )
        self.assertIn(
            "invalid float value",
            self._usage_error("--with-llm", "--llm-timeout", "soon"),
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
