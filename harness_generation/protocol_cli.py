"""CLI for mining the A/B protocol facts and inferring the C convention block.

The two halves of a protocol contract come from different places, and this
command keeps their failure modes apart:

* :func:`~protocol_miner.mine_protocol_facts` recovers the **A** (frame format)
  and **B** (constant constraints) blocks statically.  It needs no LLM, so that
  is the default mode.
* :func:`~protocol_conventions.infer_protocol_conventions` infers the **C**
  block (command loop, context lifetime, stateful opcodes).  There is no offline
  substitute for it that would not be a fabrication, so ``--with-llm`` without a
  usable provider configuration is a hard error -- never a mock, an empty C
  block, or a ``not_inferred`` marker.  The key lookup is
  :func:`~llm_config.resolve_llm`, shared with ``generate`` rather than
  reimplemented: a second, subtly different lookup is exactly how a silent
  fallback reappears.

Both modes persist through :meth:`~artifacts.ArtifactStore.write_protocol`, so a
downstream stage reads the same three files either way.  Only the C block's
*content* is absent when nothing was inferred, and ``protocol_conventions.json``
says so explicitly rather than being missing.

Typical use::

    python -m harness_generation protocol-mine \\
      --source benchmarks/mini_parser/target.c --function mp_parse \\
      --output artifacts/mini_parser
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path
import re
import sys

from .artifacts import ArtifactStore
from .llm import LLMClient, LLMError
from .llm_config import resolve_llm
from .protocol_conventions import (
    ConventionInferenceResult,
    infer_protocol_conventions,
)
from .protocol_ir import ProtocolIR
from .protocol_miner import ProtocolFacts, mine_protocol_facts
from .source_analysis import SourceAnalysisError


DEFAULT_SAMPLES = 3

#: Printed for the two C-block lines when no inference ran at all.  The IR and
#: the conventions file carry the same statement in machine-readable form; this
#: is the human reading of it.
_NOT_INFERRED = "not inferred (run with --with-llm to infer the C block)"


def main(argv: list[str] | None = None, *, llm: LLMClient | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv or []))
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.function):
        parser.error("--function must be a C identifier")
    if args.source.suffix != ".c":
        parser.error("--source must be a .c file")
    # `--samples` defaults to None so an explicit value can be told apart from
    # the default: a request for C-block samples is meaningless without the
    # inference that uses them.
    if args.samples is not None and not args.with_llm:
        parser.error("--samples requires --with-llm")
    if (args.model or args.mock_responses or args.recorded_responses) and not args.with_llm:
        parser.error("--model, --mock-responses and --recorded-responses require --with-llm")
    if args.llm_timeout is not None and not args.with_llm:
        parser.error("--llm-timeout requires --with-llm")
    if args.fail_fast_on_llm_error and not args.with_llm:
        parser.error("--fail-fast-on-llm-error requires --with-llm")
    samples = DEFAULT_SAMPLES if args.samples is None else args.samples
    if samples < 1:
        parser.error("--samples must be positive")
    if args.llm_timeout is not None:
        # float("inf") and float("nan") both parse as floats, so the bound has
        # to be checked rather than assumed: `inf > 0` is True and would sail
        # through a positivity test, while every comparison against `nan` is
        # False, so `nan <= 0` would not reject it either.  isfinite is the
        # check that actually rules both out, and rejecting them here keeps the
        # failure a usage error instead of a traceback out of LLMConfig.
        if not math.isfinite(args.llm_timeout) or args.llm_timeout <= 0:
            parser.error("--llm-timeout must be a positive number of seconds")

    try:
        original = args.source.read_bytes()
        # The convention prompt is fed the source text, not the bytes.
        source_text = original.decode("utf-8")
        # Resolve the client before anything is mined or written: a missing key
        # has to fail leaving no artifact behind, so the output root must not be
        # touched on this path.
        client = (
            resolve_llm(
                llm,
                provider=None,
                model=args.model,
                mock_responses=args.mock_responses,
                recorded_responses=args.recorded_responses,
                # None means "leave LLMConfig's default alone"; the timeout is
                # not re-defaulted here, so llm.py stays its only owner.
                timeout=args.llm_timeout,
            )
            if args.with_llm
            else None
        )
        facts = mine_protocol_facts(original, args.function, filename=args.source.name)
        conventions = (
            infer_protocol_conventions(
                facts,
                source_text,
                client,
                samples=samples,
                fail_fast_on_llm_error=args.fail_fast_on_llm_error,
            )
            if client is not None
            else None
        )
        # One merge, used for both the persisted IR and the summary, so the two
        # cannot describe different models.
        ir = ProtocolIR.from_facts_and_conventions(
            facts, conventions.conventions if conventions is not None else None,
            strict=True,
        )
        written = ArtifactStore(args.output).write_protocol(facts, conventions, ir)
    except (OSError, ValueError, LLMError, SourceAnalysisError) as exc:
        # SourceAnalysisError is not a ValueError.  The miner raises it when the
        # tree-sitter runtime is unavailable, which is an environment problem
        # this CLI should report like any other rather than let reach the user
        # as a traceback; protocol_miner's own CLI catches it the same way.
        print(f"Protocol mining failed: {exc}", file=sys.stderr)
        return 1

    _print_summary(
        facts,
        ir,
        conventions,
        written,
        client=client,
        samples=samples,
        fail_fast=args.fail_fast_on_llm_error,
    )
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harness-generation protocol-mine",
        description=(
            "Mine the frame-format and constant blocks of a protocol contract, "
            "optionally inferring the convention block with an LLM"
        ),
    )
    parser.add_argument("--source", required=True, type=Path, help="C source to analyse")
    parser.add_argument("--function", required=True, help="Target C entry function")
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Artifact root; created if absent, and reused on a later run",
    )
    parser.add_argument(
        "--with-llm",
        action="store_true",
        help="Infer the C block with an LLM and merge it into the protocol IR",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=None,
        help=f"Convention samples to request; requires --with-llm (default: {DEFAULT_SAMPLES})",
    )
    providers = parser.add_mutually_exclusive_group()
    providers.add_argument(
        "--mock-responses",
        type=Path,
        help="Offline JSON list/object containing deterministic response strings",
    )
    providers.add_argument(
        "--recorded-responses",
        type=Path,
        help="Replay a versioned recorded-response JSON artifact",
    )
    parser.add_argument(
        "--fail-fast-on-llm-error",
        action="store_true",
        help=(
            "Stop at the first sample that fails instead of voting around it; "
            "requires --with-llm.  Disagreeing samples are not failures and are "
            "still voted on."
        ),
    )
    parser.add_argument("--model", help="Override LLM_MODEL for the real provider")
    # The default is None, not the number, so this flag never becomes a second
    # source of truth for the timeout: `None` means "do not override LLMConfig",
    # and the value that ends up in force is the one llm.py declares.
    parser.add_argument(
        "--llm-timeout",
        type=float,
        default=None,
        help=(
            "Per-sample LLM request timeout in seconds; requires --with-llm "
            "(default: the value LLMConfig declares)"
        ),
    )
    return parser


def _print_summary(
    facts: ProtocolFacts,
    ir: ProtocolIR,
    conventions: ConventionInferenceResult | None,
    written: tuple[Path, Path, Path],
    *,
    client: LLMClient | None = None,
    samples: int = DEFAULT_SAMPLES,
    fail_fast: bool = False,
) -> None:
    """Human-readable account of what was mined, inferred and written."""

    print(f"Protocol mining: {ir.entry_function}")
    print(f"Source: {ir.source_name}")
    print(f"Fields: {len(ir.frame.fields)}")
    # Opcodes are a B-block fact and live only in the facts; the IR keeps the
    # *stateful* opcodes, which are a C-block inference.
    print(f"Opcodes: {len(facts.opcodes)}")
    # Nothing was asked of any provider in the default mode -- there are no
    # samples and no timeout -- so the exposure line is absent rather than zero.
    if client is not None:
        print(_exposure_line(client, samples))
        print(_fail_fast_line(fail_fast))
    print(_context_line(ir, conventions))
    print(_stateful_line(ir, conventions))
    _print_limitations(facts, ir)
    print(f"Candidates: {written[0]}")
    print(f"Conventions: {written[1]}")
    print(f"IR: {written[2]}")


def _exposure_line(client: LLMClient, samples: int) -> str:
    """Report how long ``--with-llm`` can hold the process, before it does.

    ``worst_case`` is the sequential sum rather than a guess: the sample loop in
    :func:`~protocol_conventions.infer_protocol_conventions` calls
    ``llm.generate`` once per sample, one after another, so the samples'
    timeouts add up.  That multiplication is only an upper bound while the loop
    stays sequential -- if it ever becomes concurrent, this line stops being
    true and this comment is what should catch it.
    """

    # Read from the client that will actually be used, so the number printed is
    # the number in force.  A re-hardcoded 120 here would be the second source
    # of truth that --llm-timeout's None default exists to prevent.
    timeout = getattr(getattr(client, "config", None), "timeout", None)
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        # A mock or recorded-response client does not wait on anything, so it
        # has no wall-clock bound to report.  Printing the default for it would
        # quote a number with no referent: nothing in that client uses it, and
        # reading "120s" there would suggest a delay that cannot happen.
        return f"samples={samples} timeout=n/a worst_case=n/a"
    # ":g" renders seconds the way a person writes them -- "120", not "120.0".
    return f"samples={samples} timeout={timeout:g}s worst_case={samples * timeout:g}s"


def _fail_fast_line(fail_fast: bool) -> str:
    """State the sample-failure policy the run actually used.

    Printed as its own line rather than appended to the exposure line: the two
    describe different things.  A mock has no wall-clock bound to report and
    still has a failure policy -- a mock is in fact the easiest way to hand the
    loop an unusable response -- so folding them together would either drop the
    policy on that path or file a statement about failures under a timeout
    reading "n/a".  The state is named in both directions because a silent
    default is indistinguishable from a flag that was not understood.
    """

    return f"LLM fail-fast on error: {'enabled' if fail_fast else 'disabled'}"


def _context_line(
    ir: ProtocolIR, conventions: ConventionInferenceResult | None,
) -> str:
    if conventions is None or ir.context is None:
        return f"Context: {_NOT_INFERRED}"
    details = ", ".join(
        f"{key}={value}"
        for key, value in (
            ("init", ir.context.init),
            ("destroy", ir.context.destroy),
            ("lifetime", ir.context.lifetime),
        )
        if value
    )
    kind = ir.context.type or "unknown type"
    return f"Context: {kind} ({details})" if details else f"Context: {kind}"


def _stateful_line(
    ir: ProtocolIR, conventions: ConventionInferenceResult | None,
) -> str:
    # "the vote found none" and "nothing was asked" are different statements,
    # exactly as they are in protocol_conventions.json.
    if conventions is None:
        return f"Stateful ops: {_NOT_INFERRED}"
    operations = ir.stateful_operations
    if not operations:
        return "Stateful ops: none"
    opcodes = ", ".join(item.opcode for item in operations)
    return f"Stateful ops: {len(operations)} ({opcodes})"


def _print_limitations(facts: ProtocolFacts, ir: ProtocolIR) -> None:
    # The IR's list is the facts' list plus whatever the merge added; the union
    # is spelled out so this line cannot go stale if that relationship changes.
    limitations = list(dict.fromkeys([*facts.limitations, *ir.limitations]))
    if not limitations:
        print("Limitations: none")
        return
    print(f"Limitations: {len(limitations)}")
    for item in limitations:
        print(f"  - {item}")
