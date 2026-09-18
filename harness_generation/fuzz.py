"""Bounded local libFuzzer execution and artifact collection (Linux/POSIX)."""

import hashlib
import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path

from .runtime_validation import classify_crash


def stop_process(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_fuzzer(output: Path, seconds: int, corpus: Path | None = None, *,
               runs: int | None = None, seed: int = 1) -> dict:
    """Run one bounded libFuzzer session over ``output``'s compiled target.

    ``seconds`` is the budget by default and the wall-clock safety cap always.
    ``runs`` switches the budget itself from wall-clock to executions: the
    session stops after that many inputs instead of when the clock runs out.
    The distinction matters when two harnesses are being compared, because a
    wall-clock budget buys each arm a *different* number of executions -- the
    execution rates differ -- and coverage counted at unequal work is not a
    comparison.  ``seconds`` still bounds the process either way, so a run that
    overshoots its wall cap is reported as ``wall_timeout`` rather than
    finishing early.

    ``seed`` is which libFuzzer seed to run with, and it matters for the same
    reason: repeating one harness at a fixed seed and a fixed ``runs`` replays
    the same search twice, so the repeats measure determinism and not
    robustness.  Independent samples need distinct seeds.  The validator paths
    that bound a *single* harness (smoke, fuzz smoke) deliberately keep the
    fixed default.
    """

    work = output / "corpus"
    artifacts = output / "artifacts"
    work.mkdir()
    artifacts.mkdir()
    if corpus is not None:
        # Copy, rather than mutate the caller's seed directory. Flat files only.
        for path in sorted(corpus.iterdir()):
            if path.is_file() and not path.is_symlink():
                data = path.read_bytes()
                (work / hashlib.sha256(data).hexdigest()).write_bytes(data)
    budget = f"-runs={runs}" if runs is not None else f"-max_total_time={seconds}"
    command = ["./fuzz_target", "corpus", budget,
               "-timeout=2", "-rss_limit_mb=512", "-max_len=4096", f"-seed={seed}",
               "-artifact_prefix=artifacts/", "-print_final_stats=1"]
    (output / "fuzz_command.json").write_text(json.dumps(command, indent=2) + "\n")
    result = run_logged(output, command, seconds + 7, "fuzz_stdout.txt", "fuzz_stderr.txt")
    result.update(requested_seconds=seconds, seed=seed, requested_runs=runs)
    stats = {}
    findings = set()
    stderr_text = (output / "fuzz_stderr.txt").read_text(
        encoding="utf-8", errors="replace"
    )
    for line in stderr_text.splitlines():
        for label, key in (("cov", "coverage_edges_or_blocks"), ("ft", "features")):
            match = re.search(rf"\b{label}: (\d+)", line)
            if match:
                stats[key] = int(match[1])
        match = re.search(r"stat::(\w+):\s+(\d+)", line)
        if match:
            stats[match[1]] = int(match[2])
        if "ERROR: AddressSanitizer:" in line:
            findings.add("address_sanitizer")
        if "ERROR: LeakSanitizer:" in line:
            findings.add("leak_sanitizer")
        if "runtime error:" in line:
            findings.add("undefined_behavior")
        if "ERROR: libFuzzer:" in line:
            findings.add("libfuzzer_error")
    saved = sorted(str(path.relative_to(output)) for path in artifacts.iterdir() if path.is_file())
    failure_artifacts = [name for name in saved if Path(name).name.startswith(("crash-", "leak-", "timeout-", "oom-"))]
    if result["status"] in ("completed", "error") and (findings or failure_artifacts):
        result["status"] = "finding"
    if result["status"] == "finding":
        result["crash_classification"] = classify_crash(
            stderr_text,
            generated_sources=(output / "harness.c",),
            target_root=output,
        )
    else:
        result["crash_classification"] = {
            "classification": "none",
            "top_frame": None,
            "attribution_frame": None,
            "stack_parser_status": "not_applicable",
        }
    result.update(statistics=stats, findings=sorted(findings), artifacts=saved,
                  corpus_files=sum(path.is_file() for path in work.iterdir()))
    (output / "fuzz_result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def run_logged(output: Path, command: list[str], wall_timeout: int,
               stdout_file: str, stderr_file: str) -> dict:
    """Run one bounded process and preserve partial logs on interruption."""
    # Only the local compiler runtime needs this environment; do not pass API keys.
    environment = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL") if key in os.environ}
    environment.update(ASAN_OPTIONS="abort_on_error=1:detect_leaks=1:symbolize=1",
                       UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    started = time.monotonic()
    result = {"status": "error", "returncode": None, "wall_timeout_seconds": wall_timeout}
    with (output / stdout_file).open("wb") as stdout, (output / stderr_file).open("wb") as stderr:
        try:
            process = subprocess.Popen(command, cwd=output, stdout=stdout, stderr=stderr,
                                       env=environment, start_new_session=True)
            try:
                result["returncode"] = process.wait(timeout=wall_timeout)
                result["status"] = "completed" if process.returncode == 0 else "error"
            except subprocess.TimeoutExpired:
                stop_process(process)
                result.update(status="wall_timeout", returncode=process.returncode)
            except KeyboardInterrupt:
                stop_process(process)
                result.update(status="interrupted", returncode=process.returncode)
        except OSError as exc:
            result["error"] = str(exc)
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return result
