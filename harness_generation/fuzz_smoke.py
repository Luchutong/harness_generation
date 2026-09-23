"""Short, bounded libFuzzer smoke execution for one Function Triplet."""

from __future__ import annotations

import math
import os
import re
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .artifacts import ArtifactStore
from .records import write_json
from .runtime_validation import (ARTIFACT_CRASH_PREFIXES, CRASH_NONE,
                                 GENERATED_HARNESS_CRASH, GENERATED_HARNESS_LEAK,
                                 LEAK_ARTIFACT_PREFIX, POTENTIAL_TARGET_CRASH,
                                 classify_crash)
from .validation import VALIDATION_SCHEMA_VERSION, ValidationResult


_STAT_FIELD = re.compile(r"stat::(?P<name>[A-Za-z0-9_]+):\s*(?P<value>[0-9]+(?:\.[0-9]+)?)")
_PULSE_FIELD = {
    "cov": re.compile(r"\bcov:\s*(\d+)"),
    "ft": re.compile(r"\bft:\s*(\d+)"),
    "corp": re.compile(r"\bcorp:\s*(\d+)(?:/\S+)?"),
    "execs_per_sec": re.compile(r"\bexec/s:\s*(\d+(?:\.\d+)?)"),
    "crashes": re.compile(r"\bcrashes:\s*(\d+)"),
    "ooms": re.compile(r"\booms:\s*(\d+)"),
    "timeouts": re.compile(r"\btimeouts:\s*(\d+)"),
}
_STAT_ALIASES = {
    "number_of_executed_units": "execs_done",
    "average_exec_per_sec": "execs_per_sec",
}
_EXECUTION_PULSE = re.compile(
    r"^#(?P<count>\d+)\s+(?:INITED|NEW|REDUCE|pulse|DONE)\b",
    re.MULTILINE,
)
_CRASH_PREFIXES = ARTIFACT_CRASH_PREFIXES
_DEFAULT_SEEDS = (
    ("empty", b""),
    ("zero", b"\x00"),
    ("ascii", b"A"),
    ("small", b"\x00\x01\xff"),
)


@dataclass(frozen=True)
class LibFuzzerSmokeConfig:
    """Bounded smoke settings; campaign durations outside 30--120s are invalid."""

    duration_seconds: int = 60
    process_timeout_seconds: float | None = None

    def __post_init__(self) -> None:
        if isinstance(self.duration_seconds, bool) or not isinstance(
            self.duration_seconds, int
        ) or not 30 <= self.duration_seconds <= 120:
            raise ValueError("libFuzzer smoke duration must be an integer from 30 to 120")
        timeout = self.process_timeout_seconds
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= self.duration_seconds
        ):
            raise ValueError("process timeout must be finite and exceed smoke duration")

    @property
    def wall_timeout(self) -> float:
        return (
            float(self.process_timeout_seconds)
            if self.process_timeout_seconds is not None
            else float(self.duration_seconds + 15)
        )


Runner = Callable[..., subprocess.CompletedProcess[str]]


class LibFuzzerSmokeValidator:
    """Run a real libFuzzer process and preserve all evidence for one attempt."""

    def __init__(
        self,
        config: LibFuzzerSmokeConfig | None = None,
        *,
        runner: Runner = subprocess.run,
    ) -> None:
        self.config = config or LibFuzzerSmokeConfig()
        self.runner = runner

    def validate_triplet(
        self,
        executable: str | Path | None,
        *,
        artifacts: str | Path,
        ft_id: str,
        generated_sources: Sequence[str | Path],
        target_root: str | Path,
        stage: str = "stage4_fuzz_smoke",
    ) -> ValidationResult:
        layout = ArtifactStore(Path(artifacts)).for_triplet(ft_id)
        attempt, directory = layout.next_fuzz_smoke()
        corpus = directory / "corpus"
        crashes = directory / "crashes"
        corpus.mkdir()
        crashes.mkdir()
        for name, data in _DEFAULT_SEEDS:
            (corpus / name).write_bytes(data)

        executable_path = _available_executable(executable)
        command: tuple[str, ...] = ()
        if executable_path is not None:
            command = (
                str(executable_path),
                f"-max_total_time={self.config.duration_seconds}",
                "-print_final_stats=1",
                "-seed=1",
                f"-artifact_prefix={crashes.resolve()}{os.sep}",
                str(corpus.resolve()),
            )
        (directory / "command.txt").write_text(
            (shlex.join(command) + "\n") if command else "",
            encoding="utf-8",
        )

        started_at = datetime.now(timezone.utc)
        started = time.monotonic()
        stdout = ""
        stderr = ""
        return_code: int | None = None
        timed_out = False
        start_error: str | None = None
        if executable_path is None:
            start_error = _unavailable_reason(executable)
        else:
            try:
                completed = self.runner(
                    list(command),
                    cwd=directory.resolve(),
                    capture_output=True,
                    text=True,
                    timeout=self.config.wall_timeout,
                    check=False,
                    env=_fuzz_environment(),
                )
                return_code = completed.returncode
                stdout = _text(completed.stdout)
                stderr = _text(completed.stderr)
            except subprocess.TimeoutExpired as error:
                timed_out = True
                stdout = _text(error.stdout)
                stderr = _text(error.stderr)
            except OSError as error:
                start_error = f"libFuzzer executable could not be started: {error}"

        (directory / "stdout.txt").write_text(stdout, encoding="utf-8")
        (directory / "stderr.txt").write_text(stderr, encoding="utf-8")
        combined = "\n".join((stdout, stderr))
        statistics, final_stats_present = parse_final_stats(combined, crashes)
        write_json(
            directory / "final_stats.json",
            {"schema_version": 1, **statistics},
            sort_keys=True,
            allow_nan=False,
        )

        crash_files = sorted(
            str(path.relative_to(directory))
            for path in crashes.iterdir()
            if path.is_file() and path.name.startswith(_CRASH_PREFIXES)
        )
        attribution = classify_crash(
            stderr,
            generated_sources=generated_sources,
            target_root=target_root,
            # A saved `leak-` input is libFuzzer's own verdict. Hold it beside
            # the sanitizer report so a leak is classified as a leak even when
            # the crash text is truncated by the wall timeout above.
            leaked=any(Path(name).name.startswith(LEAK_ARTIFACT_PREFIX)
                       for name in crash_files),
        ) if return_code not in (None, 0) else {
            "classification": CRASH_NONE, "top_frame": None,
            "attribution_frame": None, "stack_parser_status": "not_needed",
        }
        initialized = _initialized(combined)
        status, errors, warnings = _policy(
            return_code=return_code,
            timed_out=timed_out,
            start_error=start_error,
            initialized=initialized,
            final_stats_present=final_stats_present,
            statistics=statistics,
            attribution=attribution,
            crash_files=crash_files,
        )
        elapsed = round(time.monotonic() - started, 3)
        finished_at = datetime.now(timezone.utc)
        signal_number = (
            -return_code if return_code is not None and return_code < 0 else None
        )
        metadata = {
            "schema_version": VALIDATION_SCHEMA_VERSION,
            "ft_id": ft_id,
            "stage": stage,
            "attempt": attempt,
            "status": status,
            "duration_seconds": self.config.duration_seconds,
            "wall_timeout_seconds": self.config.wall_timeout,
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "elapsed_seconds": elapsed,
            "executable": None if executable_path is None else str(executable_path),
            "command": list(command),
            "return_code": return_code,
            "signal": signal_number,
            "signal_name": _signal_name(signal_number),
            "timed_out": timed_out,
            "initialized": initialized,
            "final_stats_present": final_stats_present,
            "crash_classification": attribution["classification"],
            "top_frame": attribution["top_frame"],
            "attribution_frame": attribution["attribution_frame"],
            "stack_parser_status": attribution["stack_parser_status"],
            "crash_inputs": crash_files,
            "corpus_files": sorted(path.name for path in corpus.iterdir()),
            "statistics": statistics,
            "errors": errors,
            "warnings": warnings,
        }
        if start_error is not None:
            metadata["reason"] = start_error
        write_json(
            directory / "metadata.json", metadata, sort_keys=True, allow_nan=False
        )
        result_metadata: dict[str, Any] = {
            "validator": "fuzz_smoke",
            "stage": stage,
            "failure_type": _failure_type(status, attribution["classification"], timed_out),
            "failed_stage": "fuzz_smoke" if status == "failed" else None,
            "attempt": attempt,
            "artifact_directory": str(directory),
            "statistics": statistics,
            "crash_classification": attribution["classification"],
        }
        return ValidationResult(
            success=(True if status in {"passed", "passed_with_limitations"}
                     else None if status in {"skipped", "unavailable"} else False),
            errors=tuple(errors),
            warnings=tuple(warnings),
            metadata=result_metadata,
            status=status,
        )


def parse_final_stats(text: str, crash_directory: str | Path) -> tuple[dict[str, Any], bool]:
    """Parse only observed libFuzzer statistics and isolated saved artifacts."""

    stats: dict[str, Any] = {}
    final_stats_present = False
    for match in _STAT_FIELD.finditer(text):
        name = match.group("name")
        value = _number(match.group("value"))
        if name == "number_of_executed_units":
            final_stats_present = True
        alias = _STAT_ALIASES.get(name)
        if alias is not None:
            stats[alias] = value
    for name, pattern in _PULSE_FIELD.items():
        matches = tuple(pattern.finditer(text))
        # Prefer the explicit final-stat value over an earlier progress pulse.
        if matches and name not in stats:
            stats[name] = _number(matches[-1].group(1))
    if "execs_done" not in stats:
        pulses = tuple(_EXECUTION_PULSE.finditer(text))
        if pulses:
            stats["execs_done"] = int(pulses[-1].group("count"))

    crash_path = Path(crash_directory)
    if crash_path.is_dir():
        names = [path.name for path in crash_path.iterdir() if path.is_file()]
        # These are observations from this empty-at-start attempt directory.
        stats.setdefault("crashes", sum(name.startswith(("crash-", "leak-")) for name in names))
        stats.setdefault("ooms", sum(name.startswith("oom-") for name in names))
        stats.setdefault("timeouts", sum(name.startswith("timeout-") for name in names))
    return stats, final_stats_present


def _policy(
    *,
    return_code: int | None,
    timed_out: bool,
    start_error: str | None,
    initialized: bool,
    final_stats_present: bool,
    statistics: Mapping[str, Any],
    attribution: Mapping[str, Any],
    crash_files: Sequence[str],
) -> tuple[str, list[str], list[str]]:
    classification = attribution["classification"]
    if start_error is not None:
        return "unavailable", [], [start_error]
    if timed_out:
        return "failed", ["libFuzzer smoke exceeded its explicit wall timeout"], []
    if classification == GENERATED_HARNESS_LEAK:
        return (
            "failed",
            ["libFuzzer smoke leaked a target resource; the generated harness "
             "did not release what it acquired"],
            [],
        )
    if classification == GENERATED_HARNESS_CRASH:
        return "failed", ["libFuzzer smoke crashed in generated harness code"], []
    if classification == POTENTIAL_TARGET_CRASH:
        if not initialized:
            return "failed", ["libFuzzer initialization was not observed before target crash"], []
        if statistics.get("execs_done", 0) <= 0:
            return "failed", ["no executed input was observed before target crash"], []
        warnings = ["libFuzzer smoke found a potential target crash; preserved for triage"]
        if not crash_files:
            warnings.append("libFuzzer did not leave a crash input artifact")
        return "passed_with_limitations", [], warnings
    if return_code not in (None, 0):
        return "failed", ["libFuzzer smoke exited nonzero and crash attribution is unavailable"], []
    if not initialized:
        return "failed", ["libFuzzer initialization was not observed"], []
    if statistics.get("execs_done", 0) <= 0:
        return "failed", ["libFuzzer smoke did not execute any inputs"], []
    if not final_stats_present:
        return "failed", ["libFuzzer final statistics were not observed"], []
    return "passed", [], []


def _available_executable(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    candidate = Path(value).expanduser().resolve()
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        return None
    return candidate


def _unavailable_reason(value: str | Path | None) -> str:
    if value is None:
        return "libFuzzer executable was not provided"
    return f"libFuzzer executable is missing or not executable: {Path(value).expanduser().resolve()}"


def _initialized(text: str) -> bool:
    return bool(
        re.search(r"^INFO:\s+(?:Seed:|Running with )", text, re.MULTILINE)
    )


def _number(value: str) -> int | float:
    return float(value) if "." in value else int(value)


def _signal_name(number: int | None) -> str | None:
    if number is None:
        return None
    try:
        return signal.Signals(number).name
    except ValueError:
        return None


def _failure_type(status: str, classification: str, timed_out: bool) -> str | None:
    if status != "failed":
        return None
    if timed_out:
        return "fuzz_smoke_timeout"
    if classification == GENERATED_HARNESS_LEAK:
        return GENERATED_HARNESS_LEAK
    if classification == GENERATED_HARNESS_CRASH:
        return GENERATED_HARNESS_CRASH
    return "fuzz_smoke_failure"


def _fuzz_environment() -> dict[str, str]:
    # The fuzzer needs no provider credentials. Keep its process environment small.
    environment = {
        key: os.environ[key]
        for key in ("PATH", "LANG", "LC_ALL", "TMPDIR")
        if key in os.environ
    }
    environment["ASAN_OPTIONS"] = "abort_on_error=1:symbolize=1"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    return environment


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
