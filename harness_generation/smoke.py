"""Fixed-input checks before fuzzing; these are not reachability measurements."""

import hashlib
from pathlib import Path

from .fuzz import run_logged
from .records import write_json
from .runtime_validation import classify_crash

SMOKE_SUITE_VERSION = "1"
SMOKE_INPUTS = (
    ("empty", b""),
    ("one_zero", b"\x00"),
    ("one_ff", b"\xff"),
    ("two_zero", b"\x00\x00"),
    ("eight_zero", b"\x00" * 8),
    ("ascending_32", bytes(range(32))),
    ("ff_4096", b"\xff" * 4096),
)


def run_smoke(output: Path) -> dict:
    directory = output / "smoke"
    directory.mkdir()
    cases = []
    for name, data in SMOKE_INPUTS:
        path = directory / (name + ".bin")
        path.write_bytes(data)
        cases.append({"name": name, "input": str(path.relative_to(output)), "size": len(data),
                      "sha256": hashlib.sha256(data).hexdigest(), "status": "not_started"})
    result = {"status": "running", "suite_version": SMOKE_SUITE_VERSION,
              "isolation": "fresh_process_per_case", "requested_cases": len(cases), "cases": cases}
    try:
        for case in cases:
            name = case["name"]
            # File arguments select libFuzzer replay mode, with no mutation.
            command = ["./fuzz_target", case["input"], "-runs=1", "-timeout=2",
                       "-rss_limit_mb=512", "-seed=1", "-artifact_prefix=smoke/"]
            write_json(directory / (name + "_command.json"), command)
            case["status"] = "running"
            write_json(output / "smoke_result.json", result)
            run = run_logged(output, command, 7, f"smoke/{name}_stdout.txt", f"smoke/{name}_stderr.txt")
            diagnostic = (directory / (name + "_stderr.txt")).read_text(errors="replace")
            if run["status"] in ("completed", "error") and any(marker in diagnostic for marker in (
                "ERROR: AddressSanitizer:", "ERROR: LeakSanitizer:", "runtime error:", "ERROR: libFuzzer:",
            )):
                run["status"] = "finding"
                run["crash_classification"] = classify_crash(
                    diagnostic,
                    generated_sources=(output / "harness.c",),
                    target_root=output,
                )
            elif run["status"] == "completed" and "Executed " not in diagnostic:
                run.update(status="error", error="libFuzzer replay completion was not observed")
            case.update(run, stdout=f"smoke/{name}_stdout.txt", stderr=f"smoke/{name}_stderr.txt")
            if run["status"] != "completed":
                result["status"] = run["status"]
                if run["status"] == "finding":
                    result["crash_classification"] = run.get("crash_classification")
                break
        else:
            result["status"] = "passed"
    except KeyboardInterrupt:
        result["status"] = "interrupted"
        case["status"] = "interrupted"
    except OSError as exc:
        result.update(status="error", error=str(exc))
        case["status"] = "error"
    finally:
        result["completed_cases"] = sum(c["status"] == "completed" for c in cases)
        result["attempted_cases"] = sum(c["status"] != "not_started" for c in cases)
        result["elapsed_seconds"] = round(sum(c.get("elapsed_seconds", 0) for c in cases), 3)
        result["artifacts"] = sorted(str(p.relative_to(output)) for p in directory.iterdir()
                                     if p.is_file() and p.name.startswith(("crash-", "timeout-", "oom-", "leak-")))
        write_json(output / "smoke_result.json", result)
    return result
