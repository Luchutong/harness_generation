"""Small, cached toolchain capability probes used by integration tests."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import shutil
import subprocess
import tempfile


@lru_cache(maxsize=1)
def libfuzzer_toolchain() -> tuple[bool, str]:
    """Require the tools and runtimes actually used by real build tests."""

    clang = shutil.which("clang")
    clangxx = shutil.which("clang++")
    archiver = shutil.which("ar")
    missing = [
        name for name, path in (
            ("clang", clang), ("clang++", clangxx), ("ar", archiver),
        ) if not path
    ]
    if missing:
        return False, "real compile/link skipped: missing " + ", ".join(missing)
    source = (
        "#include <stddef.h>\n#include <stdint.h>\n"
        "extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) "
        "{ (void)data; (void)size; return 0; }\n"
    )
    try:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "probe-fuzzer"
            completed = subprocess.run(
                [
                    str(clangxx), "-x", "c++", "-std=c++17", "-",
                    "-fsanitize=fuzzer,address,undefined", "-o", str(output),
                ],
                input=source,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if completed.returncode == 0 and output.is_file():
                return True, ""
    except (OSError, subprocess.TimeoutExpired):
        pass
    return (
        False,
        "real compile/link skipped: clang++ libFuzzer/ASan/UBSan runtime unavailable",
    )


LIBFUZZER_AVAILABLE, LIBFUZZER_SKIP_REASON = libfuzzer_toolchain()


def _versioned_tool(name: str) -> str | None:
    direct = shutil.which(name)
    if direct:
        return direct
    for version in ("20", "19", "18", "17", "16", "15", "14"):
        candidate = shutil.which(f"{name}-{version}")
        if candidate:
            return candidate
    return None


@lru_cache(maxsize=1)
def llvm_coverage_toolchain() -> tuple[bool, str]:
    clang = shutil.which("clang")
    profdata = _versioned_tool("llvm-profdata")
    cov = _versioned_tool("llvm-cov")
    missing = [
        name for name, path in (
            ("clang", clang), ("llvm-profdata", profdata), ("llvm-cov", cov),
        ) if not path
    ]
    if missing:
        return False, "target coverage skipped: missing " + ", ".join(missing)
    available, reason = libfuzzer_toolchain()
    if not available:
        return False, reason
    return True, ""


LLVM_COVERAGE_AVAILABLE, LLVM_COVERAGE_SKIP_REASON = llvm_coverage_toolchain()
