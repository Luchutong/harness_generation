"""Compile and replay fixed inputs using generic adapters, without legacy IR."""
from dataclasses import replace
from pathlib import Path
import os
import subprocess

from ..compiler_validation import BuildAdapter, CompilerConfig, CompilerValidator
from ..runtime_validation import RuntimeValidator
from ..records import write_json

BUILD_POLICY_VERSION = "frozen_context_build_v3"
SANITIZERS = ("-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer", "-g", "-O1")
SMOKE_INPUTS = (b"", b"\0", b"\xff", b"{}", b"a\0b", bytes(range(256)))
DRIVER = """#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef __cplusplus
extern "C" {
#endif
int LLVMFuzzerTestOneInput(const uint8_t *, size_t);
#ifdef __cplusplus
}
#endif
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *f = fopen(argv[1], "rb"); if (!f) return 3;
    if (fseek(f, 0, SEEK_END)) { fclose(f); return 4; }
    long n = ftell(f); if (n < 0 || n > 16777216) { fclose(f); return 5; }
    rewind(f);
    uint8_t *p = (uint8_t *)malloc(n ? (size_t)n : 1);
    if (!p) { fclose(f); return 6; }
    if (fread(p, 1, (size_t)n, f) != (size_t)n) { free(p); fclose(f); return 7; }
    fclose(f); int result = LLVMFuzzerTestOneInput(p, (size_t)n); free(p);
    return result;
}
"""


def _sanitized_run(*args, **kwargs):
    kwargs["env"] = {**os.environ, "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1:symbolize=0",
                     "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=0"}
    return subprocess.run(*args, **kwargs)


def build_and_run(harness, directory, plan, recipe, *, runtime=False, inherit_target_flags=False):
    recipe.validate_inputs()
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    adapter = BuildAdapter()
    commands, objects = [], []
    target_config = replace(recipe.compiler_config, compiler_flags=recipe.compiler_flags + SANITIZERS)
    harness_compiler = "clang++" if plan["language"] == "c++" else recipe.compiler if inherit_target_flags else "clang"
    inherited_flags = tuple(flag for flag in recipe.compiler_flags
        if plan["language"] == "c" or not flag.startswith("-std=")) if inherit_target_flags else ()
    language_flags = (("-std=c++17",) if plan["language"] == "c++" else
        () if any(flag.startswith("-std=") for flag in inherited_flags) else ("-std=c11",))
    harness_config = CompilerConfig(compiler=harness_compiler, include_paths=(recipe.project_root, *recipe.include_paths),
        compiler_flags=inherited_flags + language_flags + SANITIZERS,
        working_directory=recipe.project_root, timeout=recipe.timeout)
    driver = directory / "smoke_driver.c"
    driver.write_text(DRIVER, encoding="utf-8")
    sources = [(source, target_config) for source in recipe.source_files] + [(Path(harness).resolve(), harness_config), (driver, harness_config)]
    status = "passed"
    for number, (source, config) in enumerate(sources):
        output = directory / f"unit_{number}.o"
        output.unlink(missing_ok=True)
        result = CompilerValidator(config=config)._run(adapter.object_command(source, output, config))
        commands.append(result.to_dict())
        if result.return_code != 0 or result.status != "completed" or not output.is_file():
            status = "failed" if result.status != "unavailable" else "unavailable"
            break
        objects.append(output)
    executable = directory / "smoke_harness"
    executable.unlink(missing_ok=True)
    if status == "passed":
        link_config = replace(harness_config, compiler=recipe.linker or harness_compiler, link_flags=SANITIZERS + recipe.link_flags)
        result = CompilerValidator(config=link_config)._run(adapter.objects_link_command(objects, executable, link_config))
        commands.append(result.to_dict())
        if result.return_code != 0 or result.status != "completed" or not executable.is_file():
            status = "failed" if result.status != "unavailable" else "unavailable"
    build = {"schema_version": 1, "status": status, "success": status == "passed", "plan_id": plan["plan_id"],
        "build_policy_version": BUILD_POLICY_VERSION,
        "recipe": recipe.to_dict(), "commands": commands, "sanitizers": ["address", "undefined"],
        "executable": str(executable) if status == "passed" else None}
    write_json(directory / "build.json", build, sort_keys=True, allow_nan=False)
    cases = []
    if runtime and status == "passed":
        for number, data in enumerate(SMOKE_INPUTS):
            case = directory / f"input_{number}.bin"
            case.write_bytes(data)
            result = RuntimeValidator(timeout=min(recipe.timeout, 10), runner=_sanitized_run).validate(executable,
                validation_path=directory / f"runtime_{number}.json", arguments=(str(case),), working_directory=directory)
            cases.append({"size": len(data), **result.to_dict()})
    replay = {"schema_version": 1, "plan_id": plan["plan_id"], "cases": cases,
        "sanitizer_policy": {"asan_detect_leaks": True, "asan_abort_on_error": True, "ubsan_halt_on_error": True,
                             "external_symbolizer": False},
        "status": "passed" if cases and all(case["success"] is True for case in cases)
                  else "failed" if cases else "skipped", "fuzz_executed": False}
    write_json(directory / "runtime.json", replay, sort_keys=True, allow_nan=False)
    return build, replay
