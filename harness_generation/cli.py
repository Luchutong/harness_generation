"""CLI and on-disk experiment records."""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .core import (DEFAULT_MODEL, PROMPT_VERSION, GenerationError, call_api,
                   compile_harness, extract_code, make_request, review_harness, validate_code)


def write_json(path: Path, data: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a C libFuzzer harness with DeepSeek and compile it.")
    parser.add_argument("--source", required=True, type=Path, help="Self-contained UTF-8 C source without main")
    parser.add_argument("--function", required=True, help="Target C function name")
    parser.add_argument("--output", required=True, type=Path, help="New experiment directory (must not exist)")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--harness", type=Path, help="Review and compile existing harness without calling the API")
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.function):
        parser.error("--function must be a C identifier")
    if args.source.suffix != ".c":
        parser.error("--source must be a .c file")
    try:
        original = args.source.read_bytes()
        source = original.decode("utf-8")
        if not source.strip():
            raise ValueError("source is empty")
        existing_code = args.harness.read_text(encoding="utf-8") if args.harness else None
        args.output.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError) as exc:
        print(f"Input/output error: {exc}", file=sys.stderr)
        return 1

    started = time.monotonic()
    result = {
        "schema_version": 2, "mode": "offline" if args.harness else "api",
        "model": None if args.harness else args.model,
        "prompt_version": None if args.harness else PROMPT_VERSION,
        "source_sha256": hashlib.sha256(original).hexdigest(),
        "function": args.function, "source": str(args.source.resolve()),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "generation": "not_started", "compilation": {"status": "not_started"}, "usage": None,
    }
    exit_code = 1
    stage = "setup"
    try:
        (args.output / "target.c").write_bytes(original)
        if existing_code is not None:
            result["generation"] = "skipped"
            result["harness_source"] = str(args.harness.resolve())
            (args.output / "input_harness.txt").write_text(existing_code, encoding="utf-8")
            stage = "validation"
            code = validate_code(existing_code)
        else:
            payload = make_request(source, args.function, args.model)
            write_json(args.output / "prompt.json", payload)
            api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
            if not api_key:
                raise GenerationError("DEEPSEEK_API_KEY is missing; set it in the terminal running this command")
            stage = "api"
            result["generation"] = "requesting"
            api_started = time.monotonic()
            try:
                status, raw = call_api(payload, api_key)
            finally:
                result["api_elapsed_seconds"] = round(time.monotonic() - api_started, 3)
            result["http_status"] = status
            (args.output / "response.txt").write_text(raw, encoding="utf-8")
            if status != 200:
                raise GenerationError(f"DeepSeek API returned HTTP {status}; see response.txt (no retry)")
            stage = "validation"
            try:
                response = json.loads(raw)
            except ValueError:
                raise GenerationError("API returned invalid JSON; see response.txt") from None
            if not isinstance(response, dict):
                raise GenerationError("API response must be a JSON object")
            result["usage"] = response.get("usage")
            result["response_model"] = response.get("model")
            code = extract_code(response)
            result["generation"] = "passed"
        (args.output / "harness.c").write_text(code, encoding="utf-8")
        result["harness_sha256"] = hashlib.sha256(code.encode("utf-8")).hexdigest()
        stage = "review"
        result["review"] = review_harness(code, args.function)
        write_json(args.output / "review.json", result["review"])
        for warning in result["review"]["warnings"]:
            print(f"Review: {warning}", file=sys.stderr)
        stage = "compilation"
        compile_started = time.monotonic()
        result["compilation"] = compile_harness(args.output)
        result["compile_elapsed_seconds"] = round(time.monotonic() - compile_started, 3)
        if result["compilation"]["status"] != "passed":
            raise GenerationError("Compilation failed; see compile_stderr.txt")
        exit_code = 0
    except (GenerationError, OSError) as exc:
        if result["generation"] not in ("passed", "skipped"):
            result["generation"] = "failed"
        result["failure_stage"] = stage
        result["error"] = str(exc)
        print(str(exc), file=sys.stderr)
    except KeyboardInterrupt:
        result["failure_stage"] = stage
        result["error"] = "Interrupted by user"
        if result["generation"] == "requesting":
            result["generation"] = "interrupted"
        if stage == "compilation":
            result["compilation"] = {"status": "interrupted"}
        exit_code = 130
    finally:
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        try:
            write_json(args.output / "result.json", result)
        except OSError as exc:
            print(f"Could not save result.json: {exc}", file=sys.stderr)
            exit_code = 1
    print(f"generation={result['generation']} compilation={result['compilation']['status']} output={args.output}")
    return exit_code
