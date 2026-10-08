"""One explicitly budgeted code correction against an unchanged FrozenPlan."""
import hashlib
import re
import shutil

from ..llm import LLMError
from ..records import write_json
from ..semantic_discovery.models import digest
from .build import build_and_run

CODE_REPAIR_POLICY_VERSION = "frozen-plan-code-repair-v1"
REPAIRABLE_STATUSES = frozenset({"invalid_code", "compile_failed"})


def translate(directory, plan, generator, *, recipe=None, runtime=False, max_code_repairs=0):
    """Retain every attempt; return final status, calls, error and attempt records.

    Source discovery, context repair and plan changes are outside this operation.
    A provider failure or a runtime failure never triggers another code request.
    """
    if type(max_code_repairs) is not int or max_code_repairs not in (0, 1):
        raise ValueError("max_code_repairs must be 0 or 1")
    frozen_digest = digest(plan)
    records = []
    previous_code, diagnostics = None, None
    final_status, final_error = "generation_failed", None
    for number in range(1, max_code_repairs + 2):
        attempt_dir = directory / "code_attempts" / f"attempt_{number:04d}"
        attempt_dir.mkdir(parents=True, exist_ok=False)
        if number > 1:
            for name in ("code_validation.json", "harness.c", "harness.cpp"):
                (directory / name).unlink(missing_ok=True)
        record = {"attempt": number, "model_call": False, "plan_digest": frozen_digest,
                  "status": "generation_failed", "error": None, "error_category": None,
                  "response_path": None, "usage_known": False, "file_digests": {}}
        code_written = False
        try:
            if digest(plan) != frozen_digest:
                raise ValueError("FrozenPlan changed before code attempt")
            prompt = (generator.render(plan) if number == 1 else
                      generator.render_repair(plan, previous_code, diagnostics))
            prompt.save(directory / "prompt.json" if number == 1 else attempt_dir / "prompt.json")
            # Count the issued model operation even when no response is returned.
            record["model_call"] = True
            response = generator.request(plan, prompt=prompt)
            response_path = directory / "response.json" if number == 1 else attempt_dir / "response.json"
            write_json(response_path, response.to_dict(), sort_keys=True, allow_nan=False)
            record["response_path"] = response_path.relative_to(directory).as_posix()
            record["usage_known"] = all(type(response.usage.get(k)) is int
                for k in ("prompt_tokens", "completion_tokens", "total_tokens"))
            if digest(plan) != frozen_digest:
                raise ValueError("FrozenPlan changed during code attempt")
            code, validation = generator.decode_response(response, plan)
            write_json(directory / "code_validation.json", validation, sort_keys=True)
            harness = directory / ("harness.cpp" if plan["language"] == "c++" else "harness.c")
            temporary = harness.with_suffix(".tmp")
            temporary.write_text(code, encoding="utf-8")
            temporary.replace(harness)
            code_written = True
            status, build, replay = "passed", None, None
            if validation["status"] != "valid":
                status = "invalid_code"
            elif recipe is not None:
                build, replay = build_and_run(harness, directory / "build", plan, recipe, runtime=runtime)
                if not build["success"]:
                    status = "compile_failed"
                elif runtime and replay["status"] != "passed":
                    status = "runtime_failed"
            record["status"] = status
            previous_code = code
            diagnostics = {"status": status, "code_validation": validation,
                           "compiler": build if status == "compile_failed" else None}
        except (LLMError, OSError, ValueError) as exc:
            record["error"] = str(exc) if isinstance(exc, LLMError) else type(exc).__name__
            if isinstance(exc, LLMError):
                http = re.search(r"(?:Error code:|HTTP(?: status)?|status_code[=:])\s*(4\d\d|5\d\d)", str(exc), re.I)
                record["error_category"] = ("configuration_error"
                    if str(exc).startswith("API key environment variable is not set:") else
                    "http_" + http[1] if http else
                    "timeout" if re.search(r"timeout|timed.?out", str(exc), re.I) else "provider_error")
                if record["error_category"] == "configuration_error":
                    # generate() stopped before its transport; there was no
                    # model/provider request and no unknown request usage.
                    record["model_call"] = False
                if http:
                    record["http_status"] = int(http[1])
            else:
                record["error_category"] = type(exc).__name__
        # Snapshot code and local diagnostics before a subsequent attempt can
        # replace them. The first provider response has only its root copy.
        names = ["prompt.json"] if number == 1 else []
        if code_written:
            names += ["code_validation.json", "harness.c", "harness.cpp"]
        for name in names:
            source = directory / name
            if source.is_file() and not (attempt_dir / name).exists():
                shutil.copyfile(source, attempt_dir / name)
        if code_written and (directory / "build").is_dir():
            shutil.copytree(directory / "build", attempt_dir / "build")
        def _sha(path):
            return hashlib.sha256(path.read_bytes()).hexdigest()
        record["file_digests"] = {p.relative_to(directory).as_posix(): _sha(p)
            for p in sorted(attempt_dir.rglob("*")) if p.is_file()}
        if record["response_path"]:
            source = directory / record["response_path"]
            record["file_digests"][record["response_path"]] = _sha(source)
        write_json(attempt_dir / "attempt.json", record, sort_keys=True, allow_nan=False)
        records.append(record)
        final_status, final_error = record["status"], record["error"]
        if final_status not in REPAIRABLE_STATUSES or number > max_code_repairs:
            break
        # Clear previous compiler/runtime files after archiving them. A failed
        # correction must not expose an earlier build as its own success.
        if (directory / "build").is_dir():
            shutil.rmtree(directory / "build")
    return final_status, sum(r["model_call"] for r in records), final_error, records
