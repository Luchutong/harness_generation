"""Frozen Context → deterministic HarnessPlan → code → compile → fixed replay."""
import argparse
import hashlib
from pathlib import Path
import sys

from ..artifacts import ArtifactStore
from ..llm import LLMConfig, LLMError, OpenAICompatibleLLM
from ..minimal_ft.persistence import _load_json, _owned
from ..records import write_json
from ..semantic_discovery.models import digest
from ..semantic_discovery.provider_config import agent_configuration, load_environment_file
from ..target_build import TargetBuildConfig
from .builder import HarnessPlanBuilder
from .build import build_and_run, BUILD_POLICY_VERSION
from .persistence import load_frozen_inputs
from .stage4 import ContextStage4Generator, PROMPT_VERSION
from .validation import validate_code, CODE_VALIDATOR_VERSION


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _files(directory):
    return {str(path.relative_to(directory)): _sha(_owned(path, directory))
            for path in sorted(directory.rglob("*")) if path.is_file() and path.name != "metadata.json"}


def _resume(directory, configuration, plan):
    marker = directory / "metadata.json"
    if not marker.is_file():
        return None
    try:
        saved = _load_json(_owned(marker, directory))
        if (saved.get("configuration") != configuration or saved.get("configuration_fingerprint") != digest(configuration)
                or saved.get("status") != "passed" or saved.get("file_digests") != _files(directory)):
            return None
        code = directory / ("harness.cpp" if plan["language"] == "c++" else "harness.c")
        if not configuration["plan_only"] and validate_code(code.read_text(encoding="utf-8"), plan)["status"] != "valid":
            return None
        return saved
    except (OSError, ValueError, KeyError, TypeError):
        return None


def main(argv=None, *, llm=None):
    parser = argparse.ArgumentParser(prog="harness-generation context-generate")
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--ft", action="append", default=[])
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--provider", choices=("deepseek", "openai-compatible"), default="openai-compatible")
    parser.add_argument("--model")
    parser.add_argument("--thinking", choices=("disabled", "enabled"))
    parser.add_argument("--language", choices=("c", "c++"), default="c++")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--max-input-bytes", type=int, default=1048576)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--harness", type=Path, help="Validate existing C/C++ code against the frozen Plan without a model call")
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--runtime", action="store_true")
    parser.add_argument("--target-build", type=Path)
    parser.add_argument("--project-root", type=Path)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args(argv)
    if args.runtime and not args.build or args.plan_only and args.build:
        parser.error("--runtime requires --build; --plan-only cannot be combined with --build")
    if llm is not None and args.model:
        parser.error("cannot combine injected LLM with --model")
    if args.harness and (args.plan_only or args.harness.suffix not in {".c", ".cc", ".cpp", ".cxx"}):
        parser.error("--harness requires a C/C++ source and cannot be combined with --plan-only")
    failed = 0
    try:
        if args.env_file:
            load_environment_file(args.env_file)
        store = ArtifactStore(args.artifacts)
        ids = sorted(path.name for path in store.minimal_fts_directory.iterdir()
                     if path.is_dir() and path.name.startswith("ft_"))
        selected = args.ft or ids
        if not selected or any(fid not in ids for fid in selected):
            raise ValueError("--ft must identify an existing Minimal FT by exact ID")
        for ft_id in sorted(set(selected)):
            root = _owned(store.root / "context_generations" / ft_id, store.root)
            root.mkdir(parents=True, exist_ok=True)
            try:
                ft, context, closure, snapshot, report, index = load_frozen_inputs(store, ft_id)
                plan = HarnessPlanBuilder().build(ft, context, closure, snapshot, report,
                    language=args.language, headers=args.header, max_input_bytes=args.max_input_bytes)
                for header in plan["headers"]:
                    _owned(index.project_root / header, index.project_root).read_bytes()
            except (OSError, ValueError, KeyError, TypeError) as error:
                write_json(root / "blocked.json", {"schema_version": 1, "ft_id": ft_id, "status": "blocked",
                    "generation_allowed": False, "model_calls": 0, "reason": str(error)}, sort_keys=True)
                print(f"[CONTEXT-GENERATE] {ft_id}: blocked model_calls=0 reason={error}", flush=True)
                failed += 1
                continue
            root.joinpath("blocked.json").unlink(missing_ok=True)
            plan_root = _owned(root / plan["plan_id"], root)
            plan_root.mkdir(parents=True, exist_ok=True)
            if not (plan_root / "harness_plan.json").is_file() or _load_json(plan_root / "harness_plan.json") != plan:
                write_json(plan_root / "harness_plan.json", plan, sort_keys=True, allow_nan=False)
            recipe = None
            if args.build:
                recipe = (TargetBuildConfig.load(args.target_build, project_root=args.project_root) if args.target_build
                          else TargetBuildConfig.for_simple_project(args.project_root or index.project_root))
                if recipe.project_root != index.project_root:
                    raise ValueError("build recipe project root must match the authenticated snapshot")
                recipe.validate_inputs()
            model_config = None
            active = llm
            if not args.plan_only and not args.harness:
                if active is None:
                    cfg = agent_configuration(args.provider, model=args.model, thinking=args.thinking)
                    model_config = LLMConfig(model=cfg.model, base_url=cfg.base_url,
                        api_key_env_name="LLM_API_KEY" if args.provider == "openai-compatible" else "DEEPSEEK_API_KEY",
                        thinking=cfg.thinking, max_tokens=8192)
                    active = OpenAICompatibleLLM(model_config)
                model_config = {"provider": args.provider, **model_config.to_dict()} if model_config else {
                    "provider": getattr(active, "provider", "injected"), "model": getattr(active, "model", "injected")}
            build_files = list(recipe.source_files) + list(recipe.header_files) if recipe else []
            # Include repository headers, including transitive project headers,
            # in the resume fingerprint. No contents reach the generation model.
            build_files += [p for p in index.project_root.rglob("*") if p.is_file() and p.suffix in {".h", ".hh", ".hpp"}]
            configuration = {"plan_id": plan["plan_id"], "plan_digest": digest(plan), "prompt_version": PROMPT_VERSION,
                "code_validator_version": CODE_VALIDATOR_VERSION,
                "build_policy_version": BUILD_POLICY_VERSION if args.build else None,
                "existing_harness_digest": _sha(args.harness) if args.harness else None,
                "model": model_config, "plan_only": args.plan_only, "build": args.build, "runtime": args.runtime,
                "recipe": recipe.to_dict() if recipe else None,
                "build_file_digests": {str(p): _sha(_owned(p, index.project_root)) for p in sorted(set(build_files))}}
            directory = _owned(plan_root / digest(configuration)[:24], plan_root)
            directory.mkdir(parents=True, exist_ok=True)
            if args.resume and _resume(directory, configuration, plan):
                print(f"[CONTEXT-GENERATE] {ft_id}: passed resumed model_calls=0 artifacts={directory}", flush=True)
                continue
            if any(directory.iterdir()):
                history = _owned(plan_root / "history" / directory.name, plan_root)
                history.mkdir(parents=True, exist_ok=True)
                attempts = [int(p.name.removeprefix("attempt_")) for p in history.iterdir()
                            if p.name.startswith("attempt_") and p.name.removeprefix("attempt_").isdigit()]
                destination = _owned(history / f"attempt_{max(attempts, default=0) + 1:04d}", plan_root)
                directory.rename(destination)
                directory.mkdir()
            write_json(directory / "harness_plan.json", plan, sort_keys=True, allow_nan=False)
            status, calls, error = "passed", 0, None
            if not args.plan_only:
                generator = ContextStage4Generator(active)
                generator.render(plan).save(directory / "prompt.json")
                try:
                    if args.harness:
                        with args.harness.open(encoding="utf-8") as stream:
                            code = stream.read(131073)
                        if not code.strip() or len(code) > 131072:
                            raise ValueError("empty or oversized input harness")
                        validation = validate_code(code, plan)
                    else:
                        calls = 1
                        code, prompt, response, validation = generator.run(plan)
                        write_json(directory / "response.json", response.to_dict(), sort_keys=True, allow_nan=False)
                    write_json(directory / "code_validation.json", validation, sort_keys=True)
                    harness = _owned(directory / ("harness.cpp" if plan["language"] == "c++" else "harness.c"), directory)
                    temporary = harness.with_suffix(".tmp")
                    temporary.write_text(code, encoding="utf-8")
                    temporary.replace(harness)
                    if validation["status"] != "valid":
                        status = "invalid_code"
                    elif args.build:
                        build, runtime = build_and_run(harness, _owned(directory / "build", directory), plan, recipe, runtime=args.runtime)
                        if not build["success"]:
                            status = "compile_failed"
                        elif args.runtime and runtime["status"] != "passed":
                            status = "runtime_failed"
                except (LLMError, OSError, ValueError) as exc:
                    status, error = "generation_failed", str(exc) if isinstance(exc, LLMError) else type(exc).__name__
            write_json(directory / "metadata.json", {"schema_version": 1, "ft_id": ft_id, "plan_id": plan["plan_id"],
                "status": status, "model_calls": calls, "error": error, "configuration": configuration,
                "code_origin": "existing_harness" if args.harness else "plan_only" if args.plan_only else "model_translation",
                "configuration_fingerprint": digest(configuration), "file_digests": _files(directory)}, sort_keys=True, allow_nan=False)
            print(f"[CONTEXT-GENERATE] {ft_id}: {status} model_calls={calls} artifacts={directory}", flush=True)
            failed += status != "passed"
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Context generation failed: {error}", file=sys.stderr)
        return 1
    return int(bool(failed))


if __name__ == "__main__":
    raise SystemExit(main())
