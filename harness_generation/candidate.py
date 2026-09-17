"""Execute and persist one independent candidate; no candidate selection here."""

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from copy import deepcopy
from dataclasses import asdict, replace

from .config import CandidateConfig
from .records import write_json
from .core import (PROMPT_VERSION, GenerationError, call_api,
                   extract_code, make_request, review_harness, validate_code)
from .assessment import execute_pipeline, collect_metrics
from .evaluation import EvaluationContext, EvaluationEngine, default_quality_engine
from .feedback import FEEDBACK_PROMPT_VERSION, StructuredFeedbackPromptBuilder
from .iteration import AutomaticFeedbackBuilder, WeightedAggregationPolicy
from .protocol_spec import (ProtocolSpecError, discover_protocol_spec,
                            load_protocol_spec)
from .source_analysis import ANALYSIS_SCHEMA_VERSION, SourceAnalysisError, analyze_c_source
from .isf import (IsfClassificationError, apply_isf_filter,
                  classify_isf_parameters, target_is_isf)


def run_candidate(config: CandidateConfig, original: bytes, existing_code: str | None = None,
                  *, evaluation_engine: EvaluationEngine | None = None,
                  analysis_cache: dict | None = None) -> tuple[dict, int]:
    started = time.monotonic()
    result = {
        "schema_version": 8, "candidate_id": config.candidate_id, "parent_id": config.parent_id,
        "round_index": config.round_index, "mode": "offline" if config.harness else "api",
        "model": None if config.harness else config.model,
        "temperature": None if config.harness else config.temperature,
        "prompt_version": None if config.harness else PROMPT_VERSION,
        "source_analysis": {"status": "skipped" if config.harness else "not_started"},
        "protocol_contract": {"status": "skipped" if config.harness else "not_started"},
        "isf_classification": {"status": "skipped" if config.harness else "not_started"},
        "api_attempts": 0,
        "source_sha256": hashlib.sha256(original).hexdigest(),
        "function": config.function, "source": str(config.source.resolve()),
        "started_at": datetime.now(timezone.utc).isoformat(),
        "generation": "not_started", "compilation": {"status": "skipped" if config.generate_only else "not_started"}, "usage": None,
        "smoke": {"status": "not_started" if config.smoke_test or config.fuzz_seconds else "skipped"},
        "fuzzing": {"status": "not_started" if config.fuzz_seconds else "skipped"},
    }
    exit_code = 1
    stage = "setup"
    try:
        (config.output / "target.c").write_bytes(original)
        if existing_code is not None:
            result["generation"] = "skipped"
            result["harness_source"] = str(config.harness.resolve())
            (config.output / "input_harness.txt").write_text(existing_code, encoding="utf-8")
            stage = "validation"
            code = validate_code(existing_code)
        else:
            stage = "source_analysis"
            cache = analysis_cache if analysis_cache is not None else {}
            syntax_summary = cache.get("syntax_summary")
            if syntax_summary is None:
                syntax_summary = analyze_c_source(original, config.function)
                cache["syntax_summary"] = syntax_summary
            write_json(config.output / "isf_candidates.json", {
                "schema_version": 1,
                "filter": "tree-sitter pointer parameters",
                "candidates": syntax_summary["pointer_candidates"],
            })
            result["source_analysis"] = {
                "status": "passed",
                "schema_version": ANALYSIS_SCHEMA_VERSION,
                "parser": syntax_summary["parser"],
                "artifact": "isf_candidates.json",
                "target_signature": syntax_summary["target"]["signature"],
            }
            api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
            if not api_key and syntax_summary["pointer_candidates"]:
                raise GenerationError("DEEPSEEK_API_KEY is missing; set it in the terminal running this command")
            cached_failure = cache.get("isf_failure")
            if cached_failure is not None:
                stage = "isf_classification"
                write_json(config.output / "isf_classification.json", cached_failure["report"])
                result["isf_classification"] = {
                    "status": "failed",
                    "artifact": "isf_classification.json",
                    "api_attempts": 0,
                    "shared_from": cached_failure["owner"],
                    "usage": None,
                }
                raise GenerationError(
                    "shared ISF classification failed: " + cached_failure["message"]
                )
            report = cache.get("isf_report")
            summary = cache.get("filtered_summary")
            classification_owner = False
            if report is None or summary is None:
                stage = "isf_classification"
                classification_started = time.monotonic()

                def classification_call(payload, key):
                    result["api_attempts"] += 1
                    status, raw = call_api(payload, key)
                    if status >= 400:
                        result["http_status"] = status
                    return status, raw

                try:
                    report = classify_isf_parameters(syntax_summary, config.model, api_key,
                                                      classification_call)
                except IsfClassificationError as exc:
                    write_json(config.output / "isf_classification.json", exc.report)
                    result["isf_classification"] = {
                        "status": "failed", "artifact": "isf_classification.json",
                        "api_attempts": exc.report["api_attempts"], "shared_from": None,
                        "usage": exc.report.get("usage"),
                    }
                    cache["isf_failure"] = {
                        "message": str(exc), "report": exc.report,
                        "owner": config.candidate_id,
                    }
                    raise
                result["isf_elapsed_seconds"] = round(time.monotonic() - classification_started, 3)
                summary = apply_isf_filter(syntax_summary, report)
                cache["isf_report"] = report
                cache["filtered_summary"] = summary
                cache["classification_owner"] = config.candidate_id
                classification_owner = True
            write_json(config.output / "isf_classification.json", report)
            write_json(config.output / "source_summary.json", summary)
            protocol_path = config.protocol.resolve() if config.protocol else discover_protocol_spec(config.source)
            if protocol_path is not None:
                stage = "protocol_contract"
                try:
                    summary["protocol_contract"] = load_protocol_spec(
                        protocol_path, config.function
                    )
                except ProtocolSpecError:
                    raise
                result["protocol_contract"] = {
                    "status": "loaded",
                    "artifact": str(protocol_path),
                }
            else:
                result["protocol_contract"] = {"status": "not_found"}
            write_json(config.output / "source_summary.json", summary)
            selected = [entry["name"] for entry in summary["isf_functions"]]
            result["isf_classification"] = {
                "status": "passed",
                "artifact": "isf_classification.json",
                "candidate_artifact": "isf_candidates.json",
                "api_attempts": report["api_attempts"] if classification_owner else 0,
                "shared_from": None if classification_owner else cache.get("classification_owner"),
                "usage": report.get("usage") if classification_owner else None,
                "selected_functions": selected,
            }
            result["source_analysis"] = {
                "status": "passed",
                "schema_version": ANALYSIS_SCHEMA_VERSION,
                "parser": summary["parser"],
                "artifact": "source_summary.json",
                "target_signature": summary["target"]["signature"],
            }
            stage = "isf_filter"
            if not target_is_isf(summary, config.function):
                raise GenerationError(
                    f"target function {config.function!r} was rejected by the ISF majority-vote filter"
                )
            if not api_key:
                raise GenerationError("DEEPSEEK_API_KEY is missing; set it in the terminal running this command")
            stage = "prompt_construction"
            if config.revision:
                result["feedback_prompt_version"] = FEEDBACK_PROMPT_VERSION
                result["parent_directory"] = str(config.revision.parent_directory)
                feedback = asdict(config.revision.feedback)
                write_json(config.output / "feedback.json", feedback)
                write_json(config.output / "feedback_evidence.json", config.revision.evidence_snapshots)
                (config.output / "parent_harness.c").write_text(config.revision.parent_harness, encoding="utf-8")
                payload = StructuredFeedbackPromptBuilder().build(summary, config.function, config.model,
                                                                   config.temperature, config.revision)
            else:
                payload = make_request(summary, config.function, config.model, temperature=config.temperature)
            write_json(config.output / "prompt.json", payload)
            stage = "api"
            result["generation"] = "requesting"
            result["api_attempts"] += 1
            api_started = time.monotonic()
            try:
                status, raw = call_api(payload, api_key)
            finally:
                result["api_elapsed_seconds"] = round(time.monotonic() - api_started, 3)
            result["http_status"] = status
            (config.output / "response.txt").write_text(raw, encoding="utf-8")
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
        (config.output / "harness.c").write_text(code, encoding="utf-8")
        result["harness_sha256"] = hashlib.sha256(code.encode("utf-8")).hexdigest()
        stage = "review"
        result["review"] = review_harness(code, config.function)
        write_json(config.output / "review.json", result["review"])
        for warning in result["review"]["warnings"]:
            print(f"Review: {warning}", file=sys.stderr)
        exit_code = 0
        if not config.generate_only:
            stage = "execution"
            exit_code = execute_pipeline(config, result)
            if exit_code:
                print(result.get("error", "Execution failed"), file=sys.stderr)
    except (GenerationError, SourceAnalysisError, ProtocolSpecError, OSError) as exc:
        exit_code = 1
        if stage == "isf_classification" or (stage == "source_analysis"
                                               and result["source_analysis"]["status"] == "passed"
                                               and result["isf_classification"]["status"] == "not_started"):
            result["isf_classification"].update(status="failed", error=str(exc))
        if result["generation"] not in ("passed", "skipped"):
            result["generation"] = "failed"
        result.setdefault("failure_stage", stage)
        result["error"] = str(exc)
        print(str(exc), file=sys.stderr)
    except KeyboardInterrupt:
        result.setdefault("failure_stage", stage)
        result["error"] = "Interrupted by user"
        if stage == "isf_classification":
            result["isf_classification"] = {"status": "interrupted"}
        if result["generation"] == "requesting":
            result["generation"] = "interrupted"
        if stage == "compilation":
            result["compilation"] = {"status": "interrupted"}
        exit_code = 130
    finally:
        try:
            metrics = collect_metrics(result)
            write_json(config.output / "metrics.json", metrics)
            result["metrics"] = {"status": metrics["status"], "report": "metrics.json"}
            context = EvaluationContext(
                config.candidate_id, config.parent_id, config.round_index, config.output,
                config.function, result["source_sha256"], result.get("harness_sha256"),
                deepcopy(result),
            )
            # A bare EvaluationEngine remains available to extension callers,
            # while normal candidate execution gets the standard, evidence
            # backed multi-dimensional signal set.
            report = (evaluation_engine or default_quality_engine()).evaluate(context)
            if evaluation_engine is None:
                report = replace(
                    report,
                    aggregate=WeightedAggregationPolicy().aggregate(report),
                )
            write_json(config.output / "evaluation.json", report.to_dict())
            result["evaluation"] = {"status": report.status, "report": "evaluation.json"}
            # Keep automatic feedback additive: a revision child already owns
            # feedback.json as immutable parent input, so never overwrite it.
            if result.get("harness_sha256"):
                automatic_feedback = AutomaticFeedbackBuilder(
                    low_score_threshold=config.automatic_feedback_threshold,
                    include_unavailable_primary=config.automatic_feedback_include_unavailable,
                ).build(context, report)
                write_json(config.output / "automatic_feedback.json", asdict(automatic_feedback),
                           sort_keys=True, allow_nan=False)
                result["automatic_feedback"] = {
                    "status": "available",
                    "report": "automatic_feedback.json",
                    "items": len(automatic_feedback.items),
                    "low_score_threshold": config.automatic_feedback_threshold,
                    "include_unavailable_primary": config.automatic_feedback_include_unavailable,
                }
        except KeyboardInterrupt:
            result["evaluation"] = {"status": "interrupted"}
            exit_code = 130
        except OSError as exc:
            result["evaluation"] = {"status": "error", "error": str(exc)}
            exit_code = 1
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        try:
            write_json(config.output / "result.json", result)
        except OSError as exc:
            print(f"Could not save result.json: {exc}", file=sys.stderr)
            exit_code = 1
    print(f"generation={result['generation']} compilation={result['compilation']['status']} "
          f"smoke={result['smoke']['status']} fuzzing={result['fuzzing']['status']} output={config.output}")
    return result, exit_code
