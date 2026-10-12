"""Generation-first services: preflight, immutable plan, real single execution."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from uuid import uuid4
import hashlib

from ..context_generation.strategy_generation import deterministic_translate, execute_strategy_plan
from ..context_generation.strategy_validation import validate_strategy_code
from ..minimal_ft.persistence import _load_json
from ..records import write_json
from ..semantic_discovery.models import digest
from .quality import assess_harness_quality
from .generation_base import NativeGenerationBase, load_strategy_inputs


class NativeGenerationServices(NativeGenerationBase):
    def __init__(self, *args, target=None, target_support_ids=(), context_budget=None, **kwargs):
        self.lightweight_context = None
        kwargs["deterministic_code"] = True
        super().__init__(*args, **kwargs)
        self.strategy_budget = replace(self.strategy_budget, max_candidates=1)
        if target is not None:
            from ..entry_candidates import CandidateCatalog
            from ..semantic_discovery.tools import RepositoryIndex
            from ..lightweight_context.builder import build_context
            from ..lightweight_context.persistence import LightweightContextStore
            if self.ft is not None or self.metadata is not None:
                raise ValueError("target context cannot inherit Minimal FT authority")
            index = RepositoryIndex(self.snapshot.artifacts, CandidateCatalog((), self.snapshot.source_fingerprint),
                                    functions_path=self.store.functions)
            context = build_context(self.snapshot, self.analysis, index, target, budget=context_budget,
                                    support_function_ids=target_support_ids)
            self.lightweight_store = LightweightContextStore(self.store.root)
            self.lightweight_store.save(context)
            # A new process always issues this receipt by live construction.
            # save also compares any existing document/metadata exactly, so
            # resumed labels cannot substitute a different callable scope.
            self.lightweight_context = context
            self.ft, self.metadata = self.lightweight_context.strategy_input, self.lightweight_context.metadata
            self.inputs_cache = {str(self.store.root): (self.store, self.ft, self.metadata, self.snapshot)}
            self._tool_account("lightweight_context_" + context.context_id, context.document["cost"])

    def verify_identity(self):
        if self.lightweight_context is None:
            return super().verify_identity()
        self.lightweight_context.validate()
        self.analysis.validate_recipe(self.effective_recipe())
        self.recipe.validate_inputs()

    def _context_fields(self):
        if self.lightweight_context is None:
            return {}
        context = self.lightweight_context
        return {"context_type": "lightweight_api_context", "context_id": context.context_id,
                "context_digest": digest(context.document), "authorization": context.scope.receipt}

    def load_single_candidate(self, run_id, *, strategy_id=None):
        if self.lightweight_context is None:
            strategy, evidence = load_strategy_inputs(self.store, self.ft, self.metadata, self.snapshot, run_id, strategy_id)
        else:
            from ..lightweight_context.persistence import load_strategy_inputs as load_lightweight_strategy_inputs
            loaded = load_lightweight_strategy_inputs(self.lightweight_store, self.lightweight_context, run_id,
                                                    strategy_id=strategy_id)
            strategy, evidence = loaded["strategy"], loaded["evidence"]
        return {"artifacts": str(self.store.root), "ft_id": self.ft["ft_id"], "ft_digest": digest(self.ft),
                **self._context_fields(), "strategy": strategy, "strategy_run": run_id,
                "effect_runs": [], "query_runs": [],
                "evidence": {"schema_version": 1, "records": evidence["records"],
                             "authorized_function_ids": evidence["authorized_function_ids"]},
                "authorized_function_ids": evidence["authorized_function_ids"]}

    def _inputs(self, candidate):
        if self.lightweight_context is None:
            return super()._inputs(candidate)
        self.verify_identity()
        if Path(candidate["artifacts"]).resolve() != self.store.root.resolve():
            raise ValueError("lightweight candidate cannot switch its context store")
        if candidate.get("effect_runs") or candidate.get("query_runs"):
            raise ValueError("lightweight candidate cannot extend its live callable scope")
        expected = self.load_single_candidate(candidate["strategy_run"], strategy_id=candidate["strategy"]["strategy_id"])
        if candidate != expected:
            raise ValueError("lightweight candidate did not reproduce from its independent context and transcript")
        return self.store, self.ft, self.metadata, self.snapshot, self.lightweight_context.index

    def plan(self, feedback, *, inputs=None):
        if self.lightweight_context is None:
            return super().plan(feedback, inputs=inputs)
        if feedback is not None or inputs is not None:
            raise ValueError("single lightweight generation cannot replan from execution feedback")
        from ..harness_strategy.planner import StrategyPlanner
        from ..lightweight_context.persistence import strategy_run_configuration, save_strategy_run
        self.verify_identity()
        context, budget = self.lightweight_context, self._stage_budget()
        run = StrategyPlanner(self.model, budget).plan(self.ft, self.snapshot, context.make_strategy_tools(budget))
        configuration = strategy_run_configuration(context, budget, self.model,
                                                  build_analysis_directory=self.analysis_directory)
        run_id = save_strategy_run(self.lightweight_store, context, run, configuration)
        self._tool_account(run_id, run.metadata)
        by_id = {row["strategy"]["strategy_id"]: row for row in run.result["candidates"]}
        evidence = {"schema_version": 1, "records": run.evidence["records"],
                    "authorized_function_ids": run.evidence["authorized_function_ids"]}
        candidates = [{"artifacts": str(self.store.root), "ft_id": self.ft["ft_id"], "ft_digest": digest(self.ft),
            **self._context_fields(), "strategy": by_id[sid]["strategy"], "strategy_run": run_id,
            "effect_runs": [], "query_runs": [], "evidence": evidence,
            "authorized_function_ids": evidence["authorized_function_ids"]}
            for sid in run.result["ranked_strategy_ids"]]
        diagnoses = []
        if not candidates:
            for attempt in run.result.get("attempts", []):
                for row in attempt.get("candidates", []):
                    diagnoses.extend({"root_cause": "strategy_not_executable", **error}
                                     for error in row.get("validation", {}).get("errors", []))
            for event in run.trace.get("events", []):
                if event.get("kind") in {"execution_error", "model_error"}:
                    diagnoses.append({"root_cause": "planning_failed", "code": event.get("error_category", "planning_error"),
                                      "recovery_allowed": False})
            if not diagnoses:
                diagnoses = [{"root_cause": "planning_failed", "code": "planning_terminal_submission_missing",
                              "termination": run.metadata.get("termination"), "recovery_allowed": False}]
        return {"candidates": candidates, "strategy_run": run_id, "status": run.result["status"], "diagnoses": diagnoses,
                "planning_inputs": {"artifacts": str(self.store.root), "ft_id": self.ft["ft_id"],
                                    "ft_digest": digest(self.ft), **self._context_fields()}}

    def verify_single_candidate(self, candidate, *, mode):
        if mode != "generate":
            raise ValueError("invalid context authority for single generation mode")
        self.verify_identity()
        self._inputs(candidate)

    def verify_single_planning(self, response, *, mode):
        if mode != "generate":
            raise ValueError("invalid context authority for single planning mode")
        self.verify_identity()
        run_id = response.get("strategy_run")
        if self.lightweight_context is None:
            from ..harness_strategy.persistence import replay_run, run_directory
            replay_run(self.store, self.ft, self.metadata, self.snapshot, run_id)
            directory = run_directory(self.store, self.ft["ft_id"], run_id)
            strategies = _load_json(directory / "strategies.json")
        else:
            from ..lightweight_context.persistence import replay_strategy_run
            strategies = replay_strategy_run(self.lightweight_store, self.lightweight_context, run_id)["run"].result
        expected = [self.load_single_candidate(run_id, strategy_id=sid) for sid in strategies["ranked_strategy_ids"]]
        if response.get("candidates") != expected or response.get("status") != strategies["status"]:
            raise ValueError("completed planning response does not match its authenticated transcript")
        for candidate in expected:
            self.verify_single_candidate(candidate, mode=mode)

    def verify_single_evaluation(self, candidate, evaluation, *, mode):
        self.verify_single_candidate(candidate, mode=mode)
        actual = self.evaluate_single(candidate, mode=mode)
        if actual != {key: value for key, value in evaluation.items() if key != "accounting"}:
            raise ValueError("saved execution preflight no longer reproduces")

    def evaluate_single(self, candidate, *, mode):
        if mode != "generate":
            raise ValueError("invalid single generation mode")
        from ..execution_preflight.gate import ExecutionPreflightGate
        store, ft, _, snapshot, index = self._inputs(candidate)
        gate = ExecutionPreflightGate().evaluate(ft, snapshot, candidate["strategy"], candidate["evidence"],
            candidate["authorized_function_ids"], build_analysis=self.analysis, project_root=index.project_root)
        return {"execution_preflight": gate, "semantic_verified": False,
                "generation_allowed": False, "diagnoses": deepcopy(gate.get("known_violations", []))}

    def _execution_request(self, candidate, evaluation):
        return {"candidate_digest": digest(candidate), "evaluation_digest": digest(evaluation),
                "language": self.language, "headers": sorted(set(self.headers)),
                "max_input_bytes": candidate["strategy"]["input_policy"]["max_input_bytes"],
                "recipe": self.effective_recipe(), "mode": "generate", "feedback_iteration": 0}

    @staticmethod
    def _plan_failure(candidate, directory, error):
        from ..context_generation.executable_plan import UnsupportedTranslationError
        status = "unsupported_translation" if isinstance(error, UnsupportedTranslationError) else "plan_preparation_failed"
        return {"mode": "generate", "statistics_category": "candidate", "experimental": False,
                "status": status, "success": False, "plan_valid": False,
                "execution_allowed": True, "generation_allowed": False, "semantic_verified": False,
                "semantic_correctness_certified_by_runtime": False, "feedback_iteration": 0,
                "repairable": False, "directory": str(directory),
                "strategy_id": candidate["strategy"]["strategy_id"],
                "strategy_digest": candidate["strategy"]["strategy_digest"],
                "code_generated": False, "build_success": None, "runtime_passed": None,
                "diagnoses": [{"code": status, "error": type(error).__name__, "detail": str(error),
                               "automatic_regeneration_allowed": False}]}

    def generate_single(self, candidate, evaluation, *, mode):
        if mode != "generate" or evaluation.get("execution_preflight", {}).get("allowed") is not True:
            raise ValueError("execution requires independent current preflight")
        from ..context_generation.executable_plan import ExecutablePlanBuilder, ExecutablePlanVerifier
        _, ft, _, snapshot, index = self._inputs(candidate)
        options = {"build_analysis": self.analysis, "project_root": index.project_root}
        validator = ExecutablePlanVerifier(ft, snapshot, candidate["evidence"], candidate["authorized_function_ids"], **options)
        directory = self.directory / ("generation_" + uuid4().hex)
        directory.mkdir()
        write_json(directory / "recipe.json", self.effective_recipe(), sort_keys=True, allow_nan=False)
        write_json(directory / "execution_request.json", self._execution_request(candidate, evaluation),
                   sort_keys=True, allow_nan=False)
        try:
            plan = ExecutablePlanBuilder().build(ft, snapshot, candidate["strategy"], candidate["evidence"],
                candidate["authorized_function_ids"], language=self.language, headers=self.headers,
                max_input_bytes=candidate["strategy"]["input_policy"]["max_input_bytes"], **options)
            if plan["execution_preflight"] != evaluation["execution_preflight"]:
                raise ValueError("execution preflight changed before plan publication")
        except (ValueError, KeyError, TypeError) as error:
            outcome = self._plan_failure(candidate, directory, error)
            outcome["quality"] = assess_harness_quality(outcome)
            write_json(directory / "execution_report.json", outcome, sort_keys=True, allow_nan=False)
            return outcome
        write_json(directory / "plan.json", plan, sort_keys=True, allow_nan=False)
        outcome = {"mode": mode, "statistics_category": "candidate", "experimental": False,
            "plan_valid": True, "execution_allowed": True, "generation_allowed": False,
            "semantic_verified": False, "semantic_correctness_certified_by_runtime": False,
            "feedback_iteration": 0, "repairable": False, "directory": str(directory),
            "plan_id": plan["plan_id"], "plan_digest": plan["plan_digest"],
            "strategy_id": plan["strategy_id"], "strategy_digest": plan["strategy_digest"],
            "code_generated": False, "build_success": None, "runtime_passed": None}
        try:
            code = deterministic_translate(plan, plan_validator=validator)
            validation = validate_strategy_code(code, plan, plan_validator=validator)
            write_json(directory / "code_validation.json", validation, sort_keys=True)
            outcome.update(code=code, code_validation=validation)
            if validation.get("valid") is not True:
                raise ValueError("unsupported_translation: canonical code failed consistency validation")
            harness = directory / ("harness.cpp" if self.language == "c++" else "harness.c")
            harness.write_text(code, encoding="utf-8")
            outcome.update(code_generated=True, code_sha256=hashlib.sha256(code.encode()).hexdigest())
            build, runtime = execute_strategy_plan(plan, code, directory, self.recipe, runtime=True,
                ft=ft, snapshot=snapshot, evidence=candidate["evidence"],
                authorized_ids=candidate["authorized_function_ids"], build_analysis=self.analysis,
                plan_validator=validator)
            outcome.update(build=build, runtime=runtime, build_success=build.get("success"),
                runtime_passed=runtime.get("status") == "passed",
                success=build.get("success") is True and runtime.get("status") == "passed")
            if build.get("success") is not True:
                outcome["diagnoses"] = [{"code": "build_failed", "automatic_regeneration_allowed": False}]
            elif runtime.get("status") != "passed":
                from ..runtime_validation import classify_crash
                observations = []
                for case in runtime.get("cases", []):
                    if case.get("success") is True:
                        continue
                    attribution = classify_crash(case.get("stderr", ""), generated_sources=(harness, directory / "smoke_driver.c"),
                        target_root=self.recipe.project_root)
                    if case.get("timed_out"):
                        attribution["classification"] = "timeout"
                    observations.append(attribution)
                outcome["diagnoses"] = [{"code": "runtime_failed", "attributions": observations,
                    "semantic_correctness_certified": False, "automatic_regeneration_allowed": False}]
        except (OSError, ValueError, KeyError, TypeError) as error:
            outcome.update(status="execution_failed" if outcome["code_generated"] else "unsupported_translation",
                success=False, diagnoses=[{"code": "execution_error", "error": type(error).__name__,
                    "detail": str(error), "automatic_regeneration_allowed": False}])
        outcome["quality"] = assess_harness_quality(outcome)
        write_json(directory / "execution_report.json", outcome, sort_keys=True, allow_nan=False)
        return outcome

    def verify_single_outcome(self, candidate, evaluation, outcome, *, mode):
        """Authenticate completed observations, never repeat their execution."""
        self.verify_single_evaluation(candidate, evaluation, mode=mode)
        from ..context_generation.executable_plan import ExecutablePlanBuilder, ExecutablePlanVerifier
        _, ft, _, snapshot, index = self._inputs(candidate)
        if outcome.get("semantic_verified") is not False or outcome.get("generation_allowed") is not False:
            raise ValueError("executable result claimed formal proof authority")
        directory = Path(outcome["directory"]).resolve()
        directory.relative_to(self.directory.resolve())
        if (_load_json(directory / "recipe.json") != self.effective_recipe()
                or _load_json(directory / "execution_request.json") != self._execution_request(candidate, evaluation)):
            raise ValueError("saved execution request or recipe changed")
        recorded = {key: value for key, value in outcome.items() if key != "accounting"}
        if _load_json(directory / "execution_report.json") != recorded:
            raise ValueError("saved execution report changed")
        if outcome.get("plan_valid") is not True:
            # Reproduce a deterministic preparation rejection from current
            # authorized inputs. This invokes neither a model nor build/runtime.
            try:
                plan = ExecutablePlanBuilder().build(ft, snapshot, candidate["strategy"], candidate["evidence"],
                    candidate["authorized_function_ids"], language=self.language, headers=self.headers,
                    max_input_bytes=candidate["strategy"]["input_policy"]["max_input_bytes"],
                    build_analysis=self.analysis, project_root=index.project_root)
                if plan["execution_preflight"] != evaluation["execution_preflight"]:
                    raise ValueError("execution preflight changed before plan publication")
            except (ValueError, KeyError, TypeError) as error:
                expected = self._plan_failure(candidate, directory, error)
                expected["quality"] = assess_harness_quality(expected)
                if recorded != expected or (directory / "plan.json").exists():
                    raise ValueError("saved preparation failure does not reproduce") from error
                return
            raise ValueError("saved preparation failure no longer reproduces")
        plan = _load_json(directory / "plan.json")
        validator = ExecutablePlanVerifier(ft, snapshot, candidate["evidence"], candidate["authorized_function_ids"],
            build_analysis=self.analysis, project_root=index.project_root)
        if validator(plan) is not True or plan["plan_digest"] != outcome["plan_digest"]:
            raise ValueError("saved executable plan no longer reproduces")
        if (plan["strategy"] != candidate["strategy"]
                or plan["execution_preflight"] != evaluation["execution_preflight"]
                or plan["language"] != self.language or plan["headers"] != sorted(set(self.headers))
                or plan["input_policy"]["max_bytes"] != candidate["strategy"]["input_policy"]["max_input_bytes"]
                or any(outcome.get(key) != plan[key] for key in
                       ("plan_id", "strategy_id", "strategy_digest"))):
            raise ValueError("saved execution does not match its selected candidate and preflight")
        harness = directory / ("harness.cpp" if self.language == "c++" else "harness.c")
        generated = outcome.get("code_generated")
        if type(generated) is not bool or generated != harness.is_file():
            raise ValueError("saved code generation axis differs from its harness artifact")
        if not generated and ("build" in outcome or "runtime" in outcome):
            raise ValueError("untranslated candidate cannot claim build or runtime observations")
        if not generated and (outcome.get("status") != "unsupported_translation" or outcome.get("success") is not False):
            raise ValueError("untranslated candidate cannot claim execution success")
        if generated and "build" not in outcome and "runtime" not in outcome:
            if outcome.get("status") != "execution_failed" or outcome.get("success") is not False:
                raise ValueError("unobserved execution cannot claim success")
        if generated:
            code = harness.read_text()
            validation = validate_strategy_code(code, plan, plan_validator=validator)
            if (code != outcome["code"] or not validation["valid"]
                    or outcome.get("code_sha256") != hashlib.sha256(code.encode()).hexdigest()
                    or outcome.get("code_validation") != validation
                    or _load_json(directory / "code_validation.json") != validation):
                raise ValueError("saved executable translation changed")
        for name in ("build", "runtime"):
            if name in outcome and _load_json(directory / (name + ".json")) != outcome[name]:
                raise ValueError("saved execution observation changed:" + name)
            if name in outcome and any(outcome[name].get(key) != plan[key] for key in
                    ("artifact_kind", "plan_id", "plan_digest", "strategy_id", "strategy_digest",
                     "statistics_category", "generation_allowed", "execution_allowed", "semantic_verified",
                     "formal_success_statistics_allowed")):
                raise ValueError("saved execution observation belongs to a different plan:" + name)
        if "runtime" in outcome and outcome.get("build", {}).get("success") is not True:
            # A failed build may record skipped runtime, but cannot claim an
            # executed successful runtime phase.
            if outcome["runtime"].get("status") != "skipped":
                raise ValueError("runtime observation requires its successful build")
        if "build" in outcome:
            build = outcome["build"]
            inputs = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in (*self.recipe.source_files, *self.recipe.header_files)}
            if (build.get("recipe") != self.recipe.to_dict()
                    or build.get("recipe_digest") != digest(self.recipe.to_dict())
                    or build.get("target_input_digests") != inputs):
                raise ValueError("saved build observation source or recipe identity changed")
            if build.get("success") is True and (build.get("status") != "passed" or not build.get("commands")
                    or any(type(row.get("return_code")) is not int or row["return_code"] != 0
                           or row.get("status") != "completed" for row in build["commands"])):
                raise ValueError("saved build success differs from its compiler observations")
        if "runtime" in outcome:
            from ..context_generation.build import SMOKE_INPUTS
            from ..runtime_validation import RuntimeValidationResult
            cases = outcome["runtime"].get("cases", [])
            if outcome["runtime"].get("status") != "skipped":
                if len(cases) != len(SMOKE_INPUTS):
                    raise ValueError("saved runtime omitted fixed-input observations")
                for number, (case, data) in enumerate(zip(cases, SMOKE_INPUTS)):
                    if (type(case.get("timed_out")) is not bool or case.get("return_code") is not None
                            and type(case["return_code"]) is not int):
                        raise ValueError("saved runtime process fields have invalid types")
                    process = RuntimeValidationResult(case.get("metadata", {}).get("runtime_status"),
                        case.get("reason"), case["stdout"], case["stderr"], case["return_code"],
                        tuple(case["command"]), case["timed_out"], case["timeout_seconds"], case["metadata"])
                    if process.to_dict() != {key: value for key, value in case.items() if key != "size"}:
                        raise ValueError("saved runtime labels differ from its process outcome")
                    if (case.get("size") != len(data) or (directory / f"input_{number}.bin").read_bytes() != data
                            or _load_json(directory / f"runtime_{number}.json") !=
                                {key: value for key, value in case.items() if key != "size"}):
                        raise ValueError("saved runtime input or process observation changed")
                passed = all(case.get("success") is True and not case.get("timed_out") for case in cases)
                if (outcome["runtime"].get("status") == "passed") != passed:
                    raise ValueError("saved runtime status differs from its process observations")
            elif cases:
                raise ValueError("skipped runtime cannot contain executed observations")
        if outcome.get("build_success") != outcome.get("build", {}).get("success"):
            raise ValueError("saved build axis differs from execution observation")
        observed_runtime = outcome.get("runtime", {}).get("status")
        expected_runtime = observed_runtime == "passed" if observed_runtime is not None else None
        if outcome.get("runtime_passed") != expected_runtime:
            raise ValueError("saved runtime axis differs from execution observation")
        if (outcome.get("mode") != mode or outcome.get("statistics_category") != "candidate"
                or outcome.get("feedback_iteration") != 0 or outcome.get("repairable") is not False
                or outcome.get("execution_allowed") is not True
                or outcome.get("quality") != assess_harness_quality(outcome)):
            raise ValueError("saved candidate execution or quality identity changed")

    def verify_single_result(self, result, checkpoint, *, mode):
        """Current identity replay may use Clang; no new harness execution."""
        from .trial_ledger import TrialLedger
        self.verify_identity()
        if (result != checkpoint.result() or result.get("mode") != mode or result.get("feedback_iteration") != 0
                or result.get("cost") != TrialLedger(checkpoint).totals()):
            raise ValueError("single generation result identity or accounting changed")
        if result.get("automatic_regeneration_allowed") is not False:
            raise ValueError("single generation cannot enable automatic regeneration")
        planned = [event["payload"]["response"] for event in checkpoint.events
                   if event["kind"] == "action_finished" and event["payload"]["action"] == "single_strategy_planning"]
        if len(planned) > 1:
            raise ValueError("single generation has multiple completed planning phases")
        for response in planned:
            self.verify_single_planning(response, mode=mode)
        candidate, evaluation, outcome = result.get("candidate"), result.get("evaluation"), result.get("outcome", {})
        if candidate is None:
            if result.get("status") != "planning_failed" or not planned:
                raise ValueError("single result omitted its candidate")
            return
        self.verify_single_evaluation(candidate, evaluation, mode=mode)
        allowed = evaluation.get("execution_preflight", {}).get("allowed") is True
        if allowed:
            self.verify_single_outcome(candidate, evaluation, outcome, mode=mode)
