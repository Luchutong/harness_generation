"""Replay saved Phase 1 LLM decisions after deterministic logic changes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from .base import SemanticDecision, SemanticReplayMismatch
from .models import AccessHint, FunctionInfo, ParameterInfo, StructInfo
from .prompts import direction_prompt, role_prompt, stream_prompt


class ReplayedSemanticAnalyzer:
    """Require an exact function ID and prompt match; never contact a provider."""

    semantic_backend = "llm"
    semantic_source = "replayed"

    def __init__(self, annotations_path: Path):
        document = json.loads(Path(annotations_path).read_text(encoding="utf-8"))
        if (not isinstance(document, dict)
                or document.get("semantic_backend") != "llm"
                or not isinstance(document.get("annotations"), list)):
            raise ValueError("replay requires annotations from a real LLM Phase 1 run")
        self._records: dict[tuple[str, str, str], Mapping[str, Any]] = {}
        for annotation in document["annotations"]:
            function_id = annotation.get("function_id")
            for decision in annotation.get("decisions", []):
                if decision.get("prompt_version") == "sfg-direction-static-v1":
                    continue
                key = (function_id, decision.get("task"), decision.get("prompt"))
                if (not all(isinstance(part, str) for part in key)
                        or decision.get("status") != "ok"
                        or not isinstance(decision.get("response"), dict)
                        or key in self._records):
                    raise ValueError("replay annotations contain invalid LLM decisions")
                self._records[key] = decision

    def _decision(self, function: FunctionInfo, task: str, prompt: str) -> SemanticDecision:
        record = self._records.get((function.id, task, prompt))
        if record is None:
            raise SemanticReplayMismatch(
                f"no recorded {task} decision for {function.id}; source or prompt changed"
            )
        response = dict(record["response"])
        return SemanticDecision(
            response, prompt, record["prompt_version"], response,
            float(record["confidence"]),
        )

    def classify_stream_parameter(
        self, function: FunctionInfo, parameter: ParameterInfo,
        structs: tuple[StructInfo, ...], variant: str,
    ) -> SemanticDecision:
        return self._decision(
            function, "stream_parameter",
            stream_prompt(function, parameter, structs, variant),
        )

    def classify_function_role(
        self, function: FunctionInfo, structs: tuple[StructInfo, ...],
    ) -> SemanticDecision:
        return self._decision(function, "function_role", role_prompt(function, structs))

    def infer_struct_direction(
        self, function: FunctionInfo, parameter: ParameterInfo,
        hint: AccessHint | None, structs: tuple[StructInfo, ...],
    ) -> SemanticDecision:
        return self._decision(
            function, "struct_direction",
            direction_prompt(function, parameter, hint, structs),
        )

    def review_usage_patterns(self, patterns, functions):
        raise SemanticReplayMismatch("usage review is unavailable in paper-minimal replay")
