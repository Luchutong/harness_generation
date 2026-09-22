"""Shared LLM client resolution for the command-line entry points.

More than one subcommand needs an LLM and therefore needs the same answer to
the same question: given ``--model``, a mock or recorded-response file, and
whatever the environment holds, which client should run?  That answer includes
the *missing-key policy* -- ``generate`` and ``protocol-mine`` both refuse to
run with an incomplete configuration rather than fall back to a mock, an empty
result or a marker, because a fabricated result looks plausible to every
downstream stage.

The logic lives here rather than in the ``generate`` command module because
that policy has to be shared, and a second, subtly different copy of it is
exactly how a silent fallback reappears.  Importing one subcommand's private
internals from another would leave the same defect in place with a shorter
import line: the policy would still be owned by a module that has no business
owning it.  Nothing here imports a command module, so there is no cycle.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping

from .llm import (
    LLMClient,
    LLMConfig,
    MockLLM,
    OpenAICompatibleLLM,
    RecordedResponseLLM,
)


def resolve_llm(
    injected: LLMClient | None,
    *,
    provider: str | None,
    model: str | None,
    mock_responses: Path | None,
    recorded_responses: Path | None,
    timeout: float | None = None,
    environ: Mapping[str, str] | None = None,
) -> LLMClient:
    environment = os.environ if environ is None else environ
    if injected is not None:
        if (
            provider is not None
            or model is not None
            or mock_responses is not None
            or recorded_responses is not None
            # An injected client was built by the caller, timeout included, so
            # accepting this flag without applying it would be a silent no-op.
            # Refusing it is the only honest outcome, and matches --model.
            or timeout is not None
        ):
            raise ValueError(
                "cannot combine an injected LLM with provider options "
                "(--model, --mock-responses, --recorded-responses, --llm-timeout)"
            )
        return injected
    if mock_responses is not None:
        if model is not None:
            raise ValueError("--model is only valid for a real LLM provider")
        return MockLLM(_load_mock_responses(mock_responses))
    if recorded_responses is not None:
        if model is not None:
            raise ValueError("--model is only valid for a real LLM provider")
        return RecordedResponseLLM.from_file(recorded_responses)
    selected_provider = provider or "openai-compatible"
    if selected_provider != "openai-compatible":
        raise ValueError(f"unsupported LLM provider: {selected_provider}")
    base_url = environment.get("LLM_BASE_URL", "").strip()
    api_key = environment.get("LLM_API_KEY", "").strip()
    selected_model = (model or environment.get("LLM_MODEL", "")).strip()
    thinking = environment.get("LLM_THINKING", "").strip().lower() or None
    missing = []
    if not base_url:
        missing.append("LLM_BASE_URL")
    if not api_key:
        missing.append("LLM_API_KEY")
    if not selected_model:
        missing.append("LLM_MODEL")
    if missing:
        raise ValueError(
            "missing LLM configuration: " + ", ".join(missing)
        )
    if thinking not in {None, "enabled", "disabled"}:
        raise ValueError("LLM_THINKING must be enabled or disabled")
    # timeout is passed only when the caller supplied one, so "no override"
    # leaves LLMConfig's own default as the single owner of that value: the
    # number cannot drift into a second copy here and stop meaning the same
    # thing as the one in llm.py.
    overrides = {} if timeout is None else {"timeout": timeout}
    return OpenAICompatibleLLM(
        LLMConfig(
            model=selected_model,
            base_url=base_url,
            api_key_env_name="LLM_API_KEY",
            thinking=thinking,
            **overrides,
        ),
        environ=environment,
    )


def _load_mock_responses(path: Path) -> tuple[str, ...]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(
            f"cannot load mock responses: {type(error).__name__}"
        ) from error
    responses = document.get("responses") if isinstance(document, dict) else document
    if not isinstance(responses, list) or any(
        not isinstance(response, str) for response in responses
    ):
        raise ValueError("mock responses must be an array of strings")
    return tuple(responses)
