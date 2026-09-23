"""Compatibility facade for the isolated semantic analyzer modules."""

from .base import SemanticAnalyzer, SemanticDecision, SemanticError
from .client import LLMSemanticAnalyzer, OpenAICompatibleTransport
from .mock import MockSemanticAnalyzer
from .prompts import (DIRECTION_PROMPT_VERSION, ROLE_PROMPT_VERSION,
                      STREAM_PROMPT_VERSION, STREAM_VARIANTS,
                      USAGE_REVIEW_PROMPT_VERSION, direction_prompt, role_prompt,
                      stream_prompt, usage_review_prompt)


__all__ = [
    "DIRECTION_PROMPT_VERSION",
    "LLMSemanticAnalyzer",
    "MockSemanticAnalyzer",
    "OpenAICompatibleTransport",
    "ROLE_PROMPT_VERSION",
    "STREAM_PROMPT_VERSION",
    "STREAM_VARIANTS",
    "USAGE_REVIEW_PROMPT_VERSION",
    "SemanticAnalyzer",
    "SemanticDecision",
    "SemanticError",
    "direction_prompt",
    "role_prompt",
    "stream_prompt",
    "usage_review_prompt",
]
