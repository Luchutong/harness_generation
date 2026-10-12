"""Bounded, source-grounded observations of generated harness quality.

These observations have no authority to close semantic proof obligations.
"""

from .contracts import inspect_entry_rejection
from .validation import evaluate_effectiveness, summarize_quality

__all__ = ["inspect_entry_rejection", "evaluate_effectiveness", "summarize_quality"]
