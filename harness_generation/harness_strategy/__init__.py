"""Opt-in, source-grounded strategy proposals; never a harness authorization."""

from .models import StrategyBudget
from .normalization import normalize_strategy

__all__ = ["StrategyBudget", "normalize_strategy"]
