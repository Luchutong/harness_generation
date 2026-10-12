"""Optional Clang compilation facts; tree-sitter source identities stay intact."""
from .analyzer import AnalysisBudget, BuildAnalysisError, analyze_build, write_analysis
from .index import BuildAwareIndex, agent_projection

__all__ = ["AnalysisBudget", "BuildAnalysisError", "BuildAwareIndex", "agent_projection", "analyze_build", "write_analysis"]
