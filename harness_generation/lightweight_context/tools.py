"""Strategy investigation bound to independent live-Clang API scope."""
from __future__ import annotations

from ..harness_strategy.tools import StrategyTools
from .models import LightweightAPIContext


class LightweightStrategyTools(StrategyTools):
    registry_version = "lightweight-strategy-tools-v1"

    def __init__(self, context, budget):
        if type(context) is not LightweightAPIContext:
            raise ValueError("lightweight tools require a live context receipt")
        context.validate()
        self.context_authorization = context
        super().__init__(context.snapshot, context.index.catalog, context.strategy_input, budget,
            index=context.index, build_analysis=context.analysis, context_authorization=context)

    def _authorize(self, ids, eid):
        # Discovery evidence is observable, but a read-only query cannot amend
        # the independently admitted Clang scope. A new context is required.
        return None

    def _scope_error(self, name, arguments):
        error = super()._scope_error(name, arguments)
        if error or not isinstance(arguments, dict):
            return error
        if name == "read_source_range":
            start, end, filename = arguments.get("line_start"), arguments.get("line_end"), arguments.get("file")
            if type(start) is int and type(end) is int and isinstance(filename, str):
                if not any(row["file"] == filename and row["start_line"] <= start <= end <= row["end_line"]
                           for fid, row in self.index.functions.items() if fid in self.authorized_ids):
                    return "outside_lightweight_source_scope"
        return None

    def _find_symbol_references(self, arguments):
        records, total = super()._find_symbol_references(arguments)
        limited = [row for row in records if row.get("function_id") in self.authorized_ids]
        return limited, total

    def execute(self, name, arguments):
        self.context_authorization.validate()
        return super().execute(name, arguments)
