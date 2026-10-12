"""Stage accounting is independent of semantic progress and runtime success."""
from copy import deepcopy
import math

from ..semantic_discovery.models import digest


class TrialLedger:
    def __init__(self, checkpoint, *, include_completed=False):
        self.checkpoint = checkpoint
        self.rows = {}
        for event in checkpoint.events:
            if event["kind"] == "stage_accounting":
                row = event["payload"]
                if row["stage_id"] in self.rows:
                    raise ValueError("duplicate stage accounting")
                self.rows[row["stage_id"]] = self.validate(row["stage_id"], row["metadata"])
        if include_completed:
            for event in checkpoint.events:
                if event["kind"] == "action_finished":
                    for row in event["payload"]["response"].get("accounting", []):
                        existing = self.rows.get(row["stage_id"])
                        if existing is not None and existing != row:
                            raise ValueError("completed action accounting changed")
                        self.rows[row["stage_id"]] = self.validate(row["stage_id"], row["metadata"])

    def record(self, stage_id, metadata):
        row = self.validate(stage_id, metadata)
        if stage_id in self.rows:
            return
        self.checkpoint.append("stage_accounting", row)
        self.rows[stage_id] = row

    def validate(self, stage_id, metadata):
        """Validate before publishing an action that depends on these costs."""
        if not isinstance(stage_id, str) or not stage_id or not isinstance(metadata, dict):
            raise ValueError("invalid stage accounting shape")
        row = {"stage_id": stage_id, "metadata": deepcopy(metadata)}
        digest(row)
        if stage_id in self.rows and self.rows[stage_id] != row:
            raise ValueError("stage accounting changed")
        self._totals({stage_id: row})
        return row

    def totals(self):
        return self._totals(self.rows)

    @staticmethod
    def _totals(rows):
        result = {"model_calls": 0, "tool_calls": 0, "source_chars": 0, "tokens": {}, "usage_complete": True,
                  "provider_events": [], "provider_requests": 0, "provider_requests_complete": True,
                  "stage_ids": sorted(rows)}
        for stage_id in sorted(rows):
            metadata = rows[stage_id]["metadata"]
            for key in ("model_calls", "tool_calls", "source_chars"):
                value = metadata.get(key, 0)
                if type(value) is not int or value < 0:
                    raise ValueError("invalid ledger count")
                result[key] += value
            if "analysis_tool_calls" in metadata:
                for key in ("analysis_tool_calls","analysis_llvm_calls","analysis_svf_calls","analysis_failed_calls"):
                    value = metadata.get(key, 0)
                    if type(value) is not int or value < 0:
                        raise ValueError("invalid analysis ledger count")
                    result[key] = result.get(key, 0) + value
                elapsed = metadata.get("analysis_elapsed_seconds", 0)
                if isinstance(elapsed, bool) or not isinstance(elapsed, (int,float)) or not math.isfinite(elapsed) or elapsed < 0:
                    raise ValueError("invalid analysis ledger elapsed time")
                result["analysis_elapsed_seconds"] = result.get("analysis_elapsed_seconds", 0) + elapsed
            usage = metadata.get("tokens", {})
            if not isinstance(usage, dict) or any(type(v) is not int or v < 0 for v in usage.values()):
                raise ValueError("invalid token accounting")
            for key, value in usage.items():
                result["tokens"][key] = result["tokens"].get(key, 0) + value
            if metadata.get("model_calls", 0):
                result["usage_complete"] &= metadata.get("usage_complete") is True
            events = metadata.get("provider_events", [])
            if not isinstance(events, list):
                raise ValueError("invalid provider events")
            result["provider_events"].extend({"stage_id": stage_id, "event": deepcopy(event)} for event in events)
            accounting = metadata.get("provider_request_accounting", {})
            if not isinstance(accounting, dict) or any(type(accounting[key]) is not int or accounting[key] < 0
                    for key in ("provider_requests", "request_count", "confirmed_started_requests", "unknown_invocations",
                                "offline_invocations", "pretransport_failures") if key in accounting):
                raise ValueError("invalid provider request accounting")
            count = accounting.get("provider_requests", accounting.get("request_count", accounting.get("confirmed_started_requests")))
            if count is not None:
                if type(count) is not int or count < 0:
                    raise ValueError("invalid provider request count")
                result["provider_requests"] += count
                if accounting.get("unknown_invocations", 0):
                    result["provider_requests_complete"] = False
            elif metadata.get("model_calls", 0):
                result["provider_requests_complete"] = False
        result["ledger_digest"] = digest(result)
        return result
