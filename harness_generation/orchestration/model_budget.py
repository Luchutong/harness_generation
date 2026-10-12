"""One invocation allowance shared by planners, investigators and repairs."""
from ..semantic_discovery.models import digest


class ModelBudgetExceeded(RuntimeError):
    model_call = False
    budget_stop_reason = "controller_model_budget_exhausted"


class SharedBudgetModel:
    def __init__(self, model, maximum, *, already_used=0):
        if type(maximum) is not int or type(already_used) is not int or not 0 <= already_used <= maximum:
            raise ValueError("invalid shared model invocation budget")
        self.adapter, self.maximum, self.used = model, maximum, already_used
        self.provider, self.model = getattr(model, "provider", "unspecified"), getattr(model, "model", "unspecified")
        self.config = getattr(model, "config", None)
        self.events = []

    def complete(self, messages, tools):
        if self.used >= self.maximum:
            raise ModelBudgetExceeded("shared_controller_model_budget_exhausted")
        self.used += 1
        request = {"messages": messages, "tools": tools}
        row = {"invocation": self.used, "request_digest": digest(request)}
        self.events.append(row)
        try:
            response = self.adapter.complete(messages, tools)
        except Exception as error:
            row.update(status="error", error_type=type(error).__name__,
                       diagnostics=dict(getattr(error, "diagnostics", {})), model_call=getattr(error, "model_call", True))
            raise
        row.update(status="completed", metadata=getattr(response, "metadata", {}))
        return response
