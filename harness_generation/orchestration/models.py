from dataclasses import asdict, dataclass

VERSION = "strategy-recovery-v1"


@dataclass(frozen=True)
class ControllerBudget:
    max_strategies: int = 3
    max_trials: int = 12
    max_actions_per_strategy: int = 3
    max_model_calls: int = 24
    max_source_tool_calls: int = 96
    max_source_chars: int = 192000
    max_replans: int = 1
    max_slice_revisits: int = 1
    max_code_repairs: int = 1

    def __post_init__(self):
        for name, value in asdict(self).items():
            if type(value) is not int or value < (0 if name in {"max_replans", "max_slice_revisits", "max_code_repairs"} else 1):
                raise ValueError("invalid controller budget: " + name)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("invalid controller budget fields")
        return cls(**value)
