from dataclasses import dataclass, field
from typing import Any


@dataclass
class FunctionResult:
    function_id: str
    result_key: str
    status: str = "success"
    data: dict[str, Any] = field(default_factory=dict)
    error: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "result_key": self.result_key,
            "status": self.status,
            "data": self.data,
            "error": self.error,
        }
