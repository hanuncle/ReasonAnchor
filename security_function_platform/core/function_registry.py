from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class FunctionRegistry:
    def __init__(self) -> None:
        self._functions: dict[str, AnalysisFunction] = {}

    def register(self, fn: AnalysisFunction) -> None:
        function_id = fn.id.strip()
        if not function_id:
            raise ValueError("function id cannot be empty")
        if function_id in self._functions:
            raise ValueError(f"function id already registered: {function_id}")
        self._functions[function_id] = fn

    def get(self, function_id: str) -> AnalysisFunction:
        if function_id not in self._functions:
            raise KeyError(function_id)
        return self._functions[function_id]

    def list_functions(self) -> list[dict[str, Any]]:
        return [fn.info() for fn in self._functions.values()]

    def run(
        self,
        function_id: str,
        context: dict[str, Any],
        params: dict[str, Any] | None = None,
    ) -> FunctionResult:
        fn = self.get(function_id)
        try:
            return fn.run(context, params or {})
        except Exception as exc:
            return FunctionResult(
                function_id=fn.id,
                result_key=fn.result_key,
                status="error",
                error={
                    "type": type(exc).__name__,
                    "message": str(exc),
                },
            )
