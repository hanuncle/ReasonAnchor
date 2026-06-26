from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ByteStatsFunction(AnalysisFunction):
    id = "file.byte_stats"
    name = "文件字节统计"
    category = "static"
    result_key = "byte_stats"

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        sample_path = context.get("sample_path")
        if not sample_path:
            return self._error("missing_sample_path", "context.sample_path is required")

        path = Path(str(sample_path))
        if not path.is_file():
            return self._error("sample_not_found", "sample file was not found")

        max_header_bytes = self._int_param(params, "max_header_bytes", 32)
        max_header_bytes = max(0, max_header_bytes)

        try:
            data = path.read_bytes()
        except OSError:
            return self._error("read_failed", "sample file could not be read")

        file_size = len(data)
        printable_ascii_count = sum(1 for byte in data if byte in {9, 10, 13} or 32 <= byte <= 126)
        printable_ratio = printable_ascii_count / file_size if file_size else 0.0

        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "file_size": file_size,
                "header_hex": data[:max_header_bytes].hex(),
                "null_byte_count": data.count(0),
                "printable_ascii_byte_count": printable_ascii_count,
                "printable_ascii_ratio": round(printable_ratio, 6),
                "entropy_estimate": self._entropy(data),
                "limitations": [
                    "static byte statistics only",
                    "does not execute sample",
                ],
            },
        )

    @staticmethod
    def _int_param(params: dict[str, Any], key: str, default: int) -> int:
        try:
            return int(params.get(key, default))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        total = len(data)
        counts = Counter(data)
        entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())
        return round(entropy, 6)

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )
