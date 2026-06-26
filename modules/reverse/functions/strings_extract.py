from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_PRINTABLE_MIN = 0x20
_PRINTABLE_MAX = 0x7E
_URL_RE = re.compile(r"https?://[^\s\x00-\x1f]+", re.IGNORECASE)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


class StringsExtractFunction(AnalysisFunction):
    id = "strings.extract"
    name = "ASCII strings extract"
    category = "static"
    result_key = "strings"

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        sample_path = context.get("sample_path")
        if not sample_path:
            return self._error("missing_sample_path", "context.sample_path is required")

        min_length = self._int_param(params, "min_length", 4)
        max_strings = self._int_param(params, "max_strings", 2000)
        extract_urls = bool(params.get("extract_urls", True))
        extract_ips = bool(params.get("extract_ips", True))
        min_length = max(1, min_length)
        max_strings = max(0, max_strings)

        try:
            data = Path(str(sample_path)).read_bytes()
        except OSError:
            return self._error("read_failed", "sample file could not be read")

        items = self._extract_ascii_strings(data, min_length, max_strings)
        urls = self._unique(self._find_matches(_URL_RE, items)) if extract_urls else []
        ips = self._unique(self._find_matches(_IPV4_RE, items)) if extract_ips else []

        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "total": len(items),
                "items": items,
                "urls": urls,
                "ips": ips,
            },
        )

    @staticmethod
    def _int_param(params: dict[str, Any], key: str, default: int) -> int:
        try:
            return int(params.get(key, default))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _extract_ascii_strings(data: bytes, min_length: int, max_strings: int) -> list[str]:
        if max_strings <= 0:
            return []

        items: list[str] = []
        current: list[int] = []
        for byte in data:
            if _PRINTABLE_MIN <= byte <= _PRINTABLE_MAX:
                current.append(byte)
                continue
            if len(current) >= min_length:
                items.append(bytes(current).decode("ascii"))
                if len(items) >= max_strings:
                    return items
            current.clear()

        if len(current) >= min_length and len(items) < max_strings:
            items.append(bytes(current).decode("ascii"))
        return items

    @staticmethod
    def _find_matches(pattern: re.Pattern[str], strings: list[str]) -> list[str]:
        matches: list[str] = []
        for value in strings:
            matches.extend(match.group(0) for match in pattern.finditer(value))
        return matches

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        seen: set[str] = set()
        unique_values: list[str] = []
        for value in values:
            if value not in seen:
                seen.add(value)
                unique_values.append(value)
        return unique_values

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )
