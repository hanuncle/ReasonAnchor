from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class LiefParseFunction(AnalysisFunction):
    id = "file.lief_parse"
    name = "LIEF 文件解析"
    category = "tool"
    result_key = "lief_parser"

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        _ = params
        sample_path = context.get("sample_path")
        if not sample_path:
            return self._error("missing_sample_path", "context.sample_path is required")
        if not Path(str(sample_path)).is_file():
            return self._error("file_not_found", "sample file was not found")
        try:
            lief = importlib.import_module("lief")
        except ImportError:
            return self._skipped(
                "dependency_missing",
                "Python lief package is not installed",
                ["Install Python package `lief` in the platform runtime when structured LIEF parsing is required."],
            )

        try:
            binary = lief.parse(str(sample_path))
        except Exception as exc:
            return self._skipped(
                "parse_failed",
                f"LIEF parse failed: {type(exc).__name__}",
                ["LIEF could not parse this sample; keep using PE/string/capa/DIE evidence."],
            )
        if binary is None:
            return self._skipped(
                "parse_failed",
                "LIEF could not parse the sample",
                ["LIEF returned no binary object; keep using other static evidence."],
            )

        sections = [
            {"name": str(getattr(section, "name", "")), "size": int(getattr(section, "size", 0))}
            for section in list(getattr(binary, "sections", []))[:50]
        ]
        imports = [str(item) for item in list(getattr(binary, "imports", []))[:200]]
        exports = [str(item) for item in list(getattr(binary, "exported_functions", []))[:200]]
        symbols = [str(item) for item in list(getattr(binary, "symbols", []))[:200]]
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "status": "completed",
                "format": str(getattr(binary, "format", "unknown")),
                "summary": {
                    "sections": len(sections),
                    "imports": len(imports),
                    "exports": len(exports),
                    "symbols": len(symbols),
                },
                "sections": sections,
                "imports": imports,
                "exports": exports,
                "symbols": symbols,
                "limitations": ["local parser only", "large lists are truncated"],
            },
        )

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )

    def _skipped(self, code: str, message: str, recommended_fix: list[str]) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="skipped",
            data={
                "status": "skipped",
                "skipped": True,
                "skip_reason": code,
                "message": message,
                "recommended_fix": recommended_fix,
                "limitations": ["optional parser only", "does not execute sample"],
            },
        )
