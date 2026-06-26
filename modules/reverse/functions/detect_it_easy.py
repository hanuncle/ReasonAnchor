from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_MAX_OUTPUT = 20 * 1024


class DetectItEasyFunction(AnalysisFunction):
    id = "tool.detect_it_easy"
    name = "Detect It Easy"
    category = "tool"
    result_key = "pe_external_tools"
    description = (
        "Optional enhancement step that depends on a configured local Detect It Easy "
        "tool path. It may fail when not configured and should not be added blindly "
        "to a basic workflow."
    )
    cost = "high"
    external_tool = True
    config_required = True
    config_requirements = ["detect_it_easy.path"]
    optional = True
    output_schema = {
        "detections": "Detected packer/compiler/signature lines from local tool output.",
        "raw_summary": "Truncated local tool output.",
        "limitations": "External local tool output; does not execute the sample.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        tool_path = params.get("path") or context.get("config", {}).get("detect_it_easy", {}).get(
            "path"
        )
        if not tool_path:
            return self._error("missing_tool_path", "Detect It Easy tool path is required")
        if not Path(str(tool_path)).is_file():
            return self._error("tool_path_not_found", "Detect It Easy tool path was not found")
        sample_path = context.get("sample_path")
        if not sample_path:
            return self._error("missing_sample_path", "context.sample_path is required")
        if not Path(str(sample_path)).is_file():
            return self._error("file_not_found", "sample file was not found")

        timeout = self._timeout(params, context, "detect_it_easy")
        try:
            completed = subprocess.run(
                [str(tool_path), str(sample_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self._error("timeout", "Detect It Easy timed out")
        except OSError:
            return self._error("request_failed", "Detect It Easy could not be started")

        raw_summary = self._truncate((completed.stdout or "") + (completed.stderr or ""))
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "tool": "detect_it_easy",
                "status": "completed" if completed.returncode == 0 else "completed_with_warnings",
                "detections": self._detections(raw_summary),
                "raw_summary": raw_summary,
                "warnings": [] if completed.returncode == 0 else ["tool returned non-zero exit code"],
                "limitations": ["external tool output is summarized", "does not execute sample"],
            },
        )

    @staticmethod
    def _timeout(params: dict[str, Any], context: dict[str, Any], key: str) -> int:
        value = params.get("timeout_seconds") or context.get("config", {}).get(key, {}).get(
            "timeout_seconds", 30
        )
        try:
            return max(1, int(value))
        except (TypeError, ValueError):
            return 30

    @staticmethod
    def _truncate(value: str) -> str:
        return value[:_MAX_OUTPUT]

    @staticmethod
    def _detections(raw_summary: str) -> list[str]:
        return [line.strip() for line in raw_summary.splitlines() if line.strip()][:100]

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )
