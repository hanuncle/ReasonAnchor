from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_MAX_OUTPUT = 20 * 1024
_MAX_STRINGS = 2000


class FlossExtractFunction(AnalysisFunction):
    id = "tool.floss_extract"
    name = "FLOSS 字符串提取"
    category = "tool"
    result_key = "floss_analysis"
    description = (
        "Optional enhancement step that depends on a configured local FLOSS path. "
        "It can return noisy decoded strings, may fail when not configured, and "
        "should be used after basic analysis when extra string evidence is needed."
    )
    cost = "high"
    external_tool = True
    config_required = True
    config_requirements = ["floss.path"]
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    output_schema = {
        "strings": "Decoded or extracted strings; high-noise candidate evidence.",
        "interesting_strings": "Small subset of strings with URL, library, or executable hints.",
        "limitations": "External local tool output is truncated and should be triaged.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        tool_path = params.get("path") or context.get("config", {}).get("floss", {}).get("path")
        if not tool_path:
            return self._error("missing_tool_path", "FLOSS tool path is required")
        if not Path(str(tool_path)).is_file():
            return self._error("tool_path_not_found", "FLOSS tool path was not found")
        sample_path = context.get("sample_path")
        if not sample_path:
            return self._error("missing_sample_path", "context.sample_path is required")
        if not Path(str(sample_path)).is_file():
            return self._error("file_not_found", "sample file was not found")

        timeout = self._timeout(params, context)
        try:
            completed = subprocess.run(
                [str(tool_path), str(sample_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self._error("timeout", "FLOSS timed out")
        except OSError:
            return self._error("request_failed", "FLOSS could not be started")

        output = ((completed.stdout or "") + (completed.stderr or ""))[:_MAX_OUTPUT]
        strings = [line.strip() for line in output.splitlines() if line.strip()][:_MAX_STRINGS]
        interesting = [
            value
            for value in strings
            if any(marker in value.lower() for marker in ("http://", "https://", ".dll", ".exe"))
        ][:200]
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "tool": "floss",
                "status": "completed" if completed.returncode == 0 else "completed_with_warnings",
                "strings": strings,
                "interesting_strings": interesting,
                "counts": {"strings": len(strings), "interesting_strings": len(interesting)},
                "warnings": [] if completed.returncode == 0 else ["tool returned non-zero exit code"],
                "limitations": ["external tool output is truncated", "does not execute sample"],
            },
        )

    @staticmethod
    def _timeout(params: dict[str, Any], context: dict[str, Any]) -> int:
        value = params.get("timeout_seconds") or context.get("config", {}).get("floss", {}).get(
            "timeout_seconds", 60
        )
        try:
            return max(1, int(value))
        except (TypeError, ValueError):
            return 60

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )
