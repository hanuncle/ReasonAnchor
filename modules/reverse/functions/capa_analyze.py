from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_MAX_OUTPUT = 20 * 1024


class CapaAnalyzeFunction(AnalysisFunction):
    id = "tool.capa_analyze"
    name = "capa 能力识别"
    category = "tool"
    result_key = "capa_analysis"
    description = (
        "Optional enhancement step that depends on a configured local capa path. "
        "capa produces rule-based capability candidates, namespaces, and rule "
        "evidence; matches are not verified behavior."
    )
    cost = "high"
    external_tool = True
    config_required = True
    config_requirements = ["capa.path"]
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    output_schema = {
        "capability_candidates": "Rule-based capability candidates, not verified behavior.",
        "namespaces": "Capability namespace grouping.",
        "rule_evidence": "Rules or matched evidence that support the candidate capability.",
        "limitations": "External local tool output; does not execute the sample.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        tool_path = params.get("path") or context.get("config", {}).get("capa", {}).get("path")
        if not tool_path:
            return self._error("missing_tool_path", "capa tool path is required")
        if not Path(str(tool_path)).is_file():
            return self._error("tool_path_not_found", "capa tool path was not found")
        sample_path = context.get("sample_path")
        if not sample_path:
            return self._error("missing_sample_path", "context.sample_path is required")
        if not Path(str(sample_path)).is_file():
            return self._error("file_not_found", "sample file was not found")

        timeout = self._timeout(params, context)
        try:
            completed = subprocess.run(
                [str(tool_path), "-j", str(sample_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self._error("timeout", "capa timed out")
        except OSError:
            return self._error("request_failed", "capa could not be started")

        try:
            parsed = json.loads((completed.stdout or "")[:_MAX_OUTPUT])
        except json.JSONDecodeError:
            return self._error("parse_failed", "capa JSON output could not be parsed")

        rules = parsed.get("rules", {}) if isinstance(parsed, dict) else {}
        capabilities = list(rules.keys())[:200] if isinstance(rules, dict) else []
        namespaces = self._unique(
            [
                str(rule.get("meta", {}).get("namespace"))
                for rule in rules.values()
                if isinstance(rule, dict) and rule.get("meta", {}).get("namespace")
            ]
        )
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "tool": "capa",
                "status": "completed" if completed.returncode == 0 else "completed_with_warnings",
                "capabilities": capabilities,
                "namespaces": namespaces[:100],
                "attack": parsed.get("attack", []) if isinstance(parsed, dict) else [],
                "mbc": parsed.get("mbc", []) if isinstance(parsed, dict) else [],
                "counts": {"capabilities": len(capabilities), "namespaces": len(namespaces)},
                "warnings": [] if completed.returncode == 0 else ["tool returned non-zero exit code"],
                "limitations": ["external tool JSON output only", "does not execute sample"],
            },
        )

    @staticmethod
    def _timeout(params: dict[str, Any], context: dict[str, Any]) -> int:
        value = params.get("timeout_seconds") or context.get("config", {}).get("capa", {}).get(
            "timeout_seconds", 60
        )
        try:
            return max(1, int(value))
        except (TypeError, ValueError):
            return 60

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for value in values:
            if value not in seen:
                seen.add(value)
                result.append(value)
        return result

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )
