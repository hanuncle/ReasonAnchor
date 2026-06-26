from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_MAX_STDIO = 4000
_BN_SCRIPT = r'''
import json
import os

import binaryninja as bn

sample_path = os.environ["SFP_SAMPLE_PATH"]
out_path = os.environ["SFP_OUTPUT_PATH"]
bv = bn.load(sample_path)
if bv is None:
    raise RuntimeError("binary view could not be loaded")
bv.update_analysis_and_wait()
items = []
for func in bv.functions:
    items.append({
        "name": str(func.name),
        "start": hex(int(func.start)),
        "end": hex(int(func.highest_address)) if func.highest_address else "",
        "size": int(max(0, func.highest_address - func.start)) if func.highest_address else 0,
    })
with open(out_path, "w", encoding="utf-8") as output:
    json.dump({"tool": "binaryninja", "functions": items}, output, ensure_ascii=False)
'''


class BinaryNinjaFunctionAnalyzeFunction(AnalysisFunction):
    id = "tool.binaryninja_function_analyze"
    name = "Binary Ninja function-level static analysis"
    category = "tool"
    result_key = "binaryninja_function_analysis"
    description = (
        "Runs configured Binary Ninja headless analysis to export function names, "
        "addresses, and sizes. Static analysis only."
    )
    cost = "high"
    external_tool = True
    config_required = True
    config_requirements = ["binaryninja.path", "binaryninja.python_path"]
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    output_schema = {
        "functions": "Function-level static analysis output from Binary Ninja.",
        "limitations": "External tool output; does not execute sample.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        tool_path = params.get("path") or context.get("config", {}).get("binaryninja", {}).get("path")
        python_path = (
            params.get("python_path")
            or context.get("config", {}).get("binaryninja", {}).get("python_path")
        )
        if not tool_path and not python_path:
            return self._error("missing_tool_path", "Binary Ninja path is required")
        if tool_path and not Path(str(tool_path)).is_file():
            return self._error("tool_path_not_found", "Binary Ninja path was not found")
        if python_path and not Path(str(python_path)).is_file():
            return self._error(
                "python_path_not_found",
                "Binary Ninja Python interpreter path was not found",
            )
        sample_path = context.get("sample_path")
        if not sample_path:
            return self._error("missing_sample_path", "context.sample_path is required")
        if not Path(str(sample_path)).is_file():
            return self._error("file_not_found", "sample file was not found")

        timeout = _timeout(params, context, "binaryninja", 600)
        max_functions = _int_param(params, "max_functions", 1000)
        with tempfile.TemporaryDirectory() as temp_dir:
            script_path = Path(temp_dir) / "sfp_binaryninja_functions.py"
            output_path = Path(temp_dir) / "binaryninja_functions.json"
            script_path.write_text(_BN_SCRIPT, encoding="utf-8")
            env = {
                **os.environ,
                "SFP_SAMPLE_PATH": str(sample_path),
                "SFP_OUTPUT_PATH": str(output_path),
            }
            command = (
                [str(python_path or sys.executable), str(script_path)]
                if python_path
                else [str(tool_path), "--headless", "--python-expr", _BN_SCRIPT]
            )
            if not python_path and not _supports_headless(Path(str(tool_path))):
                return self._error(
                    "headless_not_available",
                    "Binary Ninja executable does not expose headless Python analysis; configure binaryninja.python_path with a Python interpreter that can import binaryninja.",
                )
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    check=False,
                    env=env,
                )
            except subprocess.TimeoutExpired:
                return self._error("timeout", "Binary Ninja function analysis timed out")
            except OSError:
                return self._error("request_failed", "Binary Ninja could not be started")

            parsed = _read_tool_json(output_path)
            if parsed is None:
                return self._error(
                    "parse_failed",
                    "Binary Ninja function output could not be parsed",
                )
            functions = _normalize_functions(parsed.get("functions", []), max_functions)
            return FunctionResult(
                function_id=self.id,
                result_key=self.result_key,
                data={
                    "tool": "binaryninja",
                    "status": "completed" if completed.returncode == 0 else "completed_with_warnings",
                    "functions": functions,
                    "counts": {"functions": len(functions)},
                    "warnings": [] if completed.returncode == 0 else ["tool returned non-zero exit code"],
                    "stdout_excerpt": (completed.stdout or "")[:_MAX_STDIO],
                    "stderr_excerpt": (completed.stderr or "")[:_MAX_STDIO],
                    "limitations": ["external tool output only", "does not execute sample"],
                },
            )

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )


def _read_tool_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _supports_headless(tool_path: Path) -> bool:
    try:
        completed = subprocess.run(
            [str(tool_path), "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    help_text = f"{completed.stdout}\n{completed.stderr}".lower()
    return "--headless" in help_text and "--python-expr" in help_text


def _normalize_functions(value: Any, limit: int) -> list[dict[str, Any]]:
    if not isinstance(value, list) or limit <= 0:
        return []
    result: list[dict[str, Any]] = []
    for item in value[:limit]:
        if not isinstance(item, dict):
            continue
        result.append(
            {
                "name": str(item.get("name", ""))[:300],
                "start": str(item.get("start", ""))[:64],
                "end": str(item.get("end", ""))[:64],
                "size": _safe_int(item.get("size")),
            }
        )
    return result


def _timeout(params: dict[str, Any], context: dict[str, Any], key: str, default: int) -> int:
    value = params.get("timeout_seconds") or context.get("config", {}).get(key, {}).get(
        "timeout_seconds",
        default,
    )
    return max(1, _safe_int(value, default))


def _int_param(params: dict[str, Any], key: str, default: int) -> int:
    return max(0, _safe_int(params.get(key), default))


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
