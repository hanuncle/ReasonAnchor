from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_MAX_STDIO = 4000
_IDA_SCRIPT = r'''
import json
import sys

import ida_funcs
import idautils
import idc

args = list(getattr(idc, "ARGV", [])) or list(sys.argv)
out_path = args[1] if len(args) > 1 else "sfp_ida_functions.json"
items = []
for ea in idautils.Functions():
    func = ida_funcs.get_func(ea)
    if not func:
        continue
    items.append({
        "name": idc.get_func_name(ea),
        "start": hex(int(func.start_ea)),
        "end": hex(int(func.end_ea)),
        "size": int(func.end_ea - func.start_ea),
    })
with open(out_path, "w", encoding="utf-8") as output:
    json.dump({"tool": "ida", "functions": items}, output, ensure_ascii=False)
idc.qexit(0)
'''


class IdaFunctionAnalyzeFunction(AnalysisFunction):
    id = "tool.ida_function_analyze"
    name = "IDA function-level static analysis"
    category = "tool"
    result_key = "ida_function_analysis"
    description = (
        "Runs configured IDA in batch mode with a generated IDAPython script to "
        "export function names, addresses, and sizes. Static analysis only."
    )
    cost = "high"
    external_tool = True
    config_required = True
    config_requirements = ["ida.path"]
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    output_schema = {
        "functions": "Function-level static analysis output from IDA.",
        "limitations": "External tool output; does not execute sample.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        tool_path = params.get("path") or context.get("config", {}).get("ida", {}).get("path")
        if not tool_path:
            return self._error("missing_tool_path", "IDA tool path is required")
        if not Path(str(tool_path)).is_file():
            return self._error("tool_path_not_found", "IDA tool path was not found")
        sample_path = context.get("sample_path")
        if not sample_path:
            return self._error("missing_sample_path", "context.sample_path is required")
        if not Path(str(sample_path)).is_file():
            return self._error("file_not_found", "sample file was not found")

        timeout = _timeout(params, context, "ida", 300)
        max_functions = _int_param(params, "max_functions", 1000)
        with tempfile.TemporaryDirectory() as temp_dir:
            script_path = Path(temp_dir) / "sfp_ida_functions.py"
            output_path = Path(temp_dir) / "ida_functions.json"
            script_path.write_text(_IDA_SCRIPT, encoding="utf-8")
            command = [
                str(tool_path),
                "-A",
                f"-S{script_path} {output_path}",
                str(sample_path),
            ]
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return self._error("timeout", "IDA function analysis timed out")
            except OSError:
                return self._error("request_failed", "IDA could not be started")

            parsed = _read_tool_json(output_path)
            if parsed is None:
                return self._error("parse_failed", "IDA function output could not be parsed")
            functions = _normalize_functions(parsed.get("functions", []), max_functions)
            return FunctionResult(
                function_id=self.id,
                result_key=self.result_key,
                data={
                    "tool": "ida",
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
