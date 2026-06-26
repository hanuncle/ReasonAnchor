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
import idaapi
import idautils
import idc

BEHAVIOR_KEYWORDS = {
    "command_execution": [
        "createprocess",
        "shellexecute",
        "winexec",
        "cmd.exe",
        "powershell",
        "rundll32",
        "regsvr32",
        "mshta",
        "schtasks",
        "wmic",
    ],
    "network_communication": [
        "internetopen",
        "httpopenrequest",
        "httpsendrequest",
        "winhttp",
        "socket",
        "connect",
        "send",
        "recv",
        "http://",
        "https://",
    ],
    "file_write": [
        "createfile",
        "writefile",
        "copyfile",
        "deletefile",
        "movefile",
    ],
    "registry_persistence": [
        "regcreatekey",
        "regsetvalue",
        "currentversion\\run",
        "runonce",
    ],
    "process_injection": [
        "openprocess",
        "virtualallocex",
        "writeprocessmemory",
        "createremotethread",
        "setwindowshookex",
    ],
    "credential_access": [
        "openprocesstoken",
        "adjusttokenprivileges",
        "lsass",
        "credential",
        "password",
    ],
    "anti_analysis": [
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "vmware",
        "virtualbox",
        "sandbox",
    ],
}


def safe_int(value, default):
    try:
        return int(value)
    except Exception:
        return default


args = list(getattr(idc, "ARGV", [])) or list(sys.argv)
out_path = args[1] if len(args) > 1 else "sfp_ida_function_features.json"
max_functions = max(0, safe_int(args[2], 500)) if len(args) > 2 else 500
max_calls = max(0, safe_int(args[3], 50)) if len(args) > 3 else 50
max_strings = max(0, safe_int(args[4], 20)) if len(args) > 4 else 20

strings_by_ea = {}
try:
    for value in idautils.Strings():
        strings_by_ea[int(value.ea)] = str(value)
except Exception:
    strings_by_ea = {}


def unique(values, limit):
    seen = set()
    result = []
    for value in values:
        text = str(value)
        if text in seen:
            continue
        seen.add(text)
        result.append(text)
        if len(result) >= limit:
            break
    return result


def candidate_behaviors(values):
    lower_values = [str(value).lower() for value in values]
    result = []
    for category, keywords in BEHAVIOR_KEYWORDS.items():
        matched = []
        for keyword in keywords:
            if any(keyword in value for value in lower_values):
                matched.append(keyword)
        if matched:
            result.append({"category": category, "keywords": unique(matched, 20)})
    return result


items = []
for ea in idautils.Functions():
    if len(items) >= max_functions:
        break
    func = ida_funcs.get_func(ea)
    if not func:
        continue

    calls = []
    refs_from = 0
    function_strings = []
    for item_ea in idautils.FuncItems(ea):
        try:
            code_refs = list(idautils.CodeRefsFrom(item_ea, False))
        except Exception:
            code_refs = []
        refs_from += len(code_refs)
        for ref in code_refs:
            name = idc.get_func_name(ref) or idc.get_name(ref) or hex(int(ref))
            calls.append(name)
        try:
            data_refs = list(idautils.DataRefsFrom(item_ea))
        except Exception:
            data_refs = []
        for ref in data_refs:
            value = strings_by_ea.get(int(ref))
            if value:
                function_strings.append(value)

    try:
        basic_blocks = sum(1 for _ in idaapi.FlowChart(func))
    except Exception:
        basic_blocks = 0
    try:
        refs_to = len(list(idautils.CodeRefsTo(ea, False)))
    except Exception:
        refs_to = 0

    calls = unique(calls, max_calls)
    function_strings = unique(function_strings, max_strings)
    behavior_values = calls + function_strings
    items.append(
        {
            "name": idc.get_func_name(ea),
            "start": hex(int(func.start_ea)),
            "end": hex(int(func.end_ea)),
            "size": int(func.end_ea - func.start_ea),
            "basic_blocks": int(basic_blocks),
            "api_calls": calls,
            "strings": function_strings,
            "xrefs_from_count": int(refs_from),
            "xrefs_to_count": int(refs_to),
            "candidate_behaviors": candidate_behaviors(behavior_values),
        }
    )

with open(out_path, "w", encoding="utf-8") as output:
    json.dump({"tool": "ida", "functions": items}, output, ensure_ascii=False)
idc.qexit(0)
'''


class IdaFunctionFeaturesFunction(AnalysisFunction):
    id = "tool.ida_function_features"
    name = "IDA function feature extraction"
    category = "tool"
    result_key = "ida_function_features"
    description = (
        "Runs configured IDA in batch mode with a generated IDAPython script to "
        "export per-function calls, referenced strings, xref counts, basic block "
        "counts, and behavior candidates. Static analysis only."
    )
    cost = "high"
    external_tool = True
    config_required = True
    config_requirements = ["ida.path"]
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    output_schema = {
        "functions": "Per-function static features exported by IDA.",
        "candidate_behaviors": "Keyword/API-based candidate behavior categories.",
        "limitations": "External local tool output; does not execute sample.",
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
        max_functions = _int_param(params, "max_functions", 500)
        max_calls = _int_param(params, "max_calls_per_function", 50)
        max_strings = _int_param(params, "max_strings_per_function", 20)
        with tempfile.TemporaryDirectory() as temp_dir:
            script_path = Path(temp_dir) / "sfp_ida_function_features.py"
            output_path = Path(temp_dir) / "ida_function_features.json"
            script_path.write_text(_IDA_SCRIPT, encoding="utf-8")
            command = [
                str(tool_path),
                "-A",
                f"-S{script_path} {output_path} {max_functions} {max_calls} {max_strings}",
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
                return self._error("timeout", "IDA function feature extraction timed out")
            except OSError:
                return self._error("request_failed", "IDA could not be started")

            parsed = _read_tool_json(output_path)
            if parsed is None:
                return self._error("parse_failed", "IDA function feature output could not be parsed")
            functions = _normalize_functions(parsed.get("functions", []), max_functions)
            return FunctionResult(
                function_id=self.id,
                result_key=self.result_key,
                data={
                    "tool": "ida",
                    "status": "completed" if completed.returncode == 0 else "completed_with_warnings",
                    "functions": functions,
                    "counts": {
                        "functions": len(functions),
                        "candidate_behavior_functions": sum(
                            1 for item in functions if item.get("candidate_behaviors")
                        ),
                    },
                    "warnings": [] if completed.returncode == 0 else ["tool returned non-zero exit code"],
                    "stdout_excerpt": (completed.stdout or "")[:_MAX_STDIO],
                    "stderr_excerpt": (completed.stderr or "")[:_MAX_STDIO],
                    "limitations": [
                        "external local tool output only",
                        "candidate behaviors are static hints",
                        "does not execute sample",
                    ],
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
                "basic_blocks": _safe_int(item.get("basic_blocks")),
                "api_calls": _bounded_strings(item.get("api_calls"), 100, 200),
                "strings": _bounded_strings(item.get("strings"), 50, 500),
                "xrefs_from_count": _safe_int(item.get("xrefs_from_count")),
                "xrefs_to_count": _safe_int(item.get("xrefs_to_count")),
                "candidate_behaviors": _normalize_behaviors(item.get("candidate_behaviors")),
            }
        )
    return result


def _normalize_behaviors(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for item in value[:20]:
        if not isinstance(item, dict):
            continue
        result.append(
            {
                "category": str(item.get("category", ""))[:100],
                "keywords": _bounded_strings(item.get("keywords"), 20, 120),
            }
        )
    return result


def _bounded_strings(value: Any, limit: int, max_length: int) -> list[str]:
    if not isinstance(value, list) or limit <= 0:
        return []
    return [str(item)[:max_length] for item in value[:limit]]


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
