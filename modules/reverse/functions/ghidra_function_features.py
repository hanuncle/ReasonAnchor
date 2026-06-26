from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_MAX_STDIO = 4000
_GHIDRA_SCRIPT = r'''
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class SfpGhidraFunctionFeatures extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = args.length > 0 ? args[0] : "sfp_ghidra_function_features.json";
        int maxFunctions = args.length > 1 ? safeInt(args[1], 500) : 500;
        int maxCalls = args.length > 2 ? safeInt(args[2], 50) : 50;
        int maxStrings = args.length > 3 ? safeInt(args[3], 20) : 20;
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(outPath), "UTF-8"));
        writer.print("{\"tool\":\"ghidra\",\"functions\":[");
        boolean first = true;
        int count = 0;
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && count < maxFunctions) {
            Function function = functions.next();
            if (!first) {
                writer.print(",");
            }
            first = false;
            writeFunction(writer, function, maxCalls, maxStrings);
            count++;
        }
        writer.print("]}");
        writer.close();
    }

    private void writeFunction(PrintWriter writer, Function function, int maxCalls, int maxStrings) throws Exception {
        AddressSetView body = function.getBody();
        List<String> calls = new ArrayList<String>();
        List<String> strings = new ArrayList<String>();
        int refsFrom = 0;
        if (body != null) {
            InstructionIterator instructions = currentProgram.getListing().getInstructions(body, true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                Reference[] refs = instruction.getReferencesFrom();
                refsFrom += refs.length;
                for (Reference ref : refs) {
                    Address to = ref.getToAddress();
                    if (ref.getReferenceType().isCall()) {
                        String callName = "";
                        Symbol symbol = getSymbolAt(to);
                        if (symbol != null) {
                            callName = symbol.getName(true);
                        }
                        if (callName.length() == 0) {
                            callName = instruction.getDefaultOperandRepresentation(0);
                        }
                        uniqueAdd(calls, callName, maxCalls);
                    }
                    Data data = currentProgram.getListing().getDataAt(to);
                    if (data != null) {
                        Object value = data.getValue();
                        if (value instanceof String) {
                            uniqueAdd(strings, (String)value, maxStrings);
                        }
                    }
                }
            }
        }

        writer.print("{\"name\":\"");
        writer.print(escape(function.getName()));
        writer.print("\",\"start\":\"");
        writer.print(escape(function.getEntryPoint().toString()));
        writer.print("\",\"end\":\"");
        writer.print(body == null ? "" : escape(body.getMaxAddress().toString()));
        writer.print("\",\"size\":");
        writer.print(body == null ? 0 : body.getNumAddresses());
        writer.print(",\"basic_blocks\":");
        writer.print(basicBlockCount(body));
        writer.print(",\"api_calls\":");
        writeStringArray(writer, calls);
        writer.print(",\"strings\":");
        writeStringArray(writer, strings);
        writer.print(",\"xrefs_from_count\":");
        writer.print(refsFrom);
        writer.print(",\"xrefs_to_count\":");
        writer.print(referenceCount(function.getEntryPoint()));
        writer.print(",\"candidate_behaviors\":");
        writeCandidateBehaviors(writer, merge(calls, strings));
        writer.print("}");
    }

    private int basicBlockCount(AddressSetView body) {
        if (body == null) {
            return 0;
        }
        try {
            int count = 0;
            BasicBlockModel model = new BasicBlockModel(currentProgram);
            CodeBlockIterator blocks = model.getCodeBlocksContaining(body, monitor);
            while (blocks.hasNext()) {
                blocks.next();
                count++;
            }
            return count;
        }
        catch (Exception ignored) {
            return 0;
        }
    }

    private int referenceCount(Address address) {
        try {
            Reference[] refs = getReferencesTo(address);
            return refs == null ? 0 : refs.length;
        }
        catch (Exception ignored) {
            return 0;
        }
    }

    private List<String> merge(List<String> left, List<String> right) {
        List<String> merged = new ArrayList<String>();
        merged.addAll(left);
        merged.addAll(right);
        return merged;
    }

    private void writeCandidateBehaviors(PrintWriter writer, List<String> values) {
        String[][] rules = new String[][] {
            {"command_execution", "createprocess,shellexecute,winexec,cmd.exe,powershell,rundll32,regsvr32,mshta,schtasks,wmic"},
            {"network_communication", "internetopen,httpopenrequest,httpsendrequest,winhttp,socket,connect,send,recv,http://,https://"},
            {"file_write", "createfile,writefile,copyfile,deletefile,movefile"},
            {"registry_persistence", "regcreatekey,regsetvalue,currentversion\\run,runonce"},
            {"process_injection", "openprocess,virtualallocex,writeprocessmemory,createremotethread,setwindowshookex"},
            {"credential_access", "openprocesstoken,adjusttokenprivileges,lsass,credential,password"},
            {"anti_analysis", "isdebuggerpresent,checkremotedebuggerpresent,ntqueryinformationprocess,vmware,virtualbox,sandbox"}
        };
        writer.print("[");
        boolean firstBehavior = true;
        for (String[] rule : rules) {
            List<String> hits = matchedKeywords(values, rule[1].split(","));
            if (hits.size() == 0) {
                continue;
            }
            if (!firstBehavior) {
                writer.print(",");
            }
            firstBehavior = false;
            writer.print("{\"category\":\"");
            writer.print(escape(rule[0]));
            writer.print("\",\"keywords\":");
            writeStringArray(writer, hits);
            writer.print("}");
        }
        writer.print("]");
    }

    private List<String> matchedKeywords(List<String> values, String[] keywords) {
        List<String> hits = new ArrayList<String>();
        for (String keyword : keywords) {
            String needle = keyword.toLowerCase();
            for (String value : values) {
                if (value != null && value.toLowerCase().contains(needle)) {
                    uniqueAdd(hits, keyword, 20);
                    break;
                }
            }
        }
        return hits;
    }

    private void writeStringArray(PrintWriter writer, List<String> values) {
        writer.print("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                writer.print(",");
            }
            writer.print("\"");
            writer.print(escape(values.get(i)));
            writer.print("\"");
        }
        writer.print("]");
    }

    private void uniqueAdd(List<String> values, String value, int limit) {
        if (value == null || value.length() == 0 || values.size() >= limit) {
            return;
        }
        for (String existing : values) {
            if (existing.equals(value)) {
                return;
            }
        }
        values.add(value);
    }

    private int safeInt(String value, int fallback) {
        try {
            return Integer.parseInt(value);
        }
        catch (Exception ignored) {
            return fallback;
        }
    }

    private String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n");
    }
}
'''


class GhidraFunctionFeaturesFunction(AnalysisFunction):
    id = "tool.ghidra_function_features"
    name = "Ghidra function feature extraction"
    category = "tool"
    result_key = "ghidra_function_features"
    description = (
        "Runs configured Ghidra analyzeHeadless with a generated Java script to "
        "export per-function calls, referenced strings, xref counts, basic block "
        "counts, and behavior candidates. Static analysis only."
    )
    cost = "high"
    external_tool = True
    config_required = True
    config_requirements = ["ghidra.analyze_headless_path"]
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    output_schema = {
        "functions": "Per-function static features exported by Ghidra.",
        "candidate_behaviors": "Keyword/API-based candidate behavior categories.",
        "limitations": "External local tool output; does not execute sample.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        tool_path = (
            params.get("path")
            or context.get("config", {}).get("ghidra", {}).get("analyze_headless_path")
        )
        if not tool_path:
            return self._error("missing_tool_path", "Ghidra analyzeHeadless path is required")
        if not Path(str(tool_path)).is_file():
            return self._error("tool_path_not_found", "Ghidra analyzeHeadless path was not found")
        sample_path = context.get("sample_path")
        if not sample_path:
            return self._error("missing_sample_path", "context.sample_path is required")
        if not Path(str(sample_path)).is_file():
            return self._error("file_not_found", "sample file was not found")

        timeout = _timeout(params, context, "ghidra", 600)
        max_functions = _int_param(params, "max_functions", 500)
        max_calls = _int_param(params, "max_calls_per_function", 50)
        max_strings = _int_param(params, "max_strings_per_function", 20)
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            script_path = temp / "SfpGhidraFunctionFeatures.java"
            output_path = temp / "ghidra_function_features.json"
            project_dir = temp / "project"
            project_dir.mkdir()
            script_path.write_text(_GHIDRA_SCRIPT, encoding="utf-8")
            command = [
                str(tool_path),
                str(project_dir),
                "sfp_function_features",
                "-import",
                str(sample_path),
                "-scriptPath",
                str(temp),
                "-postScript",
                script_path.name,
                str(output_path),
                str(max_functions),
                str(max_calls),
                str(max_strings),
                "-deleteProject",
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
                return self._error("timeout", "Ghidra function feature extraction timed out")
            except OSError:
                return self._error("request_failed", "Ghidra could not be started")

            parsed = _read_tool_json(output_path)
            if parsed is None:
                return self._error(
                    "parse_failed",
                    "Ghidra function feature output could not be parsed",
                )
            functions = _normalize_functions(parsed.get("functions", []), max_functions)
            return FunctionResult(
                function_id=self.id,
                result_key=self.result_key,
                data={
                    "tool": "ghidra",
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
