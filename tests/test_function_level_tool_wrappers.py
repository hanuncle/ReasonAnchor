from __future__ import annotations

import json
import types
from pathlib import Path

from tests.module_function_helpers import reverse_function_module

ida_module = reverse_function_module("ida_function_analyze.py")
ghidra_module = reverse_function_module("ghidra_function_analyze.py")
ida_features_module = reverse_function_module("ida_function_features.py")
ghidra_features_module = reverse_function_module("ghidra_function_features.py")
binaryninja_module = reverse_function_module("binaryninja_function_analyze.py")

IdaFunctionAnalyzeFunction = ida_module.IdaFunctionAnalyzeFunction
GhidraFunctionAnalyzeFunction = ghidra_module.GhidraFunctionAnalyzeFunction
IdaFunctionFeaturesFunction = ida_features_module.IdaFunctionFeaturesFunction
GhidraFunctionFeaturesFunction = ghidra_features_module.GhidraFunctionFeaturesFunction
BinaryNinjaFunctionAnalyzeFunction = binaryninja_module.BinaryNinjaFunctionAnalyzeFunction


def test_function_level_tool_wrappers_missing_paths_return_errors(tmp_path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x00")
    context = {"sample_path": str(sample), "config": {}}

    assert IdaFunctionAnalyzeFunction().run(context, {}).error["code"] == "missing_tool_path"
    assert GhidraFunctionAnalyzeFunction().run(context, {}).error["code"] == "missing_tool_path"
    assert IdaFunctionFeaturesFunction().run(context, {}).error["code"] == "missing_tool_path"
    assert GhidraFunctionFeaturesFunction().run(context, {}).error["code"] == "missing_tool_path"
    assert BinaryNinjaFunctionAnalyzeFunction().run(context, {}).error["code"] == "missing_tool_path"


def test_ida_function_analyze_parses_mocked_output(tmp_path, monkeypatch) -> None:
    tool = _fake_tool(tmp_path, "idat.exe")
    sample = _sample(tmp_path)

    def fake_run(command, **kwargs):
        _ = kwargs
        script_arg = next(str(item) for item in command if str(item).startswith("-S"))
        output_path = Path(script_arg.split(" ", 1)[1])
        _write_functions(output_path, "ida")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ida_module.subprocess, "run", fake_run)
    result = IdaFunctionAnalyzeFunction().run(
        {"sample_path": str(sample), "config": {"ida": {"path": str(tool)}}},
        {},
    )

    assert result.status == "success"
    assert result.data["tool"] == "ida"
    assert result.data["functions"][0]["name"] == "main"


def test_ghidra_function_analyze_parses_mocked_output(tmp_path, monkeypatch) -> None:
    tool = _fake_tool(tmp_path, "analyzeHeadless.bat")
    sample = _sample(tmp_path)

    def fake_run(command, **kwargs):
        _ = kwargs
        post_index = command.index("-postScript")
        output_path = Path(command[post_index + 2])
        _write_functions(output_path, "ghidra")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ghidra_module.subprocess, "run", fake_run)
    result = GhidraFunctionAnalyzeFunction().run(
        {
            "sample_path": str(sample),
            "config": {"ghidra": {"analyze_headless_path": str(tool)}},
        },
        {},
    )

    assert result.status == "success"
    assert result.data["tool"] == "ghidra"
    assert result.data["counts"]["functions"] == 1


def test_ida_function_features_parses_mocked_output(tmp_path, monkeypatch) -> None:
    tool = _fake_tool(tmp_path, "idat.exe")
    sample = _sample(tmp_path)

    def fake_run(command, **kwargs):
        _ = kwargs
        script_arg = next(str(item) for item in command if str(item).startswith("-S"))
        output_path = Path(script_arg.split(" ", 2)[1])
        _write_function_features(output_path, "ida")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ida_features_module.subprocess, "run", fake_run)
    result = IdaFunctionFeaturesFunction().run(
        {"sample_path": str(sample), "config": {"ida": {"path": str(tool)}}},
        {},
    )

    assert result.status == "success"
    assert result.data["tool"] == "ida"
    function = result.data["functions"][0]
    assert function["name"] == "main"
    assert "CreateProcessW" in function["api_calls"]
    assert function["candidate_behaviors"][0]["category"] == "command_execution"


def test_ghidra_function_features_parses_mocked_output(tmp_path, monkeypatch) -> None:
    tool = _fake_tool(tmp_path, "analyzeHeadless.bat")
    sample = _sample(tmp_path)

    def fake_run(command, **kwargs):
        _ = kwargs
        post_index = command.index("-postScript")
        output_path = Path(command[post_index + 2])
        _write_function_features(output_path, "ghidra")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ghidra_features_module.subprocess, "run", fake_run)
    result = GhidraFunctionFeaturesFunction().run(
        {
            "sample_path": str(sample),
            "config": {"ghidra": {"analyze_headless_path": str(tool)}},
        },
        {},
    )

    assert result.status == "success"
    assert result.data["tool"] == "ghidra"
    assert result.data["counts"]["candidate_behavior_functions"] == 1


def test_binaryninja_function_analyze_parses_mocked_output(tmp_path, monkeypatch) -> None:
    tool = _fake_tool(tmp_path, "binaryninja.exe")
    sample = _sample(tmp_path)

    def fake_run(command, **kwargs):
        assert "--headless" in command
        output_path = Path(kwargs["env"]["SFP_OUTPUT_PATH"])
        _write_functions(output_path, "binaryninja")
        return types.SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(binaryninja_module.subprocess, "run", fake_run)
    monkeypatch.setattr(binaryninja_module, "_supports_headless", lambda tool_path: True)
    result = BinaryNinjaFunctionAnalyzeFunction().run(
        {"sample_path": str(sample), "config": {"binaryninja": {"path": str(tool)}}},
        {},
    )

    assert result.status == "success"
    assert result.data["tool"] == "binaryninja"
    assert result.data["functions"][0]["size"] == 16


def _sample(tmp_path) -> Path:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00\x00")
    return sample


def _fake_tool(tmp_path, name: str) -> Path:
    tool = tmp_path / name
    tool.write_text("tool", encoding="utf-8")
    return tool


def _write_functions(path: Path, tool: str) -> None:
    path.write_text(
        json.dumps(
            {
                "tool": tool,
                "functions": [
                    {"name": "main", "start": "0x1000", "end": "0x1010", "size": 16}
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_function_features(path: Path, tool: str) -> None:
    path.write_text(
        json.dumps(
            {
                "tool": tool,
                "functions": [
                    {
                        "name": "main",
                        "start": "0x1000",
                        "end": "0x1020",
                        "size": 32,
                        "basic_blocks": 3,
                        "api_calls": ["CreateProcessW", "InternetOpenA"],
                        "strings": ["powershell -enc AAAA"],
                        "xrefs_from_count": 2,
                        "xrefs_to_count": 1,
                        "candidate_behaviors": [
                            {
                                "category": "command_execution",
                                "keywords": ["createprocess", "powershell"],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
