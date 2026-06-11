import sys
import types

from tests.module_function_helpers import reverse_function_class

CapaAnalyzeFunction = reverse_function_class("capa_analyze.py", "CapaAnalyzeFunction")
DetectItEasyFunction = reverse_function_class(
    "detect_it_easy.py",
    "DetectItEasyFunction",
)
FlossExtractFunction = reverse_function_class("floss_extract.py", "FlossExtractFunction")
LiefParseFunction = reverse_function_class("lief_parse.py", "LiefParseFunction")
YaraScanLocalFunction = reverse_function_class("yara_scan_local.py", "YaraScanLocalFunction")


def test_yara_scan_missing_rules_dir_returns_error(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello")

    result = YaraScanLocalFunction().run({"sample_path": str(sample), "config": {}}, {})

    assert result.status == "error"
    assert result.error["code"] == "missing_rules_dir"


def test_external_tool_functions_missing_paths_return_errors(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello")
    context = {"sample_path": str(sample), "config": {}}

    assert DetectItEasyFunction().run(context, {}).error["code"] == "missing_tool_path"
    assert CapaAnalyzeFunction().run(context, {}).error["code"] == "missing_tool_path"
    assert FlossExtractFunction().run(context, {}).error["code"] == "missing_tool_path"


def test_lief_parse_dependency_missing_or_mock_success(tmp_path, monkeypatch) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ\x00\x00")

    if "lief" in sys.modules:
        monkeypatch.delitem(sys.modules, "lief", raising=False)

    result = LiefParseFunction().run({"sample_path": str(sample)}, {})
    if result.status == "error":
        assert result.error["code"] == "dependency_missing"
        return

    assert result.status == "success"


def test_lief_parse_mock_success(tmp_path, monkeypatch) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"MZ\x00\x00")

    class Section:
        name = ".text"
        size = 10

    class Binary:
        format = "PE"
        sections = [Section()]
        imports = ["kernel32.dll"]
        exported_functions = ["Exported"]
        symbols = ["symbol"]

    fake_lief = types.SimpleNamespace(parse=lambda path: Binary())
    monkeypatch.setitem(sys.modules, "lief", fake_lief)

    result = LiefParseFunction().run({"sample_path": str(sample)}, {})

    assert result.status == "success"
    assert result.data["format"] == "PE"
    assert result.data["sections"] == [{"name": ".text", "size": 10}]
