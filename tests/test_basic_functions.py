import hashlib

from security_function_platform.core.function_registry import FunctionRegistry
from security_function_platform.core.function_result import FunctionResult

from tests.module_function_helpers import reverse_function_class

FileTypeDetectFunction = reverse_function_class(
    "file_type_detect.py",
    "FileTypeDetectFunction",
)
HashComputeFunction = reverse_function_class("hash_compute.py", "HashComputeFunction")
StringsExtractFunction = reverse_function_class("strings_extract.py", "StringsExtractFunction")


ALL_FUNCTIONS = [HashComputeFunction(), FileTypeDetectFunction(), StringsExtractFunction()]


def run_functions(registry, function_ids, context):
    for function_id in function_ids:
        result = registry.run(function_id, context, params={})
        context.setdefault("results", {})[result.result_key] = result.to_dict()
    return context


def test_hash_compute_calculates_hashes(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    content = b"hello world"
    sample.write_bytes(content)

    result = HashComputeFunction().run({"sample_path": str(sample)}, {})

    assert isinstance(result, FunctionResult)
    assert result.data == {
        "md5": hashlib.md5(content).hexdigest(),
        "sha1": hashlib.sha1(content).hexdigest(),
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def test_hash_compute_missing_sample_path_returns_error() -> None:
    result = HashComputeFunction().run({}, {})

    assert isinstance(result, FunctionResult)
    assert result.status == "error"
    assert result.error["code"] == "missing_sample_path"


def test_file_type_detect_handles_txt_and_exe(tmp_path) -> None:
    txt = tmp_path / "note.txt"
    exe = tmp_path / "tool.exe"
    txt.write_text("plain text", encoding="utf-8")
    exe.write_bytes(b"MZ\x00\x00")

    txt_result = FileTypeDetectFunction().run({"sample_path": str(txt)}, {})
    exe_result = FileTypeDetectFunction().run({"sample_path": str(exe)}, {})

    assert isinstance(txt_result, FunctionResult)
    assert txt_result.data["extension"] == ".txt"
    assert txt_result.data["detected_type"] == "text"
    assert exe_result.data["extension"] == ".exe"
    assert exe_result.data["detected_type"] == "windows_pe"


def test_strings_extract_gets_ascii_urls_and_ips(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00abcd\x00http://example.test/a\x00192.168.1.10\x00")

    result = StringsExtractFunction().run({"sample_path": str(sample)}, {"min_length": 4})

    assert isinstance(result, FunctionResult)
    assert result.status == "success"
    assert "abcd" in result.data["items"]
    assert result.data["urls"] == ["http://example.test/a"]
    assert result.data["ips"] == ["192.168.1.10"]


def test_strings_extract_supports_min_length_and_max_strings(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc\x00abcd\x00abcde\x00abcdef\x00")

    result = StringsExtractFunction().run(
        {"sample_path": str(sample)},
        {"min_length": 4, "max_strings": 2},
    )

    assert result.data["items"] == ["abcd", "abcde"]
    assert result.data["total"] == 2


def test_functions_return_function_result_and_do_not_modify_results(tmp_path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00hello world\x0010.0.0.1\x00")

    for fn in ALL_FUNCTIONS:
        context = {"sample_path": str(sample), "results": {}}
        result = fn.run(context, {})

        assert isinstance(result, FunctionResult)
        assert context["results"] == {}


def test_simple_order_runner_collects_results(tmp_path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00hello world\x00")
    registry = FunctionRegistry()
    for fn in ALL_FUNCTIONS:
        registry.register(fn)

    context = run_functions(
        registry,
        ["hash.compute", "file.type_detect", "strings.extract"],
        {"sample_path": str(sample)},
    )

    assert set(context["results"]) == {"hash", "file_type", "strings"}
