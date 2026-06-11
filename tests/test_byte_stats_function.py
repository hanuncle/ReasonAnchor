from security_function_platform.core.function_result import FunctionResult

from tests.module_function_helpers import reverse_function_class

ByteStatsFunction = reverse_function_class("byte_stats.py", "ByteStatsFunction")


def test_byte_stats_reads_file_and_returns_statistics(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    content = b"MZ\x00ABC\n\x00"
    sample.write_bytes(content)

    result = ByteStatsFunction().run(
        {"sample_path": str(sample)},
        {"max_header_bytes": 4},
    )

    assert isinstance(result, FunctionResult)
    assert result.status == "success"
    assert result.data["file_size"] == len(content)
    assert result.data["header_hex"] == content[:4].hex()
    assert result.data["null_byte_count"] == 2
    assert result.data["printable_ascii_byte_count"] == 6
    assert "printable_ascii_ratio" in result.data
    assert "entropy_estimate" in result.data


def test_byte_stats_missing_sample_path_returns_error() -> None:
    result = ByteStatsFunction().run({}, {})

    assert result.status == "error"
    assert result.error["code"] == "missing_sample_path"


def test_byte_stats_missing_file_returns_error(tmp_path) -> None:
    result = ByteStatsFunction().run({"sample_path": str(tmp_path / "missing.bin")}, {})

    assert result.status == "error"
    assert result.error["code"] == "sample_not_found"
