from tests.module_function_helpers import reverse_function_class

IocExtractFunction = reverse_function_class("ioc_extract.py", "IocExtractFunction")
MultiFormatParseFunction = reverse_function_class(
    "multi_format_parse.py",
    "MultiFormatParseFunction",
)


def strings_context(items):
    return {
        "results": {
            "strings": {
                "status": "success",
                "data": {"items": items},
            }
        }
    }


def test_ioc_extract_gets_iocs_and_keeps_stable_dedup() -> None:
    result = IocExtractFunction().run(
        strings_context(
            [
                "visit http://example.com/a user admin@example.com",
                "connect 192.168.1.10 and example.com",
                r"C:\Windows\System32\cmd.exe",
                r"HKCU\Software\Test",
                "sample.dll example.com 192.168.1.10",
            ]
        ),
        {},
    )

    assert result.status == "success"
    assert result.data["urls"] == ["http://example.com/a"]
    assert result.data["ipv4"] == ["192.168.1.10"]
    assert result.data["domains"] == ["example.com"]
    assert result.data["emails"] == ["admin@example.com"]
    assert result.data["windows_paths"] == [r"C:\Windows\System32\cmd.exe"]
    assert result.data["registry_keys"] == [r"HKCU\Software\Test"]
    assert "sample.dll" in result.data["filtered_domains"]


def test_ioc_extract_filters_code_artifacts_and_short_pseudo_domains() -> None:
    result = IocExtractFunction().run(
        strings_context(["b.symtab v.uh example.org real.example.com"]),
        {},
    )

    assert result.status == "success"
    assert result.data["domains"] == ["example.org", "real.example.com"]
    assert "b.symtab" in result.data["filtered_domains"]
    assert "v.uh" in result.data["filtered_domains"]


def test_ioc_extract_missing_strings_returns_error() -> None:
    result = IocExtractFunction().run({"results": {}}, {})

    assert result.status == "error"
    assert result.error["code"] == "missing_strings_result"


def test_ioc_extract_failed_strings_returns_error() -> None:
    result = IocExtractFunction().run(
        {"results": {"strings": {"status": "error", "data": {}}}},
        {},
    )

    assert result.status == "error"
    assert result.error["code"] == "invalid_strings_result"


def test_ioc_extract_invalid_items_returns_error() -> None:
    result = IocExtractFunction().run(
        {"results": {"strings": {"status": "success", "data": {"items": "bad"}}}},
        {},
    )

    assert result.status == "error"
    assert result.error["code"] == "invalid_strings_items"


def test_multi_format_parse_detects_known_formats(tmp_path) -> None:
    cases = [
        ("sample.exe", b"MZ\x00\x00", "pe"),
        ("sample.elf", b"\x7fELF\x00", "elf"),
        ("sample.pdf", b"%PDF-1.7", "pdf"),
        ("sample.zip", b"PK\x03\x04", "zip"),
        ("script.ps1", b"Write-Host hello", "script"),
    ]

    for filename, content, expected in cases:
        sample = tmp_path / filename
        sample.write_bytes(content)
        result = MultiFormatParseFunction().run(
            {"sample_path": str(sample), "filename": filename},
            {},
        )

        assert result.status == "success"
        assert result.data["detected_format"] == expected
        assert result.data["metadata"]["filename"] == filename


def test_multi_format_parse_detects_unknown(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"\x00\x01\x02\x03")

    result = MultiFormatParseFunction().run({"sample_path": str(sample)}, {})

    assert result.status == "success"
    assert result.data["detected_format"] == "unknown"


def test_multi_format_parse_missing_and_missing_file_errors(tmp_path) -> None:
    missing_path = tmp_path / "missing.bin"

    missing_sample = MultiFormatParseFunction().run({}, {})
    missing_file = MultiFormatParseFunction().run({"sample_path": str(missing_path)}, {})

    assert missing_sample.status == "error"
    assert missing_sample.error["code"] == "missing_sample_path"
    assert missing_file.status == "error"
    assert missing_file.error["code"] == "file_not_found"
