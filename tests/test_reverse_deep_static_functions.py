from __future__ import annotations

from tests.module_function_helpers import reverse_function_class

PeDeepParseFunction = reverse_function_class("pe_deep_parse.py", "PeDeepParseFunction")
StringsEnhancedExtractFunction = reverse_function_class(
    "strings_enhanced_extract.py",
    "StringsEnhancedExtractFunction",
)
PackerDetectEnhancedFunction = reverse_function_class(
    "packer_detect_enhanced.py",
    "PackerDetectEnhancedFunction",
)


def test_pe_deep_parse_extracts_headers_sections_and_imports(tmp_path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(_minimal_pe())

    result = PeDeepParseFunction().run({"sample_path": str(sample)}, {})

    assert result.status == "success"
    assert result.data["format"] == "pe32"
    assert result.data["headers"]["machine"] == "i386"
    assert result.data["headers"]["entry_point_section"] == ".text"
    assert result.data["counts"]["sections"] == 2
    assert result.data["imports"][0]["dll"] == "KERNEL32.dll"
    assert result.data["imports"][0]["functions"] == ["CreateFileA"]
    assert result.data["overlay"]["present"] is True


def test_pe_deep_parse_rejects_non_pe(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello")

    result = PeDeepParseFunction().run({"sample_path": str(sample)}, {})

    assert result.status == "error"
    assert result.error["code"] == "not_pe"


def test_strings_enhanced_extracts_ascii_utf16_and_candidates(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(
        b"http://example.com/a\x00"
        b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
        b"QWxhZGRpbjpPcGVuU2VzYW1l\x00"
        + "powershell -enc test".encode("utf-16le")
    )

    result = StringsEnhancedExtractFunction().run({"sample_path": str(sample)}, {})

    assert result.status == "success"
    assert "http://example.com/a" in result.data["urls"]
    assert result.data["registry_keys"]
    assert result.data["base64_candidates"][0]["decoded_size"] > 0
    assert result.data["suspicious_keywords"]["powershell"]
    assert "powershell -enc test" in result.data["utf16le_items"]


def test_packer_detect_enhanced_flags_static_candidates(tmp_path) -> None:
    sample = tmp_path / "packed.exe"
    sample.write_bytes(b"MZ" + bytes(range(256)) * 256)
    context = {
        "sample_path": str(sample),
        "results": {
            "pe_deep_parse": {
                "status": "success",
                "data": {
                    "sections": [
                        {
                            "name": "UPX0",
                            "entropy": 7.8,
                            "raw_size": 4096,
                            "virtual_size": 20000,
                            "characteristics": ["executable"],
                        }
                    ],
                    "counts": {"import_functions": 0},
                    "overlay": {"size": 20000},
                },
            },
            "enhanced_strings": {
                "status": "success",
                "data": {"total_ascii": 2, "total_utf16le": 0},
            },
            "byte_stats": {
                "status": "success",
                "data": {"printable_ascii_ratio": 0.01},
            },
        },
    }

    result = PackerDetectEnhancedFunction().run(context, {})

    assert result.status == "success"
    assert result.data["likely_packed"] is True
    assert result.data["confidence"] in {"medium", "high"}
    assert {item["code"] for item in result.data["indicators"]} >= {
        "packer_section_name",
        "very_few_imports",
    }


def _minimal_pe() -> bytes:
    data = bytearray(0x800)
    data[0:2] = b"MZ"
    _put32(data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    _put16(data, coff, 0x014C)
    _put16(data, coff + 2, 2)
    _put16(data, coff + 16, 0xE0)
    _put16(data, coff + 18, 0x0102)

    optional = coff + 20
    _put16(data, optional, 0x10B)
    _put32(data, optional + 16, 0x1000)
    _put32(data, optional + 28, 0x400000)
    _put32(data, optional + 32, 0x1000)
    _put32(data, optional + 36, 0x200)
    _put32(data, optional + 56, 0x3000)
    _put32(data, optional + 60, 0x200)
    _put16(data, optional + 68, 3)
    _put32(data, optional + 92, 16)
    _put32(data, optional + 96 + 8, 0x2000)
    _put32(data, optional + 96 + 12, 40)

    section_table = optional + 0xE0
    _section(data, section_table, b".text", 0x1000, 0x200, 0x200, 0x200, 0x60000020)
    _section(data, section_table + 40, b".rdata", 0x2000, 0x200, 0x400, 0x200, 0x40000040)
    data[0x200:0x300] = b"\x90" * 0x100

    _put32(data, 0x400, 0x2040)
    _put32(data, 0x400 + 12, 0x2050)
    _put32(data, 0x400 + 16, 0x2040)
    _put32(data, 0x440, 0x2060)
    data[0x450:0x45D] = b"KERNEL32.dll\x00"
    _put16(data, 0x460, 0)
    data[0x462:0x46E] = b"CreateFileA\x00"
    data[0x600:] = b"OVERLAY" * ((0x800 - 0x600) // 7)
    return bytes(data)


def _section(
    data: bytearray,
    offset: int,
    name: bytes,
    virtual_address: int,
    virtual_size: int,
    raw_pointer: int,
    raw_size: int,
    characteristics: int,
) -> None:
    data[offset : offset + len(name)] = name
    _put32(data, offset + 8, virtual_size)
    _put32(data, offset + 12, virtual_address)
    _put32(data, offset + 16, raw_size)
    _put32(data, offset + 20, raw_pointer)
    _put32(data, offset + 36, characteristics)


def _put16(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 2] = value.to_bytes(2, "little")


def _put32(data: bytearray, offset: int, value: int) -> None:
    data[offset : offset + 4] = value.to_bytes(4, "little")
