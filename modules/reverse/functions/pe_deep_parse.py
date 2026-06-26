from __future__ import annotations

import hashlib
import math
from collections import Counter
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_DIRECTORY_NAMES = [
    "export",
    "import",
    "resource",
    "exception",
    "security",
    "base_relocation",
    "debug",
    "architecture",
    "global_ptr",
    "tls",
    "load_config",
    "bound_import",
    "iat",
    "delay_import",
    "clr_runtime",
    "reserved",
]
_MACHINES = {
    0x014C: "i386",
    0x8664: "amd64",
    0x01C0: "arm",
    0xAA64: "arm64",
}
_SUBSYSTEMS = {
    1: "native",
    2: "windows_gui",
    3: "windows_cui",
    9: "windows_ce_gui",
    10: "efi_application",
    14: "xbox",
}
_CHARACTERISTICS = {
    0x0002: "executable_image",
    0x0020: "large_address_aware",
    0x2000: "dll",
    0x0100: "32bit_machine",
}
_SECTION_CHARACTERISTICS = {
    0x00000020: "contains_code",
    0x00000040: "initialized_data",
    0x00000080: "uninitialized_data",
    0x20000000: "executable",
    0x40000000: "readable",
    0x80000000: "writable",
}


class PeDeepParseFunction(AnalysisFunction):
    id = "pe.deep_parse"
    name = "PE deep parse"
    category = "static"
    result_key = "pe_deep_parse"
    description = (
        "Parses PE headers, sections, data directories, imports, exports, TLS "
        "presence, overlay size, and import-hash-like fingerprints without "
        "executing the sample."
    )
    output_schema = {
        "headers": "COFF and optional header summary.",
        "sections": "Section table with entropy and permission flags.",
        "imports": "Imported DLLs and function names when parseable.",
        "exports": "Exported function names when parseable.",
        "overlay": "Static overlay offset and size.",
        "limitations": "Best-effort static parser; not a replacement for full PE tooling.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        sample_path = context.get("sample_path")
        if not sample_path:
            return self._error("missing_sample_path", "context.sample_path is required")
        path = Path(str(sample_path))
        if not path.is_file():
            return self._error("file_not_found", "sample file was not found")
        try:
            data = path.read_bytes()
        except OSError:
            return self._error("read_failed", "sample file could not be read")

        max_imports = self._int_param(params, "max_imports", 400)
        max_exports = self._int_param(params, "max_exports", 300)

        parsed = _PeParser(data).parse(max_imports=max_imports, max_exports=max_exports)
        if parsed.get("status") == "error":
            return self._error(str(parsed["code"]), str(parsed["message"]))
        return FunctionResult(function_id=self.id, result_key=self.result_key, data=parsed)

    @staticmethod
    def _int_param(params: dict[str, Any], key: str, default: int) -> int:
        try:
            return max(0, int(params.get(key, default)))
        except (TypeError, ValueError):
            return default

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )


class _PeParser:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.sections: list[dict[str, Any]] = []
        self.image_base = 0
        self.is_pe32_plus = False
        self.size_of_headers = 0

    def parse(self, max_imports: int, max_exports: int) -> dict[str, Any]:
        if len(self.data) < 0x40 or not self.data.startswith(b"MZ"):
            return self._parse_error("not_pe", "file does not start with MZ")
        pe_offset = self._u32(0x3C)
        if pe_offset <= 0 or pe_offset + 0x18 >= len(self.data):
            return self._parse_error("invalid_pe_offset", "PE header offset is invalid")
        if self.data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return self._parse_error("invalid_pe_signature", "PE signature was not found")

        coff = pe_offset + 4
        machine = self._u16(coff)
        section_count = self._u16(coff + 2)
        timestamp = self._u32(coff + 4)
        optional_size = self._u16(coff + 16)
        characteristics_value = self._u16(coff + 18)
        optional = coff + 20
        if optional + optional_size > len(self.data):
            return self._parse_error("invalid_optional_header", "optional header is truncated")

        magic = self._u16(optional)
        if magic not in {0x10B, 0x20B}:
            return self._parse_error("unknown_optional_header", "optional header magic is unknown")
        self.is_pe32_plus = magic == 0x20B
        entry_point_rva = self._u32(optional + 16)
        self.image_base = self._u64(optional + 24) if self.is_pe32_plus else self._u32(optional + 28)
        section_alignment = self._u32(optional + 32)
        file_alignment = self._u32(optional + 36)
        size_of_image = self._u32(optional + 56)
        self.size_of_headers = self._u32(optional + 60)
        subsystem_value = self._u16(optional + 68)
        dll_characteristics = self._u16(optional + 70)
        data_dir_offset = optional + (112 if self.is_pe32_plus else 96)
        number_of_rva = self._u32(optional + (108 if self.is_pe32_plus else 92))

        self.sections = self._parse_sections(optional + optional_size, section_count)
        directories = self._parse_directories(data_dir_offset, number_of_rva)
        imports = self._parse_imports(directories.get("import", {}), max_imports)
        exports = self._parse_exports(directories.get("export", {}), max_exports)
        overlay = self._overlay()
        import_names = [
            f"{item['dll'].lower()}.{name.lower()}"
            for item in imports
            for name in item.get("functions", [])
        ]

        return {
            "format": "pe32+" if self.is_pe32_plus else "pe32",
            "headers": {
                "machine": _MACHINES.get(machine, hex(machine)),
                "number_of_sections": section_count,
                "timestamp": timestamp,
                "characteristics": self._flags(characteristics_value, _CHARACTERISTICS),
                "entry_point_rva": entry_point_rva,
                "entry_point_section": self._section_for_rva(entry_point_rva),
                "image_base": self.image_base,
                "section_alignment": section_alignment,
                "file_alignment": file_alignment,
                "size_of_image": size_of_image,
                "size_of_headers": self.size_of_headers,
                "subsystem": _SUBSYSTEMS.get(subsystem_value, hex(subsystem_value)),
                "dll_characteristics": dll_characteristics,
            },
            "directories": directories,
            "sections": self.sections,
            "imports": imports,
            "exports": exports,
            "tls": self._parse_tls(directories.get("tls", {})),
            "overlay": overlay,
            "hashes": {
                "import_hash_like": hashlib.md5(",".join(import_names).encode("utf-8")).hexdigest()
                if import_names
                else "",
            },
            "counts": {
                "sections": len(self.sections),
                "import_dlls": len(imports),
                "import_functions": sum(int(item.get("count", 0)) for item in imports),
                "exports": len(exports),
            },
            "limitations": [
                "best-effort static parser",
                "does not execute sample",
                "import_hash_like is not a full pefile-compatible imphash",
            ],
        }

    def _parse_sections(self, section_table: int, section_count: int) -> list[dict[str, Any]]:
        sections: list[dict[str, Any]] = []
        for index in range(min(section_count, 96)):
            offset = section_table + index * 40
            if offset + 40 > len(self.data):
                break
            name = self.data[offset : offset + 8].split(b"\x00", 1)[0].decode(
                "ascii",
                errors="replace",
            )
            virtual_size = self._u32(offset + 8)
            virtual_address = self._u32(offset + 12)
            raw_size = self._u32(offset + 16)
            raw_pointer = self._u32(offset + 20)
            characteristics = self._u32(offset + 36)
            raw = self.data[raw_pointer : raw_pointer + raw_size] if raw_pointer < len(self.data) else b""
            sections.append(
                {
                    "name": name,
                    "virtual_address": virtual_address,
                    "virtual_size": virtual_size,
                    "raw_pointer": raw_pointer,
                    "raw_size": raw_size,
                    "entropy": _entropy(raw),
                    "characteristics": self._flags(characteristics, _SECTION_CHARACTERISTICS),
                }
            )
        return sections

    def _parse_directories(self, offset: int, number_of_rva: int) -> dict[str, dict[str, Any]]:
        directories: dict[str, dict[str, Any]] = {}
        for index, name in enumerate(_DIRECTORY_NAMES):
            if index >= number_of_rva or offset + index * 8 + 8 > len(self.data):
                directories[name] = {"rva": 0, "size": 0, "present": False}
                continue
            rva = self._u32(offset + index * 8)
            size = self._u32(offset + index * 8 + 4)
            directories[name] = {"rva": rva, "size": size, "present": bool(rva and size)}
        return directories

    def _parse_imports(self, directory: dict[str, Any], max_imports: int) -> list[dict[str, Any]]:
        offset = self._rva_to_offset(int(directory.get("rva", 0)))
        if offset is None:
            return []
        imports: list[dict[str, Any]] = []
        total = 0
        for descriptor_index in range(128):
            descriptor = offset + descriptor_index * 20
            if descriptor + 20 > len(self.data):
                break
            original_first_thunk = self._u32(descriptor)
            name_rva = self._u32(descriptor + 12)
            first_thunk = self._u32(descriptor + 16)
            if not any(self.data[descriptor : descriptor + 20]):
                break
            dll_name = self._cstring_from_rva(name_rva)
            thunk_rva = original_first_thunk or first_thunk
            functions = self._parse_thunks(thunk_rva, max(0, max_imports - total))
            total += len(functions)
            imports.append({"dll": dll_name or f"unknown_{descriptor_index}", "functions": functions, "count": len(functions)})
            if total >= max_imports:
                break
        return imports

    def _parse_thunks(self, thunk_rva: int, max_count: int) -> list[str]:
        if max_count <= 0:
            return []
        offset = self._rva_to_offset(thunk_rva)
        if offset is None:
            return []
        pointer_size = 8 if self.is_pe32_plus else 4
        ordinal_flag = 0x8000000000000000 if self.is_pe32_plus else 0x80000000
        functions: list[str] = []
        for index in range(min(max_count, 512)):
            item_offset = offset + index * pointer_size
            if item_offset + pointer_size > len(self.data):
                break
            value = self._u64(item_offset) if self.is_pe32_plus else self._u32(item_offset)
            if value == 0:
                break
            if value & ordinal_flag:
                functions.append(f"ordinal_{value & 0xFFFF}")
                continue
            name_offset = self._rva_to_offset(int(value))
            if name_offset is None or name_offset + 2 >= len(self.data):
                continue
            functions.append(self._cstring(name_offset + 2) or f"import_{index}")
        return functions

    def _parse_exports(self, directory: dict[str, Any], max_exports: int) -> list[str]:
        offset = self._rva_to_offset(int(directory.get("rva", 0)))
        if offset is None or offset + 40 > len(self.data):
            return []
        names_count = self._u32(offset + 24)
        names_rva = self._u32(offset + 32)
        names_offset = self._rva_to_offset(names_rva)
        if names_offset is None:
            return []
        exports: list[str] = []
        for index in range(min(names_count, max_exports)):
            entry = names_offset + index * 4
            if entry + 4 > len(self.data):
                break
            name = self._cstring_from_rva(self._u32(entry))
            if name:
                exports.append(name)
        return exports

    def _parse_tls(self, directory: dict[str, Any]) -> dict[str, Any]:
        rva = int(directory.get("rva", 0))
        offset = self._rva_to_offset(rva)
        if offset is None:
            return {"present": False, "callbacks": []}
        callbacks_va = self._u64(offset + 24) if self.is_pe32_plus else self._u32(offset + 12)
        callbacks_rva = callbacks_va - self.image_base if callbacks_va >= self.image_base else 0
        callbacks_offset = self._rva_to_offset(int(callbacks_rva))
        callbacks: list[int] = []
        if callbacks_offset is not None:
            pointer_size = 8 if self.is_pe32_plus else 4
            for index in range(32):
                item_offset = callbacks_offset + index * pointer_size
                if item_offset + pointer_size > len(self.data):
                    break
                value = self._u64(item_offset) if self.is_pe32_plus else self._u32(item_offset)
                if value == 0:
                    break
                callbacks.append(int(value - self.image_base) if value >= self.image_base else int(value))
        return {"present": True, "callbacks": callbacks, "callbacks_count": len(callbacks)}

    def _overlay(self) -> dict[str, Any]:
        end = self.size_of_headers
        for section in self.sections:
            raw_pointer = int(section["raw_pointer"])
            raw_size = int(section["raw_size"])
            if raw_pointer and raw_size:
                end = max(end, raw_pointer + raw_size)
        if end < len(self.data):
            return {"offset": end, "size": len(self.data) - end, "present": True}
        return {"offset": len(self.data), "size": 0, "present": False}

    def _section_for_rva(self, rva: int) -> str:
        for section in self.sections:
            start = int(section["virtual_address"])
            size = max(int(section["virtual_size"]), int(section["raw_size"]))
            if start <= rva < start + size:
                return str(section["name"])
        return ""

    def _rva_to_offset(self, rva: int) -> int | None:
        if rva <= 0:
            return None
        if 0 <= rva < self.size_of_headers:
            return rva
        for section in self.sections:
            start = int(section["virtual_address"])
            size = max(int(section["virtual_size"]), int(section["raw_size"]))
            if start <= rva < start + size:
                offset = int(section["raw_pointer"]) + (rva - start)
                return offset if 0 <= offset < len(self.data) else None
        return None

    def _cstring_from_rva(self, rva: int) -> str:
        offset = self._rva_to_offset(rva)
        return self._cstring(offset) if offset is not None else ""

    def _cstring(self, offset: int) -> str:
        if offset < 0 or offset >= len(self.data):
            return ""
        end = self.data.find(b"\x00", offset, min(len(self.data), offset + 512))
        if end < 0:
            end = min(len(self.data), offset + 512)
        return self.data[offset:end].decode("utf-8", errors="replace")

    def _u16(self, offset: int) -> int:
        return int.from_bytes(self.data[offset : offset + 2], "little") if offset + 2 <= len(self.data) else 0

    def _u32(self, offset: int) -> int:
        return int.from_bytes(self.data[offset : offset + 4], "little") if offset + 4 <= len(self.data) else 0

    def _u64(self, offset: int) -> int:
        return int.from_bytes(self.data[offset : offset + 8], "little") if offset + 8 <= len(self.data) else 0

    @staticmethod
    def _flags(value: int, mapping: dict[int, str]) -> list[str]:
        return [name for bit, name in mapping.items() if value & bit]

    @staticmethod
    def _parse_error(code: str, message: str) -> dict[str, Any]:
        return {"status": "error", "code": code, "message": message}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    return round(-sum((count / total) * math.log2(count / total) for count in counts.values()), 6)
