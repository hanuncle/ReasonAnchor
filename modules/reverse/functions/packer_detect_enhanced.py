from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_PACKER_SECTION_NAMES = {
    "upx0",
    "upx1",
    "upx2",
    ".aspack",
    ".adata",
    ".petite",
    ".mpress",
    ".themida",
    ".vmp0",
    ".vmp1",
    ".vmp2",
    ".enigma",
    ".packed",
}


class PackerDetectEnhancedFunction(AnalysisFunction):
    id = "packer.detect_enhanced"
    name = "Enhanced packer and obfuscation detection"
    category = "static"
    result_key = "packer_detection"
    description = (
        "Uses static entropy, section layout, imports, overlay, and string-count "
        "heuristics to identify packer or obfuscation candidates."
    )
    cost = "medium"
    candidate_only = True
    requires_human_confirmation = True
    recommended_before = ["pe.deep_parse", "strings.enhanced_extract", "file.byte_stats"]
    output_schema = {
        "likely_packed": "Boolean candidate assessment.",
        "indicators": "Heuristic indicators and supporting evidence.",
        "confidence": "low, medium, or high candidate confidence.",
        "limitations": "Static heuristic only; not confirmed packer identification.",
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

        pe_data = _result_data(context, "pe_deep_parse")
        strings_data = _result_data(context, "enhanced_strings")
        byte_stats = _result_data(context, "byte_stats")
        sections = pe_data.get("sections") if isinstance(pe_data.get("sections"), list) else []
        if not sections:
            sections = _parse_pe_sections(data)

        indicators: list[dict[str, Any]] = []
        score = 0
        file_entropy = _entropy(data)
        printable_ratio = _float(byte_stats.get("printable_ascii_ratio"), _printable_ratio(data))

        if file_entropy >= 7.2:
            score += 3
            indicators.append(_indicator("high_file_entropy", 3, {"entropy": file_entropy}))
        elif file_entropy >= 6.8:
            score += 1
            indicators.append(_indicator("elevated_file_entropy", 1, {"entropy": file_entropy}))

        high_entropy_sections = [
            {
                "name": str(section.get("name", "")),
                "entropy": _float(section.get("entropy"), 0.0),
            }
            for section in sections
            if _float(section.get("entropy"), 0.0) >= 7.2 and int(section.get("raw_size", 0)) >= 512
        ]
        if high_entropy_sections:
            score += min(4, len(high_entropy_sections) * 2)
            indicators.append(_indicator("high_entropy_sections", 2, high_entropy_sections[:10]))

        suspicious_names = [
            str(section.get("name", "")).lower()
            for section in sections
            if str(section.get("name", "")).lower() in _PACKER_SECTION_NAMES
        ]
        if suspicious_names:
            score += 4
            indicators.append(_indicator("packer_section_name", 4, suspicious_names))

        sparse_sections = [
            str(section.get("name", ""))
            for section in sections
            if int(section.get("virtual_size", 0)) > max(4096, int(section.get("raw_size", 0)) * 3)
        ]
        if sparse_sections:
            score += 1
            indicators.append(_indicator("virtual_size_much_larger_than_raw", 1, sparse_sections[:10]))

        executable_empty = [
            str(section.get("name", ""))
            for section in sections
            if "executable" in section.get("characteristics", []) and int(section.get("raw_size", 0)) == 0
        ]
        if executable_empty:
            score += 2
            indicators.append(_indicator("empty_executable_section", 2, executable_empty[:10]))

        imports_count = int(pe_data.get("counts", {}).get("import_functions", 0)) if pe_data else 0
        if pe_data and imports_count <= 5:
            score += 2
            indicators.append(_indicator("very_few_imports", 2, {"import_functions": imports_count}))

        overlay = pe_data.get("overlay", {}) if isinstance(pe_data.get("overlay"), dict) else {}
        overlay_size = int(overlay.get("size", 0))
        if overlay_size and overlay_size / max(1, len(data)) >= 0.2:
            score += 2
            indicators.append(
                _indicator(
                    "large_overlay",
                    2,
                    {"overlay_size": overlay_size, "file_size": len(data)},
                )
            )

        strings_total = int(strings_data.get("total_ascii", 0)) + int(strings_data.get("total_utf16le", 0))
        if strings_data and len(data) >= 50_000 and strings_total <= 20:
            score += 1
            indicators.append(_indicator("low_string_count_for_file_size", 1, {"strings": strings_total}))

        if printable_ratio < 0.05 and len(data) >= 20_000:
            score += 1
            indicators.append(_indicator("low_printable_ratio", 1, {"printable_ratio": printable_ratio}))

        confidence = "high" if score >= 7 else "medium" if score >= 4 else "low"
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "likely_packed": score >= 4,
                "confidence": confidence,
                "score": score,
                "file_entropy": file_entropy,
                "indicators": indicators,
                "counts": {
                    "indicators": len(indicators),
                    "sections": len(sections),
                    "high_entropy_sections": len(high_entropy_sections),
                },
                "limitations": [
                    "static heuristic only",
                    "packer or obfuscation candidates require human confirmation",
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


def _result_data(context: dict[str, Any], result_key: str) -> dict[str, Any]:
    result = context.get("results", {}).get(result_key)
    if not isinstance(result, dict) or result.get("status") == "error":
        return {}
    data = result.get("data", {})
    return data if isinstance(data, dict) else {}


def _indicator(code: str, weight: int, evidence: Any) -> dict[str, Any]:
    return {"code": code, "weight": weight, "evidence": evidence}


def _parse_pe_sections(data: bytes) -> list[dict[str, Any]]:
    if len(data) < 0x40 or not data.startswith(b"MZ"):
        return []
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    if pe_offset + 0x18 >= len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return []
    coff = pe_offset + 4
    section_count = int.from_bytes(data[coff + 2 : coff + 4], "little")
    optional_size = int.from_bytes(data[coff + 16 : coff + 18], "little")
    section_table = coff + 20 + optional_size
    sections: list[dict[str, Any]] = []
    for index in range(min(section_count, 96)):
        offset = section_table + index * 40
        if offset + 40 > len(data):
            break
        name = data[offset : offset + 8].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virtual_size = int.from_bytes(data[offset + 8 : offset + 12], "little")
        raw_size = int.from_bytes(data[offset + 16 : offset + 20], "little")
        raw_pointer = int.from_bytes(data[offset + 20 : offset + 24], "little")
        characteristics_value = int.from_bytes(data[offset + 36 : offset + 40], "little")
        raw = data[raw_pointer : raw_pointer + raw_size] if raw_pointer < len(data) else b""
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "entropy": _entropy(raw),
                "characteristics": ["executable"] if characteristics_value & 0x20000000 else [],
            }
        )
    return sections


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    return round(-sum((count / total) * math.log2(count / total) for count in counts.values()), 6)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for byte in data if byte in {9, 10, 13} or 32 <= byte <= 126)
    return round(printable / len(data), 6)


def _float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
