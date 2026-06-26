from __future__ import annotations

from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_HEADER_SIZE = 4096
_SCRIPT_EXTENSIONS = {".bat", ".cmd", ".js", ".ps1", ".py", ".sh", ".vbs"}


class MultiFormatParseFunction(AnalysisFunction):
    id = "file.multi_format_parse"
    name = "多格式文件识别"
    category = "static"
    result_key = "multi_format_parser"

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        _ = params
        sample_path = context.get("sample_path")
        if not sample_path:
            return self._error("missing_sample_path", "context.sample_path is required")

        path = Path(str(sample_path))
        if not path.is_file():
            return self._error("file_not_found", "sample file was not found")

        filename = str(context.get("filename") or path.name)
        extension = Path(filename).suffix.lower()
        try:
            header = path.read_bytes()[:_HEADER_SIZE]
            size = path.stat().st_size
        except OSError:
            return self._error("read_failed", "sample file could not be read")

        detected_format = self._detect_format(header, extension)
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "detected_format": detected_format,
                "metadata": {
                    "filename": filename,
                    "extension": extension,
                    "header_hex": header[:32].hex(),
                    "size": size,
                },
                "parsers_attempted": ["header"],
                "limitations": [
                    "lightweight format detection only",
                    "does not execute sample",
                    "does not unpack archives",
                ],
            },
        )

    @staticmethod
    def _detect_format(header: bytes, extension: str) -> str:
        if header.startswith(b"MZ"):
            return "pe"
        if header.startswith(b"\x7fELF"):
            return "elf"
        if header[:4] in {
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe",
        }:
            return "mach_o"
        if header.startswith(b"PK\x03\x04"):
            return "zip"
        if header.startswith(b"%PDF"):
            return "pdf"
        if extension in _SCRIPT_EXTENSIONS:
            return "script"
        if header and MultiFormatParseFunction._looks_text(header):
            return "text"
        return "unknown"

    @staticmethod
    def _looks_text(header: bytes) -> bool:
        printable = sum(1 for byte in header if byte in {9, 10, 13} or 32 <= byte <= 126)
        return printable / max(len(header), 1) > 0.9

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )
