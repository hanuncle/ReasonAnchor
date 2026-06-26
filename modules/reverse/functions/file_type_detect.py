from __future__ import annotations

from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_PE_EXTENSIONS = {".exe", ".dll", ".sys"}
_OFFICE_EXTENSIONS = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"}
_MIME_BY_TYPE = {
    "windows_pe": "application/vnd.microsoft.portable-executable",
    "pdf": "application/pdf",
    "office": "application/vnd.ms-office",
    "archive": "application/zip",
    "text": "text/plain",
    "unknown": "application/octet-stream",
}


class FileTypeDetectFunction(AnalysisFunction):
    id = "file.type_detect"
    name = "File type detect"
    category = "static"
    result_key = "file_type"

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        _ = params
        sample_path = context.get("sample_path")
        filename = context.get("filename") or sample_path or ""
        extension = Path(str(filename)).suffix.lower()
        detected_type = self._detect_from_context(context.get("file_type"))

        if detected_type == "unknown":
            detected_type = self._detect_from_extension(extension)
        if detected_type == "unknown" and sample_path:
            detected_type = self._detect_from_magic(Path(str(sample_path)))

        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "extension": extension,
                "detected_type": detected_type,
                "mime_like": _MIME_BY_TYPE.get(detected_type, _MIME_BY_TYPE["unknown"]),
            },
        )

    @staticmethod
    def _detect_from_context(file_type: Any) -> str:
        if not isinstance(file_type, str):
            return "unknown"
        value = file_type.strip().lower()
        if not value or value == "binary":
            return "unknown"
        return value

    @staticmethod
    def _detect_from_extension(extension: str) -> str:
        if extension in _PE_EXTENSIONS:
            return "windows_pe"
        if extension == ".pdf":
            return "pdf"
        if extension in _OFFICE_EXTENSIONS:
            return "office"
        if extension == ".zip":
            return "archive"
        if extension in {".txt", ".log", ".csv"}:
            return "text"
        return "unknown"

    @staticmethod
    def _detect_from_magic(path: Path) -> str:
        try:
            with path.open("rb") as sample:
                header = sample.read(8)
        except OSError:
            return "unknown"
        if header.startswith(b"MZ"):
            return "windows_pe"
        if header.startswith(b"%PDF"):
            return "pdf"
        if header.startswith(b"PK\x03\x04"):
            return "archive"
        return "unknown"
