from __future__ import annotations

import base64
import binascii
import re
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_PRINTABLE_MIN = 0x20
_PRINTABLE_MAX = 0x7E
_URL_RE = re.compile(r"https?://[^\s\x00-\x1f\"'<>]+", re.IGNORECASE)
_TRUNCATED_URL_RE = re.compile(r"\bttps?://[^\s\x00-\x1f\"'<>]+", re.IGNORECASE)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{2,}\.)+[a-zA-Z]{2,15}\b")
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")
_WINDOWS_PATH_RE = re.compile(r"\b[A-Za-z]:\\[^\x00\r\n\t\"']+")
_REGISTRY_RE = re.compile(r"\bHK(?:LM|CU|CR|U|CC)\\[^\x00\r\n\t\"']+", re.IGNORECASE)
_BASE64_RE = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
_HEX_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{32,}\b")
_NAMESPACE_PREFIXES = {
    "android",
    "java",
    "javax",
    "microsoft",
    "mono",
    "mscorlib",
    "system",
    "windows",
}
_COMMON_PUBLIC_TLDS = {
    "app",
    "biz",
    "cc",
    "cn",
    "co",
    "com",
    "dev",
    "edu",
    "gov",
    "info",
    "io",
    "me",
    "net",
    "org",
    "ru",
    "top",
    "uk",
    "us",
    "xyz",
}
_FILELIKE_SUFFIXES = {
    "bat",
    "bin",
    "cmd",
    "dat",
    "dll",
    "doc",
    "docx",
    "drv",
    "exe",
    "js",
    "json",
    "log",
    "msi",
    "pdf",
    "ps1",
    "sys",
    "tmp",
    "txt",
    "vbs",
    "xls",
    "xlsx",
    "xml",
    "zip",
}
_CODE_ARTIFACT_SUFFIXES = {"bss", "data", "debug", "idata", "pdata", "rdata", "reloc", "rsrc", "text"}
_KEYWORD_GROUPS = {
    "powershell": [
        "powershell",
        "-enc",
        "frombase64string",
        "downloadstring",
        "invoke-webrequest",
        "invoke-expression",
        "iex",
    ],
    "command_execution": [
        "cmd.exe",
        "rundll32",
        "regsvr32",
        "mshta",
        "wmic",
        "schtasks",
        "certutil",
        "bitsadmin",
    ],
    "persistence": [
        r"software\microsoft\windows\currentversion\run",
        "runonce",
        "startup",
        "createservice",
        "startservice",
        "schtasks",
    ],
    "credential_access": [
        "password",
        "credential",
        "mimikatz",
        "lsass",
        "sekurlsa",
    ],
    "anti_analysis": [
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "virtualbox",
        "vmware",
        "sandbox",
        "wireshark",
        "procmon",
    ],
    "network": [
        "winhttp",
        "wininet",
        "internetopen",
        "httpopenrequest",
        "ws2_32",
        "socket",
        "connect",
    ],
}
_KEYWORD_BOUNDARY_PATTERNS = {
    "credential_access": [
        re.compile(r"(?<![a-z0-9])sam(?![a-z0-9])", re.IGNORECASE),
    ],
}


class StringsEnhancedExtractFunction(AnalysisFunction):
    id = "strings.enhanced_extract"
    name = "Enhanced strings extract"
    category = "static"
    result_key = "enhanced_strings"
    description = (
        "Extracts ASCII and UTF-16LE strings and highlights candidate encodings, "
        "paths, registry keys, command fragments, and suspicious keyword groups."
    )
    cost = "medium"
    candidate_only = True
    requires_human_confirmation = True
    output_schema = {
        "ascii_items": "Printable ASCII strings.",
        "utf16le_items": "Printable UTF-16LE strings.",
        "candidate_indicators": "Regex and keyword candidates; not confirmed behavior.",
        "limitations": "Static strings only; decoded candidates require review.",
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

        min_length = self._int_param(params, "min_length", 4)
        max_strings = self._int_param(params, "max_strings", 3000)
        max_candidates = self._int_param(params, "max_candidates", 200)
        min_length = max(1, min_length)
        max_strings = max(0, max_strings)
        max_candidates = max(0, max_candidates)

        ascii_items = _extract_ascii_strings(data, min_length, max_strings)
        utf16le_items = _extract_utf16le_strings(data, min_length, max_strings)
        all_items = ascii_items + utf16le_items
        keyword_hits = _keyword_hits(all_items)
        base64_candidates = _valid_base64_candidates(_find_matches(_BASE64_RE, all_items), max_candidates)
        hex_candidates = _bounded_unique(_find_matches(_HEX_RE, all_items), max_candidates)
        raw_ips = _bounded_unique(_find_matches(_IPV4_RE, all_items), max_candidates * 2)
        ips, filtered_ips = _filter_ipv4(raw_ips, max_candidates)
        raw_domains = _bounded_unique(_find_matches(_DOMAIN_RE, all_items), max_candidates * 2)
        domains, filtered_domains = _filter_domains(raw_domains, max_candidates)
        urls = _bounded_unique(_find_urls(all_items), max_candidates)

        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "total_ascii": len(ascii_items),
                "total_utf16le": len(utf16le_items),
                "ascii_items": ascii_items,
                "utf16le_items": utf16le_items,
                "urls": urls,
                "ips": ips,
                "domains": domains,
                "filtered_ips": filtered_ips,
                "filtered_domains": filtered_domains,
                "emails": _bounded_unique(_find_matches(_EMAIL_RE, all_items), max_candidates),
                "windows_paths": _bounded_unique(
                    _find_matches(_WINDOWS_PATH_RE, all_items),
                    max_candidates,
                ),
                "registry_keys": _bounded_unique(
                    _find_matches(_REGISTRY_RE, all_items),
                    max_candidates,
                ),
                "base64_candidates": base64_candidates,
                "hex_candidates": hex_candidates,
                "suspicious_keywords": keyword_hits,
                "counts": {
                    "urls": len(urls),
                    "ips": len(ips),
                    "domains": len(domains),
                    "filtered_ips": len(filtered_ips),
                    "filtered_domains": len(filtered_domains),
                    "base64_candidates": len(base64_candidates),
                    "hex_candidates": len(hex_candidates),
                    "keyword_groups": sum(1 for values in keyword_hits.values() if values),
                },
                "limitations": [
                    "static strings only",
                    "candidate encodings and keywords require human confirmation",
                    "does not execute sample",
                ],
            },
        )

    @staticmethod
    def _int_param(params: dict[str, Any], key: str, default: int) -> int:
        try:
            return int(params.get(key, default))
        except (TypeError, ValueError):
            return default

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )


def _extract_ascii_strings(data: bytes, min_length: int, max_strings: int) -> list[str]:
    if max_strings <= 0:
        return []
    items: list[str] = []
    current: list[int] = []
    for byte in data:
        if _PRINTABLE_MIN <= byte <= _PRINTABLE_MAX:
            current.append(byte)
            continue
        if len(current) >= min_length:
            items.append(bytes(current).decode("ascii", errors="replace"))
            if len(items) >= max_strings:
                return items
        current.clear()
    if len(current) >= min_length and len(items) < max_strings:
        items.append(bytes(current).decode("ascii", errors="replace"))
    return items


def _extract_utf16le_strings(data: bytes, min_length: int, max_strings: int) -> list[str]:
    if max_strings <= 0:
        return []
    items: list[str] = []
    index = 0
    while index < len(data) - 1:
        if not (_PRINTABLE_MIN <= data[index] <= _PRINTABLE_MAX and data[index + 1] == 0):
            index += 1
            continue
        if index > 0 and _PRINTABLE_MIN <= data[index - 1] <= _PRINTABLE_MAX:
            index += 1
            continue
        current: list[int] = []
        scan = index
        while scan < len(data) - 1:
            char = data[scan]
            null = data[scan + 1]
            if _PRINTABLE_MIN <= char <= _PRINTABLE_MAX and null == 0:
                current.append(char)
                scan += 2
                continue
            break
        if len(current) >= min_length:
            items.append(bytes(current).decode("ascii", errors="replace"))
            if len(items) >= max_strings:
                return _unique(items)
        index = max(scan, index + 1)
    return _unique(items)[:max_strings]


def _find_matches(pattern: re.Pattern[str], strings: list[str]) -> list[str]:
    matches: list[str] = []
    for value in strings:
        matches.extend(match.group(0) for match in pattern.finditer(value))
    return matches


def _find_urls(strings: list[str]) -> list[str]:
    matches = _find_matches(_URL_RE, strings)
    for value in _find_matches(_TRUNCATED_URL_RE, strings):
        lower = value.lower()
        if lower.startswith("ttp://") or lower.startswith("ttps://"):
            matches.append("h" + value)
        else:
            matches.append(value)
    return matches


def _valid_base64_candidates(values: list[str], max_candidates: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for value in _bounded_unique(values, max_candidates * 2):
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            continue
        printable = sum(1 for byte in decoded if byte in {9, 10, 13} or 32 <= byte <= 126)
        ratio = printable / len(decoded) if decoded else 0.0
        candidates.append(
            {
                "value": value[:200],
                "length": len(value),
                "decoded_size": len(decoded),
                "decoded_printable_ratio": round(ratio, 4),
            }
        )
        if len(candidates) >= max_candidates:
            break
    return candidates


def _keyword_hits(strings: list[str]) -> dict[str, list[str]]:
    lowered = [(value, value.lower()) for value in strings]
    result: dict[str, list[str]] = {}
    for group, keywords in _KEYWORD_GROUPS.items():
        patterns = _KEYWORD_BOUNDARY_PATTERNS.get(group, [])
        hits: list[str] = []
        for original, value in lowered:
            if any(keyword.lower() in value for keyword in keywords) or any(
                pattern.search(original) for pattern in patterns
            ):
                hits.append(original[:300])
            if len(hits) >= 50:
                break
        result[group] = _unique(hits)
    return result


def _bounded_unique(values: list[str], limit: int) -> list[str]:
    if limit <= 0:
        return []
    return _unique(values)[:limit]


def _filter_ipv4(values: list[str], limit: int) -> tuple[list[str], list[str]]:
    accepted: list[str] = []
    filtered: list[str] = []
    for value in values:
        if _looks_like_version_ipv4(value):
            filtered.append(value)
            continue
        accepted.append(value)
        if len(accepted) >= limit:
            break
    return _unique(accepted), _unique(filtered)


def _filter_domains(values: list[str], limit: int) -> tuple[list[str], list[str]]:
    accepted: list[str] = []
    filtered: list[str] = []
    for value in values:
        domain = value.lower().strip(".")
        if _valid_domain(domain):
            accepted.append(domain)
        else:
            filtered.append(domain)
        if len(accepted) >= limit:
            break
    return _unique(accepted), _unique(filtered)


def _valid_domain(domain: str) -> bool:
    parts = domain.rsplit(".", 1)
    if len(parts) != 2:
        return False
    label, suffix = parts[0].lower(), parts[1].lower()
    if suffix in _FILELIKE_SUFFIXES or suffix in _CODE_ARTIFACT_SUFFIXES:
        return False
    labels = domain.split(".")
    if len(labels) < 2 or labels[0] in _NAMESPACE_PREFIXES:
        return False
    if suffix not in _COMMON_PUBLIC_TLDS and len(suffix) > 6:
        return False
    if len(label) < 3:
        return False
    if any(not item or item.startswith("-") or item.endswith("-") for item in labels):
        return False
    return True


def _looks_like_version_ipv4(value: str) -> bool:
    try:
        octets = [int(part) for part in value.split(".")]
    except ValueError:
        return False
    if len(octets) != 4:
        return False
    if octets[2:] == [0, 0] and max(octets[:2]) <= 32:
        return True
    if octets[1:] == [0, 0, 0] and octets[0] <= 32:
        return True
    return False


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
