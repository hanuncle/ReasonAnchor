from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_TRUNCATED_URL_RE = re.compile(r"\bttps?://[^\s\"'<>]+", re.IGNORECASE)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[A-Z0-9-]+\.)+[A-Z]{2,}\b", re.IGNORECASE)
_WINDOWS_PATH_RE = re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
_REGISTRY_RE = re.compile(
    r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|"
    r"HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\\[^\r\n\x00]+",
    re.IGNORECASE,
)
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
    "ocx",
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
_CODE_ARTIFACT_SUFFIXES = {
    "bss",
    "data",
    "debug",
    "idata",
    "pdata",
    "rdata",
    "reloc",
    "rsrc",
    "symtab",
    "text",
    "xdata",
}
_MIN_DOMAIN_LABEL_LENGTH = 3
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


class IocExtractFunction(AnalysisFunction):
    id = "ioc.extract"
    name = "IOC 提取"
    category = "static"
    result_key = "ioc_extractor"
    description = "从 strings.extract 的输出中提取候选 IOC。"
    requires_results = ["strings"]
    recommended_before = ["strings.extract"]
    candidate_only = True
    requires_human_confirmation = True
    output_schema = {
        "urls": "Candidate URLs extracted from strings output.",
        "ipv4": "Candidate IPv4 addresses extracted from strings output.",
        "domains": "Candidate domains extracted from strings output.",
        "registry_keys": "Candidate registry keys extracted from strings output.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        _ = params
        strings_result = context.get("results", {}).get("strings")
        if strings_result is None:
            return self._error("missing_strings_result", "strings result is required")
        if not isinstance(strings_result, dict) or strings_result.get("status") != "success":
            return self._error("invalid_strings_result", "strings result must be successful")

        items = strings_result.get("data", {}).get("items")
        if not isinstance(items, list) or not all(isinstance(item, str) for item in items):
            return self._error("invalid_strings_items", "strings result data.items must be a list")
        items = list(items)
        enhanced_result = context.get("results", {}).get("enhanced_strings")
        if isinstance(enhanced_result, dict) and enhanced_result.get("status") == "success":
            enhanced_data = enhanced_result.get("data", {})
            if isinstance(enhanced_data, dict):
                for key in ("ascii_items", "utf16le_items", "urls"):
                    values = enhanced_data.get(key)
                    if isinstance(values, list):
                        items.extend(str(value) for value in values if isinstance(value, str))

        urls: list[str] = []
        ipv4: list[str] = []
        domains: list[str] = []
        emails: list[str] = []
        windows_paths: list[str] = []
        registry_keys: list[str] = []
        filtered_domains: list[str] = []
        filtered_ipv4: list[str] = []

        for item in items:
            urls.extend(_find_urls(item))
            for match in _IPV4_RE.findall(item):
                if self._looks_like_version_ipv4(match):
                    filtered_ipv4.append(match)
                    continue
                ipv4.append(match)
            emails.extend(_EMAIL_RE.findall(item))
            windows_paths.extend(_WINDOWS_PATH_RE.findall(item))
            registry_keys.extend(_REGISTRY_RE.findall(item))
            for url in _find_urls(item):
                hostname = urlparse(url).hostname
                if hostname:
                    host = hostname.lower().strip(".")
                    if self._valid_domain(host):
                        domains.append(host)
                    else:
                        filtered_domains.append(host)
            for match in _DOMAIN_RE.findall(item):
                domain = match.lower().strip(".")
                if "@" in domain:
                    continue
                if not self._valid_domain(domain):
                    filtered_domains.append(domain)
                    continue
                domains.append(domain)

        data = {
            "urls": self._unique(urls),
            "ipv4": self._unique(ipv4),
            "domains": self._unique(domains),
            "emails": self._unique(emails),
            "windows_paths": self._unique(windows_paths),
            "registry_keys": self._unique(registry_keys),
            "filtered_domains": self._unique(filtered_domains),
            "filtered_ipv4": self._unique(filtered_ipv4),
            "limitations": [
                "static string extraction only",
                "candidate IOCs require context review",
                "bare domains are conservatively filtered to reduce namespace and file-name false positives",
            ],
        }
        data["counts"] = {
            key: len(value)
            for key, value in data.items()
            if isinstance(value, list)
        }
        return FunctionResult(function_id=self.id, result_key=self.result_key, data=data)

    @classmethod
    def _valid_domain(cls, domain: str) -> bool:
        if cls._looks_like_file(domain):
            return False
        labels = domain.split(".")
        if len(labels) < 2:
            return False
        if labels[0] in _NAMESPACE_PREFIXES:
            return False
        suffix = labels[-1]
        if suffix not in _COMMON_PUBLIC_TLDS and len(suffix) > 6:
            return False
        if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
            return False
        return True

    @staticmethod
    def _looks_like_file(domain: str) -> bool:
        parts = domain.rsplit(".", 1)
        if len(parts) != 2:
            return False
        label, suffix = parts[0].lower(), parts[1].lower()
        if suffix in _FILELIKE_SUFFIXES or suffix in _CODE_ARTIFACT_SUFFIXES:
            return True
        if len(label) < _MIN_DOMAIN_LABEL_LENGTH:
            return True
        return False

    @staticmethod
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

    @staticmethod
    def _unique(values: list[str]) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for value in values:
            if value not in seen:
                seen.add(value)
                result.append(value)
        return result

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )


def _find_urls(value: str) -> list[str]:
    matches = _URL_RE.findall(value)
    for item in _TRUNCATED_URL_RE.findall(value):
        lower = item.lower()
        if lower.startswith("ttp://") or lower.startswith("ttps://"):
            matches.append("h" + item)
        else:
            matches.append(item)
    return matches
