from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_DEFAULT_ENDPOINT = "https://www.virustotal.com/api/v3/files/{hash}"


class VirusTotalHashLookupFunction(AnalysisFunction):
    id = "ti.virustotal.hash_lookup"
    name = "VirusTotal Hash 查询"
    category = "threat_intelligence"
    result_key = "virustotal_lookup"
    description = (
        "External VirusTotal hash lookup. Threat intelligence results are candidate "
        "evidence only and must not be written as verified local behavior without "
        "human confirmation."
    )
    recommended_before = ["hash.compute"]
    requires_results = ["hash"]
    cost = "high"
    network = True
    external = True
    config_required = True
    config_requirements = ["virustotal.api_key"]
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    output_schema = {
        "detection": "External reputation summary; candidate evidence only.",
        "summary": "Provider analysis statistics, not verified local behavior.",
        "limitations": "Hash lookup only; requires human confirmation.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        _ = params
        sha256 = self._sha256(context)
        if sha256 is None:
            return self._error("missing_hash_result", "hash result is required")
        if not sha256:
            return self._error("missing_sha256", "hash result data.sha256 is required")

        config = context.get("config", {}).get("virustotal", {})
        api_key = config.get("api_key")
        if not api_key:
            return self._error("missing_api_key", "VirusTotal api_key is required")
        endpoint = str(config.get("endpoint") or _DEFAULT_ENDPOINT)
        if not self._valid_endpoint(endpoint):
            return self._error("invalid_endpoint", "VirusTotal endpoint is invalid")

        url = endpoint.format(hash=urllib.parse.quote(sha256))
        request = urllib.request.Request(url, headers={"x-apikey": str(api_key)})
        try:
            with urllib.request.urlopen(
                request, timeout=self._timeout(config)
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return self._http_error(exc.code)
        except (socket.timeout, TimeoutError):
            return self._error("timeout", "VirusTotal request timed out")
        except urllib.error.URLError:
            return self._error("request_failed", "VirusTotal request failed")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._error("parse_failed", "VirusTotal response could not be parsed")

        try:
            attributes = payload.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
        except AttributeError:
            return self._error("parse_failed", "VirusTotal response shape was unexpected")

        detection = ", ".join(f"{key}:{value}" for key, value in stats.items() if value)
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "provider": "virustotal",
                "query": "hash_lookup",
                "hash": sha256,
                "found": True,
                "detection": detection,
                "name": str(attributes.get("meaningful_name") or attributes.get("names", [""])[0] or ""),
                "tags": list(attributes.get("tags", []))[:50],
                "summary": {"last_analysis_stats": stats},
                "limitations": ["hash lookup only", "does not upload sample bytes"],
            },
        )

    @staticmethod
    def _sha256(context: dict[str, Any]) -> str | None:
        hash_result = context.get("results", {}).get("hash")
        if hash_result is None:
            return None
        data = hash_result.get("data", {}) if isinstance(hash_result, dict) else {}
        return data.get("sha256") or ""

    @staticmethod
    def _valid_endpoint(endpoint: str) -> bool:
        parsed = urllib.parse.urlparse(endpoint)
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc) and "{hash}" in endpoint

    @staticmethod
    def _timeout(config: dict[str, Any]) -> int:
        try:
            return max(1, int(config.get("timeout_seconds", 30)))
        except (TypeError, ValueError):
            return 30

    def _http_error(self, status_code: int) -> FunctionResult:
        mapping = {
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            429: "rate_limited",
        }
        code = mapping.get(status_code, "request_failed")
        return self._error(code, f"VirusTotal returned HTTP {status_code}")

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )
