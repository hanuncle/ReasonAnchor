from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_DEFAULT_ENDPOINT = "https://www.virustotal.com/api/v3/files/{hash}/behaviour_summary"
_LIST_KEYS = [
    "command_executions",
    "files_written",
    "registry_keys_set",
    "dns_lookups",
    "ip_traffic",
    "http_conversations",
    "mitre_attack_techniques",
    "ids_alerts",
]


class VirusTotalBehaviourSummaryFunction(AnalysisFunction):
    id = "ti.virustotal.behaviour_summary"
    name = "VirusTotal 行为查询"
    category = "threat_intelligence"
    result_key = "virustotal_behaviour_summary"
    description = (
        "External VirusTotal sandbox behaviour summary by hash. External sandbox "
        "results are candidate evidence only, not verified local behavior, and "
        "require human confirmation."
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
        "behaviour_available": "Whether external sandbox behaviour summary exists.",
        "command_executions": "External sandbox command candidates; not local verification.",
        "network": "External sandbox network indicators; candidate evidence only.",
        "limitations": "External sandbox context only; requires human confirmation.",
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
        endpoint = str(config.get("behaviour_endpoint") or _DEFAULT_ENDPOINT)
        if not self._valid_endpoint(endpoint):
            return self._error("invalid_endpoint", "VirusTotal behaviour endpoint is invalid")

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
            return self._error("timeout", "VirusTotal behaviour request timed out")
        except urllib.error.URLError:
            return self._error("request_failed", "VirusTotal behaviour request failed")
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self._error("parse_failed", "VirusTotal behaviour response could not be parsed")

        if not isinstance(payload, dict):
            return self._error("parse_failed", "VirusTotal behaviour response shape was unexpected")
        attributes = payload.get("data", {}).get("attributes", {})
        if not isinstance(attributes, dict):
            return self._error("parse_failed", "VirusTotal behaviour attributes were unexpected")

        data: dict[str, Any] = {
            "provider": "virustotal",
            "query": "behaviour_summary_hash_lookup",
            "hash": sha256,
            "behaviour_available": bool(attributes),
        }
        for key in _LIST_KEYS:
            data[key] = self._list(attributes.get(key, []))
        data["counts"] = {key: len(data[key]) for key in _LIST_KEYS}
        data["requires_human_confirmation"] = True
        data["note"] = (
            "VirusTotal external sandbox behaviour summary; not confirmed local behaviour."
        )
        data["limitations"] = [
            "external sandbox context only",
            "hash lookup only",
            "does not upload sample bytes",
        ]
        return FunctionResult(function_id=self.id, result_key=self.result_key, data=data)

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

    @staticmethod
    def _list(value: Any) -> list[Any]:
        items = value if isinstance(value, list) else []
        result: list[Any] = []
        for item in items[:20]:
            if isinstance(item, str):
                result.append(item[:500])
            elif isinstance(item, dict):
                result.append(
                    {
                        str(key): str(item_value)[:500]
                        for key, item_value in list(item.items())[:20]
                    }
                )
            else:
                result.append(str(item)[:500])
        return result

    def _http_error(self, status_code: int) -> FunctionResult:
        mapping = {
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            429: "rate_limited",
        }
        code = mapping.get(status_code, "request_failed")
        return self._error(code, f"VirusTotal behaviour returned HTTP {status_code}")

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )
