from __future__ import annotations

import urllib.parse
from typing import Any

from scan_common import compact_strings, parse_http_output, parse_urls, result_data, success
from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ReconUrlInventoryFunction(AnalysisFunction):
    id = "recon.url_inventory"
    name = "Recon URL inventory"
    category = "recon"
    result_key = "recon_url_inventory"
    description = "Ingest URL-like text or HTTP probe output and build a deduplicated URL inventory."
    cost = "low"
    optional = True
    output_schema = {
        "urls": "Deduplicated normalized URLs.",
        "hosts": "Hosts observed in the URL inventory.",
        "by_host": "URL counts and examples grouped by host.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        items: list[dict[str, Any]] = []
        sources: list[str] = []

        explicit_urls = params.get("urls")
        if isinstance(explicit_urls, list):
            for url in explicit_urls:
                items.append({"url": str(url), "source": "params.urls"})
            sources.append("params.urls")

        for key, source in [
            ("text", "params.text"),
            ("url_output", "params.url_output"),
            ("crawl_output", "params.crawl_output"),
        ]:
            value = str(params.get(key) or "")
            if value:
                items.extend(parse_urls(value, source))
                sources.append(source)

        http_output = str(params.get("http_output") or "")
        if http_output:
            items.extend(parse_http_output(http_output))
            sources.append("params.http_output")

        existing_http = result_data(context, "recon_http")
        web_endpoints = existing_http.get("web_endpoints")
        if isinstance(web_endpoints, list):
            for endpoint in web_endpoints:
                if isinstance(endpoint, dict) and endpoint.get("url"):
                    items.append({**endpoint, "source": endpoint.get("source") or "recon_http"})
            sources.append("context.recon_http")

        urls = _dedupe_urls(items)
        by_host = _group_by_host(urls)

        return success(
            self.id,
            self.result_key,
            {
                "urls": urls,
                "hosts": compact_strings([item.get("host") for item in urls]),
                "by_host": by_host,
                "counts": {
                    "urls": len(urls),
                    "hosts": len(by_host),
                },
                "sources": compact_strings(sources),
            },
        )


def _dedupe_urls(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    urls: list[dict[str, Any]] = []
    for item in items:
        raw_url = str(item.get("url") or "").strip()
        normalized = _normalize_url(raw_url)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        parsed = urllib.parse.urlparse(normalized)
        urls.append(
            {
                "url": normalized,
                "host": parsed.hostname or "",
                "scheme": parsed.scheme,
                "path": parsed.path or "/",
                "status_code": item.get("status_code") or item.get("status"),
                "title": str(item.get("title") or ""),
                "source": str(item.get("source") or ""),
            }
        )
    return urls


def _normalize_url(value: str) -> str:
    if not value.startswith(("http://", "https://")):
        return ""
    parsed = urllib.parse.urlparse(value.strip())
    if not parsed.scheme or not parsed.netloc:
        return ""
    path = parsed.path or "/"
    return urllib.parse.urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            path,
            "",
            parsed.query,
            "",
        )
    )


def _group_by_host(urls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for item in urls:
        host = str(item.get("host") or "")
        if not host:
            continue
        row = grouped.setdefault(host, {"host": host, "count": 0, "examples": []})
        row["count"] += 1
        if len(row["examples"]) < 5:
            row["examples"].append(item["url"])
    return sorted(grouped.values(), key=lambda row: (-int(row["count"]), row["host"]))
