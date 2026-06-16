from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import shlex
import subprocess
import tempfile
import urllib.parse
from pathlib import Path
from typing import Any

from security_function_platform.core.function_result import FunctionResult

AUTHORIZATION_TOKEN = "I_CONFIRM_AUTHORIZED_ACTIVE_RECON"
MAX_ITEMS = 500
MAX_OUTPUT_BYTES = 512 * 1024

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def success(function_id: str, result_key: str, data: dict[str, Any]) -> FunctionResult:
    return FunctionResult(function_id=function_id, result_key=result_key, data=data)


def error(function_id: str, result_key: str, code: str, message: str) -> FunctionResult:
    return FunctionResult(
        function_id=function_id,
        result_key=result_key,
        status="error",
        error={"code": code, "message": message},
    )


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    text = text.replace(",", "\n")
    return [line.strip() for line in text.splitlines() if line.strip()]


def recon_config(context: dict[str, Any]) -> dict[str, Any]:
    config = context.get("config", {})
    if not isinstance(config, dict):
        return {}
    nested = config.get("recon_scan", {})
    return nested if isinstance(nested, dict) else {}


def config_or_param(
    context: dict[str, Any],
    params: dict[str, Any],
    key: str,
    default: Any = None,
) -> Any:
    if key in params:
        return params.get(key)
    return recon_config(context).get(key, default)


def normalize_target(value: str) -> tuple[dict[str, Any] | None, str | None]:
    original = str(value).strip()
    if not original:
        return None, "empty_target"
    if "://" in original:
        return _normalize_url(original)

    stripped = original.strip().strip(".").lower()
    try:
        if "/" in stripped:
            network = ipaddress.ip_network(stripped, strict=False)
            return {
                "original": original,
                "value": str(network),
                "kind": "cidr",
                "host": str(network.network_address),
                "network": str(network),
            }, None
        address = ipaddress.ip_address(stripped)
        return {
            "original": original,
            "value": str(address),
            "kind": "ip",
            "host": str(address),
        }, None
    except ValueError:
        pass

    if stripped.startswith("*."):
        host = stripped[2:]
        if _DOMAIN_RE.match(host):
            return {
                "original": original,
                "value": f"*.{host}",
                "kind": "wildcard_domain",
                "host": host,
            }, None
        return None, "invalid_wildcard_domain"

    if _DOMAIN_RE.match(stripped):
        return {
            "original": original,
            "value": stripped,
            "kind": "domain",
            "host": stripped,
        }, None
    return None, "invalid_target"


def _normalize_url(original: str) -> tuple[dict[str, Any] | None, str | None]:
    parsed = urllib.parse.urlparse(original)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None, "invalid_url"
    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        return None, "invalid_url_host"
    value = urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc.lower(),
            parsed.path or "",
            "",
            parsed.query or "",
            "",
        )
    )
    return {
        "original": original,
        "value": value,
        "kind": "url",
        "host": host,
        "scheme": parsed.scheme,
        "port": parsed.port,
        "path": parsed.path or "/",
    }, None


def normalize_many(values: list[str]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    normalized: list[dict[str, Any]] = []
    invalid: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for value in values:
        item, code = normalize_target(value)
        if item is None:
            invalid.append({"target": value, "reason": str(code or "invalid_target")})
            continue
        key = (str(item["kind"]), str(item["value"]))
        if key in seen:
            continue
        seen.add(key)
        normalized.append(item)
    return normalized[:MAX_ITEMS], invalid[:MAX_ITEMS]


def target_matches_scope(target: dict[str, Any], scope_patterns: list[str]) -> bool:
    if not scope_patterns:
        return False
    host = str(target.get("host") or target.get("value") or "").lower()
    value = str(target.get("value") or "").lower()
    for pattern in scope_patterns:
        normalized, _ = normalize_target(pattern)
        if normalized is None:
            continue
        kind = normalized.get("kind")
        scope_value = str(normalized.get("value") or "").lower()
        scope_host = str(normalized.get("host") or "").lower()
        if kind == "wildcard_domain":
            if host == scope_host or host.endswith(f".{scope_host}"):
                return True
        elif kind == "domain":
            if host == scope_value or host.endswith(f".{scope_value}"):
                return True
        elif kind == "url":
            if host == scope_host:
                return True
        elif kind == "ip":
            if value == scope_value or host == scope_value:
                return True
        elif kind == "cidr":
            try:
                candidate = ipaddress.ip_address(host)
                if candidate in ipaddress.ip_network(scope_value, strict=False):
                    return True
            except ValueError:
                continue
    return False


def result_data(context: dict[str, Any], result_key: str) -> dict[str, Any]:
    result = context.get("results", {}).get(result_key, {})
    if not isinstance(result, dict):
        return {}
    data = result.get("data", {})
    return data if isinstance(data, dict) else {}


def result_status(context: dict[str, Any], result_key: str) -> str:
    result = context.get("results", {}).get(result_key, {})
    return str(result.get("status") or "") if isinstance(result, dict) else ""


def selected_targets(context: dict[str, Any], params: dict[str, Any]) -> list[dict[str, Any]]:
    explicit, _invalid = normalize_many(as_list(params.get("targets")))
    if explicit:
        return explicit
    scope = result_data(context, "recon_scope")
    allowed = scope.get("allowed_targets")
    if isinstance(allowed, list):
        return [item for item in allowed if isinstance(item, dict)]
    targets = result_data(context, "recon_targets").get("targets")
    if isinstance(targets, list):
        return [item for item in targets if isinstance(item, dict)]
    return []


def active_scope_authorized(context: dict[str, Any]) -> bool:
    scope = result_data(context, "recon_scope")
    return bool(scope.get("active_authorized") is True)


def compact_strings(values: list[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= MAX_ITEMS:
            break
    return out


def merge_unique_dicts(items: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in items:
        value = str(item.get(key) or "")
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(item)
        if len(out) >= MAX_ITEMS:
            break
    return out


def host_targets(targets: list[dict[str, Any]]) -> list[str]:
    hosts: list[str] = []
    for target in targets:
        host = str(target.get("host") or target.get("value") or "")
        if host:
            hosts.append(host)
    return compact_strings(hosts)


def domain_targets(targets: list[dict[str, Any]]) -> list[str]:
    domains: list[str] = []
    for target in targets:
        kind = str(target.get("kind") or "")
        if kind in {"domain", "wildcard_domain", "url"}:
            host = str(target.get("host") or target.get("value") or "")
            if host:
                domains.append(host)
    return compact_strings(domains)


def url_targets(targets: list[dict[str, Any]]) -> list[str]:
    urls: list[str] = []
    for target in targets:
        kind = str(target.get("kind") or "")
        host = str(target.get("host") or target.get("value") or "")
        value = str(target.get("value") or "")
        if kind == "url" and value:
            urls.append(value)
        elif host:
            urls.extend([f"https://{host}", f"http://{host}"])
    return compact_strings(urls)


def tool_path(context: dict[str, Any], params: dict[str, Any], tool: str) -> str:
    return str(config_or_param(context, params, f"{tool}_path", tool) or tool)


def resolve_tool(context: dict[str, Any], params: dict[str, Any], tool: str) -> str | None:
    configured = tool_path(context, params, tool)
    path = Path(configured)
    if path.is_file():
        return str(path)
    found = shutil.which(configured)
    return found if found else None


def timeout_seconds(context: dict[str, Any], params: dict[str, Any], default: int = 60) -> int:
    raw = config_or_param(context, params, "timeout_seconds", default)
    try:
        return max(1, min(int(raw), 900))
    except (TypeError, ValueError):
        return default


def max_output_bytes(context: dict[str, Any], params: dict[str, Any]) -> int:
    raw = config_or_param(context, params, "max_output_bytes", MAX_OUTPUT_BYTES)
    try:
        return max(4096, min(int(raw), 5 * 1024 * 1024))
    except (TypeError, ValueError):
        return MAX_OUTPUT_BYTES


def rate_limit_value(context: dict[str, Any], params: dict[str, Any]) -> str:
    value = str(config_or_param(context, params, "rate_limit", "") or "").strip().lower()
    if not value:
        value = str(config_or_param(context, params, "default_rate_limit", "low") or "low")
    return value if value in {"low", "medium", "high"} else "low"


def rate_number(rate_limit: str, tool: str) -> str:
    matrix = {
        "dnsx": {"low": "50", "medium": "150", "high": "300"},
        "httpx": {"low": "25", "medium": "75", "high": "150"},
        "naabu": {"low": "200", "medium": "800", "high": "1500"},
        "ffuf": {"low": "20", "medium": "60", "high": "120"},
        "nuclei": {"low": "15", "medium": "50", "high": "100"},
    }
    return matrix.get(tool, matrix["httpx"]).get(rate_limit, "25")


def command_preview(argv: list[str]) -> str:
    return " ".join(shlex.quote(str(part)) for part in argv)


def run_tool(
    argv: list[str],
    context: dict[str, Any],
    params: dict[str, Any],
    input_text: str | None = None,
    timeout: int | None = None,
) -> dict[str, Any]:
    limit = max_output_bytes(context, params)
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate(
            input=input_text,
            timeout=timeout or timeout_seconds(context, params),
        )
    except subprocess.TimeoutExpired:
        if process is not None:
            _terminate_process_tree(process)
            stdout, stderr = process.communicate()
        else:
            stdout, stderr = "", ""
        return {
            "status": "timeout",
            "returncode": None,
            "stdout": _truncate_text(stdout or "", limit),
            "stderr": _truncate_text(stderr or "", limit),
            "command": command_preview(argv),
        }
    except OSError as exc:
        return {
            "status": "not_started",
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
            "command": command_preview(argv),
        }
    return {
        "status": "completed" if process.returncode == 0 else "completed_with_warnings",
        "returncode": process.returncode,
        "stdout": _truncate_text(stdout or "", limit),
        "stderr": _truncate_text(stderr or "", limit),
        "command": command_preview(argv),
    }


def _terminate_process_tree(process: subprocess.Popen[str]) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            check=False,
        )
        return
    process.kill()


def run_tool_with_input_file(
    argv_template: list[str],
    placeholder: str,
    lines: list[str],
    context: dict[str, Any],
    params: dict[str, Any],
    timeout: int | None = None,
) -> dict[str, Any]:
    if not lines:
        return {
            "status": "skipped",
            "returncode": None,
            "stdout": "",
            "stderr": "no input lines",
            "command": command_preview(argv_template),
            "input_count": 0,
        }
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            temp_path = handle.name
            handle.write("\n".join(lines))
            handle.write("\n")
        argv = [temp_path if part == placeholder else part for part in argv_template]
        result = run_tool(argv, context, params, timeout=timeout)
        result["input_count"] = len(lines)
        return result
    finally:
        if temp_path:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except OSError:
                pass


def _truncate_text(value: str, limit: int) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return value
    return encoded[:limit].decode("utf-8", errors="replace") + "\n[truncated]"


def parse_json_lines(text: Any) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            records.append(item)
        if len(records) >= MAX_ITEMS:
            break
    return records


def parse_dns_output(text: Any) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    hosts: list[str] = []
    addresses: list[str] = []
    for item in parse_json_lines(text):
        host = str(item.get("host") or item.get("input") or "").strip()
        values: list[str] = []
        for key in ("a", "aaaa", "cname"):
            raw = item.get(key)
            if isinstance(raw, list):
                values.extend(str(entry) for entry in raw if entry)
            elif raw:
                values.append(str(raw))
        if host:
            hosts.append(host)
        addresses.extend(values)
        records.append({"host": host, "values": compact_strings(values), "source": "dnsx"})
    if not records:
        for line in str(text or "").splitlines():
            candidate = line.strip().split()[0] if line.strip() else ""
            if _is_dns_candidate(candidate):
                hosts.append(candidate)
                records.append({"host": candidate, "values": [], "source": "text"})
    return {
        "records": records[:MAX_ITEMS],
        "hosts": compact_strings(hosts),
        "addresses": compact_strings(addresses),
    }


def _is_dns_candidate(value: Any) -> bool:
    text = str(value or "").strip().strip("[]").strip(".").lower()
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return bool(_DOMAIN_RE.match(text))


def parse_http_output(text: Any) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    for item in parse_json_lines(text):
        url = item.get("url") or item.get("input")
        if not url:
            continue
        endpoints.append(
            {
                "url": str(url),
                "status_code": item.get("status_code"),
                "title": repair_mojibake(str(item.get("title") or "")),
                "webserver": str(item.get("webserver") or item.get("server") or ""),
                "technologies": item.get("tech") or item.get("technologies") or [],
                "source": "httpx",
            }
        )
    if endpoints:
        return endpoints[:MAX_ITEMS]
    return [
        {
            "url": line.strip(),
            "status_code": None,
            "title": "",
            "webserver": "",
            "technologies": [],
            "source": "text",
        }
        for line in str(text or "").splitlines()
        if line.strip().startswith(("http://", "https://"))
    ][:MAX_ITEMS]


def repair_mojibake(text: str) -> str:
    value = str(text or "")
    if not value:
        return ""
    repaired = _try_repair_mojibake(value)
    return repaired if repaired is not None else value


def _try_repair_mojibake(value: str) -> str | None:
    candidates: list[str] = []
    for encoding in ("gb18030", "gbk", "latin1"):
        try:
            candidate = value.encode(encoding).decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
        if candidate and candidate != value:
            candidates.append(candidate)
    if not candidates:
        return None
    current_score = _mojibake_score(value)
    best = min(candidates, key=_mojibake_score)
    return best if _mojibake_score(best) < current_score else None


def _mojibake_score(value: str) -> int:
    markers = (
        "Ã",
        "Â",
        "â",
        "æ",
        "å",
        "ç",
        "�",
        "鎵",
        "惧",
        "埌",
        "浣",
        "犵",
        "殑",
        "涔",
        "愯",
        "叮",
        "锛",
        "銆",
        "鈥",
        "鐩",
        "绋",
        "妗",
    )
    return sum(value.count(marker) for marker in markers)


def parse_port_output(text: Any, source: str = "naabu") -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(host: Any, port: Any, service: Any = "") -> None:
        host_text = str(host or "").strip().strip("[]")
        port_text = str(port or "").strip()
        if not host_text or not port_text or not port_text.isdigit():
            return
        key = (host_text, port_text)
        if key in seen:
            return
        seen.add(key)
        services.append(
            {
                "host": host_text,
                "port": port_text,
                "service": str(service or ""),
                "source": source,
            }
        )

    for item in parse_json_lines(text):
        add(item.get("host") or item.get("ip"), item.get("port"), item.get("service") or "")
    for line in str(text or "").splitlines():
        candidate = line.strip().split()[0] if line.strip() else ""
        if not candidate or candidate.startswith("{"):
            continue
        if "://" in candidate:
            parsed = urllib.parse.urlparse(candidate)
            add(parsed.hostname or "", parsed.port or "")
        elif ":" in candidate:
            host, port = candidate.rsplit(":", 1)
            add(host, port)
    return services[:MAX_ITEMS]


def parse_nmap_output(text: Any) -> list[dict[str, Any]]:
    services: list[dict[str, Any]] = []
    current_host = ""
    host_re = re.compile(r"Nmap scan report for (?P<host>.+)$")
    port_re = re.compile(r"^(?P<port>\d+)/tcp\s+open\s+(?P<service>\S+)(?:\s+(?P<product>.*))?$")
    for line in str(text or "").splitlines():
        stripped = line.strip()
        host_match = host_re.search(stripped)
        if host_match:
            current_host = host_match.group("host").strip()
            continue
        port_match = port_re.search(stripped)
        if port_match and current_host:
            services.append(
                {
                    "host": current_host,
                    "port": port_match.group("port"),
                    "service": port_match.group("service"),
                    "product": (port_match.group("product") or "").strip(),
                    "source": "nmap",
                }
            )
    return services[:MAX_ITEMS]


def parse_urls(text: Any, source: str) -> list[dict[str, Any]]:
    if source == "ffuf":
        return parse_ffuf_urls(text)
    urls: list[dict[str, Any]] = []
    raw = str(text or "")
    for item in parse_json_lines(raw):
        url = item.get("url") or item.get("request") or item.get("endpoint") or item.get("input")
        if url:
            urls.append({"url": str(url), "source": source})
    if not urls:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            results = payload.get("results")
            if isinstance(results, list):
                for item in results:
                    if isinstance(item, dict) and item.get("url"):
                        urls.append({"url": str(item["url"]), "source": source})
            elif payload.get("url"):
                urls.append({"url": str(payload["url"]), "source": source})
    urls.extend({"url": match.group(0).rstrip(").,;"), "source": source} for match in _URL_RE.finditer(raw))
    return merge_unique_dicts(urls, "url")


def parse_ffuf_urls(text: Any) -> list[dict[str, Any]]:
    urls: list[dict[str, Any]] = []
    payloads: list[dict[str, Any]] = []
    raw = str(text or "")
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            payloads.append(item)
    if not payloads:
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            item = None
        if isinstance(item, dict):
            payloads.append(item)

    for payload in payloads:
        results = payload.get("results")
        if not isinstance(results, list):
            continue
        for item in results:
            if not isinstance(item, dict):
                continue
            url = str(item.get("url") or item.get("input") or "").strip()
            if not _is_reliable_ffuf_url(url):
                continue
            status = item.get("status")
            if isinstance(status, int) and status >= 400:
                continue
            length = item.get("length")
            words = item.get("words")
            lines = item.get("lines")
            urls.append(
                {
                    "url": url,
                    "source": "ffuf",
                    "status": status,
                    "length": length,
                    "words": words,
                    "lines": lines,
                }
            )
    return merge_unique_dicts(urls, "url")


def _is_reliable_ffuf_url(url: str) -> bool:
    if not url.startswith(("http://", "https://")) or any(char.isspace() for char in url):
        return False
    parsed = urllib.parse.urlparse(url)
    if parsed.fragment:
        return False
    if not parsed.netloc:
        return False
    return True


def parse_nuclei_output(text: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in parse_json_lines(text):
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        title = info.get("name") or item.get("template-id") or item.get("template")
        target = item.get("matched-at") or item.get("host") or item.get("url") or ""
        if not title:
            continue
        findings.append(
            {
                "title": str(title),
                "severity": str(info.get("severity") or item.get("severity") or "unknown").lower(),
                "affected_asset": str(target),
                "template_id": str(item.get("template-id") or item.get("template") or ""),
                "verification": "unverified",
                "source": "nuclei",
            }
        )
    return findings[:MAX_ITEMS]


def merge_services(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for item in items:
        host = str(item.get("host") or "")
        port = str(item.get("port") or "")
        if not host or not port:
            continue
        key = (host, port)
        if key not in seen:
            seen[key] = {
                "host": host,
                "port": port,
                "service": str(item.get("service") or ""),
                "product": str(item.get("product") or ""),
                "source": str(item.get("source") or ""),
            }
            continue
        current = seen[key]
        if not current.get("service") and item.get("service"):
            current["service"] = str(item.get("service") or "")
        if not current.get("product") and item.get("product"):
            current["product"] = str(item.get("product") or "")
        if item.get("source") and str(item.get("source")) not in str(current.get("source") or ""):
            current["source"] = ",".join(filter(None, [str(current.get("source") or ""), str(item["source"])]))
    return list(seen.values())[:MAX_ITEMS]


def stage_status(data: dict[str, Any]) -> str:
    if not data:
        return "not_run"
    if data.get("blocked"):
        return "blocked"
    if data.get("warnings"):
        return "completed_with_warnings"
    return "completed"


def finding_evidence(item: dict[str, Any], function_id: str, result_key: str) -> dict[str, Any]:
    return {
        "summary": f"Candidate finding from {item.get('source') or function_id}.",
        "sources": [
            {
                "source_type": "ai_output",
                "raw_output_id": "",
                "function_id": function_id,
                "result_key": result_key,
                "description": str(item.get("template_id") or item.get("title") or "candidate finding"),
            }
        ],
    }
