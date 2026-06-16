from __future__ import annotations

from typing import Any


def sort_output(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    function_id = str(raw_output_item.get("function_id") or "")
    data = _data(raw_output_item)
    return {
        "summary": _summary(function_id, data),
        "key_fields": {
            "blocked": bool(data.get("blocked")),
            "executes": bool(data.get("executes")),
            "sources": _strings(data.get("sources")),
            "commands_count": len(_list(data.get("commands"))),
            "counts": _counts(data),
        },
        "evidence_hints": _hints(function_id, data),
        "warnings": _strings(data.get("warnings"))[:20],
        "limitations": [
            "Raw tool output is compacted; fetch the raw_output_id only if exact evidence is needed.",
            "Automated scan findings are candidate evidence until manually verified.",
        ],
    }


def _data(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    output = raw_output_item.get("output")
    if isinstance(output, dict):
        data = output.get("data")
        if isinstance(data, dict):
            return data
    return {}


def _summary(function_id: str, data: dict[str, Any]) -> str:
    if data.get("blocked"):
        return f"{function_id} was blocked pending active authorization."
    counts = _counts(data)
    details = ", ".join(f"{key}={value}" for key, value in counts.items())
    return f"{function_id} completed with {details or 'no parsed observations'}."


def _counts(data: dict[str, Any]) -> dict[str, int]:
    return {
        "records": len(_list(data.get("records"))),
        "resolved_hosts": len(_list(data.get("resolved_hosts"))),
        "addresses": len(_list(data.get("addresses"))),
        "web_endpoints": len(_list(data.get("web_endpoints"))),
        "services": len(_list(data.get("services"))),
        "urls": len(_list(data.get("urls"))),
        "candidate_findings": len(_list(data.get("candidate_findings"))),
    }


def _hints(function_id: str, data: dict[str, Any]) -> dict[str, Any]:
    _ = function_id
    return {
        "resolved_hosts": _strings(data.get("resolved_hosts"))[:30],
        "addresses": _strings(data.get("addresses"))[:30],
        "web_endpoints": _endpoint_hints(data.get("web_endpoints"))[:20],
        "services": _service_hints(data.get("services"))[:20],
        "urls": _url_hints(data.get("urls"))[:30],
        "candidate_findings": _finding_hints(data.get("candidate_findings"))[:20],
    }


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if value:
        return [str(value)]
    return []


def _endpoint_hints(value: Any) -> list[dict[str, Any]]:
    return [
        {
            "url": str(item.get("url") or ""),
            "status_code": item.get("status_code"),
            "title": _clean_title(str(item.get("title") or "")),
            "source": str(item.get("source") or ""),
        }
        for item in _list(value)
        if isinstance(item, dict)
    ]


def _service_hints(value: Any) -> list[dict[str, str]]:
    return [
        {
            "host": str(item.get("host") or ""),
            "port": str(item.get("port") or ""),
            "service": str(item.get("service") or ""),
            "product": str(item.get("product") or ""),
            "source": str(item.get("source") or ""),
        }
        for item in _list(value)
        if isinstance(item, dict)
    ]


def _url_hints(value: Any) -> list[str]:
    return [
        str(item.get("url"))
        for item in _list(value)
        if isinstance(item, dict) and item.get("url")
    ]


def _finding_hints(value: Any) -> list[dict[str, str]]:
    return [
        {
            "title": str(item.get("title") or "Candidate finding"),
            "severity": str(item.get("severity") or "unknown"),
            "affected_asset": str(item.get("affected_asset") or ""),
            "verification": str(item.get("verification") or "unverified"),
        }
        for item in _list(value)
        if isinstance(item, dict)
    ]


def _clean_title(value: str) -> str:
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
    markers = ("Ã", "Â", "â", "æ", "å", "ç", "�", "鎵", "惧", "埌", "浣", "犵", "殑", "涔", "愯", "叮", "锛", "銆", "鈥", "鐩", "绋", "妗")
    return sum(value.count(marker) for marker in markers)
