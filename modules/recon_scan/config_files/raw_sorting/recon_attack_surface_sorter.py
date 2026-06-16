from __future__ import annotations

from typing import Any


def sort_output(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    data = _data(raw_output_item)
    assets = data.get("assets") if isinstance(data.get("assets"), dict) else {}
    findings = data.get("candidate_findings") if isinstance(data.get("candidate_findings"), list) else []
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    target_scope = data.get("target_scope") if isinstance(data.get("target_scope"), dict) else {}
    return {
        "summary": str(summary.get("overall") or "Recon attack surface summary."),
        "key_fields": {
            "risk_level": summary.get("risk_level", "unknown"),
            "planned_only": bool(summary.get("planned_only")),
            "authorized": bool(target_scope.get("authorized")),
            "active_authorized": bool(target_scope.get("active_authorized")),
            "stage_coverage": data.get("stage_coverage", {}),
            "counts": {
                "domains": len(_list(assets.get("domains"))),
                "hosts": len(_list(assets.get("hosts"))),
                "addresses": len(_list(assets.get("addresses"))),
                "web_endpoints": len(_list(assets.get("web_endpoints"))),
                "services": len(_list(assets.get("services"))),
                "urls": len(_list(assets.get("urls"))),
                "candidate_findings": len(findings),
            },
        },
        "evidence_hints": {
            "domains": _strings(assets.get("domains"))[:30],
            "hosts": _strings(assets.get("hosts"))[:30],
            "addresses": _strings(assets.get("addresses"))[:30],
            "web_endpoints": _endpoint_hints(assets.get("web_endpoints"))[:20],
            "services": _service_hints(assets.get("services"))[:20],
            "urls": _url_hints(assets.get("urls"))[:30],
            "candidate_findings": _finding_hints(findings)[:20],
            "next_step_candidates": _list(data.get("next_step_candidates"))[:10],
        },
        "warnings": _strings(target_scope.get("warnings"))[:20],
        "limitations": _strings(summary.get("limitations"))
        + _strings(target_scope.get("limitations"))
        + ["Attack surface output is compacted for AI review."],
    }


def _data(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    output = raw_output_item.get("output")
    if isinstance(output, dict):
        data = output.get("data")
        if isinstance(data, dict):
            return data
    return {}


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
