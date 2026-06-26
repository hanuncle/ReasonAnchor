from __future__ import annotations

from typing import Any


def sort_output(item: dict[str, Any]) -> dict[str, Any]:
    result_key = str(item.get("result_key") or "")
    output = item.get("output") if isinstance(item.get("output"), dict) else {}
    if output.get("status") == "error":
        return {
            "summary": f"{result_key} returned an external-intelligence error.",
            "error": output.get("error", {}),
            "warnings": ["External-intelligence result is unavailable for this provider call."],
            "limitations": ["No raw provider payload is included in the compact view."],
        }
    data = output.get("data") if isinstance(output.get("data"), dict) else {}
    if result_key == "malwarebazaar_lookup":
        return _malwarebazaar_lookup(data)
    if result_key == "virustotal_lookup":
        return _virustotal_lookup(data)
    if result_key == "virustotal_behaviour_summary":
        return _virustotal_behaviour(data)
    return {
        "summary": f"External-intelligence output for {result_key}.",
        "key_fields": _limited_dict(data),
        "limitations": ["No specialized threat-intelligence branch matched this result_key."],
    }


def _malwarebazaar_lookup(data: dict[str, Any]) -> dict[str, Any]:
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    return {
        "summary": (
            "MalwareBazaar hash lookup "
            f"found={bool(data.get('found'))}, "
            f"signature={str(data.get('signature') or 'unknown')[:120]}."
        ),
        "key_fields": {
            "provider": str(data.get("provider") or "malwarebazaar"),
            "hash": str(data.get("hash") or ""),
            "found": bool(data.get("found")),
            "signature": str(data.get("signature") or ""),
            "tags": _string_list(data.get("tags"))[:20],
            "query_status": str(summary.get("query_status") or ""),
            "file_type": str(summary.get("file_type") or ""),
        },
        "evidence_hints": _tag_hints(data.get("tags")),
        "warnings": ["External provider labels are candidate intelligence, not local behavior."],
        "limitations": _string_list(data.get("limitations")),
    }


def _virustotal_lookup(data: dict[str, Any]) -> dict[str, Any]:
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    stats = summary.get("last_analysis_stats") if isinstance(summary.get("last_analysis_stats"), dict) else {}
    return {
        "summary": (
            "VirusTotal hash lookup "
            f"found={bool(data.get('found'))}, "
            f"detection={str(data.get('detection') or 'none')[:160]}."
        ),
        "key_fields": {
            "provider": str(data.get("provider") or "virustotal"),
            "hash": str(data.get("hash") or ""),
            "found": bool(data.get("found")),
            "name": str(data.get("name") or ""),
            "detection": str(data.get("detection") or ""),
            "tags": _string_list(data.get("tags"))[:20],
            "last_analysis_stats": _limited_dict(stats),
        },
        "evidence_hints": _stat_hints(stats),
        "warnings": ["VirusTotal reputation is candidate intelligence, not local verification."],
        "limitations": _string_list(data.get("limitations")),
    }


def _virustotal_behaviour(data: dict[str, Any]) -> dict[str, Any]:
    counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
    non_empty = [key for key, value in counts.items() if _safe_int(value) > 0]
    return {
        "summary": (
            "VirusTotal behaviour summary "
            f"available={bool(data.get('behaviour_available'))}, "
            f"non_empty_sections={len(non_empty)}."
        ),
        "key_fields": {
            "provider": str(data.get("provider") or "virustotal"),
            "hash": str(data.get("hash") or ""),
            "behaviour_available": bool(data.get("behaviour_available")),
            "counts": _limited_dict(counts),
            "non_empty_sections": non_empty[:20],
            "requires_human_confirmation": bool(data.get("requires_human_confirmation")),
        },
        "evidence_hints": _behaviour_hints(data, non_empty),
        "warnings": ["External sandbox behavior is not the same as local VM verification."],
        "limitations": _string_list(data.get("limitations")),
    }


def _behaviour_hints(data: dict[str, Any], non_empty: list[str]) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    for key in non_empty:
        values = data.get(key)
        if not isinstance(values, list) or not values:
            continue
        hints.append(
            {
                "section": key,
                "count": len(values),
                "sample": _short_value(values[0]),
            }
        )
    return hints[:20]


def _tag_hints(value: Any) -> list[dict[str, str]]:
    return [{"type": "tag", "value": item[:120]} for item in _string_list(value)[:20]]


def _stat_hints(stats: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"type": "last_analysis_stat", "name": str(key), "count": _safe_int(value)}
        for key, value in stats.items()
        if _safe_int(value) > 0
    ][:20]


def _limited_dict(value: dict[str, Any]) -> dict[str, Any]:
    return {str(key): _short_value(item) for key, item in list(value.items())[:30]}


def _short_value(value: Any) -> Any:
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, dict):
        return _limited_dict(value)
    if isinstance(value, list):
        return [_short_value(item) for item in value[:10]]
    return str(value)[:500]


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
