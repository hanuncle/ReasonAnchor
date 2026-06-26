from __future__ import annotations

from typing import Any


def sort_output(item: dict[str, Any]) -> dict[str, Any]:
    result_key = str(item.get("result_key") or "")
    output = item.get("output") if isinstance(item.get("output"), dict) else {}
    if output.get("status") == "error":
        return {
            "summary": f"{result_key} returned an error.",
            "error": output.get("error", {}),
            "limitations": ["Sorter returned compact error view."],
        }
    data = output.get("data") if isinstance(output.get("data"), dict) else {}

    if result_key == "strings":
        items = _string_list(data.get("items"))
        return {
            "summary": f"Extracted {data.get('total', len(items))} ASCII strings.",
            "key_fields": {
                "total": data.get("total", len(items)),
                "urls": _string_list(data.get("urls"))[:20],
                "ips": _string_list(data.get("ips"))[:20],
            },
            "representative_strings": _representative_strings(items),
            "warnings": ["Only representative strings are returned; fetch raw output if exact full string list is needed."],
            "limitations": ["Static strings only; strings are not confirmed behavior."],
        }

    if result_key == "enhanced_strings":
        suspicious = data.get("suspicious_keywords") if isinstance(data.get("suspicious_keywords"), dict) else {}
        keyword_summary = {
            str(group): _string_list(values)[:10]
            for group, values in suspicious.items()
            if _string_list(values)
        }
        return {
            "summary": (
                f"Enhanced strings extracted: ascii={data.get('total_ascii', 0)}, "
                f"utf16le={data.get('total_utf16le', 0)}, keyword_groups={len(keyword_summary)}."
            ),
            "key_fields": {
                "total_ascii": data.get("total_ascii", 0),
                "total_utf16le": data.get("total_utf16le", 0),
                "counts": data.get("counts", {}),
                "urls": _string_list(data.get("urls"))[:20],
                "ips": _string_list(data.get("ips"))[:20],
                "domains": _string_list(data.get("domains"))[:20],
                "filtered_ips": _string_list(data.get("filtered_ips"))[:20],
                "filtered_domains": _string_list(data.get("filtered_domains"))[:20],
                "emails": _string_list(data.get("emails"))[:20],
                "windows_paths": _string_list(data.get("windows_paths"))[:20],
                "registry_keys": _string_list(data.get("registry_keys"))[:20],
            },
            "suspicious_keyword_hits": keyword_summary,
            "representative_ascii": _representative_strings(_string_list(data.get("ascii_items"))),
            "representative_utf16le": _representative_strings(_string_list(data.get("utf16le_items"))),
            "base64_candidates": data.get("base64_candidates", [])[:10] if isinstance(data.get("base64_candidates"), list) else [],
            "hex_candidates": _string_list(data.get("hex_candidates"))[:10],
            "warnings": ["Candidate indicators require review; this sorter suppresses full string lists."],
            "limitations": _string_list(data.get("limitations")),
        }

    if result_key == "ioc_extractor":
        counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
        return {
            "summary": (
                f"IOC candidates extracted: urls={counts.get('urls', 0)}, "
                f"domains={counts.get('domains', 0)}, ipv4={counts.get('ipv4', 0)}, "
                f"registry={counts.get('registry_keys', 0)}."
            ),
            "key_fields": {
                "urls": _string_list(data.get("urls"))[:30],
                "ipv4": _string_list(data.get("ipv4"))[:30],
                "domains": _string_list(data.get("domains"))[:30],
                "emails": _string_list(data.get("emails"))[:30],
                "windows_paths": _string_list(data.get("windows_paths"))[:30],
                "registry_keys": _string_list(data.get("registry_keys"))[:30],
                "counts": counts,
            },
            "filtered_candidates": {
                "domains": _string_list(data.get("filtered_domains"))[:30],
                "ipv4": _string_list(data.get("filtered_ipv4"))[:30],
            },
            "warnings": [
                "IOC candidates are not confirmed behavior.",
                "Filtered candidates are shown to help diagnose extraction false positives.",
            ],
            "limitations": _string_list(data.get("limitations")),
        }

    return {
        "summary": f"String/IOC output for {result_key}.",
        "key_fields": data,
        "limitations": ["No specialized branch matched this result_key."],
    }


def _representative_strings(values: list[str], limit: int = 20) -> list[str]:
    selected: list[str] = []
    for value in values:
        text = value.strip()
        if not text:
            continue
        lower = text.lower()
        if any(marker in lower for marker in ("http", "powershell", "cmd.exe", "run", "reg", "socket", "connect")):
            selected.append(text[:300])
        if len(selected) >= limit:
            return selected
    for value in values:
        text = value.strip()
        if text and text[:300] not in selected:
            selected.append(text[:300])
        if len(selected) >= limit:
            break
    return selected


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []
