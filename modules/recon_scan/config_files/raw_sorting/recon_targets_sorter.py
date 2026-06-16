from __future__ import annotations

from typing import Any


def sort_output(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    data = _data(raw_output_item)
    counts = data.get("counts") if isinstance(data.get("counts"), dict) else {}
    return {
        "summary": (
            f"Normalized {counts.get('targets', 0)} target(s), "
            f"{counts.get('hosts', 0)} host(s), and {counts.get('urls', 0)} URL seed(s)."
        ),
        "key_fields": {"counts": counts},
        "evidence_hints": {
            "domains": _strings(data.get("domains"))[:30],
            "hosts": _strings(data.get("hosts"))[:30],
            "urls": _strings(data.get("urls"))[:30],
        },
        "warnings": [],
        "limitations": ["Targets were compacted for AI review."],
    }


def _data(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    output = raw_output_item.get("output")
    if isinstance(output, dict):
        data = output.get("data")
        if isinstance(data, dict):
            return data
    return {}


def _strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if value:
        return [str(value)]
    return []
