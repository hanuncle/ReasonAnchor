from __future__ import annotations

from typing import Any


def sort_output(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    data = _data(raw_output_item)
    options = _list(data.get("options"))
    return {
        "summary": f"Prepared {len(options)} AI-gated next-step option(s).",
        "key_fields": {
            "options_count": len(options),
            "completion_condition": str(data.get("completion_condition") or ""),
        },
        "evidence_hints": {
            "operator_rule": str(data.get("operator_rule") or ""),
            "options": options[:10],
        },
        "warnings": [],
        "limitations": ["AI must choose and run at most one next function at a time."],
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
