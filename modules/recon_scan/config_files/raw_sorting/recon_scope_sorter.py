from __future__ import annotations

from typing import Any


def sort_output(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    data = _data(raw_output_item)
    return {
        "summary": (
            f"Scope validation allowed {len(_list(data.get('allowed_targets')))} target(s), "
            f"excluded {len(_list(data.get('excluded_targets')))}, "
            f"and rejected {len(_list(data.get('out_of_scope_targets')))} out-of-scope target(s)."
        ),
        "key_fields": {
            "authorized": bool(data.get("authorized")),
            "active_scan_requested": bool(data.get("active_scan_requested")),
            "active_authorized": bool(data.get("active_authorized")),
            "confirmation_required": bool(data.get("confirmation_required")),
            "counts": {
                "allowed": len(_list(data.get("allowed_targets"))),
                "excluded": len(_list(data.get("excluded_targets"))),
                "out_of_scope": len(_list(data.get("out_of_scope_targets"))),
            },
        },
        "evidence_hints": {
            "allowed_targets": _target_values(data.get("allowed_targets"))[:30],
            "excluded_targets": _target_values(data.get("excluded_targets"))[:30],
            "out_of_scope_targets": _target_values(data.get("out_of_scope_targets"))[:30],
        },
        "warnings": _strings(data.get("warnings"))[:20],
        "limitations": _strings(data.get("limitations"))
        + ["Scope validation is syntactic and does not prove legal authorization."],
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


def _target_values(value: Any) -> list[str]:
    return [
        str(item.get("value") or item.get("host") or item)
        for item in _list(value)
        if isinstance(item, dict)
    ]
