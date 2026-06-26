from __future__ import annotations

from typing import Any


def sort_output(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    data = _data(raw_output_item)
    counts = data.get("counts", {})
    if not isinstance(counts, dict):
        counts = {}
    status = str(raw_output_item.get("status") or "")
    if status == "skipped":
        return {
            "summary": (
                "Dynamic behavior mapping was skipped: "
                f"{str(data.get('skip_reason') or 'upstream_skipped')[:160]}."
            ),
            "key_fields": {
                "source": str(data.get("source", "")),
                "skipped": True,
                "skip_reason": str(data.get("skip_reason") or ""),
                "counts": counts,
            },
            "evidence_hints": [],
            "warnings": ["Dynamic behavior mapping skipped because telemetry was unavailable."],
            "limitations": _limitations(data),
        }
    behaviors = data.get("behaviors", [])
    if not isinstance(behaviors, list):
        behaviors = []
    categories = [
        str(item.get("category") or item.get("behavior_id"))
        for item in behaviors
        if isinstance(item, dict)
    ]
    categories = [category for category in categories if category]
    return {
        "summary": (
            f"Dynamic behavior mapping found {len(categories)} observed behavior categories "
            f"from {_safe_int(counts.get('mapped_events'))} attributed events."
        ),
        "key_fields": {
            "source": str(data.get("source", "")),
            "telemetry_id": str(data.get("telemetry_id", "")),
            "categories": categories,
            "counts": counts,
            "attribution": data.get("attribution", {}),
        },
        "evidence_hints": _behavior_hints(behaviors, limit=25),
        "warnings": [],
        "limitations": _limitations(data),
    }


def _data(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    output = raw_output_item.get("output", {})
    if isinstance(output, dict):
        data = output.get("data", {})
        if isinstance(data, dict):
            return data
    return {}


def _behavior_hints(behaviors: list[Any], limit: int) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    for behavior in behaviors:
        if len(hints) >= limit:
            return hints
        if not isinstance(behavior, dict):
            continue
        evidence = behavior.get("evidence", [])
        first_evidence = evidence[0] if isinstance(evidence, list) and evidence else {}
        if not isinstance(first_evidence, dict):
            first_evidence = {}
        hints.append(
            {
                "category": str(behavior.get("category") or behavior.get("behavior_id", "")),
                "confidence": str(behavior.get("confidence", "")),
                "score": _safe_int(behavior.get("score")),
                "event_group": str(first_evidence.get("event_group", "")),
                "event_type": str(first_evidence.get("event_type", "")),
                "reason": str(first_evidence.get("reason", ""))[:300],
                "value": _evidence_value(first_evidence),
            }
        )
    return hints


def _evidence_value(evidence: dict[str, Any]) -> str:
    for key in ["command_line", "destination", "key_path", "path", "target_process_name"]:
        value = evidence.get(key)
        if value:
            return str(value)[:500]
    return ""


def _limitations(data: dict[str, Any]) -> list[str]:
    limitations = data.get("limitations", [])
    if isinstance(limitations, list):
        return [str(item)[:300] for item in limitations[:8]]
    return []


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
