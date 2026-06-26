from __future__ import annotations

from typing import Any


def sort_output(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    data = _data(raw_output_item)
    status = str(raw_output_item.get("status") or "")
    if status == "skipped":
        return {
            "summary": (
                "Focused dynamic validation was skipped: "
                f"{str(data.get('skip_reason') or 'upstream_skipped')[:160]}."
            ),
            "key_fields": {
                "observed": False,
                "skipped": True,
                "skip_reason": str(data.get("skip_reason") or ""),
                "preflight_status": str(data.get("preflight_status") or ""),
            },
            "evidence_hints": [],
            "warnings": ["Focused dynamic validation skipped because prerequisites were not ready."],
            "limitations": [
                "This is focused validation output, not broad sample behavior proof.",
                "No focused runtime validation was performed.",
            ],
        }
    target = data.get("target", {}) if isinstance(data.get("target"), dict) else {}
    matched = data.get("matched_behavior")
    matched_behavior = matched if isinstance(matched, dict) else {}
    telemetry = data.get("telemetry", {}) if isinstance(data.get("telemetry"), dict) else {}
    category = str(target.get("behavior_category") or "")
    observed = bool(data.get("observed", False))

    return {
        "summary": (
            f"Focused dynamic validation for {category or 'unknown_behavior'} "
            f"{'observed matching telemetry' if observed else 'did not observe matching telemetry'}."
        ),
        "key_fields": {
            "behavior_category": category,
            "observed": observed,
            "validation_sample_id": str(target.get("validation_sample_id") or ""),
            "scenario_id": str(target.get("scenario_id") or ""),
            "technique_id": str(target.get("technique_id") or ""),
            "total_events": _safe_int(telemetry.get("total_events")),
            "event_counts": telemetry.get("event_counts", {}),
            "validation_scope": str(data.get("validation_scope") or ""),
        },
        "evidence_hints": _evidence_hints(matched_behavior),
        "warnings": _warnings(data, observed),
        "limitations": [
            "This is focused validation output, not broad sample behavior proof.",
            "Inspect raw output only if the focused evidence is insufficient.",
        ],
    }


def _data(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    output = raw_output_item.get("output", {})
    if isinstance(output, dict):
        data = output.get("data", {})
        if isinstance(data, dict):
            return data
    return {}


def _evidence_hints(behavior: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = behavior.get("evidence", []) if behavior else []
    if not isinstance(evidence, list):
        return []
    result: list[dict[str, Any]] = []
    for item in evidence[:20]:
        if not isinstance(item, dict):
            continue
        result.append(
            {
                "event_group": str(item.get("event_group") or "")[:120],
                "event_type": str(item.get("event_type") or "")[:120],
                "process_name": str(item.get("process_name") or "")[:200],
                "target": _target(item),
                "reason": str(item.get("reason") or "")[:300],
            }
        )
    return result


def _target(item: dict[str, Any]) -> str:
    for key in ["command_line", "path", "key_path", "destination", "target_process_name"]:
        value = item.get(key)
        if value:
            return str(value)[:500]
    return ""


def _warnings(data: dict[str, Any], observed: bool) -> list[str]:
    warnings: list[str] = []
    if not observed:
        warnings.append("Target behavior was not observed in focused telemetry.")
    for item in data.get("limitations", []):
        warnings.append(str(item)[:300])
    return warnings


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
