from __future__ import annotations

from typing import Any

_EVENT_GROUPS = [
    "process_events",
    "file_events",
    "registry_events",
    "network_events",
    "service_events",
    "scheduled_task_events",
    "module_load_events",
]
_NOISE_MARKERS = [
    "export-dynamictelemetry.ps1",
    "export_dynamic_now.bat",
    "cleanup_uploaded_sample.bat",
    "vmware tools",
    "__psscriptpolicytest_",
]
_SAMPLE_MARKERS = [
    "\\samples\\",
    "/samples/",
    "guest_sample_path",
]


def sort_output(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    data = _data(raw_output_item)
    counts = {
        group: len(data.get(group, [])) if isinstance(data.get(group), list) else 0
        for group in _EVENT_GROUPS
    }
    total_events = sum(counts.values())
    key_events = _key_events(data, limit=30)
    non_empty_groups = [group for group, count in counts.items() if count]
    return {
        "summary": (
            f"Dynamic telemetry contains {total_events} events across "
            f"{len(non_empty_groups)} event groups."
        ),
        "key_fields": {
            "telemetry_id": str(data.get("telemetry_id", "")),
            "schema_version": str(data.get("schema_version", "")),
            "event_counts": counts,
            "total_events": total_events,
            "non_empty_groups": non_empty_groups,
        },
        "evidence_hints": key_events,
        "warnings": _warnings(data, total_events),
        "limitations": [
            "Sorted telemetry is a compact view; inspect raw output for full logs.",
            "Telemetry presence means observed log data, not automatic behavior attribution.",
        ],
    }


def _data(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    output = raw_output_item.get("output", {})
    if isinstance(output, dict):
        data = output.get("data", {})
        if isinstance(data, dict):
            return data
    return {}


def _key_events(data: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for group in _EVENT_GROUPS:
        events = data.get(group, [])
        if not isinstance(events, list):
            continue
        for event in events:
            if not isinstance(event, dict):
                continue
            bucket = _attribution_bucket(event)
            candidates.append(
                {
                    "event_group": group,
                    "event_id": str(event.get("event_id", ""))[:120],
                    "event_type": str(event.get("event_type", ""))[:120],
                    "process_name": str(event.get("process_name", ""))[:200],
                    "target": _target(event),
                    "value": _value(event),
                    "attribution": bucket,
                }
            )
    candidates.sort(key=lambda item: _bucket_rank(str(item.get("attribution") or "")))
    return candidates[:limit]


def _attribution_bucket(event: dict[str, Any]) -> str:
    text = _event_text(event)
    if any(marker in text for marker in _SAMPLE_MARKERS):
        return "sample_attributed"
    if any(marker in text for marker in _NOISE_MARKERS):
        return "collector_noise"
    return "unattributed"


def _bucket_rank(bucket: str) -> int:
    return {
        "sample_attributed": 0,
        "unattributed": 1,
        "collector_noise": 2,
    }.get(bucket, 9)


def _event_text(event: dict[str, Any]) -> str:
    values: list[str] = []
    for value in event.values():
        if isinstance(value, list):
            values.extend(str(item) for item in value if item is not None)
        elif value is not None:
            values.append(str(value))
    return " ".join(values).lower()


def _target(event: dict[str, Any]) -> str:
    for key in [
        "target_process_name",
        "path",
        "key_path",
        "destination_host",
        "destination_ip",
        "url",
        "service_name",
        "task_name",
        "module_path",
    ]:
        value = event.get(key)
        if value:
            return str(value)[:300]
    return ""


def _value(event: dict[str, Any]) -> str:
    for key in ["command_line", "data", "api", "raw"]:
        value = event.get(key)
        if value:
            return str(value)[:500]
    return ""


def _warnings(data: dict[str, Any], total_events: int) -> list[str]:
    warnings: list[str] = []
    if total_events == 0:
        warnings.append("No telemetry events were found.")
    limitations = data.get("limitations", [])
    if isinstance(limitations, list):
        warnings.extend(str(item)[:200] for item in limitations[:5])
    return warnings
