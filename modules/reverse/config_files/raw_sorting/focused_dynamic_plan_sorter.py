from __future__ import annotations

from typing import Any


def sort_output(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    data = _data(raw_output_item)
    status = str(raw_output_item.get("status") or "")
    error = _error(raw_output_item)
    if status == "error" or error:
        return {
            "summary": f"Focused dynamic validation plan failed: {str(error.get('code') or 'error')}.",
            "key_fields": {
                "failed": True,
                "error": error,
                "required_next_step": _required_next_step(error),
                "targets": 0,
                "ready": 0,
                "missing_fixture": 0,
            },
            "evidence_hints": [],
            "warnings": ["Planning failed; do not interpret this as no validation targets."],
            "limitations": list(data.get("limitations", []))[:5]
            if isinstance(data.get("limitations"), list)
            else [],
        }
    targets = data.get("targets", []) if isinstance(data.get("targets"), list) else []
    ready = [item for item in targets if isinstance(item, dict) and item.get("status") == "ready"]
    missing = [
        item
        for item in targets
        if isinstance(item, dict) and item.get("status") == "missing_validation_sample"
    ]
    if status == "skipped":
        return {
            "summary": (
                "Focused dynamic validation plan was skipped: "
                f"{str(data.get('skip_reason') or 'upstream_skipped')[:160]}."
            ),
            "key_fields": {
                "targets": 0,
                "ready": 0,
                "missing_fixture": 0,
                "skipped": True,
                "skip_reason": str(data.get("skip_reason") or ""),
            },
            "evidence_hints": [],
            "warnings": ["Focused dynamic validation planning skipped."],
            "limitations": list(data.get("limitations", []))[:5]
            if isinstance(data.get("limitations"), list)
            else [],
        }
    return {
        "summary": (
            f"Focused dynamic validation plan has {len(targets)} targets, "
            f"{len(ready)} ready and {len(missing)} missing fixtures."
        ),
        "key_fields": {
            "targets": len(targets),
            "ready": len(ready),
            "missing_fixture": len(missing),
            "ready_categories": [str(item.get("behavior_category") or "") for item in ready],
            "missing_categories": [str(item.get("behavior_category") or "") for item in missing],
        },
        "evidence_hints": [
            {
                "behavior_category": str(item.get("behavior_category") or ""),
                "validation_sample_id": str(item.get("validation_sample_id") or ""),
                "scenario_id": str(item.get("scenario_id") or ""),
                "technique_id": str(item.get("technique_id") or ""),
                "status": str(item.get("status") or ""),
            }
            for item in targets[:30]
            if isinstance(item, dict)
        ],
        "warnings": [
            "Planning only; run dynamic.vm_validate_behavior to execute focused validation."
        ],
        "limitations": list(data.get("limitations", []))[:5]
        if isinstance(data.get("limitations"), list)
        else [],
    }


def _data(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    output = raw_output_item.get("output", {})
    if isinstance(output, dict):
        data = output.get("data", {})
        if isinstance(data, dict):
            return data
    return {}


def _error(raw_output_item: dict[str, Any]) -> dict[str, str]:
    output = raw_output_item.get("output", {})
    if isinstance(output, dict) and isinstance(output.get("error"), dict):
        error = output["error"]
        return {
            "code": str(error.get("code") or ""),
            "message": str(error.get("message") or "")[:500],
        }
    return {}


def _required_next_step(error: dict[str, str]) -> str:
    code = error.get("code", "")
    if code == "missing_static_dynamic_validation":
        return "Run static/dynamic validation after dynamic behavior mapping is available."
    return "Resolve the focused validation planning prerequisite error and rerun planning."
