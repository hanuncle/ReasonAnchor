from __future__ import annotations

from typing import Any


def sort_output(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    output = raw_output_item.get("output", {})
    result_key = str(raw_output_item.get("result_key") or "")
    function_id = str(raw_output_item.get("function_id") or "")
    status = str(raw_output_item.get("status") or "")
    data = output.get("data", {}) if isinstance(output, dict) else {}
    error = output.get("error") if isinstance(output, dict) else None
    if not isinstance(data, dict):
        data = {}

    return {
        "summary": _summary(function_id, result_key, status, data, error),
        "key_fields": _key_fields(result_key, data),
        "evidence_hints": _evidence_hints(result_key, data),
        "warnings": _warnings(status, data, error),
        "limitations": [
            "This is a compact VM operation view, not the full dynamic telemetry.",
            "VM operation success does not by itself confirm sample behavior.",
        ],
    }


def _summary(
    function_id: str,
    result_key: str,
    status: str,
    data: dict[str, Any],
    error: Any,
) -> str:
    if result_key == "dynamic_vm_preflight":
        if bool(data.get("ready")):
            return "VMware dynamic workflow preflight passed."
        return "VMware dynamic workflow preflight did not pass; dynamic steps should be skipped."
    if status == "skipped":
        reason = str(data.get("skip_reason") or "skipped")[:160]
        return f"{function_id} was skipped: {reason}."
    if status == "error":
        code = ""
        if isinstance(error, dict):
            code = str(error.get("code") or "")
        return f"{function_id} returned error: {code or 'unknown_error'}."
    if result_key == "dynamic_vm_status":
        return (
            "VMware status checked: "
            f"running={bool(data.get('running'))}, "
            f"tools_state={str(data.get('tools_state') or 'unknown')}."
        )
    if result_key == "dynamic_vm_tools_ready":
        return (
            "VMware Tools readiness checked: "
            f"ready={bool(data.get('ready'))}, "
            f"running={bool(data.get('running'))}, "
            f"tools_state={str(data.get('tools_state') or 'unknown')}."
        )
    if result_key == "dynamic_vm_upload":
        return "Sample was copied into the configured VMware guest."
    if result_key == "dynamic_vm_run":
        return "Sample execution was launched inside the configured VMware guest."
    if result_key == "dynamic_vm_snapshot":
        return "VMware snapshot was saved after dynamic collection."
    if result_key == "dynamic_vm_restore":
        return "VMware VM was restored to the configured snapshot."
    return f"{function_id} completed."


def _key_fields(result_key: str, data: dict[str, Any]) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "requires_human_confirmation": bool(data.get("requires_human_confirmation", False)),
    }
    for key in [
        "running",
        "tools_state",
        "ready_snapshot",
        "snapshot",
        "stopped_before_restore",
        "stopped_before_snapshot",
        "guest_sample_path",
        "filename",
        "upload_verified",
        "duration_seconds",
        "execution_confirmed",
        "ready",
        "skipped",
        "skip_reason",
        "preflight_status",
        "require_guest_credentials",
    ]:
        if key in data:
            fields[key] = _safe_value(data[key])
    for key in ["missing_config_fields", "invalid_path_fields", "checked_path_fields"]:
        if isinstance(data.get(key), list):
            fields[key] = [str(item)[:120] for item in data[key][:20]]
    if result_key == "dynamic_vm_status" and isinstance(data.get("snapshots"), list):
        fields["snapshots_count"] = len(data["snapshots"])
        fields["snapshots_sample"] = [str(item)[:120] for item in data["snapshots"][:10]]
    return fields


def _evidence_hints(result_key: str, data: dict[str, Any]) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    if data.get("guest_sample_path"):
        hints.append(
            {
                "type": "guest_sample_path",
                "value": str(data["guest_sample_path"])[:300],
            }
        )
    if data.get("snapshot"):
        hints.append({"type": "snapshot", "value": str(data["snapshot"])[:200]})
    if result_key == "dynamic_vm_status":
        hints.append(
            {
                "type": "vm_state",
                "running": bool(data.get("running")),
                "tools_state": str(data.get("tools_state") or "unknown")[:120],
            }
        )
    return hints


def _warnings(status: str, data: dict[str, Any], error: Any) -> list[str]:
    warnings: list[str] = []
    if status == "error":
        if isinstance(error, dict):
            message = str(error.get("message") or "")[:300]
            if message:
                warnings.append(message)
        else:
            warnings.append("VMware operation failed.")
    if status == "skipped":
        warnings.append("VMware operation skipped because preflight was not ready.")
    if data.get("ready") is False:
        warnings.append("VMware configuration preflight is not ready.")
    for item in data.get("limitations", []):
        warnings.append(str(item)[:300])
    return warnings


def _safe_value(value: Any) -> Any:
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, list):
        return [str(item)[:200] for item in value[:10]]
    return str(value)[:300]
