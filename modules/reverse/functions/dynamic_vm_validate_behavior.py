from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

from behavior_map_dynamic import BehaviorMapDynamicFunction
from vmware_dynamic import (
    EXECUTE_CONFIRMATION,
    RESTORE_CONFIRMATION,
    VmrunClient,
    VmwareConfig,
    config_error,
    create_export_batch,
    host_output_path,
    join_guest_path,
    load_telemetry_json,
    operation_error,
    preflight_blocked_result,
    safe_guest_filename,
)

FOCUSED_EXECUTE_CONFIRMATION = "I_UNDERSTAND_RUN_FOCUSED_BEHAVIOR_VALIDATION_IN_VM"


class DynamicVmValidateBehaviorFunction(AnalysisFunction):
    id = "dynamic.vm_validate_behavior"
    name = "Focused VMware behavior validation"
    category = "dynamic"
    result_key = "focused_dynamic_validation"
    description = (
        "Runs a benign single-point validation fixture in VMware for one behavior category, "
        "collects Sysmon telemetry, and maps whether that category was observed."
    )
    cost = "high"
    external_tool = True
    optional = True
    config_required = True
    requires_human_confirmation = True
    requires_results = ["focused_dynamic_validation_plan"]
    recommended_before = ["validation.plan_focused_dynamic"]
    config_requirements = [
        "vmware.vmrun_path",
        "vmware.vmx_path",
        "vmware.vm_password",
        "vmware.guest_user",
        "vmware.guest_password",
    ]
    output_schema = {
        "target": "Focused behavior and validation fixture metadata.",
        "observed": "Whether dynamic telemetry mapped the target behavior.",
        "matched_behavior": "Mapped dynamic behavior for the target category when observed.",
        "telemetry": "Compact focused telemetry metadata and event counts.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        if params.get("confirm_execute") not in {
            FOCUSED_EXECUTE_CONFIRMATION,
            EXECUTE_CONFIRMATION,
        }:
            return operation_error(
                self.id,
                self.result_key,
                "execution_not_confirmed",
                (
                    "Set confirm_execute to "
                    f"{FOCUSED_EXECUTE_CONFIRMATION} to run focused validation in the VM."
                ),
            )
        target = _select_target(context, params)
        if not target:
            if _has_focused_plan(context):
                return _skipped_no_validation_target(context, self.id, self.result_key)
            return operation_error(
                self.id,
                self.result_key,
                "missing_validation_target",
                "behavior_category, validation_sample_id, or focused_dynamic_validation_plan is required",
            )
        if target.get("status") == "missing_validation_sample":
            return operation_error(
                self.id,
                self.result_key,
                "missing_validation_sample",
                f"No validation sample is registered for {target.get('behavior_category', '')}",
            )

        skipped = preflight_blocked_result(context, self.id, self.result_key)
        if skipped is not None:
            return skipped
        config = VmwareConfig.from_context(context, params)
        missing = config.validate(require_guest=True)
        if missing:
            return config_error(self.id, self.result_key, missing)

        fixture = _fixture_path(str(target.get("validation_sample_path") or ""))
        if not fixture.is_file():
            return operation_error(
                self.id,
                self.result_key,
                "validation_sample_not_found",
                str(fixture),
            )

        client = VmrunClient(config)
        duration = _duration(params)
        restore_before = bool(params.get("restore_before", False))
        restore_after = bool(params.get("restore_after", False))
        if (restore_before or restore_after) and params.get("confirm_restore") != RESTORE_CONFIRMATION:
            return operation_error(
                self.id,
                self.result_key,
                "restore_not_confirmed",
                f"Set confirm_restore to {RESTORE_CONFIRMATION} to restore VM snapshots.",
            )

        try:
            if restore_before:
                _restore_snapshot(client, config, params)
            telemetry = _run_fixture_and_collect(
                client,
                config,
                context,
                params,
                target,
                fixture,
                duration,
            )
            mapped = _map_target_behavior(telemetry, str(target["behavior_category"]))
            if bool(params.get("save_snapshot_after", False)):
                _save_snapshot(client, config, context, params, target)
            if restore_after:
                _restore_snapshot(client, config, params)
        except RuntimeError as exc:
            return operation_error(self.id, self.result_key, "vmrun_failed", str(exc))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return operation_error(
                self.id,
                self.result_key,
                "focused_validation_failed",
                str(exc),
            )

        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "target": target,
                "observed": mapped["matched_behavior"] is not None,
                "matched_behavior": mapped["matched_behavior"],
                "dynamic_behavior_map": mapped["dynamic_behavior_map"],
                "telemetry": _telemetry_summary(telemetry),
                "telemetry_host_output_path": str(telemetry.get("host_output_path") or ""),
                "requires_human_confirmation": True,
                "validation_scope": "benign_single_point_fixture",
                "limitations": [
                    "This validates telemetry and mapping for one behavior category.",
                    "It does not prove the original uploaded sample performed the behavior.",
                    "Use the result together with static evidence and broad dynamic telemetry.",
                ],
            },
        )


def _select_target(context: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    sample_id = str(params.get("validation_sample_id") or "")
    category = str(params.get("behavior_category") or "")
    if sample_id or category:
        return _target_from_manifest(sample_id=sample_id, category=category)

    plan = context.get("results", {}).get("focused_dynamic_validation_plan")
    if isinstance(plan, dict) and plan.get("status") != "error":
        data = plan.get("data", {})
        targets = data.get("targets", []) if isinstance(data, dict) else []
        for target in targets:
            if isinstance(target, dict) and target.get("status") == "ready":
                return dict(target)
    return {}


def _has_focused_plan(context: dict[str, Any]) -> bool:
    plan = context.get("results", {}).get("focused_dynamic_validation_plan")
    return isinstance(plan, dict) and plan.get("status") != "error"


def _skipped_no_validation_target(
    context: dict[str, Any],
    function_id: str,
    result_key: str,
) -> FunctionResult:
    plan = context.get("results", {}).get("focused_dynamic_validation_plan")
    data = plan.get("data", {}) if isinstance(plan, dict) else {}
    targets = data.get("targets", []) if isinstance(data, dict) else []
    return FunctionResult(
        function_id=function_id,
        result_key=result_key,
        status="skipped",
        data={
            "skipped": True,
            "skip_reason": "no_focused_validation_targets",
            "target": {},
            "observed": False,
            "matched_behavior": None,
            "dynamic_behavior_map": {},
            "telemetry": {},
            "requires_human_confirmation": True,
            "validation_scope": "benign_single_point_fixture",
            "counts": {
                "targets": len(targets) if isinstance(targets, list) else 0,
                "ready_targets": sum(
                    1
                    for target in targets
                    if isinstance(target, dict) and target.get("status") == "ready"
                )
                if isinstance(targets, list)
                else 0,
            },
            "limitations": [
                "Focused dynamic validation skipped because the plan had no ready target.",
                "Broad dynamic telemetry did not identify a static-only behavior requiring a single-point fixture.",
            ],
        },
    )


def _target_from_manifest(sample_id: str, category: str) -> dict[str, Any]:
    manifest = _read_json(_module_config_root() / "validation_samples" / "samples_manifest.json")
    samples = manifest.get("samples", []) if isinstance(manifest, dict) else []
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        if sample_id and str(sample.get("sample_id") or "") != sample_id:
            continue
        if category and str(sample.get("behavior_category") or "") != category:
            continue
        return {
            "behavior_category": str(sample.get("behavior_category") or ""),
            "scenario_id": str(sample.get("scenario_id") or ""),
            "technique_id": str(sample.get("technique_id") or ""),
            "validation_sample_id": str(sample.get("sample_id") or ""),
            "validation_sample_path": str(sample.get("path") or ""),
            "expected_dynamic_events": list(sample.get("expected_dynamic_events") or []),
            "status": "ready",
        }
    return {"behavior_category": category, "validation_sample_id": sample_id, "status": "missing_validation_sample"}


def _run_fixture_and_collect(
    client: VmrunClient,
    config: VmwareConfig,
    context: dict[str, Any],
    params: dict[str, Any],
    target: dict[str, Any],
    fixture: Path,
    duration: int,
) -> dict[str, Any]:
    client.wait_for_running_tools(config.timeout_seconds)
    sample_id = safe_guest_filename(str(target.get("validation_sample_id") or fixture.stem))
    guest_dir = join_guest_path(config.guest_sample_dir, "focused_validation")
    guest_fixture = join_guest_path(guest_dir, fixture.name)
    client.create_guest_dir(guest_dir)
    client.copy_to_guest(str(fixture), guest_fixture)
    client.run_guest_program(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        f'-NoProfile -ExecutionPolicy Bypass -File "{guest_fixture}"',
        no_wait=True,
    )
    time.sleep(duration)

    last_minutes = _last_minutes(params)
    max_events = _max_events(params)
    output_name = f"focused_dynamic_{sample_id}.json"
    host_telemetry = host_output_path(config, context, output_name)
    host_export_bat = host_telemetry.with_suffix(".bat")
    guest_export_bat = join_guest_path(config.guest_tools_dir, f"export_{sample_id}.bat")
    guest_telemetry = join_guest_path(config.guest_telemetry_dir, "dynamic_telemetry.json")
    create_export_batch(host_export_bat, config, last_minutes, max_events)
    client.copy_to_guest(str(host_export_bat), guest_export_bat)
    client.run_guest_program(
        r"C:\Windows\System32\cmd.exe",
        f'/c "{guest_export_bat}"',
        timeout=config.timeout_seconds,
    )
    client.copy_from_guest(guest_telemetry, str(host_telemetry))
    telemetry = load_telemetry_json(host_telemetry)
    telemetry["host_output_path"] = str(host_telemetry)
    telemetry["focused_validation"] = {
        "behavior_category": str(target.get("behavior_category") or ""),
        "validation_sample_id": str(target.get("validation_sample_id") or ""),
        "validation_sample_path": str(target.get("validation_sample_path") or ""),
        "duration_seconds": duration,
    }
    return telemetry


def _map_target_behavior(telemetry: dict[str, Any], category: str) -> dict[str, Any]:
    result = BehaviorMapDynamicFunction().run({"results": {}}, {"telemetry": telemetry})
    dynamic_map = result.to_dict()
    matched = None
    if result.status == "success":
        for behavior in result.data.get("behaviors", []):
            if isinstance(behavior, dict) and behavior.get("category") == category:
                matched = behavior
                break
    return {"dynamic_behavior_map": dynamic_map, "matched_behavior": matched}


def _restore_snapshot(client: VmrunClient, config: VmwareConfig, params: dict[str, Any]) -> None:
    snapshot = str(params.get("snapshot") or config.ready_snapshot)
    if client.is_running():
        client.stop("hard")
    client.host_command("revertToSnapshot", config.vmx_path, snapshot)


def _save_snapshot(
    client: VmrunClient,
    config: VmwareConfig,
    context: dict[str, Any],
    params: dict[str, Any],
    target: dict[str, Any],
) -> None:
    category = safe_guest_filename(str(target.get("behavior_category") or "behavior"))
    snapshot = str(params.get("snapshot_after") or f"focused-{category}-{_context_short_id(context)}")
    if client.is_running():
        client.stop("soft")
    client.host_command("snapshot", config.vmx_path, snapshot)


def _telemetry_summary(telemetry: dict[str, Any]) -> dict[str, Any]:
    groups = [
        "process_events",
        "file_events",
        "registry_events",
        "network_events",
        "service_events",
        "scheduled_task_events",
        "module_load_events",
    ]
    counts = {
        group: len(telemetry.get(group, [])) if isinstance(telemetry.get(group), list) else 0
        for group in groups
    }
    return {
        "telemetry_id": str(telemetry.get("telemetry_id") or ""),
        "schema_version": str(telemetry.get("schema_version") or ""),
        "event_counts": counts,
        "total_events": sum(counts.values()),
    }


def _fixture_path(relative_path: str) -> Path:
    path = Path(relative_path)
    root = (_module_config_root() / "validation_samples").resolve()
    if path.is_absolute() or ".." in path.parts or not relative_path:
        return root / "__invalid__"
    target = (root / path).resolve()
    if root != target and root not in target.parents:
        return root / "__invalid__"
    return target


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _module_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _module_config_root() -> Path:
    return _module_root() / "config_files"


def _duration(params: dict[str, Any]) -> int:
    try:
        return max(1, min(600, int(params.get("duration_seconds", 20))))
    except (TypeError, ValueError):
        return 20


def _last_minutes(params: dict[str, Any]) -> int:
    try:
        return max(1, min(1440, int(params.get("last_minutes", 30))))
    except (TypeError, ValueError):
        return 30


def _max_events(params: dict[str, Any]) -> int:
    try:
        return max(100, min(50000, int(params.get("max_events", 5000))))
    except (TypeError, ValueError):
        return 5000


def _context_short_id(context: dict[str, Any]) -> str:
    import hashlib

    seed = str(context.get("sample_path", "")) + str(context.get("filename", ""))
    return hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()[:8]
