from __future__ import annotations

import time
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

from vmware_dynamic import (
    RESTORE_CONFIRMATION,
    VmrunClient,
    VmwareConfig,
    config_error,
    operation_error,
    preflight_blocked_result,
)


class DynamicVmRestoreSnapshotFunction(AnalysisFunction):
    id = "dynamic.vm_restore_snapshot"
    name = "VMware restore dynamic snapshot"
    category = "dynamic"
    result_key = "dynamic_vm_restore"
    description = "Restores the configured VMware VM to a named snapshot."
    cost = "medium"
    external_tool = True
    optional = True
    config_required = True
    config_requirements = ["vmware.vmrun_path", "vmware.vmx_path", "vmware.vm_password"]
    requires_human_confirmation = True
    output_schema = {
        "snapshot": "Snapshot restored.",
        "stopped_before_restore": "Whether the VM was stopped before restore.",
        "running_after_restore": "Whether the VM is running after restore.",
        "tools_state_after_restore": "VMware Tools state after optional startup.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        if params.get("confirm_restore") != RESTORE_CONFIRMATION:
            return operation_error(
                self.id,
                self.result_key,
                "restore_not_confirmed",
                f"Set confirm_restore to {RESTORE_CONFIRMATION} to restore the VM snapshot.",
            )
        skipped = preflight_blocked_result(context, self.id, self.result_key)
        if skipped is not None:
            return skipped
        restore_params = {
            key: value
            for key, value in params.items()
            if key != "stop_if_running"
        }
        config = VmwareConfig.from_context(context, restore_params)
        missing = config.validate()
        if missing:
            return config_error(self.id, self.result_key, missing)
        snapshot = str(
            params.get("snapshot")
            or params.get("ready_snapshot")
            or config.ready_snapshot
        )
        client = VmrunClient(config)
        stopped = False
        snapshots: list[str] = []
        snapshot_exists: bool | None = None
        checks: list[dict[str, Any]] = []
        stop_timeout_seconds = _int_param(params, "stop_timeout_seconds", 90, 5, 600)
        start_after_restore = _bool_param(params, "start_after_restore", False)
        wait_tools_after_restore = _bool_param(params, "wait_tools_after_restore", False)
        start_mode = str(params.get("start_mode") or "gui")
        try:
            snapshots = client.list_snapshots()
            snapshot_exists = snapshot in snapshots
            checks.append(
                {
                    "phase": "list_snapshots",
                    "snapshot_exists": snapshot_exists,
                    "snapshots_count": len(snapshots),
                }
            )
            if not snapshot_exists:
                return operation_error(
                    self.id,
                    self.result_key,
                    "snapshot_not_found",
                    f"Snapshot was not found for configured VM: {snapshot}",
                    {
                        "snapshot": snapshot,
                        "snapshots": snapshots[:20],
                        "vmx_path": config.vmx_path,
                        "requires_human_confirmation": True,
                    },
                )

            running_before = client.is_running()
            checks.append({"phase": "running_before_restore", "running": running_before})
            if running_before and bool(params.get("stop_if_running", True)):
                client.stop("hard")
                stopped = True
                stopped_cleanly = _wait_for_not_running(client, stop_timeout_seconds)
                checks.append(
                    {
                        "phase": "stop_before_restore",
                        "stopped": stopped,
                        "stopped_cleanly": stopped_cleanly,
                        "timeout_seconds": stop_timeout_seconds,
                    }
                )
                if not stopped_cleanly:
                    return operation_error(
                        self.id,
                        self.result_key,
                        "vm_stop_timeout",
                        f"VM did not stop within {stop_timeout_seconds}s before restore.",
                        {
                            "snapshot": snapshot,
                            "stopped_before_restore": stopped,
                            "checks": checks,
                            "requires_human_confirmation": True,
                        },
                    )

            client.host_command(
                "revertToSnapshot",
                config.vmx_path,
                snapshot,
                timeout=_int_param(params, "restore_timeout_seconds", config.timeout_seconds, 30, 1800),
            )
            checks.append({"phase": "revert_to_snapshot", "snapshot": snapshot})

            started_after_restore = False
            if start_after_restore or wait_tools_after_restore:
                client.start(start_mode, timeout=_int_param(params, "start_timeout_seconds", 120, 30, 600))
                started_after_restore = True
                checks.append({"phase": "start_after_restore", "started": True, "start_mode": start_mode})

            running_after = client.is_running()
            tools_state_after = "not_running"
            if running_after:
                try:
                    tools_state_after = client.tools_state(timeout=15)
                except RuntimeError as exc:
                    tools_state_after = "unknown"
                    checks.append({"phase": "tools_state_after_restore", "error": str(exc)[:300]})

            if wait_tools_after_restore:
                wait_timeout = _int_param(params, "tools_timeout_seconds", 240, 30, 1200)
                tools_state_after = client.wait_for_running_tools(wait_timeout)
                running_after = client.is_running()
                checks.append(
                    {
                        "phase": "wait_tools_after_restore",
                        "tools_state": tools_state_after,
                        "timeout_seconds": wait_timeout,
                    }
                )
                if tools_state_after != "running":
                    return operation_error(
                        self.id,
                        self.result_key,
                        "vmware_tools_not_running_after_restore",
                        f"VMware Tools did not reach running state after restore; state={tools_state_after}.",
                        {
                            "snapshot": snapshot,
                            "stopped_before_restore": stopped,
                            "started_after_restore": started_after_restore,
                            "running_after_restore": running_after,
                            "tools_state_after_restore": tools_state_after,
                            "checks": checks,
                            "requires_human_confirmation": True,
                        },
                    )
        except RuntimeError as exc:
            return operation_error(
                self.id,
                self.result_key,
                "vmrun_failed",
                str(exc),
                {
                    "snapshot": snapshot,
                    "stopped_before_restore": stopped,
                    "snapshots": snapshots[:20],
                    "snapshot_exists": snapshot_exists,
                    "checks": checks,
                    "requires_human_confirmation": True,
                },
            )
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "snapshot": snapshot,
                "snapshot_exists": snapshot_exists,
                "snapshots_count": len(snapshots),
                "stopped_before_restore": stopped,
                "started_after_restore": started_after_restore,
                "running_after_restore": running_after,
                "tools_state_after_restore": tools_state_after,
                "restore_mode": "requested_or_default_snapshot",
                "vmx_path": config.vmx_path,
                "checks": checks,
                "requires_human_confirmation": True,
            },
        )


def _wait_for_not_running(client: VmrunClient, timeout_seconds: int) -> bool:
    deadline = time.monotonic() + max(1, timeout_seconds)
    while time.monotonic() < deadline:
        if not client.is_running(timeout=10):
            return True
        time.sleep(2)
    return not client.is_running(timeout=10)


def _int_param(params: dict[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
    try:
        return max(minimum, min(maximum, int(params.get(key, default))))
    except (TypeError, ValueError):
        return default


def _bool_param(params: dict[str, Any], key: str, default: bool) -> bool:
    value = params.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)
