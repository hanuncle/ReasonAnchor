from __future__ import annotations

import time
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

from vmware_dynamic import (
    VmrunClient,
    VmwareConfig,
    config_error,
    operation_error,
    preflight_blocked_result,
)


class DynamicVmStartToolsFunction(AnalysisFunction):
    id = "dynamic.vm_start_tools"
    name = "VMware start VM and wait for Tools"
    category = "dynamic"
    result_key = "dynamic_vm_tools_ready"
    description = "Starts the configured VMware VM when needed and waits for VMware Tools readiness."
    cost = "medium"
    external_tool = True
    optional = True
    config_required = True
    config_requirements = ["vmware.vmrun_path", "vmware.vmx_path", "vmware.vm_password"]
    output_schema = {
        "ready": "Whether the VM is running and VMware Tools reported running.",
        "tools_state": "Final VMware Tools state.",
        "started_vm": "Whether this step started the VM.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        skipped = preflight_blocked_result(context, self.id, self.result_key)
        if skipped is not None:
            return skipped
        config = VmwareConfig.from_context(context, params)
        missing = config.validate()
        if missing:
            return config_error(self.id, self.result_key, missing)

        timeout_seconds = _timeout_seconds(params)
        deadline = time.monotonic() + timeout_seconds
        client = VmrunClient(config)
        started = False
        power_cycles = 0
        max_power_cycles = _int_param(params, "power_cycle_attempts", 1, 0, 3)
        power_cycle_after = _int_param(params, "power_cycle_after_seconds", 90, 30, 600)
        power_cycle_on_installed = _bool_param(params, "power_cycle_on_installed", True)
        checks: list[dict[str, Any]] = []
        started_at = time.monotonic()
        try:
            try:
                initial_state = client.tools_state(timeout=min(10, _remaining_seconds(deadline)))
                checks.append({"phase": "initial_tools_check", "tools_state": initial_state})
                if initial_state == "running":
                    return FunctionResult(
                        function_id=self.id,
                        result_key=self.result_key,
                        data={
                            "ready": True,
                            "running": True,
                            "tools_state": initial_state,
                            "started_vm": False,
                            "power_cycles": 0,
                            "wait_timeout_seconds": timeout_seconds,
                            "elapsed_seconds": round(time.monotonic() - started_at, 3),
                            "checks": checks[-10:],
                            "requires_human_confirmation": False,
                        },
                    )
            except RuntimeError as exc:
                checks.append({"phase": "initial_tools_check", "error": str(exc)[:300]})
            running = client.is_running(timeout=min(15, _remaining_seconds(deadline)))
            checks.append({"phase": "initial_running_check", "running": running})
            if not running and _bool_param(params, "start_if_needed", True):
                try:
                    client.start(
                        str(params.get("start_mode") or "gui"),
                        timeout=min(60, _remaining_seconds(deadline)),
                    )
                    checks.append({"phase": "start_vm", "started": True})
                except RuntimeError as exc:
                    checks.append({"phase": "start_vm", "started": "unknown", "error": str(exc)[:300]})
                started = True
            state = "unknown"
            while time.monotonic() < deadline:
                running = client.is_running(timeout=min(10, _remaining_seconds(deadline)))
                if not running:
                    checks.append({"phase": "poll", "running": False, "tools_state": "not_running"})
                    time.sleep(_poll_interval(params))
                    continue
                state = client.tools_state(timeout=min(10, _remaining_seconds(deadline)))
                checks.append({"phase": "poll", "running": True, "tools_state": state})
                if state == "running":
                    return FunctionResult(
                        function_id=self.id,
                        result_key=self.result_key,
                        data={
                            "ready": True,
                            "running": True,
                            "tools_state": state,
                            "started_vm": started,
                            "power_cycles": power_cycles,
                            "wait_timeout_seconds": timeout_seconds,
                            "elapsed_seconds": round(time.monotonic() - started_at, 3),
                            "checks": checks[-10:],
                            "requires_human_confirmation": False,
                        },
                    )
                if (
                    power_cycle_on_installed
                    and state == "installed"
                    and power_cycles < max_power_cycles
                    and (time.monotonic() - started_at) >= power_cycle_after
                    and _remaining_seconds(deadline) > 90
                ):
                    power_cycles += 1
                    checks.append({"phase": "power_cycle", "attempt": power_cycles, "reason": "tools_state_installed"})
                    try:
                        client.stop("hard")
                    except RuntimeError as exc:
                        checks.append({"phase": "power_cycle_stop", "attempt": power_cycles, "error": str(exc)[:300]})
                    time.sleep(5)
                    try:
                        client.start(str(params.get("start_mode") or "gui"), timeout=min(90, _remaining_seconds(deadline)))
                        checks.append({"phase": "power_cycle_start", "attempt": power_cycles, "started": True})
                        started = True
                    except RuntimeError as exc:
                        checks.append({"phase": "power_cycle_start", "attempt": power_cycles, "started": False, "error": str(exc)[:300]})
                time.sleep(_poll_interval(params))
        except RuntimeError as exc:
            return operation_error(
                self.id,
                self.result_key,
                "vmrun_failed",
                str(exc),
                {
                    "ready": False,
                    "started_vm": started,
                    "power_cycles": power_cycles,
                    "wait_timeout_seconds": timeout_seconds,
                    "elapsed_seconds": round(time.monotonic() - started_at, 3),
                    "checks": checks[-10:],
                },
            )

        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            data={
                "ready": False,
                "running": running,
                "tools_state": state,
                "started_vm": started,
                "power_cycles": power_cycles,
                "wait_timeout_seconds": timeout_seconds,
                "elapsed_seconds": round(time.monotonic() - started_at, 3),
                "checks": checks[-10:],
                "requires_human_confirmation": False,
            },
            error={
                "code": "vmware_tools_not_running",
                "message": f"VMware Tools did not reach running state within {timeout_seconds}s.",
            },
        )


def _timeout_seconds(params: dict[str, Any]) -> int:
    try:
        return max(10, min(1200, int(params.get("timeout_seconds", 240))))
    except (TypeError, ValueError):
        return 240


def _poll_interval(params: dict[str, Any]) -> int:
    try:
        return max(1, min(30, int(params.get("poll_interval_seconds", 5))))
    except (TypeError, ValueError):
        return 5


def _remaining_seconds(deadline: float) -> int:
    return max(1, int(deadline - time.monotonic()))


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
