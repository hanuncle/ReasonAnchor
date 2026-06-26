from __future__ import annotations

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


class DynamicVmSaveSnapshotFunction(AnalysisFunction):
    id = "dynamic.vm_save_snapshot"
    name = "VMware save dynamic snapshot"
    category = "dynamic"
    result_key = "dynamic_vm_snapshot"
    description = "Saves a VMware VM snapshot after dynamic collection."
    cost = "medium"
    external_tool = True
    optional = True
    config_required = True
    config_requirements = ["vmware.vmrun_path", "vmware.vmx_path", "vmware.vm_password"]
    output_schema = {
        "snapshot": "Snapshot name created.",
        "stopped_before_snapshot": "Whether the VM was stopped before snapshot.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        skipped = preflight_blocked_result(context, self.id, self.result_key)
        if skipped is not None:
            return skipped
        config = VmwareConfig.from_context(context, params)
        missing = config.validate()
        if missing:
            return config_error(self.id, self.result_key, missing)
        snapshot = str(
            params.get("snapshot")
            or f"dynamic-collected-{int(time_like_context_id(context), 16) % 100000000:08d}"
        )
        client = VmrunClient(config)
        stopped = False
        try:
            if client.is_running() and bool(params.get("stop_before_snapshot", True)):
                client.stop("soft")
                stopped = True
            client.host_command("snapshot", config.vmx_path, snapshot)
        except RuntimeError as exc:
            return operation_error(self.id, self.result_key, "vmrun_failed", str(exc))
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "snapshot": snapshot,
                "stopped_before_snapshot": stopped,
                "requires_human_confirmation": False,
            },
        )


def time_like_context_id(context: dict[str, Any]) -> str:
    import hashlib

    seed = str(context.get("sample_path", "")) + str(context.get("filename", ""))
    return hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()[:8]
