from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

from vmware_dynamic import VmwareConfig


class DynamicVmPreflightFunction(AnalysisFunction):
    id = "dynamic.vm_preflight"
    name = "VMware dynamic workflow preflight"
    category = "dynamic"
    result_key = "dynamic_vm_preflight"
    description = (
        "Checks whether the configured VMware fields are present before a dynamic "
        "workflow attempts restore, upload, execution, or telemetry collection."
    )
    cost = "low"
    external_tool = True
    optional = True
    config_required = True
    config_requirements = [
        "vmware.vmrun_path",
        "vmware.vmx_path",
        "vmware.vm_password",
        "vmware.guest_user",
        "vmware.guest_password",
    ]
    output_schema = {
        "ready": "Whether the dynamic VMware workflow has enough configuration to run.",
        "missing_config_fields": "Required VMware config fields that are empty.",
        "invalid_path_fields": "Configured local path fields that do not resolve.",
        "limitations": "Configuration preflight only; does not execute the sample.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        require_guest = _bool_param(params, "require_guest_credentials", True)
        config = VmwareConfig.from_context(context, params)
        missing = config.validate(require_guest=require_guest)
        invalid_paths = _invalid_path_fields(config)
        ready = not missing and not invalid_paths
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "ready": ready,
                "require_guest_credentials": require_guest,
                "missing_config_fields": missing,
                "invalid_path_fields": invalid_paths,
                "checked_path_fields": ["vmware.vmrun_path", "vmware.vmx_path"],
                "vm_profile": {
                    "profile_name": config.profile_name,
                    "guest_os": config.guest_os,
                    "guest_tools_dir": config.guest_tools_dir,
                    "guest_sample_dir": config.guest_sample_dir,
                    "guest_telemetry_dir": config.guest_telemetry_dir,
                    "packet_capture_driver": config.packet_capture_driver,
                },
                "ready_snapshot": config.ready_snapshot,
                "requires_human_confirmation": False,
                "limitations": [
                    "Preflight checks configuration presence and local path resolution only.",
                    "It does not start VMware, restore snapshots, upload files, or execute samples.",
                    "Path values and credentials are intentionally not returned.",
                ],
            },
        )


def _invalid_path_fields(config: VmwareConfig) -> list[str]:
    invalid: list[str] = []
    if config.vmrun_path and not _command_or_file_exists(config.vmrun_path):
        invalid.append("vmware.vmrun_path")
    if config.vmx_path and not Path(config.vmx_path).is_file():
        invalid.append("vmware.vmx_path")
    return invalid


def _command_or_file_exists(value: str) -> bool:
    path = Path(value)
    if path.is_file():
        return True
    return shutil.which(value) is not None


def _bool_param(params: dict[str, Any], key: str, default: bool) -> bool:
    value = params.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)
