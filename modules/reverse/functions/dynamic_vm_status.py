from __future__ import annotations

from pathlib import Path
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


class DynamicVmStatusFunction(AnalysisFunction):
    id = "dynamic.vm_status"
    name = "VMware dynamic VM status"
    category = "dynamic"
    result_key = "dynamic_vm_status"
    description = "Checks VMware VM running state, Tools state, and snapshots."
    cost = "medium"
    external_tool = True
    optional = True
    config_required = True
    config_requirements = ["vmware.vmrun_path", "vmware.vmx_path", "vmware.vm_password"]
    output_schema = {
        "running": "Whether the VM is listed as running.",
        "tools_state": "VMware Tools state when available.",
        "snapshots": "Snapshot names visible through vmrun.",
        "guest_tooling": "Optional guest tool and packet-capture capability probe when VMware Tools is running.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        skipped = preflight_blocked_result(context, self.id, self.result_key)
        if skipped is not None:
            return skipped
        config = VmwareConfig.from_context(context, params)
        missing = config.validate()
        if missing:
            return config_error(self.id, self.result_key, missing)
        client = VmrunClient(config)
        try:
            running = client.is_running()
            tools_state = client.tools_state() if running else "not_running"
            snapshots = client.list_snapshots()
            guest_tooling = (
                _probe_guest_tooling(client, config, params)
                if running and tools_state == "running" and _bool_param(params, "probe_guest_tooling", True)
                else {"probed": False, "reason": "vm_or_tools_not_running"}
            )
        except RuntimeError as exc:
            return operation_error(self.id, self.result_key, "vmrun_failed", str(exc))
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "running": running,
                "tools_state": tools_state,
                "snapshots": snapshots,
                "vmx_path": config.vmx_path,
                "ready_snapshot": config.ready_snapshot,
                "vm_profile": {
                    "profile_name": config.profile_name,
                    "guest_os": config.guest_os,
                    "guest_tools_dir": config.guest_tools_dir,
                    "guest_sample_dir": config.guest_sample_dir,
                    "guest_telemetry_dir": config.guest_telemetry_dir,
                    "packet_capture_driver": config.packet_capture_driver,
                },
                "guest_tooling": guest_tooling,
                "requires_human_confirmation": False,
            },
        )


def _probe_guest_tooling(
    client: VmrunClient,
    config: VmwareConfig,
    params: dict[str, Any],
) -> dict[str, Any]:
    timeout = _timeout(params, config)
    tool_names = [
        "python",
        "tshark",
        "procmon",
        "noriben",
        "sysmon",
        "hayabusa",
        "chainsaw",
        "chainsaw_mapping",
        "sigma_rules",
        "deepbluecli",
        "pe_sieve",
        "hollowshunter",
    ]
    tools: dict[str, Any] = {}
    for name in tool_names:
        found_path = ""
        for candidate in config.guest_tool_candidates(name):
            exists = (
                client.directory_exists_in_guest(candidate, timeout=timeout)
                if name == "sigma_rules"
                else client.file_exists_in_guest(candidate, timeout=timeout)
            )
            if exists:
                found_path = candidate
                break
        tools[name] = {
            "available": bool(found_path),
            "path": found_path,
        }
    packet_capture = _probe_packet_capture(client, config, timeout)
    return {
        "probed": True,
        "tools": tools,
        "packet_capture": packet_capture,
        "capabilities": {
            "evtx_processing_ready": bool(
                tools["hayabusa"]["available"]
                or (tools["chainsaw"]["available"] and tools["sigma_rules"]["available"])
            ),
            "procmon_noriben_ready": bool(
                tools["python"]["available"]
                and tools["procmon"]["available"]
                and tools["noriben"]["available"]
            ),
            "memory_scan_ready": bool(tools["pe_sieve"]["available"] or tools["hollowshunter"]["available"]),
            "packet_capture_ready": bool(packet_capture.get("ready")),
        },
    }


def _probe_packet_capture(client: VmrunClient, config: VmwareConfig, timeout: int) -> dict[str, Any]:
    host_probe = _host_probe_path(config)
    guest_probe = config.guest_telemetry_dir.rstrip("\\/") + r"\packet_capture_probe.txt"
    host_probe.parent.mkdir(parents=True, exist_ok=True)
    guest_probe_cmd = guest_probe.replace("\\", "\\")
    guest_telemetry_cmd = config.guest_telemetry_dir.rstrip("\\/")
    command = (
        f"mkdir {guest_telemetry_cmd} 2>nul & "
        f"sc.exe query npcap > {guest_probe_cmd} 2>&1 & "
        f"sc.exe query npf >> {guest_probe_cmd} 2>&1 & "
        "exit /b 0"
    )
    try:
        client.run_guest_program(r"C:\Windows\System32\cmd.exe", f"/c {command}", timeout=timeout)
        client.copy_from_guest(guest_probe, str(host_probe))
    except RuntimeError as exc:
        return {"ready": False, "driver": "", "error": str(exc)[:200]}
    text = host_probe.read_text(encoding="utf-8", errors="ignore") if host_probe.is_file() else ""
    lower = text.lower()
    npcap_ready = "service_name: npcap" in lower and "running" in lower
    winpcap_ready = "service_name: npf" in lower and "running" in lower
    driver = "npcap" if npcap_ready else "winpcap" if winpcap_ready else ""
    return {
        "ready": bool(driver),
        "driver": driver,
        "npcap_running": npcap_ready,
        "winpcap_npf_running": winpcap_ready,
        "host_probe_path": str(host_probe) if host_probe.is_file() else "",
    }


def _host_probe_path(config: VmwareConfig) -> Path:
    root = Path(config.host_output_dir)
    if not root.is_absolute():
        root = Path.cwd() / root
    safe_profile = "".join(char if char.isalnum() or char in {"_", "-"} else "_" for char in config.profile_name)
    return root / "_vm_status" / safe_profile / "packet_capture_probe.txt"


def _timeout(params: dict[str, Any], config: VmwareConfig) -> int:
    try:
        return max(5, min(60, int(params.get("probe_timeout_seconds") or config.timeout_seconds or 15)))
    except (TypeError, ValueError):
        return 15


def _bool_param(params: dict[str, Any], key: str, default: bool) -> bool:
    value = params.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)
