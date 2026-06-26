from __future__ import annotations

import time
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

from vmware_dynamic import (
    VmrunClient,
    VmwareConfig,
    config_error,
    ensure_host_sample_exists,
    join_guest_path,
    operation_error,
    preflight_blocked_result,
    safe_guest_filename,
)


class DynamicVmUploadSampleFunction(AnalysisFunction):
    id = "dynamic.vm_upload_sample"
    name = "Upload sample to VMware guest"
    category = "dynamic"
    result_key = "dynamic_vm_upload"
    description = "Copies the current platform sample into the configured VMware guest."
    cost = "medium"
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
        "guest_sample_path": "Path of the uploaded sample inside the guest.",
        "host_sample_path": "Platform sample path on the host.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        skipped = preflight_blocked_result(context, self.id, self.result_key)
        if skipped is not None:
            return skipped
        config = VmwareConfig.from_context(context, params)
        missing = config.validate(require_guest=True)
        if missing:
            return config_error(self.id, self.result_key, missing)
        try:
            sample_path = ensure_host_sample_exists(str(context.get("sample_path", "")))
        except FileNotFoundError as exc:
            return operation_error(self.id, self.result_key, "sample_not_found", str(exc))

        filename = safe_guest_filename(str(context.get("filename") or sample_path.name))
        guest_sample_path = join_guest_path(config.guest_sample_dir, filename)
        client = VmrunClient(config)
        started_at = time.monotonic()
        deadline = time.monotonic() + max(1, config.timeout_seconds)
        diagnostics: dict[str, Any] = {
            "guest_sample_path": guest_sample_path,
            "filename": filename,
            "file_size": sample_path.stat().st_size,
            "timeout_seconds": config.timeout_seconds,
            "phase_timings": [],
        }
        guard = _pe_persistence_guard(context)
        diagnostics["pe_persistence_guard"] = guard
        if guard.get("blocked") and not _bool_param(params, "ignore_pe_persistence_guard", False):
            return FunctionResult(
                function_id=self.id,
                result_key=self.result_key,
                status="error",
                data=diagnostics
                | {
                    "upload_verified": False,
                    "requires_human_confirmation": False,
                    "safe_next_step": guard.get("safe_next_step", ""),
                },
                error={
                    "code": "pe_persistence_guard_failed",
                    "message": "The VM PE persistence probe failed; refusing to upload the real sample into a guest that removes PE files.",
                },
            )
        chunk_upload_max_bytes = _int_param(params, "chunk_upload_max_bytes", 1024 * 1024)
        upload_method = str(params.get("upload_method") or "vmrun_copy").lower()
        allow_fallback = _bool_param(params, "fallback_to_guest_powershell", True)
        try:
            phase_started = time.monotonic()
            if not client.is_running(timeout=min(15, _remaining_seconds(deadline))):
                diagnostics["tools_state"] = "not_running"
                _record_phase(diagnostics, "check_vm_running", phase_started)
                return operation_error(
                    self.id,
                    self.result_key,
                    "vm_not_running",
                    "The VM is not running; run dynamic.vm_start_tools before uploading.",
                    diagnostics,
                )
            _record_phase(diagnostics, "check_vm_running", phase_started)
            phase_started = time.monotonic()
            tools_state = client.tools_state(timeout=min(15, _remaining_seconds(deadline)))
            _record_phase(diagnostics, "wait_for_running_tools", phase_started)
            if tools_state != "running":
                diagnostics["tools_state"] = tools_state
                return operation_error(
                    self.id,
                    self.result_key,
                    "vmware_tools_not_running",
                    f"VMware Tools is not ready; state={tools_state}. Run dynamic.vm_start_tools before uploading.",
                    diagnostics,
                )
            diagnostics["tools_state"] = tools_state
            phase_started = time.monotonic()
            guest_dir_exists = client.directory_exists_in_guest(
                config.guest_sample_dir,
                timeout=min(15, _remaining_seconds(deadline)),
            )
            _record_phase(diagnostics, "check_guest_dir", phase_started)
            diagnostics["guest_sample_dir_exists"] = guest_dir_exists
            if not guest_dir_exists:
                phase_started = time.monotonic()
                client.create_guest_dir(
                    config.guest_sample_dir,
                    timeout=_remaining_seconds(deadline),
                )
                _record_phase(diagnostics, "create_guest_dir", phase_started)
            phase_started = time.monotonic()
            if upload_method == "guest_powershell":
                chunk_result = client.upload_file_via_guest_powershell(
                    str(sample_path),
                    guest_sample_path,
                    timeout=_remaining_seconds(deadline),
                )
                diagnostics["upload_method"] = chunk_result["method"]
                diagnostics["upload_chunks"] = chunk_result["chunks"]
                diagnostics["upload_encoded_size"] = chunk_result["encoded_size"]
            else:
                try:
                    client.copy_to_guest(
                        str(sample_path),
                        guest_sample_path,
                        timeout=_remaining_seconds(deadline),
                    )
                    diagnostics["upload_method"] = "vmrun_copy_file"
                except RuntimeError as exc:
                    diagnostics["vmrun_copy_error"] = str(exc)[:500]
                    if not allow_fallback or sample_path.stat().st_size > chunk_upload_max_bytes:
                        raise
                    phase_fallback = time.monotonic()
                    chunk_result = client.upload_file_via_guest_powershell(
                        str(sample_path),
                        guest_sample_path,
                        timeout=_remaining_seconds(deadline),
                    )
                    diagnostics["upload_method"] = "guest_powershell_base64_chunks_after_vmrun_copy_failed"
                    diagnostics["upload_chunks"] = chunk_result["chunks"]
                    diagnostics["upload_encoded_size"] = chunk_result["encoded_size"]
                    _record_phase(diagnostics, "fallback_guest_powershell_upload", phase_fallback)
            _record_phase(diagnostics, "copy_to_guest", phase_started)
            phase_started = time.monotonic()
            if not client.file_exists_in_guest(guest_sample_path, timeout=_remaining_seconds(deadline)):
                if (
                    upload_method != "guest_powershell"
                    and allow_fallback
                    and sample_path.stat().st_size <= chunk_upload_max_bytes
                ):
                    phase_fallback = time.monotonic()
                    chunk_result = client.upload_file_via_guest_powershell(
                        str(sample_path),
                        guest_sample_path,
                        timeout=_remaining_seconds(deadline),
                    )
                    diagnostics["upload_method"] = "guest_powershell_base64_chunks_after_verify_failed"
                    diagnostics["upload_chunks"] = chunk_result["chunks"]
                    diagnostics["upload_encoded_size"] = chunk_result["encoded_size"]
                    _record_phase(diagnostics, "fallback_guest_powershell_upload", phase_fallback)
                if client.file_exists_in_guest(guest_sample_path, timeout=_remaining_seconds(deadline)):
                    _record_phase(diagnostics, "verify_guest_file_exists", phase_started)
                    diagnostics["verified_after_fallback"] = True
                    return FunctionResult(
                        function_id=self.id,
                        result_key=self.result_key,
                        data={
                            "guest_sample_path": guest_sample_path,
                            "host_sample_path": str(sample_path),
                            "filename": filename,
                            "tools_state": "running",
                            "upload_verified": True,
                            "upload_method": diagnostics.get("upload_method", ""),
                            "upload_chunks": diagnostics.get("upload_chunks", 0),
                            "timeout_seconds": config.timeout_seconds,
                            "elapsed_seconds": round(time.monotonic() - started_at, 3),
                            "phase_timings": diagnostics["phase_timings"],
                            "pe_persistence_guard": guard,
                            "requires_human_confirmation": False,
                        },
                    )
                _record_phase(diagnostics, "verify_guest_file_exists", phase_started)
                return operation_error(
                    self.id,
                    self.result_key,
                    "guest_upload_verify_failed",
                    "Uploaded sample was not found in the guest after copy.",
                    diagnostics,
                )
            _record_phase(diagnostics, "verify_guest_file_exists", phase_started)
        except RuntimeError as exc:
            diagnostics["elapsed_seconds"] = round(time.monotonic() - started_at, 3)
            return operation_error(self.id, self.result_key, "vmrun_failed", str(exc), diagnostics)
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "guest_sample_path": guest_sample_path,
                "host_sample_path": str(sample_path),
                "filename": filename,
                "tools_state": "running",
                "upload_verified": True,
                "upload_method": diagnostics.get("upload_method", ""),
                "upload_chunks": diagnostics.get("upload_chunks", 0),
                "pe_persistence_guard": guard,
                "timeout_seconds": config.timeout_seconds,
                "elapsed_seconds": round(time.monotonic() - started_at, 3),
                "phase_timings": diagnostics["phase_timings"],
                "requires_human_confirmation": False,
            },
        )


def _remaining_seconds(deadline: float) -> int:
    return max(1, int(deadline - time.monotonic()))


def _record_phase(diagnostics: dict[str, Any], phase: str, started: float) -> None:
    phases = diagnostics.setdefault("phase_timings", [])
    if not isinstance(phases, list):
        phases = []
        diagnostics["phase_timings"] = phases
    phases.append(
        {
            "phase": phase,
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }
    )


def _int_param(params: dict[str, Any], key: str, default: int) -> int:
    try:
        return max(1, int(params.get(key, default)))
    except (TypeError, ValueError):
        return default


def _bool_param(params: dict[str, Any], key: str, default: bool) -> bool:
    value = params.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return bool(value)


def _pe_persistence_guard(context: dict[str, Any]) -> dict[str, Any]:
    result = context.get("results", {}).get("malware_vm_security_repair")
    if not isinstance(result, dict):
        return {"available": False, "blocked": False, "reason": "no_prior_pe_persistence_probe"}
    data = result.get("data", {})
    if not isinstance(data, dict) or not data.get("cmd_probe_only"):
        return {"available": False, "blocked": False, "reason": "no_prior_cmd_probe"}
    pe_exists = data.get("pe_exists")
    fake_exists = data.get("fake_exists")
    blocked = bool(data.get("pe_persistence_blocked")) or (pe_exists is False and fake_exists is True)
    return {
        "available": True,
        "blocked": blocked,
        "pe_exists": pe_exists,
        "fake_exists": fake_exists,
        "host_output_path": data.get("host_output_path", ""),
        "probable_blocking_layer": data.get("probable_blocking_layer", ""),
        "safe_next_step": data.get("safe_next_step")
        or "restore the known-good malware analysis snapshot and rerun the PE persistence probe before upload",
    }
