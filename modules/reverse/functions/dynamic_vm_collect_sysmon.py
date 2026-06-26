from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from pathlib import PureWindowsPath
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

from vmware_dynamic import (
    VmrunClient,
    VmwareConfig,
    config_error,
    copy_module_export_script_if_available,
    create_cleanup_batch,
    create_export_batch,
    host_output_path,
    join_guest_path,
    load_telemetry_json,
    operation_error,
    preflight_blocked_result,
)


class DynamicVmCollectSysmonFunction(AnalysisFunction):
    id = "dynamic.vm_collect_sysmon"
    name = "Collect VMware Sysmon telemetry"
    category = "dynamic"
    result_key = "dynamic_telemetry"
    description = "Exports Sysmon logs from the VMware guest and returns normalized dynamic telemetry."
    cost = "high"
    external_tool = True
    optional = True
    config_required = True
    requires_results = ["dynamic_vm_run"]
    recommended_before = ["dynamic.vm_run_sample"]
    config_requirements = [
        "vmware.vmrun_path",
        "vmware.vmx_path",
        "vmware.vm_password",
        "vmware.guest_user",
        "vmware.guest_password",
    ]
    output_schema = {
        "process_events": "Process telemetry exported from Sysmon.",
        "file_events": "File telemetry exported from Sysmon.",
        "registry_events": "Registry telemetry exported from Sysmon.",
        "network_events": "Network telemetry exported from Sysmon.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        skipped = preflight_blocked_result(context, self.id, self.result_key)
        if skipped is not None:
            return skipped
        config = VmwareConfig.from_context(context, params)
        missing = config.validate(require_guest=True)
        if missing:
            return config_error(self.id, self.result_key, missing)
        last_minutes = _last_minutes(params)
        max_events = _max_events(params)
        client = VmrunClient(config)
        host_root = host_output_path(config, context, "dynamic_telemetry.json").parent
        host_export_bat = host_root / "export_dynamic_now.bat"
        host_cleanup_bat = host_root / "cleanup_uploaded_sample.bat"
        host_telemetry = host_root / "dynamic_telemetry.json"
        host_export_log = host_root / "export.log"
        guest_export_bat = join_guest_path(config.guest_tools_dir, "export_dynamic_now.bat")
        guest_telemetry = join_guest_path(config.guest_telemetry_dir, "dynamic_telemetry.json")
        guest_export_log = join_guest_path(config.guest_telemetry_dir, "export.log")
        run_window = _run_window(context, params)
        guest_sample_path = _guest_sample_path(context)
        sample_filename = PureWindowsPath(guest_sample_path).name if guest_sample_path else str(context.get("filename") or "")

        try:
            client.wait_for_running_tools(config.timeout_seconds)
            _copy_export_script_force(config, client)
            _create_export_batch_compat(
                host_export_bat,
                config,
                last_minutes,
                max_events,
                start_time_utc=run_window.get("collection_window_start", ""),
                end_time_utc=run_window.get("collection_window_end", ""),
                sample_path=guest_sample_path,
                sample_filename=sample_filename,
            )
            client.copy_to_guest(str(host_export_bat), guest_export_bat)
            client.run_guest_program(
                r"C:\Windows\System32\cmd.exe",
                f'/c "{guest_export_bat}"',
                timeout=config.timeout_seconds,
            )
            client.copy_from_guest(guest_telemetry, str(host_telemetry))
            try:
                client.copy_from_guest(guest_export_log, str(host_export_log))
            except RuntimeError:
                pass
            if bool(params.get("cleanup_uploaded_sample", True)):
                if guest_sample_path:
                    create_cleanup_batch(host_cleanup_bat, guest_sample_path)
                    guest_cleanup_bat = join_guest_path(
                        config.guest_tools_dir,
                        "cleanup_uploaded_sample.bat",
                    )
                    client.copy_to_guest(str(host_cleanup_bat), guest_cleanup_bat)
                    client.run_guest_program(
                        r"C:\Windows\System32\cmd.exe",
                        f'/c "{guest_cleanup_bat}"',
                        timeout=config.timeout_seconds,
                    )
            telemetry = load_telemetry_json(host_telemetry)
        except RuntimeError as exc:
            diagnostics: dict[str, Any] = {
                "host_export_log": "",
                "host_telemetry": "",
                "export_log_lines": [],
            }
            try:
                client.copy_from_guest(guest_export_log, str(host_export_log))
                diagnostics["host_export_log"] = str(host_export_log)
                diagnostics["export_log_lines"] = host_export_log.read_text(
                    encoding="utf-8",
                    errors="ignore",
                ).splitlines()[:80]
            except (RuntimeError, OSError):
                pass
            try:
                client.copy_from_guest(guest_telemetry, str(host_telemetry))
                diagnostics["host_telemetry"] = str(host_telemetry)
            except (RuntimeError, OSError):
                pass
            return operation_error(self.id, self.result_key, "vmrun_failed", str(exc), diagnostics)
        except (OSError, ValueError) as exc:
            return operation_error(self.id, self.result_key, "telemetry_parse_failed", str(exc))

        telemetry["host_output_path"] = str(host_telemetry)
        telemetry["collection_diagnostics"] = _collection_diagnostics(
            telemetry,
            run_window=run_window,
            sample_filename=sample_filename,
            guest_sample_path=guest_sample_path,
            max_events=max_events,
        )
        telemetry.setdefault("limitations", []).append(
            "Telemetry was collected from the configured VMware guest."
        )
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data=telemetry,
        )


def _last_minutes(params: dict[str, Any]) -> int:
    try:
        return max(1, min(1440, int(params.get("last_minutes", 60))))
    except (TypeError, ValueError):
        return 60


def _max_events(params: dict[str, Any]) -> int:
    try:
        return max(100, min(50000, int(params.get("max_events", 5000))))
    except (TypeError, ValueError):
        return 5000


def _copy_export_script_force(config: VmwareConfig, client: VmrunClient) -> None:
    candidates = [
        Path("data/vm_dynamic/Export-DynamicTelemetry.ps1"),
        Path("data/vm_dynamic/win10_tool_migration/Export-DynamicTelemetry.ps1"),
        Path("D:/vmware/win10_tools/Export-DynamicTelemetry.ps1"),
        Path("D:/vmware/win11_tools/Export-DynamicTelemetry.ps1"),
    ]
    for source in candidates:
        if source.is_file():
            try:
                client.copy_to_guest(str(source), config.telemetry_script_path)
                return
            except RuntimeError:
                pass
    copy_module_export_script_if_available(config, client)


def _create_export_batch_compat(
    host_path: Path,
    config: VmwareConfig,
    last_minutes: int,
    max_events: int,
    *,
    start_time_utc: str = "",
    end_time_utc: str = "",
    sample_path: str = "",
    sample_filename: str = "",
) -> None:
    try:
        create_export_batch(
            host_path,
            config,
            last_minutes,
            max_events,
            start_time_utc=start_time_utc,
            end_time_utc=end_time_utc,
            sample_path=sample_path,
            sample_filename=sample_filename,
        )
    except TypeError:
        guest_telemetry = join_guest_path(config.guest_telemetry_dir, "dynamic_telemetry.json")
        guest_log = join_guest_path(config.guest_telemetry_dir, "export.log")
        window_args = ""
        if start_time_utc:
            window_args += f" -StartTimeUtc \"{start_time_utc}\""
        if end_time_utc:
            window_args += f" -EndTimeUtc \"{end_time_utc}\""
        if sample_path:
            window_args += f" -SamplePath \"{sample_path}\""
        if sample_filename:
            window_args += f" -SampleFilename \"{sample_filename}\""
        script = (
            "@echo off\r\n"
            "setlocal\r\n"
            f"mkdir \"{config.guest_telemetry_dir}\" 2>nul\r\n"
            "powershell.exe -NoProfile -ExecutionPolicy Bypass "
            f"-File \"{config.telemetry_script_path}\" "
            f"-LastMinutes {max(1, last_minutes)} "
            f"-MaxEvents {max(1, max_events)} "
            f"-OutFile \"{guest_telemetry}\" "
            f"{window_args} "
            f"> \"{guest_log}\" 2>&1\r\n"
            "exit /b %errorlevel%\r\n"
        )
        host_path.parent.mkdir(parents=True, exist_ok=True)
        host_path.write_text(script, encoding="ascii")


def _guest_sample_path(context: dict[str, Any]) -> str:
    upload = context.get("results", {}).get("dynamic_vm_upload", {})
    if isinstance(upload, dict):
        data = upload.get("data", {})
        if isinstance(data, dict):
            return str(data.get("guest_sample_path") or "")
    return ""


def _run_window(context: dict[str, Any], params: dict[str, Any]) -> dict[str, str]:
    started = str(params.get("start_time_utc") or params.get("run_started_at") or "")
    finished = str(params.get("end_time_utc") or params.get("run_finished_at") or "")
    if not started or not finished:
        for result_key in ("dynamic_vm_run", "malware_vm_procmon_noriben_behavior", "malware_vm_procmon_capture"):
            data = _result_data(context, result_key)
            manifest = data.get("run_manifest") if isinstance(data.get("run_manifest"), dict) else data
            started = started or str(manifest.get("run_started_at") or manifest.get("sample_launch_start") or "")
            finished = finished or str(manifest.get("run_finished_at") or manifest.get("procmon_capture_end") or "")
            if started and finished:
                break
    start_dt = _parse_dt(started)
    end_dt = _parse_dt(finished)
    if not start_dt or not end_dt:
        return {}
    start_dt = start_dt - timedelta(seconds=30)
    end_dt = end_dt + timedelta(seconds=30)
    if end_dt <= start_dt:
        return {}
    return {
        "collection_window_start": start_dt.astimezone(timezone.utc).isoformat(),
        "collection_window_end": end_dt.astimezone(timezone.utc).isoformat(),
    }


def _collection_diagnostics(
    telemetry: dict[str, Any],
    *,
    run_window: dict[str, str],
    sample_filename: str,
    guest_sample_path: str,
    max_events: int,
) -> dict[str, Any]:
    groups = [
        "process_events",
        "file_events",
        "registry_events",
        "network_events",
        "service_events",
        "scheduled_task_events",
        "module_load_events",
    ]
    total = 0
    sample_candidates = []
    sample_tokens = {
        token.lower()
        for token in [sample_filename, PureWindowsPath(guest_sample_path).name if guest_sample_path else "", guest_sample_path]
        if token
    }
    for group in groups:
        values = telemetry.get(group)
        if not isinstance(values, list):
            continue
        total += len(values)
        for item in values:
            if not isinstance(item, dict):
                continue
            text = str(item).lower()
            if sample_tokens and any(token in text for token in sample_tokens):
                sample_candidates.append(
                    {
                        "event_group": group,
                        "event_id": item.get("event_id") or item.get("RecordId") or "",
                        "event_type": item.get("event_type") or "",
                        "process_name": item.get("process_name") or "",
                        "image": item.get("image") or item.get("image_path") or "",
                        "command_line": _raw_value(item, "CommandLine"),
                    }
                )
    return {
        **run_window,
        "events_after_cap": total,
        "max_events": max_events,
        "events_dropped_by_cap": max(0, int(telemetry.get("events_before_cap") or 0) - total) if telemetry.get("events_before_cap") else 0,
        "sample_process_create_candidates": [
            item for item in sample_candidates if str(item.get("event_type") or "").lower() == "process_create"
        ][:25],
        "sample_window_events": sample_candidates[:50],
        "window_source": "run_manifest" if run_window else "last_minutes",
    }


def _result_data(context: dict[str, Any], result_key: str) -> dict[str, Any]:
    result = context.get("results", {}).get(result_key)
    if not isinstance(result, dict) or result.get("status") == "error":
        return {}
    data = result.get("data")
    return data if isinstance(data, dict) else {}


def _parse_dt(value: str) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def _raw_value(item: dict[str, Any], key: str) -> str:
    raw = item.get("raw")
    if isinstance(raw, dict):
        return str(raw.get(key) or "")
    return str(item.get(key) or item.get(key.lower()) or "")
