from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import re
import tempfile
import time
import uuid
from pathlib import Path
from pathlib import PureWindowsPath
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

from vmware_dynamic import (
    EXECUTE_CONFIRMATION,
    VmrunClient,
    VmwareConfig,
    config_error,
    join_guest_path,
    operation_error,
    preflight_blocked_result,
)


class DynamicVmRunSampleFunction(AnalysisFunction):
    id = "dynamic.vm_run_sample"
    name = "Run sample inside VMware guest"
    category = "dynamic"
    result_key = "dynamic_vm_run"
    description = "Runs an uploaded sample in the configured VMware guest after explicit confirmation."
    cost = "high"
    external_tool = True
    optional = True
    config_required = True
    requires_human_confirmation = True
    requires_results = ["dynamic_vm_upload"]
    recommended_before = ["dynamic.vm_restore_snapshot", "dynamic.vm_upload_sample"]
    config_requirements = [
        "vmware.vmrun_path",
        "vmware.vmx_path",
        "vmware.vm_password",
        "vmware.guest_user",
        "vmware.guest_password",
    ]
    output_schema = {
        "guest_sample_path": "Executed guest path.",
        "duration_seconds": "Collection wait period after launch.",
        "execution_confirmed": "True only when explicit confirmation was supplied.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        if params.get("confirm_execute") != EXECUTE_CONFIRMATION:
            return operation_error(
                self.id,
                self.result_key,
                "execution_not_confirmed",
                f"Set confirm_execute to {EXECUTE_CONFIRMATION} to run the sample in the VM.",
            )
        skipped = preflight_blocked_result(context, self.id, self.result_key)
        if skipped is not None:
            return skipped
        config = VmwareConfig.from_context(context, params)
        missing = config.validate(require_guest=True)
        if missing:
            return config_error(self.id, self.result_key, missing)

        guest_sample_path = _guest_sample_path(context, params, config)
        duration = _duration(params)
        client = VmrunClient(config)
        try:
            tools_state = client.wait_for_running_tools(config.timeout_seconds)
            if tools_state != "running":
                return operation_error(
                    self.id,
                    self.result_key,
                    "vmware_tools_not_running",
                    f"VMware Tools did not reach running state; last state={tools_state}",
                )
            if not client.file_exists_in_guest(guest_sample_path, timeout=config.timeout_seconds):
                return operation_error(
                    self.id,
                    self.result_key,
                    "guest_sample_not_found",
                    "The uploaded sample was not found in the guest; rerun vm_upload_sample.",
                )
            started_at = datetime.now(timezone.utc)
            launch = _launch_guest_sample_with_identity(client, guest_sample_path, timeout=config.timeout_seconds)
            if launch.get("launch_status") != "started":
                _run_guest_sample(client, guest_sample_path)
                launch = {
                    "launch_status": "started_without_identity",
                    "identity_error": launch.get("identity_error") or launch.get("error") or "",
                    "source": "vmrun_direct_fallback",
                }
            process_identity = _process_identity_from_launch(launch)
            if process_identity.get("pid"):
                sysmon_identity = _lookup_sysmon_process_identity(
                    client,
                    guest_sample_path,
                    process_identity.get("pid") or "",
                    started_at.isoformat(),
                    timeout=min(config.timeout_seconds, 60),
                )
                process_identity = _merge_process_identity(process_identity, sysmon_identity)
            time.sleep(duration)
            finished_at = datetime.now(timezone.utc)
        except RuntimeError as exc:
            return operation_error(self.id, self.result_key, "vmrun_failed", str(exc))

        manifest = {
            "guest_sample_path": guest_sample_path,
            "sample_filename": PureWindowsPath(guest_sample_path).name,
            "launch_command_line": guest_sample_path,
            "run_started_at": started_at.isoformat(),
            "run_finished_at": finished_at.isoformat(),
            "duration_seconds": duration,
            "source_tool": "vmrun",
            "launch_status": launch.get("launch_status") or "unknown",
            "process_identity": process_identity,
        }
        manifest.update(_flatten_process_identity(process_identity))
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "guest_sample_path": guest_sample_path,
                "sample_filename": manifest["sample_filename"],
                "launch_command_line": manifest["launch_command_line"],
                "run_started_at": manifest["run_started_at"],
                "run_finished_at": manifest["run_finished_at"],
                "duration_seconds": duration,
                "process_identity": process_identity,
                "execution_confirmed": True,
                "run_manifest": manifest,
                "requires_human_confirmation": True,
                "limitations": [
                    "Execution happens only inside the configured VM.",
                    "Behavior depends on VM isolation and telemetry quality.",
                ],
            },
        )


def _guest_sample_path(
    context: dict[str, Any],
    params: dict[str, Any],
    config: VmwareConfig,
) -> str:
    if params.get("guest_sample_path"):
        return str(params["guest_sample_path"])
    upload = context.get("results", {}).get("dynamic_vm_upload", {})
    if isinstance(upload, dict):
        data = upload.get("data", {})
        if isinstance(data, dict) and data.get("guest_sample_path"):
            return str(data["guest_sample_path"])
    filename = str(context.get("filename") or "sample.bin")
    return join_guest_path(config.guest_sample_dir, filename)


def _run_guest_sample(client: VmrunClient, guest_sample_path: str) -> None:
    suffix = PureWindowsPath(guest_sample_path).suffix.lower()
    if suffix == ".ps1":
        client.run_guest_program(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            f'-NoProfile -ExecutionPolicy Bypass -File "{guest_sample_path}"',
            no_wait=True,
        )
        return
    client.run_guest_program(guest_sample_path, no_wait=True)


def _launch_guest_sample_with_identity(
    client: VmrunClient,
    guest_sample_path: str,
    *,
    timeout: int,
) -> dict[str, Any]:
    launch_id = uuid.uuid4().hex[:12]
    guest_dir = client.config.guest_telemetry_dir.rstrip("\\/")
    guest_script_path = rf"{guest_dir}\launch_sample_{launch_id}.ps1"
    guest_manifest_path = rf"{guest_dir}\launch_sample_{launch_id}.json"
    host_dir = Path(tempfile.gettempdir()) / "sfp_vm_launch_manifests"
    host_dir.mkdir(parents=True, exist_ok=True)
    host_script_path = host_dir / f"launch_sample_{launch_id}.ps1"
    host_manifest_path = host_dir / f"launch_sample_{launch_id}.json"
    suffix = PureWindowsPath(guest_sample_path).suffix.lower()
    if suffix == ".ps1":
        file_path = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        argument_list = f'-NoProfile -ExecutionPolicy Bypass -File "{guest_sample_path}"'
    else:
        file_path = guest_sample_path
        argument_list = ""
    script = f"""
$ErrorActionPreference = 'Stop'
$manifestPath = {_ps_quote(guest_manifest_path)}
try {{
  $startedAt = (Get-Date).ToUniversalTime().ToString('o')
  $filePath = {_ps_quote(file_path)}
  $argumentList = {_ps_quote(argument_list)}
  $samplePath = {_ps_quote(guest_sample_path)}
  $workingDirectory = Split-Path -Parent $samplePath
  if ($argumentList) {{
    $p = Start-Process -FilePath $filePath -ArgumentList $argumentList -WorkingDirectory $workingDirectory -PassThru
  }} else {{
    $p = Start-Process -FilePath $filePath -WorkingDirectory $workingDirectory -PassThru
  }}
  Start-Sleep -Milliseconds 1000
  $proc = $null
  try {{
    $proc = Get-CimInstance Win32_Process -Filter ("ProcessId={{0}}" -f $p.Id) -ErrorAction Stop
  }} catch {{}}
  $image = if ($proc -and $proc.ExecutablePath) {{ $proc.ExecutablePath }} else {{ $samplePath }}
  $cmd = if ($proc -and $proc.CommandLine) {{ $proc.CommandLine }} elseif ($argumentList) {{ ($filePath + ' ' + $argumentList) }} else {{ $filePath }}
  $name = if ($proc -and $proc.Name) {{ $proc.Name }} else {{ [IO.Path]::GetFileName($image) }}
  $parent = if ($proc -and $proc.ParentProcessId) {{ [string]$proc.ParentProcessId }} else {{ '' }}
  $queryStatus = if ($proc) {{ 'found' }} else {{ 'process_exited_or_not_queryable' }}
  $sysmonStatus = 'not_found'
  $sysmonMap = $null
  $deadline = (Get-Date).AddSeconds(8)
  while ((Get-Date) -lt $deadline -and -not $sysmonMap) {{
    try {{
      $events = Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=([datetime]$startedAt).AddMinutes(-2)}} -MaxEvents 500 -ErrorAction Stop
      foreach ($ev in $events) {{
        $xml = [xml]$ev.ToXml()
        $map = @{{}}
        foreach ($d in $xml.Event.EventData.Data) {{ $map[$d.Name] = [string]$d.'#text' }}
        $eventPid = [string]$map['ProcessId']
        $eventImage = [string]$map['Image']
        $eventCommandLine = [string]$map['CommandLine']
        if (
          ($eventPid -and $eventPid -eq [string]$p.Id) -or
          ($eventImage -and $eventImage.Equals($samplePath, [System.StringComparison]::OrdinalIgnoreCase)) -or
          ($eventCommandLine -and $eventCommandLine.IndexOf([IO.Path]::GetFileName($samplePath), [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
        ) {{
          $sysmonMap = $map
          break
        }}
      }}
    }} catch {{
      $sysmonStatus = 'error'
    }}
    if (-not $sysmonMap) {{ Start-Sleep -Milliseconds 500 }}
  }}
  if ($sysmonMap) {{
    $sysmonStatus = 'found'
    $image = [string]$sysmonMap['Image']
    $cmd = [string]$sysmonMap['CommandLine']
    $name = [IO.Path]::GetFileName($image)
    $parent = [string]$sysmonMap['ParentProcessId']
  }}
  $processGuid = ''
  $parentProcessGuid = ''
  $parentProcessName = ''
  $parentImage = ''
  $sysmonUtcTime = ''
  if ($sysmonMap) {{
    $processGuid = [string]$sysmonMap['ProcessGuid']
    $parentProcessGuid = [string]$sysmonMap['ParentProcessGuid']
    $parentImage = [string]$sysmonMap['ParentImage']
    $parentProcessName = [IO.Path]::GetFileName($parentImage)
    $sysmonUtcTime = [string]$sysmonMap['UtcTime']
  }}
  $result = [ordered]@{{
    launch_status = 'started'
    source = 'guest_manifest_start_process'
    pid = [string]$p.Id
    process_id = [string]$p.Id
    process_guid = $processGuid
    process_name = $name
    process_path = $image
    command_line = $cmd
    parent_pid = $parent
    parent_process_guid = $parentProcessGuid
    parent_process_name = $parentProcessName
    parent_image = $parentImage
    started_at = $startedAt
    sysmon_lookup_status = $sysmonStatus
    sysmon_utc_time = $sysmonUtcTime
    process_query_status = $queryStatus
    manifest_path = $manifestPath
  }}
}} catch {{
  $result = [ordered]@{{
    launch_status = 'identity_launch_failed'
    source = 'guest_manifest_start_process'
    identity_error = $_.Exception.Message
    manifest_path = $manifestPath
  }}
}}
$json = $result | ConvertTo-Json -Compress -Depth 5
[IO.File]::WriteAllText($manifestPath, $json, [Text.Encoding]::UTF8)
exit 0
"""
    try:
        host_script_path.write_text(script, encoding="utf-8")
        try:
            client.create_guest_dir(guest_dir, timeout=min(timeout, 60))
        except RuntimeError:
            pass
        client.copy_to_guest(str(host_script_path), guest_script_path, timeout=timeout)
        _run_guest_powershell_script_via_cmd(
            client,
            guest_script_path,
            no_wait=True,
            timeout=min(timeout, 60),
        )
        value = _wait_for_guest_manifest(
            client,
            guest_manifest_path,
            host_manifest_path,
            timeout=min(timeout, 30),
        )
        return value
    except (RuntimeError, OSError, json.JSONDecodeError) as exc:
        return {
            "launch_status": "identity_launch_failed",
            "identity_error": str(exc)[:500],
            "source": "guest_manifest_start_process",
        }
    finally:
        for path in [host_script_path, host_manifest_path]:
            try:
                path.unlink()
            except OSError:
                pass
        try:
            _capture_guest_powershell_via_cmd(
                client,
                (
                    f"Remove-Item -LiteralPath {_ps_quote(guest_script_path)} -Force "
                    "-ErrorAction SilentlyContinue; "
                    f"Remove-Item -LiteralPath {_ps_quote(guest_manifest_path)} -Force "
                    "-ErrorAction SilentlyContinue"
                ),
                timeout=min(timeout, 30),
            )
        except RuntimeError:
            pass


def _lookup_sysmon_process_identity(
    client: VmrunClient,
    guest_sample_path: str,
    pid: str,
    started_at: str,
    *,
    timeout: int,
) -> dict[str, Any]:
    script = f"""
$ErrorActionPreference = 'SilentlyContinue'
$samplePath = {_ps_quote(guest_sample_path)}
$pidText = {_ps_quote(pid)}
$startedText = {_ps_quote(started_at)}
$start = [datetime]::MinValue
[datetime]::TryParse($startedText, [ref]$start) | Out-Null
if ($start -eq [datetime]::MinValue) {{ $start = (Get-Date).AddMinutes(-10) }}
$events = Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1; StartTime=$start.AddMinutes(-2)}} -MaxEvents 200 -ErrorAction SilentlyContinue
$match = $null
foreach ($ev in $events) {{
  $xml = [xml]$ev.ToXml()
  $map = @{{}}
  foreach ($d in $xml.Event.EventData.Data) {{ $map[$d.Name] = [string]$d.'#text' }}
  $image = [string]$map['Image']
  $procId = [string]$map['ProcessId']
  if (($pidText -and $procId -eq $pidText) -or ($image -and $image.Equals($samplePath, [System.StringComparison]::OrdinalIgnoreCase))) {{
    $match = $map
    break
  }}
}}
if ($match) {{
  [ordered]@{{
    sysmon_lookup_status = 'found'
    source = 'sysmon_event_id_1'
    pid = [string]$match['ProcessId']
    process_id = [string]$match['ProcessId']
    process_guid = [string]$match['ProcessGuid']
    process_name = [IO.Path]::GetFileName([string]$match['Image'])
    process_path = [string]$match['Image']
    command_line = [string]$match['CommandLine']
    parent_pid = [string]$match['ParentProcessId']
    parent_process_guid = [string]$match['ParentProcessGuid']
    parent_process_name = [IO.Path]::GetFileName([string]$match['ParentImage'])
    parent_image = [string]$match['ParentImage']
    utc_time = [string]$match['UtcTime']
  }} | ConvertTo-Json -Compress -Depth 5
}} else {{
  [ordered]@{{
    sysmon_lookup_status = 'not_found'
    source = 'sysmon_event_id_1'
    pid = $pidText
  }} | ConvertTo-Json -Compress -Depth 5
}}
"""
    try:
        completed = _capture_guest_powershell_via_cmd(client, script, timeout=timeout)
        return _json_from_stdout(completed.stdout)
    except RuntimeError as exc:
        return {
            "sysmon_lookup_status": "error",
            "source": "sysmon_event_id_1",
            "pid": pid,
            "error": str(exc)[:500],
        }


def _run_guest_powershell_script_via_cmd(
    client: VmrunClient,
    guest_script_path: str,
    *,
    no_wait: bool,
    timeout: int,
) -> None:
    runner = f"& {_ps_quote(guest_script_path)}; exit $LASTEXITCODE"
    encoded = base64.b64encode(runner.encode("utf-16le")).decode("ascii")
    powershell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    args = f"/c {powershell} -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}"
    client.run_guest_program(
        r"C:\Windows\System32\cmd.exe",
        args,
        no_wait=no_wait,
        timeout=timeout,
    )


def _capture_guest_powershell_via_cmd(
    client: VmrunClient,
    script: str,
    *,
    timeout: int,
) -> Any:
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    powershell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    args = f'/c {powershell} -NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}'
    return client.guest_command(
        "runProgramInGuest",
        client.config.vmx_path,
        r"C:\Windows\System32\cmd.exe",
        args,
        timeout=timeout,
    )


def _wait_for_guest_manifest(
    client: VmrunClient,
    guest_manifest_path: str,
    host_manifest_path: Path,
    *,
    timeout: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + max(1, timeout)
    last_error = ""
    while time.monotonic() < deadline:
        try:
            client.copy_from_guest(guest_manifest_path, str(host_manifest_path))
            text = host_manifest_path.read_text(encoding="utf-8-sig")
            value = json.loads(text)
            return value if isinstance(value, dict) else {}
        except (RuntimeError, OSError, json.JSONDecodeError) as exc:
            last_error = str(exc)
            time.sleep(1)
    return {
        "launch_status": "identity_launch_failed",
        "identity_error": f"guest launch manifest was not available: {last_error}"[:500],
        "source": "guest_manifest_start_process",
    }


def _process_identity_from_launch(launch: dict[str, Any]) -> dict[str, Any]:
    if not launch:
        return {}
    pid = _clean(launch.get("pid") or launch.get("process_id"))
    identity = {
        "pid": pid,
        "process_id": pid,
        "process_guid": _clean(launch.get("process_guid")),
        "process_name": _clean(launch.get("process_name")),
        "process_path": _clean(launch.get("process_path")),
        "command_line": _clean(launch.get("command_line")),
        "parent_pid": _clean(launch.get("parent_pid")),
        "parent_process_guid": _clean(launch.get("parent_process_guid")),
        "parent_process_name": _clean(launch.get("parent_process_name")),
        "parent_image": _clean(launch.get("parent_image")),
        "source": _clean(launch.get("source")) or "guest_powershell_start_process",
        "launch_status": _clean(launch.get("launch_status")),
        "sysmon_lookup_status": _clean(launch.get("sysmon_lookup_status")),
        "sysmon_utc_time": _clean(launch.get("sysmon_utc_time")),
        "process_query_status": _clean(launch.get("process_query_status")),
        "confidence": "high" if _clean(launch.get("process_guid")) else ("medium" if pid else "low"),
    }
    if launch.get("identity_error"):
        identity["identity_error"] = _clean(launch.get("identity_error"))
    return {key: value for key, value in identity.items() if value not in ("", None)}


def _merge_process_identity(identity: dict[str, Any], sysmon: dict[str, Any]) -> dict[str, Any]:
    merged = dict(identity or {})
    if not sysmon:
        return merged
    for key in [
        "pid",
        "process_id",
        "process_guid",
        "process_name",
        "process_path",
        "command_line",
        "parent_pid",
        "parent_process_guid",
        "parent_process_name",
        "parent_image",
    ]:
        value = _clean(sysmon.get(key))
        if value:
            merged[key] = value
    merged["sysmon_lookup_status"] = _clean(sysmon.get("sysmon_lookup_status")) or "unknown"
    merged["sysmon_source"] = _clean(sysmon.get("source")) or "sysmon_event_id_1"
    if sysmon.get("utc_time"):
        merged["sysmon_utc_time"] = _clean(sysmon.get("utc_time"))
    if sysmon.get("error"):
        merged["sysmon_lookup_error"] = _clean(sysmon.get("error"))
    if merged.get("process_guid"):
        merged["confidence"] = "high"
        merged["source"] = "guest_powershell_start_process+sysmon_event_id_1"
    elif merged.get("pid"):
        merged["confidence"] = "medium"
    else:
        merged["confidence"] = "low"
    return merged


def _flatten_process_identity(identity: dict[str, Any]) -> dict[str, Any]:
    if not identity:
        return {}
    keys = [
        "pid",
        "process_id",
        "process_guid",
        "process_name",
        "process_path",
        "command_line",
        "parent_pid",
        "parent_process_guid",
        "parent_process_name",
        "parent_image",
        "launch_status",
    ]
    return {key: identity[key] for key in keys if identity.get(key) not in ("", None)}


def _json_from_stdout(stdout: str) -> dict[str, Any]:
    text = str(stdout or "").strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        pass
    matches = re.findall(r"\{.*\}", text, flags=re.DOTALL)
    for candidate in reversed(matches):
        try:
            value = json.loads(candidate)
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            continue
    return {}


def _ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _clean(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _duration(params: dict[str, Any]) -> int:
    try:
        return max(1, min(600, int(params.get("duration_seconds", 30))))
    except (TypeError, ValueError):
        return 30
