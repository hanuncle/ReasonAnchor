from __future__ import annotations

import json
import base64
import locale
import ntpath
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from security_function_platform.core.function_result import FunctionResult

EXECUTE_CONFIRMATION = "I_UNDERSTAND_RUN_SAMPLE_IN_VM"
RESTORE_CONFIRMATION = "I_UNDERSTAND_RESTORE_VM_SNAPSHOT"
PROJECT_ROOT = Path(__file__).resolve().parents[3]


@dataclass
class VmwareConfig:
    vmrun_path: str
    vmx_path: str
    vm_password: str
    guest_user: str
    guest_password: str
    profile_name: str = "malware-lab"
    guest_os: str = "windows"
    guest_sample_dir: str = r"C:\Samples"
    guest_tools_dir: str = r"C:\Tools"
    guest_telemetry_dir: str = r"C:\Telemetry"
    telemetry_script_path: str = r"C:\Tools\Export-DynamicTelemetry.ps1"
    host_output_dir: str = "data/vm_dynamic"
    ready_snapshot: str = "malware-tools-ready"
    timeout_seconds: int = 120
    packet_capture_driver: str = "auto"

    @classmethod
    def from_context(cls, context: dict[str, Any], params: dict[str, Any]) -> "VmwareConfig":
        config = context.get("config", {}).get("vmware", {})
        if not isinstance(config, dict):
            config = {}
        return cls(
            vmrun_path=str(
                params.get("vmrun_path")
                or config.get("vmrun_path")
                or ""
            ),
            vmx_path=str(
                params.get("vmx_path")
                or config.get("vmx_path")
                or ""
            ),
            vm_password=str(params.get("vm_password") or config.get("vm_password") or ""),
            guest_user=str(params.get("guest_user") or config.get("guest_user") or ""),
            guest_password=str(
                params.get("guest_password") or config.get("guest_password") or ""
            ),
            profile_name=str(
                params.get("profile_name")
                or config.get("profile_name")
                or config.get("profile")
                or "malware-lab"
            ),
            guest_os=str(params.get("guest_os") or config.get("guest_os") or "windows"),
            guest_sample_dir=str(
                params.get("guest_sample_dir")
                or config.get("guest_sample_dir")
                or r"C:\Samples"
            ),
            guest_tools_dir=str(
                params.get("guest_tools_dir")
                or config.get("guest_tools_dir")
                or r"C:\Tools"
            ),
            guest_telemetry_dir=str(
                params.get("guest_telemetry_dir")
                or config.get("guest_telemetry_dir")
                or r"C:\Telemetry"
            ),
            telemetry_script_path=str(
                params.get("telemetry_script_path")
                or config.get("telemetry_script_path")
                or r"C:\Tools\Export-DynamicTelemetry.ps1"
            ),
            host_output_dir=str(
                params.get("host_output_dir")
                or config.get("host_output_dir")
                or "data/vm_dynamic"
            ),
            ready_snapshot=str(
                params.get("ready_snapshot")
                or config.get("ready_snapshot")
                or "malware-tools-ready"
            ),
            timeout_seconds=_int_value(
                params.get("timeout_seconds", config.get("timeout_seconds", 120)),
                120,
            ),
            packet_capture_driver=str(
                params.get("packet_capture_driver")
                or config.get("packet_capture_driver")
                or "auto"
            ),
        )

    def validate(self, *, require_guest: bool = False) -> list[str]:
        missing = []
        if not self.vmrun_path:
            missing.append("vmware.vmrun_path")
        if not self.vmx_path:
            missing.append("vmware.vmx_path")
        if not self.vm_password:
            missing.append("vmware.vm_password")
        if require_guest and not self.guest_user:
            missing.append("vmware.guest_user")
        if require_guest and not self.guest_password:
            missing.append("vmware.guest_password")
        return missing

    def guest_tool_candidates(self, tool_name: str) -> list[str]:
        root = self.guest_tools_dir.rstrip("\\/")
        candidates: dict[str, list[str]] = {
            "python": [
                rf"{root}\Python313\python.exe",
                rf"{root}\Python312\python.exe",
                rf"{root}\Python311\python.exe",
                rf"{root}\Python\python.exe",
            ],
            "tshark": [
                rf"{root}\Wireshark\tshark.exe",
                r"C:\Program Files\Wireshark\tshark.exe",
                r"C:\Program Files (x86)\Wireshark\tshark.exe",
            ],
            "procmon": [
                rf"{root}\procmon\Procmon64.exe",
                rf"{root}\ProcessMonitor\Procmon64.exe",
                rf"{root}\Procmon\Procmon64.exe",
                rf"{root}\Sysinternals\Procmon64.exe",
                rf"{root}\Procmon64.exe",
            ],
            "noriben": [
                rf"{root}\noriben\Noriben-main\Noriben.py",
                rf"{root}\noriben\Noriben.py",
                rf"{root}\Noriben\Noriben-main\Noriben.py",
                rf"{root}\Noriben\Noriben.py",
            ],
            "sysmon": [
                rf"{root}\Sysmon\Sysmon64.exe",
                rf"{root}\Sysmon64.exe",
            ],
            "hayabusa": [
                rf"{root}\hayabusa\hayabusa.exe",
                rf"{root}\Hayabusa\hayabusa.exe",
            ],
            "chainsaw": [
                rf"{root}\chainsaw\chainsaw.exe",
                rf"{root}\Chainsaw\chainsaw.exe",
            ],
            "chainsaw_mapping": [
                rf"{root}\chainsaw\chainsaw\mappings\sigma-event-logs-all.yml",
                rf"{root}\chainsaw\mappings\sigma-event-logs-all.yml",
            ],
            "sigma_rules": [
                rf"{root}\sigma\sigma-master\rules\windows",
                rf"{root}\sigma\sigma-main\rules\windows",
                rf"{root}\sigma\rules\windows",
            ],
            "deepbluecli": [
                rf"{root}\deepbluecli\DeepBlue.ps1",
                rf"{root}\DeepBlueCLI\DeepBlue.ps1",
            ],
            "pe_sieve": [
                rf"{root}\pe-sieve\pe-sieve64.exe",
                rf"{root}\pe_sieve\pe-sieve64.exe",
            ],
            "hollowshunter": [
                rf"{root}\hollows_hunter\hollows_hunter64.exe",
                rf"{root}\hollows_hunter64.exe",
            ],
        }
        return candidates.get(tool_name, [])


class VmrunClient:
    def __init__(self, config: VmwareConfig) -> None:
        self.config = config

    def host_command(self, *args: str, timeout: int | None = None) -> subprocess.CompletedProcess:
        return self._run(
            [
                self.config.vmrun_path,
                "-T",
                "ws",
                "-vp",
                self.config.vm_password,
                *args,
            ],
            timeout=timeout,
        )

    def guest_command(self, *args: str, timeout: int | None = None) -> subprocess.CompletedProcess:
        return self._run(
            [
                self.config.vmrun_path,
                "-T",
                "ws",
                "-vp",
                self.config.vm_password,
                "-gu",
                self.config.guest_user,
                "-gp",
                self.config.guest_password,
                *args,
            ],
            timeout=timeout,
        )

    def is_running(self, timeout: int | None = None) -> bool:
        expected = _normalize_vm_path(self.config.vmx_path)
        return any(
            _normalize_vm_path(line) == expected
            for line in self.list_running_vms(timeout=timeout or 30)
        )

    def list_snapshots(self) -> list[str]:
        snapshots: list[str] = []
        try:
            completed = self.host_command("listSnapshots", self.config.vmx_path)
            snapshots = [
                line.strip()
                for line in (completed.stdout or "").splitlines()
                if line.strip() and not line.lower().startswith("total snapshots:")
            ]
        except RuntimeError:
            snapshots = []
        if snapshots:
            return snapshots
        metadata = read_vmsd_snapshot_metadata(self.config.vmx_path)
        return [
            str(item.get("display_name") or "")
            for item in metadata.get("snapshots", [])
            if item.get("display_name")
        ]

    def snapshot_metadata(self) -> dict[str, Any]:
        return read_vmsd_snapshot_metadata(self.config.vmx_path)

    def current_snapshot_name(self) -> str:
        metadata = self.snapshot_metadata()
        current_uid = str(metadata.get("current_uid") or "")
        for item in metadata.get("snapshots", []):
            if str(item.get("uid") or "") == current_uid:
                return str(item.get("display_name") or "")
        return ""

    def snapshot_exists(self, snapshot: str) -> bool:
        target = str(snapshot)
        return any(name == target for name in self.list_snapshots())

    def list_running_vms(self, timeout: int | None = None) -> list[str]:
        completed = self.host_command("list", timeout=timeout or 30)
        return [
            line.strip()
            for line in (completed.stdout or "").splitlines()
            if line.strip() and not line.lower().startswith("total running vms:")
        ]

    def tools_state(self, timeout: int | None = None) -> str:
        completed = self.host_command("checkToolsState", self.config.vmx_path, timeout=timeout)
        return (completed.stdout or "").strip() or "unknown"

    def start(self, mode: str = "gui", timeout: int | None = None) -> None:
        self.host_command("start", self.config.vmx_path, mode, timeout=timeout or 90)

    def stop(self, mode: str = "soft") -> None:
        self.host_command("stop", self.config.vmx_path, mode, timeout=90)

    def wait_for_running_tools(self, timeout_seconds: int = 120) -> str:
        deadline = time.monotonic() + max(1, timeout_seconds)
        state = "unknown"
        while time.monotonic() < deadline:
            remaining = _remaining_seconds(deadline)
            if remaining <= 0:
                break
            if not self.is_running(timeout=min(30, remaining)):
                try:
                    self.start("gui", timeout=min(90, _remaining_seconds(deadline)))
                except RuntimeError:
                    pass
            try:
                state = self.tools_state(timeout=min(30, _remaining_seconds(deadline)))
                if state == "running":
                    return state
            except RuntimeError:
                pass
            time.sleep(3)
        return state

    def create_guest_dir(self, path: str, timeout: int | None = None) -> None:
        self.guest_command("createDirectoryInGuest", self.config.vmx_path, path, timeout=timeout)

    def copy_to_guest(self, host_path: str, guest_path: str, timeout: int | None = None) -> None:
        if not Path(host_path).is_file():
            raise RuntimeError(f"host sample does not exist: {host_path}")
        self.guest_command(
            "copyFileFromHostToGuest",
            self.config.vmx_path,
            host_path,
            guest_path,
            timeout=timeout or self.config.timeout_seconds,
        )

    def upload_file_via_guest_powershell(
        self,
        host_path: str,
        guest_path: str,
        timeout: int | None = None,
        *,
        chunk_size: int = 8000,
    ) -> dict[str, Any]:
        path = Path(host_path)
        if not path.is_file():
            raise RuntimeError(f"host sample does not exist: {host_path}")
        timeout_value = max(1, int(timeout or self.config.timeout_seconds))
        deadline = time.monotonic() + timeout_value
        encoded = base64.b64encode(path.read_bytes()).decode("ascii")
        chunks = [
            encoded[index : index + max(1024, chunk_size)]
            for index in range(0, len(encoded), max(1024, chunk_size))
        ]
        b64_guest_path = f"{guest_path}.b64"
        self._run_guest_powershell(
            (
                f"Remove-Item -LiteralPath {_ps_quote(b64_guest_path)} -Force "
                "-ErrorAction SilentlyContinue; "
                f"Remove-Item -LiteralPath {_ps_quote(guest_path)} -Force "
                "-ErrorAction SilentlyContinue; "
                f"New-Item -ItemType File -Path {_ps_quote(b64_guest_path)} "
                "-Force | Out-Null"
            ),
            timeout=_remaining_seconds(deadline),
        )
        for chunk in chunks:
            self._run_guest_powershell(
                (
                    f"Add-Content -LiteralPath {_ps_quote(b64_guest_path)} "
                    f"-Value {_ps_quote(chunk)} -Encoding ASCII"
                ),
                timeout=_remaining_seconds(deadline),
            )
        self._run_guest_powershell(
            (
                f"$b64 = Get-Content -LiteralPath {_ps_quote(b64_guest_path)} -Raw; "
                f"[IO.File]::WriteAllBytes({_ps_quote(guest_path)}, "
                "[Convert]::FromBase64String($b64)); "
                f"Remove-Item -LiteralPath {_ps_quote(b64_guest_path)} -Force "
                "-ErrorAction SilentlyContinue"
            ),
            timeout=_remaining_seconds(deadline),
        )
        return {
            "method": "guest_powershell_base64_chunks",
            "chunks": len(chunks),
            "chunk_size": max(1024, chunk_size),
            "encoded_size": len(encoded),
        }

    def file_exists_in_guest(self, guest_path: str, timeout: int | None = None) -> bool:
        try:
            self.guest_command(
                "fileExistsInGuest",
                self.config.vmx_path,
                guest_path,
                timeout=timeout or self.config.timeout_seconds,
            )
        except RuntimeError:
            return False
        return True

    def directory_exists_in_guest(self, guest_path: str, timeout: int | None = None) -> bool:
        try:
            self.guest_command(
                "directoryExistsInGuest",
                self.config.vmx_path,
                guest_path,
                timeout=timeout or self.config.timeout_seconds,
            )
        except RuntimeError:
            return False
        return True

    def copy_from_guest(self, guest_path: str, host_path: str) -> None:
        self.guest_command(
            "copyFileFromGuestToHost",
            self.config.vmx_path,
            guest_path,
            host_path,
            timeout=self.config.timeout_seconds,
        )

    def run_guest_program(
        self,
        program: str,
        program_args: str = "",
        *,
        no_wait: bool = False,
        timeout: int | None = None,
    ) -> None:
        args = ["runProgramInGuest", self.config.vmx_path]
        if no_wait:
            args.append("-noWait")
        args.append(program)
        if program_args:
            args.append(program_args)
        self.guest_command(*args, timeout=timeout or self.config.timeout_seconds)

    def _run_guest_powershell(self, script: str, timeout: int | None = None) -> None:
        self.run_guest_powershell(script, timeout=timeout)

    def run_guest_powershell(self, script: str, timeout: int | None = None) -> None:
        self._run_guest_powershell_command(script, timeout=timeout)

    def capture_guest_powershell(self, script: str, timeout: int | None = None) -> subprocess.CompletedProcess:
        return self._run_guest_powershell_command(script, timeout=timeout)

    def _run_guest_powershell_command(self, script: str, timeout: int | None = None) -> subprocess.CompletedProcess:
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        return self.guest_command(
            "runProgramInGuest",
            self.config.vmx_path,
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            f"-NoProfile -ExecutionPolicy Bypass -EncodedCommand {encoded}",
            timeout=timeout or self.config.timeout_seconds,
        )

    def _run(self, args: list[str], timeout: int | None = None) -> subprocess.CompletedProcess:
        timeout_value = max(1, int(timeout or self.config.timeout_seconds))
        try:
            completed = _run_vmrun_process(args, timeout=timeout_value)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"vmrun timed out after {timeout_value}s: {_safe_command_label(args)}"
            ) from exc
        except OSError as exc:
            raise RuntimeError(str(exc)) from exc
        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "").strip()
            raise RuntimeError(message or f"vmrun exited with code {completed.returncode}")
        return completed


def _remaining_seconds(deadline: float) -> int:
    return max(1, int(deadline - time.monotonic()))


def _ps_quote(value: str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def config_error(function_id: str, result_key: str, missing: list[str]) -> FunctionResult:
    return FunctionResult(
        function_id=function_id,
        result_key=result_key,
        status="error",
        error={
            "code": "missing_vmware_config",
            "message": "VMware configuration is incomplete",
            "missing": missing,
        },
    )


def preflight_blocked_result(
    context: dict[str, Any],
    function_id: str,
    result_key: str,
) -> FunctionResult | None:
    preflight = context.get("results", {}).get("dynamic_vm_preflight")
    if not isinstance(preflight, dict):
        return None
    data = preflight.get("data", {})
    if not isinstance(data, dict):
        data = {}
    if preflight.get("status") == "success" and data.get("ready") is True:
        return None
    return FunctionResult(
        function_id=function_id,
        result_key=result_key,
        status="skipped",
        data={
            "skipped": True,
            "skip_reason": "dynamic_vm_preflight_not_ready",
            "preflight_status": str(preflight.get("status") or ""),
            "missing_config_fields": list(data.get("missing_config_fields") or []),
            "invalid_path_fields": list(data.get("invalid_path_fields") or []),
            "requires_human_confirmation": False,
            "limitations": [
                "Dynamic VMware step skipped because dynamic.vm_preflight did not pass.",
            ],
        },
    )


def operation_error(
    function_id: str,
    result_key: str,
    code: str,
    message: str,
    data: dict[str, Any] | None = None,
) -> FunctionResult:
    return FunctionResult(
        function_id=function_id,
        result_key=result_key,
        status="error",
        data=data or {},
        error={"code": code, "message": sanitize_error(message)},
    )


def sanitize_error(message: str) -> str:
    text = str(message)
    for marker in ["-vp", "-gp"]:
        if marker in text:
            return "vmrun command failed"
    return text[:1000]


def safe_guest_filename(filename: str) -> str:
    name = Path(filename).name
    safe = "".join(char if char.isalnum() or char in {"_", "-", "."} else "_" for char in name)
    return safe or "sample.bin"


def join_guest_path(parent: str, child: str) -> str:
    return parent.rstrip("\\/") + "\\" + child.lstrip("\\/")


def session_like_id(context: dict[str, Any]) -> str:
    sample_path = Path(str(context.get("sample_path", "")))
    parts = sample_path.parts
    if "sessions" in parts:
        index = parts.index("sessions")
        if index + 1 < len(parts):
            return safe_guest_filename(parts[index + 1])
    return uuid.uuid4().hex


def host_output_path(config: VmwareConfig, context: dict[str, Any], filename: str) -> Path:
    root = Path(config.host_output_dir)
    if not root.is_absolute():
        root = Path.cwd() / root
    path = root / session_like_id(context) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def load_telemetry_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return data if isinstance(data, dict) else {}


def create_export_batch(
    host_path: Path,
    config: VmwareConfig,
    last_minutes: int,
    max_events: int = 5000,
    *,
    start_time_utc: str = "",
    end_time_utc: str = "",
    sample_path: str = "",
    sample_filename: str = "",
) -> None:
    guest_telemetry = join_guest_path(config.guest_telemetry_dir, "dynamic_telemetry.json")
    guest_log = join_guest_path(config.guest_telemetry_dir, "export.log")
    script = (
        "@echo off\r\n"
        "setlocal\r\n"
        f"mkdir \"{config.guest_telemetry_dir}\" 2>nul\r\n"
        "powershell.exe -NoProfile -ExecutionPolicy Bypass "
        f"-File \"{config.telemetry_script_path}\" "
        f"-LastMinutes {max(1, last_minutes)} "
        f"-MaxEvents {max(1, max_events)} "
        f"-OutFile \"{guest_telemetry}\" "
        f"{'-StartTimeUtc ' + _cmd_quote(start_time_utc) + ' ' if start_time_utc else ''}"
        f"{'-EndTimeUtc ' + _cmd_quote(end_time_utc) + ' ' if end_time_utc else ''}"
        f"{'-SamplePath ' + _cmd_quote(sample_path) + ' ' if sample_path else ''}"
        f"{'-SampleFilename ' + _cmd_quote(sample_filename) + ' ' if sample_filename else ''}"
        f"> \"{guest_log}\" 2>&1\r\n"
        "exit /b %errorlevel%\r\n"
    )
    host_path.parent.mkdir(parents=True, exist_ok=True)
    host_path.write_text(script, encoding="ascii")


def _cmd_quote(value: str) -> str:
    return '"' + str(value).replace('"', r'\"') + '"'


def create_cleanup_batch(host_path: Path, guest_sample_path: str) -> None:
    script = (
        "@echo off\r\n"
        "setlocal\r\n"
        f"del /f /q \"{guest_sample_path}\" >nul 2>nul\r\n"
        "exit /b 0\r\n"
    )
    host_path.parent.mkdir(parents=True, exist_ok=True)
    host_path.write_text(script, encoding="ascii")


def copy_module_export_script_if_available(config: VmwareConfig, client: VmrunClient) -> None:
    candidates = [
        Path("data/vm_dynamic/Export-DynamicTelemetry.ps1"),
        Path("data/vm_dynamic/win10_tool_migration/Export-DynamicTelemetry.ps1"),
        Path("D:/vmware/win10_tools/Export-DynamicTelemetry.ps1"),
        Path("D:/vmware/win11_tools/Export-DynamicTelemetry.ps1"),
    ]
    for source in candidates:
        if not source.is_file():
            continue
        try:
            client.copy_to_guest(str(source), config.telemetry_script_path)
            return
        except RuntimeError:
            pass
    if client.file_exists_in_guest(config.telemetry_script_path, timeout=min(30, config.timeout_seconds)):
        return


def ensure_host_sample_exists(sample_path: str) -> Path:
    path = Path(sample_path)
    candidates = [path]
    if not path.is_absolute():
        candidates.append(Path.cwd() / path)
        candidates.append(PROJECT_ROOT / path)
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError(sample_path)


def copy_tree_file_if_exists(source: Path, destination: Path) -> bool:
    if not source.is_file():
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    return True


def _int_value(value: Any, default: int) -> int:
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def _safe_command_label(args: list[str]) -> str:
    for command in (
        "list",
        "checkToolsState",
        "start",
        "stop",
        "createDirectoryInGuest",
        "copyFileFromHostToGuest",
        "copyFileFromGuestToHost",
        "runProgramInGuest",
        "fileExistsInGuest",
        "directoryExistsInGuest",
    ):
        if command in args:
            return command
    return "vmrun"


def _normalize_vm_path(value: str) -> str:
    value = str(value or "").strip().strip('"')
    if not value:
        return ""
    return ntpath.normcase(ntpath.normpath(value))


def read_vmsd_snapshot_metadata(vmx_path: str) -> dict[str, Any]:
    path = Path(str(vmx_path or ""))
    if path.suffix.lower() == ".vmx":
        vmsd = path.with_suffix(".vmsd")
    else:
        vmsd = path
    if not vmsd.is_file():
        return {"path": str(vmsd), "snapshots": [], "current_uid": "", "num_snapshots": 0}
    data = vmsd.read_bytes()
    text = _decode_vmware_text(data)
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"')
    snapshots: dict[str, dict[str, Any]] = {}
    for key, value in values.items():
        if not key.startswith("snapshot") or "." not in key:
            continue
        prefix, field = key.split(".", 1)
        if not prefix[len("snapshot") :].isdigit():
            continue
        entry = snapshots.setdefault(prefix, {})
        if field == "displayName":
            entry["display_name"] = value
        else:
            entry[field] = value
    ordered = [
        {"index": key[len("snapshot") :], **item}
        for key, item in sorted(snapshots.items(), key=lambda pair: int(pair[0][len("snapshot") :]))
    ]
    return {
        "path": str(vmsd),
        "snapshots": ordered,
        "current_uid": values.get("snapshot.current", ""),
        "num_snapshots": _int_value(values.get("snapshot.numSnapshots"), len(ordered)),
        "last_uid": values.get("snapshot.lastUID", ""),
    }


def _decode_vmware_text(data: bytes) -> str:
    encodings = [
        "utf-8-sig",
        locale.getpreferredencoding(False) or "",
        "gbk",
        "gb2312",
        "mbcs",
    ]
    for encoding in dict.fromkeys(item for item in encodings if item):
        try:
            return data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


def _kill_process_tree(pid: int) -> None:
    if pid <= 0:
        return
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def _run_vmrun_process(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess:
    timeout_value = max(1, int(kwargs.get("timeout", 1)))
    creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=creationflags,
        )
        stdout, stderr = process.communicate(timeout=timeout_value)
    except subprocess.TimeoutExpired:
        if process is not None:
            _kill_process_tree(process.pid)
        raise
    return subprocess.CompletedProcess(
        args,
        process.returncode if process is not None else 1,
        stdout,
        stderr,
    )
