import json
import sys
from pathlib import Path

import pytest

import subprocess


FUNCTIONS_DIR = Path(__file__).resolve().parents[1] / "modules" / "reverse" / "functions"
if not FUNCTIONS_DIR.is_dir():
    pytest.skip(
        "reverse module is not included in this platform-only checkout",
        allow_module_level=True,
    )
if str(FUNCTIONS_DIR) not in sys.path:
    sys.path.insert(0, str(FUNCTIONS_DIR))

import vmware_dynamic  # noqa: E402
from dynamic_vm_collect_sysmon import DynamicVmCollectSysmonFunction  # noqa: E402
from dynamic_vm_run_sample import DynamicVmRunSampleFunction  # noqa: E402
from dynamic_vm_upload_sample import DynamicVmUploadSampleFunction  # noqa: E402
from vmware_dynamic import EXECUTE_CONFIRMATION  # noqa: E402


def _context(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ test")
    return {
        "sample_path": str(sample),
        "filename": "sample.exe",
        "results": {},
        "config": {
            "vmware": {
                "vmrun_path": "vmrun.exe",
                "vmx_path": "guest.vmx",
                "vm_password": "secret-vm",
                "guest_user": "user",
                "guest_password": "secret-guest",
                "host_output_dir": str(tmp_path / "vm_output"),
                "timeout_seconds": 1,
            }
        },
    }


def test_vm_run_sample_requires_explicit_confirmation(tmp_path, monkeypatch) -> None:
    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args[0], 0, "", "")

    monkeypatch.setattr(vmware_dynamic.subprocess, "run", fake_run)

    result = DynamicVmRunSampleFunction().run(_context(tmp_path), {})

    assert result.status == "error"
    assert result.error["code"] == "execution_not_confirmed"
    assert calls == []


def test_vm_upload_sample_builds_guest_copy_commands(tmp_path, monkeypatch) -> None:
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[-1] == "list":
            return subprocess.CompletedProcess(args, 0, "guest.vmx\n", "")
        if "checkToolsState" in args:
            return subprocess.CompletedProcess(args, 0, "running\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(vmware_dynamic.subprocess, "run", fake_run)

    result = DynamicVmUploadSampleFunction().run(_context(tmp_path), {})

    assert result.status == "success"
    assert result.result_key == "dynamic_vm_upload"
    assert result.data["guest_sample_path"].endswith(r"\sample.exe")
    assert any("createDirectoryInGuest" in call for call in calls)
    assert any("CopyFileFromHostToGuest" in call for call in calls)


def test_vm_collect_sysmon_copies_and_parses_telemetry(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path)
    context["results"]["dynamic_vm_upload"] = {
        "data": {"guest_sample_path": r"C:\Samples\sample.exe"}
    }

    def fake_run(args, **kwargs):
        if args[-1] == "list":
            return subprocess.CompletedProcess(args, 0, "guest.vmx\n", "")
        if "checkToolsState" in args:
            return subprocess.CompletedProcess(args, 0, "running\n", "")
        if "CopyFileFromGuestToHost" in args and args[-2].endswith("dynamic_telemetry.json"):
            Path(args[-1]).write_text(
                json.dumps(
                    {
                        "schema_version": "1",
                        "telemetry_id": "unit-test",
                        "process_events": [
                            {
                                "event_id": "evt-1",
                                "event_type": "process_create",
                                "process_name": "sample.exe",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
        if "CopyFileFromGuestToHost" in args and args[-2].endswith("export.log"):
            Path(args[-1]).write_text("ok", encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(vmware_dynamic.subprocess, "run", fake_run)

    result = DynamicVmCollectSysmonFunction().run(context, {"last_minutes": 5})

    assert result.status == "success"
    assert result.result_key == "dynamic_telemetry"
    assert result.data["telemetry_id"] == "unit-test"
    assert result.data["process_events"][0]["process_name"] == "sample.exe"


def test_vm_run_sample_confirmed_uses_guest_program(tmp_path, monkeypatch) -> None:
    calls = []
    context = _context(tmp_path)
    context["results"]["dynamic_vm_upload"] = {
        "data": {"guest_sample_path": r"C:\Samples\sample.exe"}
    }

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[-1] == "list":
            return subprocess.CompletedProcess(args, 0, "guest.vmx\n", "")
        if "checkToolsState" in args:
            return subprocess.CompletedProcess(args, 0, "running\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(vmware_dynamic.subprocess, "run", fake_run)
    monkeypatch.setattr("dynamic_vm_run_sample.time.sleep", lambda seconds: None)

    result = DynamicVmRunSampleFunction().run(
        context,
        {"confirm_execute": EXECUTE_CONFIRMATION, "duration_seconds": 1},
    )

    assert result.status == "success"
    assert result.data["execution_confirmed"] is True
    assert any("runProgramInGuest" in call and "-noWait" in call for call in calls)
