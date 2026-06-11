import json
import subprocess
import sys
from pathlib import Path

import pytest


FUNCTIONS_DIR = Path(__file__).resolve().parents[1] / "modules" / "reverse" / "functions"
if not FUNCTIONS_DIR.is_dir():
    pytest.skip(
        "reverse module is not included in this platform-only checkout",
        allow_module_level=True,
    )
if str(FUNCTIONS_DIR) not in sys.path:
    sys.path.insert(0, str(FUNCTIONS_DIR))

import vmware_dynamic  # noqa: E402
from dynamic_vm_validate_behavior import (  # noqa: E402
    FOCUSED_EXECUTE_CONFIRMATION,
    DynamicVmValidateBehaviorFunction,
)
from validation_plan_focused_dynamic import ValidationPlanFocusedDynamicFunction  # noqa: E402


def _comparison_context():
    return {
        "results": {
            "static_dynamic_validation": {
                "function_id": "validation.compare_static_dynamic",
                "result_key": "static_dynamic_validation",
                "status": "success",
                "data": {
                    "comparisons": [
                        {
                            "category": "command_execution",
                            "consistency": "matched",
                            "static_confidence": "medium",
                            "static_score": 3,
                        },
                        {
                            "category": "registry_persistence",
                            "consistency": "static_candidate_not_observed",
                            "static_confidence": "low",
                            "static_score": 1,
                        },
                    ]
                },
                "error": None,
            }
        }
    }


def _vm_context(tmp_path):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ")
    context = {
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
    context["results"]["focused_dynamic_validation_plan"] = (
        ValidationPlanFocusedDynamicFunction().run(_comparison_context(), {}).to_dict()
    )
    return context


def test_focused_dynamic_plan_selects_static_not_observed_behavior() -> None:
    result = ValidationPlanFocusedDynamicFunction().run(_comparison_context(), {})

    assert result.status == "success"
    assert result.result_key == "focused_dynamic_validation_plan"
    assert result.data["counts"]["targets"] == 1
    target = result.data["targets"][0]
    assert target["behavior_category"] == "registry_persistence"
    assert target["status"] == "ready"
    assert target["validation_sample_id"] == "registry_run_key_fixture"


def test_focused_dynamic_validation_requires_confirmation(tmp_path, monkeypatch) -> None:
    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args[0], 0, "", "")

    monkeypatch.setattr(vmware_dynamic.subprocess, "run", fake_run)

    result = DynamicVmValidateBehaviorFunction().run(_vm_context(tmp_path), {})

    assert result.status == "error"
    assert result.error["code"] == "execution_not_confirmed"
    assert calls == []


def test_focused_dynamic_validation_runs_fixture_and_maps_target(tmp_path, monkeypatch) -> None:
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[-1] == "list":
            return subprocess.CompletedProcess(args, 0, "guest.vmx\n", "")
        if "checkToolsState" in args:
            return subprocess.CompletedProcess(args, 0, "running\n", "")
        if "CopyFileFromGuestToHost" in args and args[-2].endswith("dynamic_telemetry.json"):
            Path(args[-1]).write_text(
                json.dumps(
                    {
                        "schema_version": "1",
                        "telemetry_id": "focused-test",
                        "registry_events": [
                            {
                                "event_id": "evt-reg",
                                "event_type": "registry_set",
                                "process_name": "powershell.exe",
                                "key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                                "value_name": "SFPValidationRunKey",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(vmware_dynamic.subprocess, "run", fake_run)
    monkeypatch.setattr("dynamic_vm_validate_behavior.time.sleep", lambda seconds: None)

    result = DynamicVmValidateBehaviorFunction().run(
        _vm_context(tmp_path),
        {
            "confirm_execute": FOCUSED_EXECUTE_CONFIRMATION,
            "duration_seconds": 1,
            "last_minutes": 5,
        },
    )

    assert result.status == "success"
    assert result.result_key == "focused_dynamic_validation"
    assert result.data["target"]["behavior_category"] == "registry_persistence"
    assert result.data["observed"] is True
    assert result.data["matched_behavior"]["category"] == "registry_persistence"
    assert any("CopyFileFromHostToGuest" in call for call in calls)
    assert any("runProgramInGuest" in call for call in calls)
