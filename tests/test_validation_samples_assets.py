import json
import zipfile
from pathlib import Path

import pytest

from security_function_platform.module_system import ModuleStore

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVERSE_ROOT = PROJECT_ROOT / "modules" / "reverse"
CONFIG_ROOT = REVERSE_ROOT / "config_files"
SAMPLES_ROOT = CONFIG_ROOT / "validation_samples"

requires_reverse_module = pytest.mark.skipif(
    not (REVERSE_ROOT / "module.json").is_file(),
    reason="reverse module is not included in this platform-only checkout",
)


def load_json(relative_path: str) -> dict:
    return json.loads((REVERSE_ROOT / relative_path).read_text(encoding="utf-8"))


@requires_reverse_module
def test_validation_samples_manifest_references_existing_files() -> None:
    manifest = load_json("config_files/validation_samples/samples_manifest.json")

    assert manifest["default_safety"]["execute_by_default"] is False
    assert manifest["default_safety"]["requires_isolated_vm"] is True
    assert manifest["default_safety"]["cleanup_supported"] is True

    sample_ids = set()
    for sample in manifest["samples"]:
        sample_ids.add(sample["sample_id"])
        path = Path(sample["path"])
        assert not path.is_absolute()
        assert ".." not in path.parts
        assert (SAMPLES_ROOT / path).is_file()
        assert sample["behavior_category"]
        assert sample["expected_dynamic_events"]
        assert sample["safety_notes"]

    assert {
        "command_execution_fixture",
        "file_write_fixture",
        "registry_run_key_fixture",
        "network_connect_fixture",
        "scheduled_task_fixture",
    } <= sample_ids


@requires_reverse_module
def test_attack_knowledge_and_scenarios_reference_known_validation_samples() -> None:
    manifest = load_json("config_files/validation_samples/samples_manifest.json")
    attack = load_json("knowledge/attack/techniques.json")
    scenarios = load_json("config_files/validation/validation_scenarios.json")
    sample_ids = {item["sample_id"] for item in manifest["samples"]}

    for technique in attack["techniques"]:
        for sample_id in technique.get("validation_samples", []):
            assert sample_id in sample_ids

    for scenario in scenarios["scenarios"]:
        for sample_id in scenario.get("validation_samples", []):
            assert sample_id in sample_ids


@requires_reverse_module
def test_reverse_module_package_includes_validation_sample_scripts(tmp_path) -> None:
    store = ModuleStore(
        "modules",
        tmp_path / "loaded_modules.json",
        tmp_path / "installed",
        tmp_path / "packages",
    )

    packaged = store.package_module("reverse")

    with zipfile.ZipFile(packaged["archive"]) as archive:
        names = set(archive.namelist())

    assert "reverse/config_files/validation_samples/samples_manifest.json" in names
    assert "reverse/config_files/validation_samples/command_execution_fixture.ps1" in names
    assert "reverse/config_files/validation_samples/registry_run_key_fixture.ps1" in names
