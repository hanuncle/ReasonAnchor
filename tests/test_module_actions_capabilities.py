from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from security_function_platform.api import main
from security_function_platform.api.module_capabilities import ModuleCapabilityCache
from security_function_platform.api.session_store import SessionStore
from security_function_platform.api.workflow_store import WorkflowStore
from security_function_platform.module_system import ModuleStore

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVERSE_MODULE = PROJECT_ROOT / "modules" / "reverse" / "module.json"
requires_reverse_module = pytest.mark.skipif(
    not REVERSE_MODULE.is_file(),
    reason="reverse module is not included in this platform-only checkout",
)


@requires_reverse_module
def test_platform_and_module_actions_are_exposed(tmp_path, monkeypatch) -> None:
    module_store = ModuleStore(
        "modules",
        tmp_path / "data" / "modules" / "loaded_modules.json",
        tmp_path / "data" / "modules_installed",
        tmp_path / "data" / "module_packages",
    )
    monkeypatch.setattr(main, "module_store", module_store)
    client = TestClient(main.app)

    platform_actions = client.get("/api/platform/actions").json()
    platform_ids = {item["id"] for item in platform_actions["actions"]}

    assert platform_actions["default_module_id"] == "reverse"
    assert "platform.select_module" in platform_ids
    assert "platform.create_module" in platform_ids
    assert "platform.export_module" in platform_ids

    module_actions = client.get("/api/modules/reverse/actions").json()
    action_ids = [item["id"] for item in module_actions["actions"]]

    assert module_actions["module_id"] == "reverse"
    assert action_ids[0] == "module.view_capabilities"
    assert "module.create_workflow" in action_ids
    assert "module.configure" in action_ids


@requires_reverse_module
def test_module_capabilities_are_generated_cached_and_refreshable(tmp_path, monkeypatch) -> None:
    module_store = ModuleStore(
        "modules",
        tmp_path / "data" / "modules" / "loaded_modules.json",
        tmp_path / "data" / "modules_installed",
        tmp_path / "data" / "module_packages",
    )
    monkeypatch.setattr(main, "module_store", module_store)
    monkeypatch.setattr(
        main,
        "workflow_store",
        WorkflowStore(tmp_path / "data" / "workflows" / "workflows.json"),
    )
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    monkeypatch.setattr(
        main,
        "capability_cache",
        ModuleCapabilityCache(tmp_path / "data" / "module_capabilities"),
    )
    client = TestClient(main.app)

    first = client.get("/api/modules/reverse/capabilities")
    assert first.status_code == 200
    first_data = first.json()
    cache_path = Path(first_data["cache"]["path"])

    assert first_data["schema_id"] == "module.capabilities.v1"
    assert first_data["module_id"] == "reverse"
    assert first_data["cache"]["hit"] is False
    assert cache_path.is_file()
    assert first_data["capability_summary"]["function_groups"]
    assert "module:reverse:reverse_auto_download_static_dynamic_focused" in {
        item["workflow_id"] for item in first_data["capability_summary"]["workflows"]
    }

    second_data = client.get("/api/modules/reverse/capabilities").json()
    assert second_data["cache"]["hit"] is True
    assert second_data["generated_from"]["source_hash"] == (
        first_data["generated_from"]["source_hash"]
    )

    refreshed = client.post("/api/modules/reverse/capabilities/refresh").json()
    assert refreshed["cache"]["hit"] is False
    assert refreshed["cache"]["refreshed"] is True
