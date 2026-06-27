import json
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
    assert module_actions["interactive_actions_count"] >= 1
    assert "reverse.basic_identify" in {
        item["id"] for item in module_actions["interactive_actions"]
    }
    preview = client.post(
        "/api/modules/reverse/actions/preview",
        json={"action_id": "reverse.basic_identify"},
    ).json()
    assert preview["ready"] is True
    assert preview["execution_plan"]["nodes"]
    assert preview["validation_errors"] == []


@requires_reverse_module
def test_run_action_returns_execution_plan(tmp_path, monkeypatch) -> None:
    module_store = ModuleStore(
        "modules",
        tmp_path / "data" / "modules" / "loaded_modules.json",
        tmp_path / "data" / "modules_installed",
        tmp_path / "data" / "module_packages",
    )
    monkeypatch.setattr(main, "module_store", module_store)
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"MZ hello http://example.test/a")},
    ).json()

    response = client.post(
        f"/api/sessions/{session['session_id']}/actions/run",
        json={"module_id": "reverse", "action_id": "reverse.basic_identify"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["execution_plan"]["plan_name"] == "reverse.basic_identify"
    assert body["execution_plan"]["order"]
    assert body["execution_status"]["status"] == "completed"
    assert body["execution_status"]["completed_steps"]
    assert body["raw_output_items"]
    assert body["summary"]["functions_run"] >= 1

    status = client.get(f"/api/sessions/{session['session_id']}/execution-status")
    assert status.status_code == 200
    assert status.json()["status"] == "completed"


def test_action_approvals_are_injected_into_step_params() -> None:
    action = {
        "id": "dynamic",
        "requires_approvals": ["confirm_restore", "confirm_execute"],
        "steps": [
            {
                "function_id": "dynamic.vm_restore_snapshot",
                "params": {"ready_snapshot": "snapshot"},
                "step_id": "restore",
            },
            {
                "function_id": "dynamic.vm_run_sample",
                "params": {"duration_seconds": 30},
                "step_id": "run",
            },
        ],
    }

    approved = main._approved_action_params(
        action,
        {
            "confirm_restore": "I_UNDERSTAND_RESTORE_VM_SNAPSHOT",
            "confirm_execute": "I_UNDERSTAND_RUN_SAMPLE_IN_VM",
        },
        {},
    )
    workflow = main._workflow_from_action(
        action,
        {"restore": {"confirm_restore": "OVERRIDE"}},
        approved,
    )

    assert workflow.steps[0].params["ready_snapshot"] == "snapshot"
    assert workflow.steps[0].params["confirm_restore"] == "OVERRIDE"
    assert workflow.steps[0].params["confirm_execute"] == "I_UNDERSTAND_RUN_SAMPLE_IN_VM"
    assert workflow.steps[1].params["confirm_restore"] == "I_UNDERSTAND_RESTORE_VM_SNAPSHOT"
    assert workflow.steps[1].params["confirm_execute"] == "I_UNDERSTAND_RUN_SAMPLE_IN_VM"


def test_malware_main_flows_export_runner_plans(tmp_path, monkeypatch) -> None:
    module_store = ModuleStore(
        "modules",
        tmp_path / "data" / "modules" / "loaded_modules.json",
        tmp_path / "data" / "modules_installed",
        tmp_path / "data" / "module_packages",
    )
    monkeypatch.setattr(main, "module_store", module_store)
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)

    flows_response = client.get("/api/modules/malware_analysis/runner/flows")
    assert flows_response.status_code == 200
    flows = flows_response.json()
    assert flows["schema_id"] == "security_function_platform.module_runner_flows.v1"
    assert flows["flows_count"] == 2
    assert flows["runner_ready_count"] == 2
    assert [flow["flow_id"] for flow in flows["flows"]] == [
        "interactive_single_sample_full",
        "interactive_multi_sample_full",
    ]

    removed_preview = client.post(
        "/api/modules/malware_analysis/runner/flows/preview",
        json={"flow_id": "interactive_single_sample_static"},
    )
    assert removed_preview.status_code == 404

    full_preview = client.post(
        "/api/modules/malware_analysis/runner/flows/preview",
        json={
            "flow_id": "interactive_single_sample_full",
            "params": {
                "dynamic_action_id": "malware.dynamic_quick_run",
                "confirm_restore": "I_UNDERSTAND_RESTORE_VM_SNAPSHOT",
                "confirm_execute": "I_UNDERSTAND_RUN_SAMPLE_IN_VM",
            },
        },
    )
    assert full_preview.status_code == 200
    full_body = full_preview.json()
    assert "malware.dynamic_quick_run" in full_body["runner_plan"]["source"]["action_ids"]
    vm_nodes = [
        node
        for node in full_body["runner_plan"]["plan"]["nodes"]
        if node["function_id"].startswith(("dynamic.vm_", "malware.vm_"))
    ]
    assert vm_nodes
    assert all(node["resource_locks"] == ["vm:default"] for node in vm_nodes)
    restore_nodes = [
        node
        for node in full_body["runner_plan"]["plan"]["nodes"]
        if node["function_id"] == "dynamic.vm_restore_snapshot"
    ]
    run_nodes = [
        node
        for node in full_body["runner_plan"]["plan"]["nodes"]
        if node["function_id"] == "dynamic.vm_run_sample"
    ]
    assert restore_nodes
    assert run_nodes
    assert restore_nodes[0]["params"]["confirm_restore"] == (
        "I_UNDERSTAND_RESTORE_VM_SNAPSHOT"
    )
    assert run_nodes[0]["params"]["confirm_execute"] == "I_UNDERSTAND_RUN_SAMPLE_IN_VM"

    multi_preview = client.post(
        "/api/modules/malware_analysis/runner/flows/preview",
        json={
            "flow_id": "interactive_multi_sample_full",
            "params": {
                "dynamic_action_id": "malware.dynamic_quick_run",
                "confirm_restore": "I_UNDERSTAND_RESTORE_VM_SNAPSHOT",
                "confirm_execute": "I_UNDERSTAND_RUN_SAMPLE_IN_VM",
            },
        },
    )
    assert multi_preview.status_code == 200
    multi_body = multi_preview.json()
    assert multi_body["runner_plan"]["scope"] == "batch"
    assert multi_body["runner_plan"]["source"]["type"] == "action_sequence"
    assert "malware.dynamic_quick_run" in multi_body["runner_plan"]["source"]["action_ids"]
    assert multi_body["runner_plan"]["plan"]["total_nodes"] == full_body["runner_plan"]["plan"]["total_nodes"]


def test_malware_report_action_uses_knowledge_lookup() -> None:
    actions = json.loads(
        (PROJECT_ROOT / "modules" / "malware_analysis" / "actions" / "actions.json").read_text(encoding="utf-8")
    )
    generate_report = next(item for item in actions if item["id"] == "malware.generate_report")
    collection_package = next(item for item in actions if item["id"] == "malware.collection_package_build")

    assert "malware.knowledge_lookup" in generate_report["allowed_next_actions"]
    assert "malware.knowledge_lookup" in collection_package["allowed_next_actions"]
    assert "malware.knowledge_lookup" in generate_report["prompt"]
    assert "knowledge_assets.next_analysis_actions" in generate_report["prompt"]


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
