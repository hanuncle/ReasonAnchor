import json

from fastapi.testclient import TestClient

from security_function_platform.api import main
from security_function_platform.api.session_store import SessionStore
from security_function_platform.api.workflow_store import WorkflowStore
from security_function_platform.core.workflow import WorkflowDefinition
from security_function_platform.module_system import ModuleStore


def test_workflow_template_api_lifecycle(tmp_path, monkeypatch) -> None:
    workflow_store = WorkflowStore(tmp_path / "data" / "workflows" / "workflows.json")
    session_store = SessionStore(tmp_path / "data" / "sessions")
    module_store = ModuleStore(
        "modules",
        tmp_path / "data" / "modules" / "loaded_modules.json",
    )
    monkeypatch.setattr(main, "workflow_store", workflow_store)
    monkeypatch.setattr(main, "store", session_store)
    monkeypatch.setattr(main, "module_store", module_store)
    client = TestClient(main.app)

    assert not [
        item
        for item in client.get("/api/workflows").json()["workflows"]
        if item.get("source") != "module"
    ]

    workflow = {
        "name": "basic_static",
        "steps": [
            {"function_id": "hash.compute", "params": {}},
            {"function_id": "file.type_detect", "params": {}},
            {"function_id": "strings.extract", "params": {"min_length": 4}},
        ],
    }
    save_response = client.post(
        "/api/workflows",
        json={
            "name": "basic_static",
            "workflow": workflow,
            "description": "Basic local static workflow.",
            "tags": ["basic", "static"],
            "risk": "low",
            "network": False,
            "config_required": False,
            "default_safe": True,
        },
    )
    assert save_response.status_code == 200
    saved = save_response.json()
    workflow_id = saved["workflow_id"]
    assert saved["workflow"] == workflow
    assert saved["description"] == "Basic local static workflow."
    assert saved["tags"] == ["basic", "static"]
    assert saved["risk"] == "low"
    assert saved["network"] is False
    assert saved["config_required"] is False
    assert saved["default_safe"] is True

    list_response = client.get("/api/workflows")
    assert list_response.status_code == 200
    listed = {
        item["workflow_id"]: item
        for item in list_response.json()["workflows"]
    }
    assert listed[workflow_id]["steps_count"] == 3
    assert listed[workflow_id]["default_safe"] is True
    assert listed[workflow_id]["tags"] == ["basic", "static"]

    get_response = client.get(f"/api/workflows/{workflow_id}")
    assert get_response.status_code == 200
    assert get_response.json()["workflow"] == workflow
    assert get_response.json()["description"] == "Basic local static workflow."

    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello")},
    ).json()
    apply_response = client.post(
        f"/api/sessions/{session['session_id']}/workflow-template",
        json={"workflow_id": workflow_id},
    )
    assert apply_response.status_code == 200
    assert apply_response.json()["workflow"] == workflow

    updated_workflow = {
        "name": "basic_static_updated",
        "steps": [
            {"function_id": "hash.compute", "params": {}},
            {"function_id": "file.type_detect", "params": {}},
        ],
    }
    update_response = client.put(
        f"/api/workflows/{workflow_id}",
        json={
            "name": "basic_static_updated",
            "workflow": updated_workflow,
            "description": "Updated local static workflow.",
            "tags": ["updated"],
            "risk": "medium",
            "network": False,
            "config_required": False,
            "default_safe": False,
        },
    )
    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["workflow_id"] == workflow_id
    assert updated["workflow"] == updated_workflow
    assert updated["description"] == "Updated local static workflow."
    assert updated["risk"] == "medium"
    assert updated["tags"] == ["updated"]

    delete_response = client.delete(f"/api/workflows/{workflow_id}")
    assert delete_response.status_code == 200
    assert delete_response.json() == {"workflow_id": workflow_id, "deleted": True}
    assert client.get(f"/api/workflows/{workflow_id}").status_code == 404


def test_workflow_template_unknown_function_returns_400(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        main,
        "workflow_store",
        WorkflowStore(tmp_path / "data" / "workflows" / "workflows.json"),
    )
    client = TestClient(main.app)

    response = client.post(
        "/api/workflows",
        json={
            "name": "bad",
            "workflow": {"name": "bad", "steps": [{"function_id": "unknown.fn"}]},
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"]["errors"][0]["code"] == "unknown_function"


def test_workflow_template_reads_metadata_from_nested_workflow(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        main,
        "workflow_store",
        WorkflowStore(tmp_path / "data" / "workflows" / "workflows.json"),
    )
    client = TestClient(main.app)

    response = client.post(
        "/api/workflows",
        json={
            "name": "dynamic_nested_metadata",
            "workflow": {
                "name": "dynamic_nested_metadata",
                "description": "Long VM workflow.",
                "tags": ["dynamic", "vmware"],
                "risk": "high",
                "network": True,
                "config_required": True,
                "default_safe": False,
                "steps": [{"function_id": "hash.compute", "params": {}}],
            },
        },
    )

    assert response.status_code == 200
    saved = response.json()
    assert saved["description"] == "Long VM workflow."
    assert saved["tags"] == ["dynamic", "vmware"]
    assert saved["risk"] == "high"
    assert saved["network"] is True
    assert saved["config_required"] is True


def test_workflow_template_does_not_save_secret_keys(tmp_path) -> None:
    store = WorkflowStore(tmp_path / "data" / "workflows" / "workflows.json")
    workflow = WorkflowDefinition.from_dict(
        {
            "name": "with_secret_param",
            "steps": [
                {
                    "function_id": "hash.compute",
                    "params": {"api_key": "test-secret", "token": "test-token"},
                }
            ],
        }
    )

    store.save_workflow_template("with_secret_param", workflow)
    serialized = json.dumps(store._load())

    assert "test-secret" not in serialized
    assert "test-token" not in serialized
    assert "api_key" not in serialized
    assert "token" not in serialized


def test_workflow_template_metadata_defaults_for_old_data(tmp_path) -> None:
    store_path = tmp_path / "data" / "workflows" / "workflows.json"
    store_path.parent.mkdir(parents=True)
    store_path.write_text(
        json.dumps(
            {
                "workflows": [
                    {
                        "workflow_id": "old",
                        "name": "old_workflow",
                        "created_at": "2026-01-01T00:00:00+00:00",
                        "updated_at": "2026-01-01T00:00:00+00:00",
                        "workflow": {"name": "old_workflow", "steps": []},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    store = WorkflowStore(store_path)

    listed = store.list_workflows()["workflows"][0]
    full = store.get_workflow("old")

    for item in [listed, full]:
        assert item["description"] == ""
        assert item["tags"] == []
        assert item["risk"] == "low"
        assert item["network"] is False
        assert item["config_required"] is False
        assert item["default_safe"] is False
