import json

from fastapi.testclient import TestClient

from security_function_platform.api import main
from security_function_platform.api.config_store import ConfigStore
from security_function_platform.api.session_store import SessionStore


def field_by_path(redacted, path):
    return next(field for field in redacted["fields"] if field["path"] == path)


def test_get_config_returns_fields(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "config_store", ConfigStore(tmp_path / "config.json"))
    client = TestClient(main.app)

    response = client.get("/api/config")

    assert response.status_code == 200
    assert field_by_path(response.json(), "yara.rules_dir")["label"] == "YARA rules directory"


def test_post_config_value_saves_regular_field(tmp_path, monkeypatch) -> None:
    store = ConfigStore(tmp_path / "config" / "local_config.json")
    monkeypatch.setattr(main, "config_store", store)
    client = TestClient(main.app)

    response = client.post(
        "/api/config/value",
        json={"path": "yara.rules_dir", "value": r"E:\rules\yara"},
    )

    assert response.status_code == 200
    assert store.load_config()["yara"]["rules_dir"] == r"E:\rules\yara"
    assert field_by_path(response.json(), "yara.rules_dir")["value"] == r"E:\rules\yara"


def test_secret_config_value_is_saved_but_redacted_and_deletable(tmp_path, monkeypatch) -> None:
    store = ConfigStore(tmp_path / "config" / "local_config.json")
    monkeypatch.setattr(main, "config_store", store)
    client = TestClient(main.app)

    save_response = client.post(
        "/api/config/value",
        json={"path": "virustotal.api_key", "value": "test-secret"},
    )
    assert save_response.status_code == 200
    assert store.load_config()["virustotal"]["api_key"] == "test-secret"

    get_response = client.get("/api/config")
    assert field_by_path(get_response.json(), "virustotal.api_key") == {
        "path": "virustotal.api_key",
        "label": "VirusTotal API key",
        "secret": True,
        "configured": True,
        "value": None,
    }

    delete_response = client.post(
        "/api/config/delete",
        json={"path": "virustotal.api_key"},
    )

    assert delete_response.status_code == 200
    assert field_by_path(delete_response.json(), "virustotal.api_key")["configured"] is False


def test_session_run_injects_local_config_without_persisting_secrets(tmp_path, monkeypatch) -> None:
    config_store = ConfigStore(tmp_path / "config" / "local_config.json")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    fields = main.module_store.load_config_fields()
    config_store.set_config_value("yara.rules_dir", str(rules_dir), fields)
    config_store.set_config_value("virustotal.api_key", "test-secret", fields)
    monkeypatch.setattr(main, "config_store", config_store)
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)

    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello world")},
    ).json()
    workflow = {
        "name": "config_injection",
        "steps": [{"function_id": "yara.scan_local", "params": {}}],
    }
    assert (
        client.post(f"/api/sessions/{session['session_id']}/workflow", json=workflow).status_code
        == 200
    )

    run_response = client.post(f"/api/sessions/{session['session_id']}/run")
    saved_session = main.store.get_session(session["session_id"])
    serialized_session = json.dumps(saved_session)

    assert run_response.status_code == 200
    yara_output = run_response.json()["raw_outputs"]["yara_scan"]
    if yara_output["status"] == "error":
        assert yara_output["error"]["code"] != "missing_rules_dir"
    else:
        assert yara_output["data"]["rules_dir"] == rules_dir.name
    assert "test-secret" not in serialized_session
    assert "api_key" not in serialized_session
    assert "Auth-Key" not in serialized_session
