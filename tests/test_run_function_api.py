import json

from fastapi.testclient import TestClient

from security_function_platform.api import main
from security_function_platform.api.config_store import ConfigStore
from security_function_platform.api.session_store import SessionStore


def test_run_function_appends_raw_output_and_updates_session(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    config_store = ConfigStore(tmp_path / "config" / "local_config.json")
    config_store.set_config_value(
        "virustotal.api_key",
        "test-secret",
        main.module_store.load_config_fields(),
    )
    monkeypatch.setattr(main, "config_store", config_store)
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.exe", b"MZ\x00hello world\x00")},
    ).json()

    hash_response = client.post(
        f"/api/sessions/{session['session_id']}/functions/run",
        json={"function_id": "hash.compute", "params": {}},
    )
    type_response = client.post(
        f"/api/sessions/{session['session_id']}/functions/run",
        json={"function_id": "file.type_detect", "params": {}},
    )

    assert hash_response.status_code == 200
    assert type_response.status_code == 200
    assert type_response.json()["summary"]["result_keys"] == ["hash", "file_type"]

    raw_output = main.store.get_raw_output(session["session_id"])
    assert [item["raw_output_id"] for item in raw_output["items"]] == [
        "raw-001-hash",
        "raw-002-file_type",
    ]
    assert raw_output["items"][1]["function_id"] == "file.type_detect"

    saved_session = main.store.get_session(session["session_id"])
    assert set(saved_session["raw_outputs"]) == {"hash", "file_type"}
    serialized = json.dumps(saved_session) + json.dumps(raw_output)
    assert "test-secret" not in serialized
    assert "api_key" not in serialized


def test_run_function_unknown_function_returns_400(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello")},
    ).json()

    response = client.post(
        f"/api/sessions/{session['session_id']}/functions/run",
        json={"function_id": "unknown.fn", "params": {}},
    )

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "unknown_function"
