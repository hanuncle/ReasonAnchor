import json

from fastapi.testclient import TestClient

from security_function_platform.api import main
from security_function_platform.api.config_store import ConfigStore
from security_function_platform.api.session_store import SessionStore


def test_raw_output_file_records_steps_in_order_and_resets_on_rerun(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    config_store = ConfigStore(tmp_path / "config" / "local_config.json")
    fields = main.module_store.load_config_fields()
    config_store.set_config_value("virustotal.api_key", "test-secret", fields)
    config_store.set_config_value("malwarebazaar.auth_key", "test-auth-key", fields)
    monkeypatch.setattr(main, "config_store", config_store)
    client = TestClient(main.app)

    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.exe", b"MZ\x00hello world\x00")},
    ).json()
    workflow = {
        "name": "basic_static_analysis",
        "steps": [
            {"function_id": "hash.compute", "params": {}},
            {"function_id": "file.type_detect", "params": {}},
            {"function_id": "strings.extract", "params": {"min_length": 4}},
        ],
    }
    assert (
        client.post(f"/api/sessions/{session['session_id']}/workflow", json=workflow).status_code
        == 200
    )

    first_run = client.post(f"/api/sessions/{session['session_id']}/run")
    assert first_run.status_code == 200

    raw_output_path = (
        tmp_path
        / "data"
        / "sessions"
        / session["session_id"]
        / "raw_output"
        / "raw_output.json"
    )
    assert raw_output_path.is_file()

    raw_output = json.loads(raw_output_path.read_text(encoding="utf-8"))
    assert raw_output["session_id"] == session["session_id"]
    assert [
        (item["index"], item["function_id"])
        for item in raw_output["items"]
    ] == [
        (1, "hash.compute"),
        (2, "file.type_detect"),
        (3, "strings.extract"),
    ]
    assert raw_output["items"][0]["output"]["result_key"] == "hash"

    api_response = client.get(f"/api/sessions/{session['session_id']}/raw-output")
    assert api_response.status_code == 200
    assert api_response.json()["items"] == raw_output["items"]

    second_run = client.post(f"/api/sessions/{session['session_id']}/run")
    assert second_run.status_code == 200
    rerun_raw_output = json.loads(raw_output_path.read_text(encoding="utf-8"))
    assert [item["index"] for item in rerun_raw_output["items"]] == [1, 2, 3]
    assert len(rerun_raw_output["items"]) == 3

    serialized = json.dumps(rerun_raw_output)
    assert "test-secret" not in serialized
    assert "test-auth-key" not in serialized
    assert "api_key" not in serialized
    assert "Auth-Key" not in serialized


def test_raw_output_missing_file_returns_empty_items(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello")},
    ).json()

    response = client.get(f"/api/sessions/{session['session_id']}/raw-output")

    assert response.status_code == 200
    assert response.json() == {"session_id": session["session_id"], "items": []}
