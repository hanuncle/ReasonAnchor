from fastapi.testclient import TestClient

from security_function_platform.api import main
from security_function_platform.api.session_store import SessionStore


def test_raw_output_id_map_and_lookup(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.exe", b"MZ\x00hello world\x00")},
    ).json()
    workflow = {
        "name": "basic_static",
        "steps": [
            {"function_id": "hash.compute", "params": {}},
            {"function_id": "file.type_detect", "params": {}},
            {"function_id": "strings.extract", "params": {"min_length": 4}},
        ],
    }
    client.post(f"/api/sessions/{session['session_id']}/workflow", json=workflow)
    client.post(f"/api/sessions/{session['session_id']}/run")

    raw_output = main.store.get_raw_output(session["session_id"])
    assert [item["raw_output_id"] for item in raw_output["items"]] == [
        "raw-001-hash",
        "raw-002-file_type",
        "raw-003-strings",
    ]
    assert raw_output["items"][0]["function_name"] == "Hash compute"

    map_response = client.get(f"/api/sessions/{session['session_id']}/raw-output-map")
    assert map_response.status_code == 200
    mapped_item = map_response.json()["items"][0]
    assert mapped_item == {
        "raw_output_id": "raw-001-hash",
        "index": 1,
        "function_id": "hash.compute",
        "function_name": "Hash compute",
        "result_key": "hash",
        "status": "success",
    }
    assert "output" not in mapped_item

    item_response = client.get(
        f"/api/sessions/{session['session_id']}/raw-output/raw-001-hash"
    )
    assert item_response.status_code == 200
    assert item_response.json()["item"]["output"]["result_key"] == "hash"

    missing_response = client.get(
        f"/api/sessions/{session['session_id']}/raw-output/raw-999-missing"
    )
    assert missing_response.status_code == 404


def test_raw_output_map_falls_back_to_session_raw_outputs(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/target",
        json={
            "targets": ["https://example.test"],
            "authorized_scope": ["example.test"],
            "module_id": "recon_scan",
            "label": "legacy recon session",
        },
    ).json()
    saved = main.store.get_session(session["session_id"])
    saved["raw_outputs"] = {
        "recon_scope": {
            "function_id": "recon.scope_validate",
            "result_key": "recon_scope",
            "status": "success",
            "data": {"authorized": True},
        }
    }
    main.store.save_session(saved)

    map_response = client.get(f"/api/sessions/{session['session_id']}/raw-output-map")

    assert map_response.status_code == 200
    assert map_response.json()["items"] == [
        {
            "raw_output_id": "raw-001-recon_scope",
            "index": 1,
            "function_id": "recon.scope_validate",
            "function_name": "recon.scope_validate",
            "result_key": "recon_scope",
            "status": "success",
        }
    ]

    item_response = client.get(
        f"/api/sessions/{session['session_id']}/raw-output/raw-001-recon_scope"
    )
    assert item_response.status_code == 200
    assert item_response.json()["item"]["output"]["data"] == {"authorized": True}


def test_raw_output_page_script_uses_map_first_loading() -> None:
    client = TestClient(main.app)

    script = client.get("/static/raw-output.js")

    assert script.status_code == 200
    text = script.text
    assert "/raw-output-map" in text
    assert "/raw-output/${encodeURIComponent(" in text
    assert 'fetch(`/api/sessions/${encodeURIComponent(sessionId)}/raw-output`)' not in text
    assert "查看原始数据" in text


def test_raw_data_page_auto_loads_map_when_session_changes() -> None:
    client = TestClient(main.app)

    script = client.get("/static/raw-data.js")

    assert script.status_code == 200
    text = script.text
    assert 'sessionSelect.addEventListener("change", handleSessionChange)' in text
    assert "async function handleSessionChange()" in text
    assert "await loadRawMap();" in text
    assert "await loadAiOutput();" in text
