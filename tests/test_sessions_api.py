from pathlib import Path

from fastapi.testclient import TestClient

from security_function_platform.api import main
from security_function_platform.api.session_store import SessionStore


def test_health_returns_ok() -> None:
    client = TestClient(main.app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_functions_returns_builtin_functions() -> None:
    client = TestClient(main.app)

    response = client.get("/api/functions")

    assert response.status_code == 200
    function_ids = {item["id"] for item in response.json()}
    assert {"hash.compute", "file.type_detect", "strings.extract"} <= function_ids


def test_upload_save_workflow_and_run(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)

    upload_response = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.exe", b"MZ\x00hello world\x00http://example.test/a\x00")},
    )
    assert upload_response.status_code == 200
    session = upload_response.json()
    assert session["workflow"] is None
    assert session["summary"]["status"] == "created"

    stored_path = Path(session["sample"]["stored_path"])
    assert stored_path.is_file()
    assert tmp_path / "data" / "sessions" in stored_path.parents

    workflow_response = client.post(
        f"/api/sessions/{session['session_id']}/workflow",
        json={
            "name": "basic_static_analysis",
            "steps": [
                {"function_id": "hash.compute", "params": {}},
                {"function_id": "file.type_detect", "params": {}},
                {
                    "function_id": "strings.extract",
                    "params": {"min_length": 4, "max_strings": 2000},
                },
            ],
        },
    )
    assert workflow_response.status_code == 200
    assert workflow_response.json()["workflow"]["name"] == "basic_static_analysis"

    run_response = client.post(f"/api/sessions/{session['session_id']}/run")
    assert run_response.status_code == 200
    completed_session = run_response.json()
    assert set(completed_session["raw_outputs"]) == {"hash", "file_type", "strings"}
    assert completed_session["raw_outputs"]["hash"]["function_id"] == "hash.compute"
    assert completed_session["summary"]["status"] == "completed"
    assert set(completed_session["summary"]["result_keys"]) == {
        "hash",
        "file_type",
        "strings",
    }


def test_upload_multiple_samples_creates_one_session_per_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)

    response = client.post(
        "/api/sessions/upload-multiple",
        files=[
            ("files", ("one.bin", b"one")),
            ("files", ("two.bin", b"two")),
        ],
    )

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    assert [session["sample"]["filename"] for session in body["sessions"]] == [
        "one.bin",
        "two.bin",
    ]
    assert body["sessions"][0]["session_id"] != body["sessions"][1]["session_id"]
    for session in body["sessions"]:
        assert Path(session["sample"]["stored_path"]).is_file()


def test_list_sessions_returns_existing_session_summaries(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    created = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello")},
    ).json()

    response = client.get("/api/sessions")

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["sessions"][0]["session_id"] == created["session_id"]
    assert body["sessions"][0]["sample"]["filename"] == "sample.bin"
    assert body["sessions"][0]["summary"]["status"] == "created"


def test_unknown_workflow_function_returns_400(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello")},
    ).json()

    response = client.post(
        f"/api/sessions/{session['session_id']}/workflow",
        json={
            "name": "invalid",
            "steps": [{"function_id": "unknown.fn", "params": {}}],
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"]["errors"][0]["code"] == "unknown_function"


def test_run_without_workflow_returns_400(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello")},
    ).json()

    response = client.post(f"/api/sessions/{session['session_id']}/run")

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "missing_workflow"
