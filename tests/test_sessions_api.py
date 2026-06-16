from pathlib import Path
import time

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


def test_create_target_session_persists_scope_without_sample_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)

    response = client.post(
        "/api/sessions/target",
        json={
            "targets": ["https://www.example.test"],
            "authorized_scope": ["example.test", "*.example.test"],
            "exclude": ["admin.example.test"],
            "module_id": "recon_scan",
            "label": "Example recon target",
            "notes": "authorized CTF target",
        },
    )

    assert response.status_code == 200
    session = response.json()
    assert session["session_type"] == "target"
    assert session["sample"]["stored_path"] == ""
    assert session["sample"]["size"] == 0
    assert session["target"]["targets"] == ["https://www.example.test"]
    assert session["target"]["authorized_scope"] == ["example.test", "*.example.test"]
    assert session["target"]["exclude"] == ["admin.example.test"]
    assert session["target"]["module_id"] == "recon_scan"

    list_response = client.get("/api/sessions")
    assert list_response.status_code == 200
    listed = list_response.json()["sessions"][0]
    assert listed["session_type"] == "target"
    assert listed["target"]["label"] == "Example recon target"


def test_target_session_context_feeds_recon_workflow_scope(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)

    session = client.post(
        "/api/sessions/target",
        json={
            "targets": ["https://www.example.test"],
            "authorized_scope": ["example.test", "*.example.test"],
            "module_id": "recon_scan",
            "label": "Example recon target",
        },
    ).json()
    workflow_response = client.post(
        f"/api/sessions/{session['session_id']}/workflow",
        json={
            "name": "target_scope_context",
            "steps": [
                {
                    "function_id": "recon.scope_validate",
                    "params": {"active_scan": False, "targets": [], "authorized_scope": []},
                },
                {"function_id": "recon.target_normalize", "params": {}},
            ],
        },
    )
    assert workflow_response.status_code == 200

    run_response = client.post(f"/api/sessions/{session['session_id']}/run")

    assert run_response.status_code == 200
    body = run_response.json()
    assert body["summary"]["status"] == "completed"
    assert body["raw_outputs"]["recon_scope"]["status"] == "success"
    assert body["raw_outputs"]["recon_scope"]["data"]["authorized"] is True
    assert body["raw_outputs"]["recon_targets"]["data"]["hosts"] == ["www.example.test"]


def test_batch_run_creates_cross_sample_report_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    upload = client.post(
        "/api/sessions/upload-multiple",
        files=[
            ("files", ("one.bin", b"powershell http://one.example/a")),
            ("files", ("two.bin", b"cmd.exe http://two.example/b")),
        ],
    ).json()
    workflow = {
        "name": "batch_static",
        "steps": [
            {"function_id": "hash.compute", "params": {}},
            {"function_id": "strings.extract", "params": {"min_length": 4}},
            {"function_id": "ioc.extract", "params": {}},
            {"function_id": "behavior.map_static", "params": {}},
            {"function_id": "attack.map_static", "params": {}},
        ],
    }
    for session in upload["sessions"]:
        response = client.post(
            f"/api/sessions/{session['session_id']}/workflow",
            json=workflow,
        )
        assert response.status_code == 200

    response = client.post(
        "/api/batches/run",
        json={"session_ids": [session["session_id"] for session in upload["sessions"]]},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    assert body["report"]["schema_id"] == "sample_set.report.v2"
    assert body["report"]["summary"]["completed"] == 2
    assert body["report"]["summary"]["behavior_category_count"] >= 2
    assert body["report"]["summary"]["attack_technique_count"] >= 2
    assert body["report"]["summary"]["validation_status"]["static_only"] == 2
    assert {"command_execution", "network_communication"} <= set(
        body["report"]["summary"]["behavior_categories"]
    )
    assert {"behavior_taxonomy", "attack_knowledge", "validation_samples"} <= set(
        body["report"]["knowledge_links"]
    )
    assert {
        "command_execution",
        "network_communication",
    } <= {item["category_id"] for item in body["report"]["behavior_matrix"]}
    assert {"T1059", "T1071"} <= {
        item["technique_id"] for item in body["report"]["attack_matrix"]
    }
    assert len(body["report"]["sample_facts"]) == 2
    report_path = tmp_path / "data" / "reports" / body["report_id"] / "report.json"
    markdown_path = tmp_path / "data" / "reports" / body["report_id"] / "report.md"
    assert report_path.is_file()
    assert markdown_path.is_file()
    assert "Behavior Matrix" in markdown_path.read_text(encoding="utf-8")

    list_response = client.get("/api/reports")
    get_response = client.get(f"/api/reports/{body['report_id']}")
    assert list_response.status_code == 200
    assert list_response.json()["reports"][0]["report_id"] == body["report_id"]
    assert list_response.json()["reports"][0]["behavior_category_count"] >= 2
    assert get_response.status_code == 200
    assert get_response.json()["report_id"] == body["report_id"]
    assert get_response.json()["artifacts"]["markdown"] == "report.md"


def test_async_batch_job_runs_and_persists_status(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    upload = client.post(
        "/api/sessions/upload-multiple",
        files=[
            ("files", ("one.bin", b"powershell http://one.example/a")),
            ("files", ("two.bin", b"cmd.exe http://two.example/b")),
        ],
    ).json()
    workflow = {
        "name": "async_batch_static",
        "steps": [
            {"function_id": "hash.compute", "params": {}},
            {"function_id": "strings.extract", "params": {"min_length": 4}},
            {"function_id": "behavior.map_static", "params": {}},
        ],
    }
    for session in upload["sessions"]:
        response = client.post(
            f"/api/sessions/{session['session_id']}/workflow",
            json=workflow,
        )
        assert response.status_code == 200

    response = client.post(
        "/api/batches/jobs",
        json={"session_ids": [session["session_id"] for session in upload["sessions"]]},
    )

    assert response.status_code == 200
    job = response.json()
    assert job["status"] in {"queued", "running", "completed"}
    job_id = job["job_id"]
    for _ in range(40):
        job_response = client.get(f"/api/batches/jobs/{job_id}")
        assert job_response.status_code == 200
        job = job_response.json()
        if job["status"] == "completed":
            break
        time.sleep(0.05)

    assert job["status"] == "completed"
    assert job["completed_count"] == 2
    assert job["failed_count"] == 0
    assert job["report_id"]
    assert job["report"]["summary"]["sample_count"] == 2
    assert (tmp_path / "data" / "batch_jobs" / job_id / "job.json").is_file()

    list_response = client.get("/api/batches/jobs")
    assert list_response.status_code == 200
    assert list_response.json()["jobs"][0]["job_id"] == job_id


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
