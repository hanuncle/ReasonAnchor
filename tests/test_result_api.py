import json
from pathlib import Path

from fastapi.testclient import TestClient

from security_function_platform.api import main
from security_function_platform.api.session_store import SessionStore
from security_function_platform.mcp_server import server


def test_result_api_default_save_and_get(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello")},
    ).json()

    default_response = client.get(f"/api/sessions/{session['session_id']}/result")
    assert default_response.status_code == 200
    assert default_response.json() == {
        "session_id": session["session_id"],
        "file": {},
        "summary": {"overall": "", "risk_level": "unknown", "limitations": []},
        "behaviors": [],
    }

    result = {
        "session_id": "wrong",
        "file": {
            "filename": "sample.bin",
            "size": 5,
            "sha256": "abc",
            "file_type": "unknown",
        },
        "summary": {
            "overall": "基于原始输出的候选分析总结。",
            "risk_level": "unknown",
            "limitations": ["candidate only"],
        },
        "behaviors": [
            {
                "behavior": "疑似进程注入相关行为",
                "evidence": {
                    "summary": "原始输出中出现相关 API。",
                    "sources": [
                        {
                            "source_type": "ai_output",
                            "raw_output_id": "raw-001-strings",
                            "function_id": "strings.extract",
                            "result_key": "strings",
                            "description": "strings output",
                        }
                    ],
                },
                "verification": "未验证",
                "function_level_source": {
                    "tool": "ida",
                    "function_name": "sub_401000",
                    "address": "0x401000",
                    "source_raw_output_id": "raw-010-ida",
                    "note": "",
                },
            }
        ],
        "api_key": "test-secret",
    }
    save_response = client.post(f"/api/sessions/{session['session_id']}/result", json=result)
    get_response = client.get(f"/api/sessions/{session['session_id']}/result")

    assert save_response.status_code == 200
    assert save_response.json()["session_id"] == session["session_id"]
    assert get_response.status_code == 200
    saved = get_response.json()
    assert saved["file"]["filename"] == "sample.bin"
    assert saved["summary"]["risk_level"] == "unknown"
    assert saved["behaviors"][0]["raw_output_ids"] == ["raw-001-strings"]
    assert saved["behaviors"][0]["evidence"]["summary"] == "原始输出中出现相关 API。"
    assert saved["behaviors"][0]["evidence"]["sources"][0]["function_id"] == "strings.extract"
    assert saved["behaviors"][0]["function_level_source"]["function_name"] == "sub_401000"
    assert saved["behaviors"][0]["evidence_missing"] is False
    assert "api_key" not in saved

    result_path = (
        tmp_path
        / "data"
        / "sessions"
        / session["session_id"]
        / "result"
        / "result.json"
    )
    assert result_path.is_file()
    serialized = result_path.read_text(encoding="utf-8")
    assert "test-secret" not in serialized
    assert "api_key" not in serialized


def test_result_page_fetches_saved_session_result() -> None:
    result_js = Path("web/result.js").read_text(encoding="utf-8")

    assert "/api/sessions/${encodeURIComponent(sessionId)}/result" in result_js


def test_result_api_missing_session_returns_404(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)

    response = client.get("/api/sessions/00000000-0000-0000-0000-000000000000/result")

    assert response.status_code == 404


def test_mcp_save_session_result_uses_http_helper(monkeypatch) -> None:
    calls = []

    def fake_request(method, path, body=None):
        calls.append((method, path, body))
        return {"saved": True}

    monkeypatch.setattr(server, "_request_json", fake_request)
    result = {
        "session_id": "session",
        "file": {},
        "summary": {"overall": "", "risk_level": "unknown", "limitations": []},
        "behaviors": [],
    }

    response = server.save_session_result("session", result)

    assert response == {"saved": True}
    assert calls == [("POST", "/api/sessions/session/result", result)]


def test_result_serialized_does_not_contain_auth_key_or_token(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello")},
    ).json()

    client.post(
        f"/api/sessions/{session['session_id']}/result",
        json={
            "file": {},
            "summary": {"overall": "", "risk_level": "unknown", "limitations": []},
            "behaviors": [],
            "auth_key": "test-auth",
            "token": "test-token",
        },
    )
    result_path = (
        tmp_path
        / "data"
        / "sessions"
        / session["session_id"]
        / "result"
        / "result.json"
    )

    serialized = json.dumps(json.loads(result_path.read_text(encoding="utf-8")))
    assert "test-auth" not in serialized
    assert "test-token" not in serialized
    assert "auth_key" not in serialized
    assert "token" not in serialized


def test_result_behavior_defaults_and_evidence_missing_flag(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello")},
    ).json()

    response = client.post(
        f"/api/sessions/{session['session_id']}/result",
        json={
            "file": {},
            "summary": {"overall": "", "risk_level": "unknown", "limitations": []},
            "behaviors": [
                {"behavior": "no evidence"},
                {
                    "behavior": "with evidence",
                    "evidence": "raw output supports this candidate.",
                    "raw_output_ids": ["raw-001-hash"],
                },
            ],
        },
    )

    assert response.status_code == 200
    behaviors = response.json()["behaviors"]
    assert behaviors[0]["verification"] == "未验证"
    assert behaviors[0]["function_level_source"]["note"] == "未进行函数级分析"
    assert behaviors[0]["evidence_missing"] is True
    assert behaviors[0]["evidence"]["summary"] == "无证据来源"
    assert behaviors[1]["verification"] == "未验证"
    assert behaviors[1]["function_level_source"]["note"] == "未进行函数级分析"
    assert behaviors[1]["evidence_missing"] is False
    assert behaviors[1]["evidence"]["summary"] == "raw output supports this candidate."
    assert behaviors[1]["evidence"]["sources"][0]["raw_output_id"] == "raw-001-hash"


def test_result_accepts_english_verification_values(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello")},
    ).json()

    response = client.post(
        f"/api/sessions/{session['session_id']}/result",
        json={
            "file": {},
            "summary": {"overall": "", "risk_level": "unknown", "limitations": []},
            "behaviors": [
                {
                    "behavior": "candidate",
                    "verification": "unverified",
                }
            ],
        },
    )

    assert response.status_code == 200
    assert response.json()["behaviors"][0]["verification"] == "unverified"
