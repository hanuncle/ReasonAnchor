import json

from fastapi.testclient import TestClient

from security_function_platform.api import main
from security_function_platform.api.session_store import SessionStore
from security_function_platform.mcp_server import server
from security_function_platform.raw_sorting import sorter


def sample_item():
    return {
        "raw_output_id": "raw-001-strings",
        "index": 1,
        "function_id": "strings.extract",
        "function_name": "ASCII strings extract",
        "result_key": "strings",
        "status": "success",
        "output": {
            "function_id": "strings.extract",
            "result_key": "strings",
            "status": "success",
            "data": {"items": ["hello", "world"]},
            "error": None,
        },
    }


def test_sort_raw_output_item_fallback_when_index_missing(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(sorter, "RAW_SORTING_DIR", tmp_path / "raw_sorting")
    monkeypatch.setattr(sorter, "RAW_SORTING_INDEX", tmp_path / "raw_sorting" / "missing.json")

    result = sorter.sort_raw_output_item(sample_item())

    assert result["sort_status"] == "raw_fallback"
    assert result["ai_payload"]["raw_output"]["raw_output_id"] == "raw-001-strings"


def test_sort_raw_output_item_fallback_when_no_match(tmp_path, monkeypatch) -> None:
    raw_sorting_dir = tmp_path / "raw_sorting"
    raw_sorting_dir.mkdir()
    index = raw_sorting_dir / "raw_sorting_index.json"
    index.write_text('{"sorters":[],"fallback":"raw"}', encoding="utf-8")
    monkeypatch.setattr(sorter, "RAW_SORTING_DIR", raw_sorting_dir)
    monkeypatch.setattr(sorter, "RAW_SORTING_INDEX", index)

    result = sorter.sort_raw_output_item(sample_item())

    assert result["sort_status"] == "raw_fallback"


def test_sort_raw_output_item_uses_matching_sorter(tmp_path, monkeypatch) -> None:
    raw_sorting_dir = tmp_path / "raw_sorting"
    raw_sorting_dir.mkdir()
    (raw_sorting_dir / "strings_extract_sorter.py").write_text(
        "def sort_output(raw_output_item):\n"
        "    return {'summary': 'sorted strings', 'key_fields': {'count': 2}, "
        "'evidence_hints': [], 'warnings': [], 'limitations': []}\n",
        encoding="utf-8",
    )
    index = raw_sorting_dir / "raw_sorting_index.json"
    index.write_text(
        json.dumps(
            {
                "sorters": [
                    {
                        "function_id": "strings.extract",
                        "result_key": "strings",
                        "sorter_file": "strings_extract_sorter.py",
                        "callable": "sort_output",
                    }
                ],
                "fallback": "raw",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sorter, "RAW_SORTING_DIR", raw_sorting_dir)
    monkeypatch.setattr(sorter, "RAW_SORTING_INDEX", index)

    result = sorter.sort_raw_output_item(sample_item())

    assert result["sort_status"] == "sorted"
    assert result["ai_payload"]["summary"] == "sorted strings"


def test_dynamic_telemetry_sorter_summarizes_event_counts() -> None:
    item = {
        "raw_output_id": "raw-001-dynamic_telemetry",
        "index": 1,
        "function_id": "dynamic.telemetry_fixture",
        "function_name": "Dynamic telemetry fixture",
        "result_key": "dynamic_telemetry",
        "status": "success",
        "output": {
            "function_id": "dynamic.telemetry_fixture",
            "result_key": "dynamic_telemetry",
            "status": "success",
            "data": {
                "schema_version": "1",
                "telemetry_id": "fixture",
                "process_events": [
                    {
                        "event_id": "evt-001",
                        "event_type": "process_create",
                        "process_name": "cmd.exe",
                        "command_line": "cmd.exe /c whoami",
                    }
                ],
                "network_events": [
                    {
                        "event_id": "evt-002",
                        "event_type": "dns_query",
                        "destination_host": "example.test",
                    }
                ],
            },
            "error": None,
        },
    }

    result = sorter.sort_raw_output_item(item)

    assert result["sort_status"] == "sorted"
    payload = result["ai_payload"]
    assert payload["key_fields"]["total_events"] == 2
    assert payload["key_fields"]["event_counts"]["process_events"] == 1
    assert len(payload["evidence_hints"]) == 2


def test_dynamic_behavior_map_sorter_summarizes_categories() -> None:
    item = {
        "raw_output_id": "raw-002-dynamic_behavior_map",
        "index": 2,
        "function_id": "behavior.map_dynamic",
        "function_name": "Dynamic behavior mapping",
        "result_key": "dynamic_behavior_map",
        "status": "success",
        "output": {
            "function_id": "behavior.map_dynamic",
            "result_key": "dynamic_behavior_map",
            "status": "success",
            "data": {
                "source": "params.telemetry",
                "telemetry_id": "fixture",
                "behaviors": [
                    {
                        "category": "command_execution",
                        "confidence": "medium",
                        "score": 3,
                        "evidence": [
                            {
                                "event_group": "process_events",
                                "event_type": "process_create",
                                "command_line": "cmd.exe /c whoami",
                                "reason": "keyword:cmd.exe",
                            }
                        ],
                    }
                ],
                "counts": {"behaviors": 1},
            },
            "error": None,
        },
    }

    result = sorter.sort_raw_output_item(item)

    assert result["sort_status"] == "sorted"
    payload = result["ai_payload"]
    assert payload["key_fields"]["categories"] == ["command_execution"]
    assert payload["evidence_hints"][0]["category"] == "command_execution"


def test_static_dynamic_validation_sorter_summarizes_consistency() -> None:
    item = {
        "raw_output_id": "raw-003-static_dynamic_validation",
        "index": 3,
        "function_id": "validation.compare_static_dynamic",
        "function_name": "Static and dynamic behavior comparison",
        "result_key": "static_dynamic_validation",
        "status": "success",
        "output": {
            "function_id": "validation.compare_static_dynamic",
            "result_key": "static_dynamic_validation",
            "status": "success",
            "data": {
                "summary": {
                    "categories": 2,
                    "matched": 1,
                    "static_candidate_not_observed": 1,
                    "dynamic_observed_without_static_candidate": 0,
                },
                "comparisons": [
                    {
                        "category": "command_execution",
                        "consistency": "matched",
                        "static_result": "candidate",
                        "dynamic_result": "observed",
                        "static_evidence": [{}],
                        "dynamic_evidence": [{}],
                    },
                    {
                        "category": "credential_access",
                        "consistency": "static_candidate_not_observed",
                        "static_result": "candidate",
                        "dynamic_result": "not_observed",
                        "static_evidence": [{}],
                        "dynamic_evidence": [],
                    },
                ],
                "limitations": ["not_observed is not proof of absence"],
            },
            "error": None,
        },
    }

    result = sorter.sort_raw_output_item(item)

    assert result["sort_status"] == "sorted"
    payload = result["ai_payload"]
    assert payload["key_fields"]["matched_categories"] == ["command_execution"]
    assert payload["key_fields"]["static_not_observed"] == ["credential_access"]
    assert payload["warnings"]


def test_dynamic_vm_operation_sorter_summarizes_vm_status() -> None:
    item = {
        "raw_output_id": "raw-004-dynamic_vm_status",
        "index": 4,
        "function_id": "dynamic.vm_status",
        "function_name": "VMware dynamic VM status",
        "result_key": "dynamic_vm_status",
        "status": "success",
        "output": {
            "function_id": "dynamic.vm_status",
            "result_key": "dynamic_vm_status",
            "status": "success",
            "data": {
                "running": True,
                "tools_state": "running",
                "snapshots": ["base", "after-run"],
                "ready_snapshot": "base",
            },
            "error": None,
        },
    }

    result = sorter.sort_raw_output_item(item)

    assert result["sort_status"] == "sorted"
    payload = result["ai_payload"]
    assert payload["key_fields"]["running"] is True
    assert payload["key_fields"]["snapshots_count"] == 2
    assert payload["evidence_hints"][0]["type"] == "vm_state"


def test_focused_dynamic_plan_sorter_summarizes_targets() -> None:
    item = {
        "raw_output_id": "raw-005-focused_dynamic_validation_plan",
        "index": 5,
        "function_id": "validation.plan_focused_dynamic",
        "function_name": "Plan focused dynamic validation",
        "result_key": "focused_dynamic_validation_plan",
        "status": "success",
        "output": {
            "function_id": "validation.plan_focused_dynamic",
            "result_key": "focused_dynamic_validation_plan",
            "status": "success",
            "data": {
                "targets": [
                    {
                        "behavior_category": "registry_persistence",
                        "validation_sample_id": "registry_run_key_fixture",
                        "status": "ready",
                    }
                ]
            },
            "error": None,
        },
    }

    result = sorter.sort_raw_output_item(item)

    assert result["sort_status"] == "sorted"
    assert result["ai_payload"]["key_fields"]["ready_categories"] == [
        "registry_persistence"
    ]


def test_focused_dynamic_validation_sorter_summarizes_observation() -> None:
    item = {
        "raw_output_id": "raw-006-focused_dynamic_validation",
        "index": 6,
        "function_id": "dynamic.vm_validate_behavior",
        "function_name": "Focused VMware behavior validation",
        "result_key": "focused_dynamic_validation",
        "status": "success",
        "output": {
            "function_id": "dynamic.vm_validate_behavior",
            "result_key": "focused_dynamic_validation",
            "status": "success",
            "data": {
                "target": {
                    "behavior_category": "registry_persistence",
                    "validation_sample_id": "registry_run_key_fixture",
                },
                "observed": True,
                "matched_behavior": {
                    "category": "registry_persistence",
                    "evidence": [
                        {
                            "event_group": "registry_events",
                            "event_type": "registry_set",
                            "key_path": "HKCU\\Run",
                            "reason": "event_type:registry_set",
                        }
                    ],
                },
                "telemetry": {"total_events": 1, "event_counts": {"registry_events": 1}},
                "validation_scope": "benign_single_point_fixture",
            },
            "error": None,
        },
    }

    result = sorter.sort_raw_output_item(item)

    assert result["sort_status"] == "sorted"
    assert result["ai_payload"]["key_fields"]["observed"] is True
    assert result["ai_payload"]["evidence_hints"][0]["event_group"] == "registry_events"


def test_sort_raw_output_item_fallback_when_sorter_errors(tmp_path, monkeypatch) -> None:
    raw_sorting_dir = tmp_path / "raw_sorting"
    raw_sorting_dir.mkdir()
    (raw_sorting_dir / "bad_sorter.py").write_text(
        "def sort_output(raw_output_item):\n    raise RuntimeError('boom')\n",
        encoding="utf-8",
    )
    index = raw_sorting_dir / "raw_sorting_index.json"
    index.write_text(
        json.dumps(
            {
                "sorters": [
                    {
                        "function_id": "strings.extract",
                        "sorter_file": "bad_sorter.py",
                        "callable": "sort_output",
                    }
                ],
                "fallback": "raw",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sorter, "RAW_SORTING_DIR", raw_sorting_dir)
    monkeypatch.setattr(sorter, "RAW_SORTING_INDEX", index)

    result = sorter.sort_raw_output_item(sample_item())

    assert result["sort_status"] == "sort_error_fallback"
    assert "boom" in result["sort_error"]
    assert "raw_output" in result["ai_payload"]


def test_workflow_run_creates_ai_output_and_raw_output_remains_available(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    monkeypatch.setattr(sorter, "RAW_SORTING_INDEX", tmp_path / "missing_index.json")
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello world")},
    ).json()
    workflow = {
        "name": "basic",
        "steps": [
            {"function_id": "hash.compute", "params": {}},
            {"function_id": "file.byte_stats", "params": {}},
        ],
    }
    client.post(f"/api/sessions/{session['session_id']}/workflow", json=workflow)

    response = client.post(f"/api/sessions/{session['session_id']}/run")

    assert response.status_code == 200
    ai_output = response.json()["ai_output"]
    raw_output = main.store.get_raw_output(session["session_id"])
    assert len(ai_output["items"]) == len(raw_output["items"]) == 2
    assert ai_output["items"][0]["sort_status"] == "raw_fallback"

    api_ai_output = client.get(f"/api/sessions/{session['session_id']}/ai-output")
    api_ai_item = client.get(
        f"/api/sessions/{session['session_id']}/ai-output/{ai_output['items'][0]['raw_output_id']}"
    )
    api_raw_item = client.get(
        f"/api/sessions/{session['session_id']}/raw-output/{raw_output['items'][0]['raw_output_id']}"
    )
    assert api_ai_output.status_code == 200
    assert api_ai_item.status_code == 200
    assert api_raw_item.status_code == 200


def test_run_function_appends_ai_output_item(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    monkeypatch.setattr(sorter, "RAW_SORTING_INDEX", tmp_path / "missing_index.json")
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello world")},
    ).json()

    response = client.post(
        f"/api/sessions/{session['session_id']}/functions/run",
        json={"function_id": "file.byte_stats", "params": {}},
    )

    assert response.status_code == 200
    assert response.json()["ai_output_item"]["sort_status"] == "raw_fallback"
    assert main.store.get_ai_output(session["session_id"])["items"][0]["function_id"] == "file.byte_stats"


def test_mcp_run_workflow_and_run_function_return_ai_payloads(monkeypatch) -> None:
    def fake_request(method, path, body=None):
        if path.endswith("/functions/run"):
            return {
                "summary": {"status": "completed"},
                "ai_output_item": {"raw_output_id": "raw-002-byte_stats"},
            }
        if path.endswith("/run"):
            return {
                "session_id": "session",
                "summary": {"status": "completed"},
                "ai_output": {"session_id": "session", "items": [{"raw_output_id": "raw-001-hash"}]},
            }
        return {
            "summary": {"status": "completed"},
            "ai_output_item": {"raw_output_id": "raw-002-byte_stats"},
        }

    monkeypatch.setattr(server, "_request_json", fake_request)

    workflow_result = server.run_workflow("session")
    function_result = server.run_function("session", "file.byte_stats", {})

    assert "ai_output" in workflow_result
    assert workflow_result["ai_output"]["items"][0]["raw_output_id"] == "raw-001-hash"
    assert function_result["ai_output_item"]["raw_output_id"] == "raw-002-byte_stats"
