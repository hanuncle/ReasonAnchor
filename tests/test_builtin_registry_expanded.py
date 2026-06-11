from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from security_function_platform.api import main
from security_function_platform.api.builtin_registry import create_builtin_registry
from security_function_platform.api.session_store import SessionStore


EXPECTED_FUNCTION_IDS = {
    "hash.compute",
    "file.type_detect",
    "file.multi_format_parse",
    "file.byte_stats",
    "pe.deep_parse",
    "strings.extract",
    "strings.enhanced_extract",
    "ioc.extract",
    "packer.detect_enhanced",
    "yara.scan_local",
    "tool.detect_it_easy",
    "tool.capa_analyze",
    "tool.floss_extract",
    "file.lief_parse",
    "tool.ida_function_analyze",
    "tool.ida_function_features",
    "tool.ghidra_function_analyze",
    "tool.ghidra_function_features",
    "tool.binaryninja_function_analyze",
    "behavior.map_static",
    "attack.map_static",
    "behavior.map_dynamic",
    "validation.compare_static_dynamic",
    "validation.plan_focused_dynamic",
    "dynamic.vm_status",
    "dynamic.vm_restore_snapshot",
    "dynamic.vm_upload_sample",
    "dynamic.vm_run_sample",
    "dynamic.vm_collect_sysmon",
    "dynamic.vm_validate_behavior",
    "dynamic.vm_save_snapshot",
    "ti.virustotal.hash_lookup",
    "ti.malwarebazaar.hash_lookup",
    "ti.virustotal.behaviour_summary",
}

MIGRATED_REVERSE_FUNCTION_IDS = {
    "hash.compute",
    "file.type_detect",
    "file.multi_format_parse",
    "file.byte_stats",
    "pe.deep_parse",
    "strings.extract",
    "strings.enhanced_extract",
    "ioc.extract",
    "packer.detect_enhanced",
    "yara.scan_local",
    "tool.detect_it_easy",
    "tool.capa_analyze",
    "tool.floss_extract",
    "file.lief_parse",
    "tool.ida_function_analyze",
    "tool.ida_function_features",
    "tool.ghidra_function_analyze",
    "tool.ghidra_function_features",
    "tool.binaryninja_function_analyze",
    "behavior.map_static",
    "attack.map_static",
    "behavior.map_dynamic",
    "validation.compare_static_dynamic",
    "validation.plan_focused_dynamic",
    "dynamic.vm_status",
    "dynamic.vm_restore_snapshot",
    "dynamic.vm_upload_sample",
    "dynamic.vm_run_sample",
    "dynamic.vm_collect_sysmon",
    "dynamic.vm_validate_behavior",
    "dynamic.vm_save_snapshot",
    "ti.virustotal.hash_lookup",
    "ti.malwarebazaar.hash_lookup",
    "ti.virustotal.behaviour_summary",
}

REVERSE_MODULE = Path(__file__).resolve().parents[1] / "modules" / "reverse" / "module.json"
requires_reverse_module = pytest.mark.skipif(
    not REVERSE_MODULE.is_file(),
    reason="reverse module is not included in this platform-only checkout",
)


def test_builtin_registry_is_empty_after_module_migration() -> None:
    registry = create_builtin_registry()

    assert registry.list_functions() == []


@requires_reverse_module
def test_api_functions_contains_expanded_functions() -> None:
    client = TestClient(main.app)

    response = client.get("/api/functions")

    assert response.status_code == 200
    assert EXPECTED_FUNCTION_IDS <= {item["id"] for item in response.json()}
    by_id = {item["id"]: item for item in response.json()}
    for function_id in MIGRATED_REVERSE_FUNCTION_IDS:
        assert by_id[function_id]["source"] == "module"
        assert by_id[function_id]["module_id"] == "reverse"


@requires_reverse_module
def test_session_workflow_can_save_and_run_new_static_functions(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={
            "file": (
                "sample.exe",
                b"MZ\x00hello world\x00http://example.com/a\x00192.168.1.10\x00",
            )
        },
    ).json()

    workflow = {
        "name": "static_ioc_multiformat",
        "steps": [
            {"function_id": "hash.compute", "params": {}},
            {"function_id": "file.multi_format_parse", "params": {}},
            {"function_id": "strings.extract", "params": {"min_length": 4}},
            {"function_id": "ioc.extract", "params": {}},
        ],
    }
    save_response = client.post(
        f"/api/sessions/{session['session_id']}/workflow",
        json=workflow,
    )
    run_response = client.post(f"/api/sessions/{session['session_id']}/run")

    assert save_response.status_code == 200
    assert run_response.status_code == 200
    raw_outputs = run_response.json()["raw_outputs"]
    assert {"hash", "multi_format_parser", "strings", "ioc_extractor"} <= set(raw_outputs)


@requires_reverse_module
def test_session_workflow_can_run_byte_stats_and_write_raw_output(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"MZ\x00ABC\n\x00")},
    ).json()
    workflow = {
        "name": "byte_stats_test",
        "steps": [
            {"function_id": "hash.compute", "params": {}},
            {"function_id": "file.byte_stats", "params": {"max_header_bytes": 16}},
        ],
    }

    save_response = client.post(
        f"/api/sessions/{session['session_id']}/workflow",
        json=workflow,
    )
    run_response = client.post(f"/api/sessions/{session['session_id']}/run")

    assert save_response.status_code == 200
    assert run_response.status_code == 200
    assert "byte_stats" in run_response.json()["raw_outputs"]
    raw_output = main.store.get_raw_output(session["session_id"])
    assert raw_output["items"][1]["function_id"] == "file.byte_stats"
    assert raw_output["items"][1]["raw_output_id"] == "raw-002-byte_stats"


@requires_reverse_module
def test_run_function_api_can_run_byte_stats(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)
    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"MZ\x00ABC\n\x00")},
    ).json()

    response = client.post(
        f"/api/sessions/{session['session_id']}/functions/run",
        json={"function_id": "file.byte_stats", "params": {"max_header_bytes": 2}},
    )

    assert response.status_code == 200
    assert response.json()["result"]["result_key"] == "byte_stats"
    assert response.json()["result"]["data"]["header_hex"] == "4d5a"
