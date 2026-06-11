from tests.module_function_helpers import reverse_function_class

BehaviorMapDynamicFunction = reverse_function_class(
    "behavior_map_dynamic.py",
    "BehaviorMapDynamicFunction",
)
ValidationCompareStaticDynamicFunction = reverse_function_class(
    "validation_compare_static_dynamic.py",
    "ValidationCompareStaticDynamicFunction",
)


def simulated_dynamic_telemetry():
    return {
        "schema_version": "1",
        "telemetry_id": "test-telemetry",
        "process_events": [
            {
                "event_id": "evt-001",
                "event_type": "process_create",
                "process_name": "cmd.exe",
                "command_line": "cmd.exe /c whoami",
                "parent_process_name": "sample.exe",
            },
            {
                "event_id": "evt-002",
                "event_type": "memory_write",
                "process_name": "sample.exe",
                "target_process_name": "explorer.exe",
                "api": "WriteProcessMemory",
            },
            {
                "event_id": "evt-003",
                "event_type": "remote_thread_create",
                "process_name": "sample.exe",
                "target_process_name": "explorer.exe",
                "api": "CreateRemoteThread",
            },
        ],
        "file_events": [
            {
                "event_id": "evt-004",
                "event_type": "file_write",
                "process_name": "sample.exe",
                "path": "C:\\Users\\Public\\drop.bin",
            }
        ],
        "registry_events": [
            {
                "event_id": "evt-005",
                "event_type": "registry_set",
                "process_name": "sample.exe",
                "key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value_name": "Demo",
                "data": "C:\\Users\\Public\\drop.bin",
            }
        ],
        "network_events": [
            {
                "event_id": "evt-006",
                "event_type": "dns_query",
                "process_name": "sample.exe",
                "destination_host": "example.test",
            }
        ],
    }


def test_behavior_map_dynamic_maps_simulated_telemetry() -> None:
    result = BehaviorMapDynamicFunction().run(
        {"results": {}},
        {"telemetry": simulated_dynamic_telemetry()},
    )

    assert result.status == "success"
    categories = {item["category"] for item in result.data["behaviors"]}
    assert {
        "command_execution",
        "process_injection",
        "file_write",
        "registry_persistence",
        "network_communication",
    } <= categories
    assert result.data["counts"]["telemetry_events"] == 6
    assert result.data["requires_human_confirmation"] is True


def test_behavior_map_dynamic_can_read_context_result() -> None:
    context = {
        "results": {
            "dynamic_telemetry": {
                "function_id": "dynamic.telemetry_fixture",
                "result_key": "dynamic_telemetry",
                "status": "success",
                "data": simulated_dynamic_telemetry(),
                "error": None,
            }
        }
    }

    result = BehaviorMapDynamicFunction().run(context, {})

    assert result.status == "success"
    assert result.data["source"] == "results.dynamic_telemetry"


def test_behavior_map_dynamic_errors_when_telemetry_missing() -> None:
    result = BehaviorMapDynamicFunction().run({"results": {}}, {})

    assert result.status == "error"
    assert result.error["code"] == "missing_dynamic_telemetry"


def test_validation_compare_static_dynamic_compares_behavior_sets() -> None:
    context = {
        "results": {
            "static_behavior_map": {
                "function_id": "behavior.map_static",
                "result_key": "static_behavior_map",
                "status": "success",
                "data": {
                    "behaviors": [
                        {
                            "category": "command_execution",
                            "confidence": "medium",
                            "score": 3,
                            "evidence": [{"source_result": "strings"}],
                        },
                        {
                            "category": "credential_access",
                            "confidence": "low",
                            "score": 1,
                            "evidence": [{"source_result": "strings"}],
                        },
                    ]
                },
                "error": None,
            },
            "dynamic_behavior_map": {
                "function_id": "behavior.map_dynamic",
                "result_key": "dynamic_behavior_map",
                "status": "success",
                "data": {
                    "behaviors": [
                        {
                            "category": "command_execution",
                            "confidence": "high",
                            "score": 6,
                            "evidence": [{"source_result": "dynamic_telemetry"}],
                        },
                        {
                            "category": "network_communication",
                            "confidence": "low",
                            "score": 2,
                            "evidence": [{"source_result": "dynamic_telemetry"}],
                        },
                    ]
                },
                "error": None,
            },
        }
    }

    result = ValidationCompareStaticDynamicFunction().run(context, {})

    assert result.status == "success"
    by_category = {item["category"]: item for item in result.data["comparisons"]}
    assert by_category["command_execution"]["consistency"] == "matched"
    assert (
        by_category["credential_access"]["consistency"]
        == "static_candidate_not_observed"
    )
    assert (
        by_category["network_communication"]["consistency"]
        == "dynamic_observed_without_static_candidate"
    )
    assert result.data["summary"]["matched"] == 1
    assert result.data["requires_human_confirmation"] is True


def test_validation_compare_static_dynamic_errors_when_inputs_missing() -> None:
    result = ValidationCompareStaticDynamicFunction().run({"results": {}}, {})

    assert result.status == "error"
    assert result.error["code"] == "missing_static_behavior_map"
