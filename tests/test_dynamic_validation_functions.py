from tests.module_function_helpers import reverse_function_class

BehaviorMapDynamicFunction = reverse_function_class(
    "behavior_map_dynamic.py",
    "BehaviorMapDynamicFunction",
)
ValidationCompareStaticDynamicFunction = reverse_function_class(
    "validation_compare_static_dynamic.py",
    "ValidationCompareStaticDynamicFunction",
)
ValidationPlanFocusedDynamicFunction = reverse_function_class(
    "validation_plan_focused_dynamic.py",
    "ValidationPlanFocusedDynamicFunction",
)
ValidationCompareStaticDynamicFunctionLevelFunction = reverse_function_class(
    "validation_compare_static_dynamic_function.py",
    "ValidationCompareStaticDynamicFunctionLevelFunction",
)
ValidationPlanFocusedFunctionLevelFunction = reverse_function_class(
    "validation_plan_focused_function_level.py",
    "ValidationPlanFocusedFunctionLevelFunction",
)
FocusedFunctionLevelAnalysisFunction = reverse_function_class(
    "focused_function_level_analysis.py",
    "FocusedFunctionLevelAnalysisFunction",
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


def test_behavior_map_dynamic_filters_environment_noise_when_sample_identity_known() -> None:
    telemetry = {
        "schema_version": "1",
        "telemetry_id": "attribution-test",
        "process_events": [
            {
                "event_id": "evt-001",
                "event_type": "process_create",
                "process_guid": "{sample}",
                "pid": 100,
                "process_name": "sample.exe",
                "command_line": "C:\\Samples\\sample.exe",
            },
            {
                "event_id": "evt-002",
                "event_type": "process_create",
                "process_guid": "{child}",
                "parent_process_guid": "{sample}",
                "pid": 101,
                "parent_pid": 100,
                "process_name": "cmd.exe",
                "command_line": "cmd.exe /c whoami",
            },
            {
                "event_id": "evt-003",
                "event_type": "process_create",
                "process_name": "powershell.exe",
                "command_line": (
                    "powershell.exe -File C:\\Tools\\Export-DynamicTelemetry.ps1 "
                    "-OutFile C:\\Telemetry\\dynamic_telemetry.json"
                ),
            },
            {
                "event_id": "evt-004",
                "event_type": "process_create",
                "process_name": "cmd.exe",
                "command_line": (
                    "C:\\WINDOWS\\system32\\cmd.exe /c "
                    "\"C:\\Program Files\\VMware\\VMware Tools\\poweron-vm-default.bat\""
                ),
            },
        ],
        "file_events": [
            {
                "event_id": "evt-005",
                "event_type": "file_create",
                "process_name": "powershell.exe",
                "path": "C:\\Users\\user\\AppData\\Local\\Temp\\__PSScriptPolicyTest_x.psm1",
            }
        ],
        "network_events": [
            {
                "event_id": "evt-006",
                "event_type": "network_connect",
                "process_guid": "{sample}",
                "process_name": "sample.exe",
                "destination_host": "example.test",
            }
        ],
    }

    result = BehaviorMapDynamicFunction().run(
        {"filename": "sample.exe", "results": {}},
        {"telemetry": telemetry},
    )

    assert result.status == "success"
    categories = {item["category"] for item in result.data["behaviors"]}
    assert "command_execution" in categories
    assert "network_communication" in categories
    assert "anti_analysis" not in categories
    assert "file_write" not in categories
    assert result.data["attribution"]["strict"] is True
    assert result.data["counts"]["mapped_events"] == 3
    assert result.data["counts"]["excluded_events"] == 3
    assert result.data["attribution"]["counts"]["environment_noise"] == 3


def test_behavior_map_dynamic_does_not_confirm_by_process_name_only() -> None:
    telemetry = {
        "schema_version": "1",
        "telemetry_id": "process-name-attribution-test",
        "process_events": [
            {
                "event_id": "evt-seed",
                "event_type": "process_create",
                "process_guid": "{sample}",
                "pid": 100,
                "process_name": "sample.exe",
                "command_line": "C:\\Samples\\sample.exe",
            },
            {
                "event_id": "evt-child",
                "event_type": "process_create",
                "process_guid": "{child}",
                "parent_process_guid": "{sample}",
                "pid": 101,
                "parent_pid": 100,
                "process_name": "svchost.exe",
                "command_line": "C:\\Windows\\System32\\svchost.exe -k sample",
            },
            {
                "event_id": "evt-noise",
                "event_type": "process_create",
                "pid": 202,
                "process_name": "svchost.exe",
                "command_line": "C:\\Windows\\System32\\svchost.exe -k unrelated",
            },
        ],
        "network_events": [
            {
                "event_id": "evt-child-net",
                "event_type": "network_connect",
                "pid": 101,
                "process_name": "svchost.exe",
                "destination_host": "sample.example",
            },
            {
                "event_id": "evt-noise-net",
                "event_type": "network_connect",
                "pid": 202,
                "process_name": "svchost.exe",
                "destination_host": "windows.example",
            },
        ],
    }

    result = BehaviorMapDynamicFunction().run(
        {"filename": "sample.exe", "results": {}},
        {"telemetry": telemetry},
    )

    assert result.status == "success"
    event_ids = {
        evidence["event_id"]
        for behavior in result.data["behaviors"]
        for evidence in behavior["evidence"]
    }
    assert "evt-child-net" in event_ids
    assert "evt-noise" not in event_ids
    assert "evt-noise-net" not in event_ids
    assert result.data["counts"]["mapped_events"] == 3
    assert result.data["counts"]["excluded_events"] == 2


def test_behavior_map_dynamic_does_not_reuse_pid_when_raw_guid_changes() -> None:
    telemetry = {
        "schema_version": "1",
        "telemetry_id": "pid-reuse-attribution-test",
        "process_events": [
            {
                "event_id": "evt-seed",
                "event_type": "process_create",
                "pid": 100,
                "process_name": "sample.exe",
                "command_line": "C:\\Samples\\sample.exe",
                "raw": (
                    "Process Create: ProcessGuid: {sample-guid} ProcessId: 100 "
                    "Image: C:\\Samples\\sample.exe"
                ),
            },
            {
                "event_id": "evt-child",
                "event_type": "process_create",
                "pid": 200,
                "parent_pid": 100,
                "process_name": "wscript.exe",
                "command_line": "wscript.exe C:\\Users\\user\\drop.vbs",
                "raw": (
                    "Process Create: ProcessGuid: {child-guid} ProcessId: 200 "
                    "Image: C:\\Windows\\System32\\wscript.exe"
                ),
            },
            {
                "event_id": "evt-reused-pid",
                "event_type": "process_create",
                "pid": 200,
                "parent_pid": 4,
                "process_name": "svchost.exe",
                "command_line": "C:\\Windows\\System32\\svchost.exe -k unrelated",
                "raw": (
                    "Process Create: ProcessGuid: {reused-guid} ProcessId: 200 "
                    "Image: C:\\Windows\\System32\\svchost.exe"
                ),
            },
        ],
        "network_events": [
            {
                "event_id": "evt-reused-net",
                "event_type": "network_connect",
                "pid": 200,
                "process_name": "svchost.exe",
                "destination_host": "windows.example",
                "raw": (
                    "Network connection detected: ProcessGuid: {reused-guid} "
                    "ProcessId: 200 Image: C:\\Windows\\System32\\svchost.exe"
                ),
            }
        ],
    }

    result = BehaviorMapDynamicFunction().run(
        {"filename": "sample.exe", "results": {}},
        {"telemetry": telemetry},
    )

    assert result.status == "success"
    event_ids = {
        evidence["event_id"]
        for behavior in result.data["behaviors"]
        for evidence in behavior["evidence"]
    }
    assert "evt-child" in event_ids
    assert "evt-reused-pid" not in event_ids
    assert "evt-reused-net" not in event_ids
    assert result.data["counts"]["mapped_events"] == 2
    assert result.data["counts"]["excluded_events"] == 2


def test_behavior_map_dynamic_errors_when_telemetry_missing() -> None:
    result = BehaviorMapDynamicFunction().run({"results": {}}, {})

    assert result.status == "error"
    assert result.error["code"] == "missing_dynamic_telemetry"


def test_behavior_map_dynamic_skips_when_telemetry_was_skipped() -> None:
    result = BehaviorMapDynamicFunction().run(
        {
            "results": {
                "dynamic_telemetry": {
                    "status": "skipped",
                    "data": {"skip_reason": "dynamic_vm_preflight_not_ready"},
                }
            }
        },
        {},
    )

    assert result.status == "skipped"
    assert result.data["skip_reason"] == "dynamic_vm_preflight_not_ready"
    assert result.data["counts"]["telemetry_events"] == 0


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


def test_validation_compare_and_plan_skip_when_dynamic_map_skipped() -> None:
    context = {
        "results": {
            "static_behavior_map": {
                "status": "success",
                "data": {"behaviors": [{"category": "network_communication"}]},
            },
            "dynamic_behavior_map": {
                "status": "skipped",
                "data": {"skip_reason": "dynamic_vm_preflight_not_ready"},
            },
        }
    }

    compare = ValidationCompareStaticDynamicFunction().run(context, {})
    context["results"]["static_dynamic_validation"] = compare.to_dict()
    plan = ValidationPlanFocusedDynamicFunction().run(context, {})

    assert compare.status == "skipped"
    assert compare.data["summary"]["static_candidates"] == 1
    assert plan.status == "skipped"
    assert plan.data["counts"]["targets"] == 0


def test_static_dynamic_function_level_compare_and_plan_gaps() -> None:
    context = {
        "results": {
            "static_behavior_map": {
                "status": "success",
                "data": {
                    "behaviors": [
                        {
                            "category": "command_execution",
                            "confidence": "high",
                            "score": 6,
                            "evidence": [{"value": "CreateProcessW"}],
                            "related_functions": [
                                {
                                    "tool": "ida",
                                    "name": "sub_140001000",
                                    "address": "0x140001000",
                                    "evidence": ["CreateProcessW"],
                                }
                            ],
                        },
                        {
                            "category": "credential_access",
                            "confidence": "low",
                            "score": 1,
                            "evidence": [{"value": "password"}],
                        },
                    ]
                },
            },
            "dynamic_behavior_map": {
                "status": "success",
                "data": {
                    "behaviors": [
                        {"category": "command_execution", "confidence": "high", "score": 5}
                    ]
                },
            },
            "ida_function_features": {
                "status": "success",
                "data": {"functions": []},
            },
        }
    }

    compare = ValidationCompareStaticDynamicFunctionLevelFunction().run(context, {})
    context["results"]["static_dynamic_function_validation"] = compare.to_dict()
    plan = ValidationPlanFocusedFunctionLevelFunction().run(context, {})

    assert compare.status == "success"
    by_category = {item["category"]: item for item in compare.data["comparisons"]}
    assert by_category["command_execution"]["gap"] == "covered"
    assert by_category["credential_access"]["gap"] == (
        "needs_focused_dynamic_and_function_level"
    )
    assert plan.status == "success"
    assert plan.data["targets"][0]["behavior_category"] == "credential_access"


def test_focused_function_level_analysis_reviews_recovered_features() -> None:
    context = {
        "results": {
            "focused_function_level_plan": {
                "status": "success",
                "data": {
                    "targets": [
                        {
                            "behavior_category": "command_execution",
                            "gap": "needs_focused_function_level",
                            "keywords": ["CreateProcess"],
                            "static_evidence": [{"value": "CreateProcessW"}],
                        }
                    ]
                },
            },
            "ida_function_features": {
                "status": "success",
                "data": {
                    "functions": [
                        {
                            "name": "sub_140001000",
                            "start": "0x140001000",
                            "size": 40,
                            "api_calls": ["CreateProcessW"],
                            "strings": [],
                            "candidate_behaviors": [
                                {
                                    "category": "command_execution",
                                    "keywords": ["createprocess"],
                                }
                            ],
                        }
                    ]
                },
            },
        }
    }

    result = FocusedFunctionLevelAnalysisFunction().run(context, {})

    assert result.status == "success"
    assert result.data["summary"]["found"] == 1
    target = result.data["targets"][0]
    assert target["status"] == "found"
    assert target["matching_functions"][0]["name"] == "sub_140001000"
