from __future__ import annotations

from tests.module_function_helpers import reverse_function_class

BehaviorMapStaticFunction = reverse_function_class(
    "behavior_map_static.py",
    "BehaviorMapStaticFunction",
)
AttackMapStaticFunction = reverse_function_class(
    "attack_map_static.py",
    "AttackMapStaticFunction",
)


def test_behavior_map_static_maps_imports_strings_features_and_packer() -> None:
    result = BehaviorMapStaticFunction().run(_static_context(), {})

    assert result.status == "success"
    by_category = {
        item["category"]: item
        for item in result.data["behaviors"]
    }
    assert {
        "command_execution",
        "network_communication",
        "registry_persistence",
        "process_injection",
        "credential_access",
        "anti_analysis",
        "packer_or_obfuscation",
    } <= set(by_category)
    assert by_category["command_execution"]["related_functions"][0]["name"] == "main"
    assert by_category["process_injection"]["confidence"] in {"medium", "high"}
    assert result.data["requires_human_confirmation"] is True


def test_attack_map_static_uses_knowledge_and_fallback_mappings() -> None:
    context = _static_context()
    behavior_result = BehaviorMapStaticFunction().run(context, {})
    context["results"]["static_behavior_map"] = behavior_result.to_dict()

    result = AttackMapStaticFunction().run(context, {})

    assert result.status == "success"
    by_id = {item["technique_id"]: item for item in result.data["techniques"]}
    assert by_id["T1059"]["source"] == "module_knowledge"
    assert by_id["T1055"]["source"] == "module_knowledge"
    assert by_id["T1547.001"]["source"] == "module_knowledge"
    assert by_id["T1027"]["source"] == "builtin_fallback"
    assert result.data["requires_human_confirmation"] is True


def test_attack_map_static_requires_behavior_map() -> None:
    result = AttackMapStaticFunction().run({"results": {}}, {})

    assert result.status == "error"
    assert result.error["code"] == "missing_behavior_map"


def _static_context() -> dict:
    return {
        "results": {
            "pe_deep_parse": {
                "status": "success",
                "data": {
                    "imports": [
                        {
                            "dll": "kernel32.dll",
                            "functions": [
                                "CreateProcessW",
                                "OpenProcess",
                                "VirtualAllocEx",
                                "WriteProcessMemory",
                                "CreateRemoteThread",
                            ],
                        },
                        {
                            "dll": "advapi32.dll",
                            "functions": ["RegSetValueExW"],
                        },
                    ]
                },
            },
            "strings": {
                "status": "success",
                "data": {
                    "items": [
                        "powershell -enc AAAA",
                        "http://example.com/payload",
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\demo",
                    ],
                    "urls": ["http://example.com/payload"],
                    "ips": [],
                },
            },
            "enhanced_strings": {
                "status": "success",
                "data": {
                    "urls": ["http://example.com/payload"],
                    "registry_keys": [
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\demo"
                    ],
                    "suspicious_keywords": {
                        "anti_analysis": ["IsDebuggerPresent"],
                        "credential_access": ["lsass.exe"],
                    },
                },
            },
            "ioc_extractor": {
                "status": "success",
                "data": {
                    "urls": ["http://example.com/payload"],
                    "ipv4": [],
                    "domains": ["example.com"],
                    "registry_keys": [
                        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\demo"
                    ],
                },
            },
            "ida_function_features": {
                "status": "success",
                "data": {
                    "functions": [
                        {
                            "name": "main",
                            "start": "0x1000",
                            "size": 32,
                            "api_calls": ["CreateProcessW", "InternetOpenA"],
                            "strings": ["powershell -enc AAAA"],
                            "candidate_behaviors": [
                                {
                                    "category": "command_execution",
                                    "keywords": ["createprocess", "powershell"],
                                }
                            ],
                        }
                    ]
                },
            },
            "ghidra_function_features": {
                "status": "success",
                "data": {
                    "functions": [
                        {
                            "name": "inject",
                            "start": "00402000",
                            "size": 64,
                            "api_calls": [
                                "OpenProcess",
                                "VirtualAllocEx",
                                "WriteProcessMemory",
                                "CreateRemoteThread",
                            ],
                            "strings": [],
                            "candidate_behaviors": [
                                {
                                    "category": "process_injection",
                                    "keywords": ["writeprocessmemory"],
                                }
                            ],
                        }
                    ]
                },
            },
            "packer_detection": {
                "status": "success",
                "data": {"likely_packed": True, "confidence": "medium"},
            },
        }
    }
