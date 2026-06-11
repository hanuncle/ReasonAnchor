from security_function_platform.api import main


METADATA_FIELDS = [
    "description",
    "requires",
    "requires_results",
    "recommended_before",
    "cost",
    "network",
    "external",
    "external_tool",
    "config_required",
    "config_requirements",
    "optional",
    "candidate_only",
    "requires_human_confirmation",
    "output_schema",
]


def test_all_function_info_contains_metadata_fields() -> None:
    registry = main._current_registry()

    for item in registry.list_functions():
        for field in METADATA_FIELDS:
            assert field in item


def test_ioc_extract_declares_strings_dependency() -> None:
    info = main._current_registry().get("ioc.extract").info()

    assert "strings" in info["requires_results"]
    assert "strings.extract" in info["recommended_before"]
    assert info["candidate_only"] is True
    assert info["requires_human_confirmation"] is True


def test_threat_intelligence_functions_are_external_candidates() -> None:
    registry = main._current_registry()

    for function_id in [
        "ti.virustotal.hash_lookup",
        "ti.malwarebazaar.hash_lookup",
        "ti.virustotal.behaviour_summary",
    ]:
        info = registry.get(function_id).info()
        assert info["network"] is True
        assert info["external"] is True
        assert info["candidate_only"] is True
        assert info["requires_human_confirmation"] is True
        assert info["config_required"] is True
        assert "hash" in info["requires_results"]


def test_external_tool_functions_are_optional_high_cost() -> None:
    registry = main._current_registry()

    for function_id in [
        "tool.detect_it_easy",
        "tool.capa_analyze",
        "tool.floss_extract",
        "tool.ida_function_analyze",
        "tool.ida_function_features",
        "tool.ghidra_function_analyze",
        "tool.ghidra_function_features",
        "tool.binaryninja_function_analyze",
    ]:
        info = registry.get(function_id).info()
        assert info["external_tool"] is True
        assert info["optional"] is True
        assert info["cost"] == "high"
        assert info["config_required"] is True


def test_dynamic_vm_functions_are_external_and_configured() -> None:
    registry = main._current_registry()

    for function_id in [
        "dynamic.vm_status",
        "dynamic.vm_restore_snapshot",
        "dynamic.vm_upload_sample",
        "dynamic.vm_run_sample",
        "dynamic.vm_collect_sysmon",
        "dynamic.vm_validate_behavior",
        "dynamic.vm_save_snapshot",
    ]:
        info = registry.get(function_id).info()
        assert info["external_tool"] is True
        assert info["optional"] is True
        assert info["config_required"] is True

    assert registry.get("dynamic.vm_run_sample").info()["requires_human_confirmation"] is True
    assert registry.get("dynamic.vm_validate_behavior").info()["requires_human_confirmation"] is True
    assert registry.get("dynamic.vm_restore_snapshot").info()["requires_human_confirmation"] is True


def test_deep_static_candidates_require_human_confirmation() -> None:
    registry = main._current_registry()

    for function_id in [
        "strings.enhanced_extract",
        "packer.detect_enhanced",
        "behavior.map_static",
        "attack.map_static",
        "behavior.map_dynamic",
        "validation.compare_static_dynamic",
        "validation.plan_focused_dynamic",
    ]:
        info = registry.get(function_id).info()
        assert info["candidate_only"] is True
        assert info["requires_human_confirmation"] is True


def test_attack_mapping_requires_behavior_map() -> None:
    info = main._current_registry().get("attack.map_static").info()

    assert "static_behavior_map" in info["requires_results"]
    assert "behavior.map_static" in info["recommended_before"]


def test_static_dynamic_validation_requires_behavior_maps() -> None:
    info = main._current_registry().get("validation.compare_static_dynamic").info()

    assert "static_behavior_map" in info["requires_results"]
    assert "dynamic_behavior_map" in info["requires_results"]
    assert "behavior.map_static" in info["recommended_before"]
    assert "behavior.map_dynamic" in info["recommended_before"]


def test_capa_and_yara_output_schema_warns_about_candidate_evidence() -> None:
    registry = main._current_registry()

    capa_schema = registry.get("tool.capa_analyze").info()["output_schema"]
    yara_schema = registry.get("yara.scan_local").info()["output_schema"]

    assert "capability_candidates" in capa_schema
    assert "rule_evidence" in capa_schema
    assert "candidate evidence" in yara_schema["matched_rules"]
    assert "confirmed" in yara_schema["verification"]
