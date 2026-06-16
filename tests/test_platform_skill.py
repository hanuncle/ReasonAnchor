import json
from pathlib import Path

import pytest

from security_function_platform.mcp_server import server


MCP_TOOL_NAMES = [
    "get_platform_skill",
    "upload_sample",
    "upload_samples",
    "create_target_session",
    "list_functions",
    "save_custom_workflow",
    "list_custom_workflows",
    "list_modules",
    "get_module_template",
    "get_module_detail",
    "get_module_skill",
    "get_module_ui",
    "get_module_knowledge",
    "create_module",
    "load_module",
    "package_module",
    "export_module",
    "import_module_archive",
    "list_module_knowledge",
    "upsert_module_ui_page",
    "select_custom_workflow",
    "run_workflow",
    "run_batch_workflow",
    "submit_batch_workflow_job",
    "list_batch_jobs",
    "get_batch_job",
    "list_sample_set_reports",
    "get_sample_set_report",
    "get_ai_output",
    "get_ai_output_by_raw_id",
    "get_raw_output_map",
    "get_raw_output_by_id",
    "run_function",
    "get_mcp_file_access_policy",
    "inspect_allowed_files",
    "write_allowed_file",
    "save_session_result",
]

MCP_REFERENCE_FIELDS = [
    "purpose",
    "use_when",
    "inputs",
    "returns",
    "do_not_use_when",
]

REVERSE_PLAYBOOK_PATH = Path("modules/reverse/skill/playbook.json")
requires_reverse_module = pytest.mark.skipif(
    not REVERSE_PLAYBOOK_PATH.is_file(),
    reason="reverse module is not included in this platform-only checkout",
)


def test_platform_skill_files_exist_and_playbook_parses() -> None:
    assert Path("config_files/codex_skill/SKILL.md").is_file()
    playbook_path = Path("config_files/codex_skill/default_analysis_playbook.json")
    assert playbook_path.is_file()

    playbook = json.loads(playbook_path.read_text(encoding="utf-8"))
    for key in [
        "required_order",
        "mcp_tools_by_step",
        "module_usage_policy",
        "decision_rules",
        "self_iteration_targets",
        "result_schema",
        "safety_rules",
        "mcp_tool_reference",
        "self_iteration_policy",
        "safe_default_functions",
        "optional_functions",
        "external_functions",
        "high_noise_functions",
        "requires_config_functions",
        "requires_prior_result",
        "function_group_source",
    ]:
        assert key in playbook


def test_skill_mentions_required_tools_and_rules() -> None:
    text = Path("config_files/codex_skill/SKILL.md").read_text(encoding="utf-8")

    for expected in [
        "upload_sample",
        "create_target_session",
        "run_workflow",
        "get_ai_output",
        "run_function",
        "write_allowed_file",
        "save_session_result",
        "get_module_template",
        "get_module_skill",
        "Self-Iteration",
        "Human Decision",
        "final_result_schema",
        "save_session_result",
    ]:
        assert expected in text


def test_skill_contains_mcp_tool_reference_for_all_tools() -> None:
    text = Path("config_files/codex_skill/SKILL.md").read_text(encoding="utf-8")

    assert "MCP Tool Reference" in text
    for tool_name in MCP_TOOL_NAMES:
        assert tool_name in text


def test_playbook_contains_mcp_tool_reference_for_all_tools() -> None:
    playbook = json.loads(
        Path("config_files/codex_skill/default_analysis_playbook.json").read_text(
            encoding="utf-8"
        )
    )

    reference = playbook["mcp_tool_reference"]
    assert set(reference) == set(MCP_TOOL_NAMES)
    for tool_name in MCP_TOOL_NAMES:
        for field in MCP_REFERENCE_FIELDS:
            assert field in reference[tool_name]


def test_get_platform_skill_returns_skill_and_playbook_without_secrets() -> None:
    result = server.get_platform_skill()
    serialized = json.dumps(result, ensure_ascii=False).lower()

    assert "skill" in result
    assert "playbook" in result
    assert "module_loading" in result
    assert "loaded_modules" not in result
    assert result["playbook"]["name"] == "security_function_platform_default_analysis_loop"
    assert result["module_loading"]["module_skill_tool"] == "get_module_skill"
    for forbidden in [
        "api key value",
        "auth-key value",
        "token value",
        "your_",
    ]:
        assert forbidden not in serialized


def test_skill_and_playbook_include_context_budget_and_noise_rules() -> None:
    skill_text = Path("config_files/codex_skill/SKILL.md").read_text(encoding="utf-8")
    playbook = json.loads(
        Path("config_files/codex_skill/default_analysis_playbook.json").read_text(
            encoding="utf-8"
        )
    )
    playbook_text = json.dumps(playbook, ensure_ascii=False)

    required_noise_rule = "When returned data is noisy, extract useful information first, then analyze it."
    if Path("AGENTS.md").is_file():
        assert required_noise_rule in Path("AGENTS.md").read_text(encoding="utf-8")
    assert required_noise_rule in skill_text
    assert required_noise_rule in playbook_text
    assert "Before raw detail, call `get_raw_output_map`" in skill_text
    assert "get_raw_output_map" in playbook_text
    assert "raw_output_id" in playbook_text


@requires_reverse_module
def test_playbook_function_groups_for_codex_orchestration() -> None:
    playbook = json.loads(
        Path("config_files/codex_skill/default_analysis_playbook.json").read_text(
            encoding="utf-8"
        )
    )
    reverse_playbook = json.loads(REVERSE_PLAYBOOK_PATH.read_text(encoding="utf-8"))

    assert playbook["function_group_source"] == (
        "Use get_module_skill(module_id).playbook for module-specific function groups."
    )
    assert playbook["module_usage_policy"]["module_template_tool"] == "get_module_template"
    assert playbook["module_usage_policy"]["module_ui_tool"] == "get_module_ui"
    assert playbook["module_usage_policy"]["module_knowledge_tool"] == "get_module_knowledge"
    assert playbook["module_usage_policy"]["module_ui_page_upsert_tool"] == (
        "upsert_module_ui_page"
    )
    assert "sample_set.report.v2" in playbook["module_usage_policy"]["cross_sample_report"]
    assert playbook["module_usage_policy"]["module_skill_loading"] == (
        "Load only the selected module skill/playbook/final_result_schema to reduce token use."
    )
    assert playbook["module_usage_policy"]["module_final_result_schema"] == (
        "Use get_module_skill(module_id).final_result_schema for the final AI summary format."
    )
    assert playbook["self_iteration_policy"]["ask_before_analysis"] is True
    assert playbook["self_iteration_policy"]["ask_after_final_summary"] is True
    assert playbook["self_iteration_policy"]["editable_scope"] == "selected_module_only"
    assert playbook["self_iteration_policy"]["forbidden_scope"] == "platform_code"
    assert playbook["safe_default_functions"] == []
    assert playbook["optional_functions"] == []
    assert playbook["external_functions"] == []
    assert playbook["high_noise_functions"] == []
    assert playbook["requires_config_functions"] == []
    assert playbook["requires_prior_result"] == {}
    assert "hash.compute" not in json.dumps(playbook)
    assert "modules/reverse" not in json.dumps(playbook)

    assert "hash.compute" in reverse_playbook["safe_default_functions"]
    assert reverse_playbook["safe_default_workflow"] == ""
    assert "module:reverse:reverse_auto_download_static_dynamic_focused" in (
        reverse_playbook["available_workflows"]
    )
    assert "tool.floss_extract" in reverse_playbook["optional_functions"]
    assert "ti.malwarebazaar.download_sample" in reverse_playbook["optional_functions"]
    assert "ti.virustotal.behaviour_summary" in reverse_playbook["external_functions"]
    assert "strings.extract" in reverse_playbook["high_noise_functions"]
    assert "tool.capa_analyze" in reverse_playbook["requires_config_functions"]
    assert reverse_playbook["requires_prior_result"]["ioc.extract"] == ["strings"]
    assert reverse_playbook["requires_prior_result"]["ti.virustotal.hash_lookup"] == ["hash"]
    assert reverse_playbook["self_iteration_targets"]["behavior_taxonomy"] == (
        "modules/reverse/knowledge/behavior_taxonomy.json"
    )


@requires_reverse_module
def test_reverse_skill_declares_knowledge_enrichment_gate() -> None:
    skill_text = Path("modules/reverse/skill/SKILL.md").read_text(encoding="utf-8")
    enrichment = Path("modules/reverse/skill/KNOWLEDGE_ENRICHMENT_SKILL.md")

    assert enrichment.is_file()
    assert "KNOWLEDGE_ENRICHMENT_SKILL.md" in skill_text
    assert "ask the user whether to enable it" in skill_text
    assert "Do not automatically apply candidate updates." in enrichment.read_text(
        encoding="utf-8"
    )


def test_platform_skill_keeps_module_specific_guidance_out_of_platform_playbook() -> None:
    skill_text = Path("config_files/codex_skill/SKILL.md").read_text(encoding="utf-8")
    playbook_text = Path("config_files/codex_skill/default_analysis_playbook.json").read_text(
        encoding="utf-8"
    )

    for reverse_specific in [
        "hash.compute",
        "behavior.map_static",
        "attack.map_static",
        "ti.virustotal",
        "modules/reverse",
    ]:
        assert reverse_specific not in skill_text
        assert reverse_specific not in playbook_text

    if REVERSE_PLAYBOOK_PATH.is_file():
        assert "behavior.map_static" in REVERSE_PLAYBOOK_PATH.read_text(encoding="utf-8")
