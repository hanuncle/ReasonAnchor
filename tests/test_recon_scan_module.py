from __future__ import annotations

import json
import sys
from pathlib import Path

from security_function_platform.module_system import ModuleStore
from security_function_platform.raw_sorting.sorter import sort_raw_output_item


def _recon_functions(tmp_path):
    store = ModuleStore("modules", tmp_path / "data" / "modules" / "loaded_modules.json")
    return {fn.id: fn for fn in store.load_function_instances("recon_scan")}


def _authorized_context(functions):
    scope = functions["recon.scope_validate"].run(
        {},
        {
            "targets": ["https://app.example.com"],
            "authorized_scope": ["example.com", "*.example.com"],
            "active_scan": True,
            "confirm_authorized": "I_CONFIRM_AUTHORIZED_ACTIVE_RECON",
        },
    )
    targets = functions["recon.target_normalize"].run(
        {"results": {"recon_scope": scope.to_dict()}},
        {},
    )
    return {
        "results": {
            "recon_scope": scope.to_dict(),
            "recon_targets": targets.to_dict(),
        }
    }


def test_recon_scan_module_declares_ai_gated_workflows(tmp_path) -> None:
    store = ModuleStore("modules", tmp_path / "data" / "modules" / "loaded_modules.json")

    validation = store.validate_module("recon_scan")
    detail = store.get_module_detail("recon_scan")
    workflows = [
        workflow
        for workflow in store.list_workflows()["workflows"]
        if workflow.get("module_id") == "recon_scan"
    ]
    knowledge = store.get_module_knowledge("recon_scan", "scan_workflow_matrix")

    assert validation["valid"] is True
    assert detail["functions_count"] == 11
    assert detail["workflows_count"] == 2
    assert knowledge["items_count"] == 6
    assert {
        "module:recon_scan:recon_scope_prepare_flow",
        "module:recon_scan:recon_basic_collection_flow",
    } == {workflow["workflow_id"] for workflow in workflows}

    basic_workflow = store.get_workflow("module:recon_scan:recon_basic_collection_flow")
    assert basic_workflow["risk"] == "high"
    assert basic_workflow["network"] is True
    assert basic_workflow["default_safe"] is False
    step_ids = [step["function_id"] for step in basic_workflow["workflow"]["steps"]]
    assert step_ids == [
        "recon.scope_validate",
        "recon.target_normalize",
        "recon.dns_probe",
        "recon.http_probe",
        "recon.port_scan",
        "recon.attack_surface_summarize",
        "recon.next_step_options",
        "recon.report_generate",
    ]
    assert "recon.service_identify" not in step_ids
    assert "recon.web_light_discover" not in step_ids
    assert "recon.vulnerability_candidate_scan" not in step_ids

    skill_context = store.get_module_skill("recon_scan")
    playbook = skill_context["playbook"]
    assert "CONTROLLED_EXECUTION_SKILL.md" in skill_context["skill"]
    assert "SCAN_STRATEGY_SKILL.md" in skill_context["skill"]
    assert "FINAL_RESULT_WRITING_SKILL.md" in skill_context["skill"]
    assert playbook["high_noise_functions"] == [
        "recon.web_light_discover",
        "recon.vulnerability_candidate_scan",
    ]
    assert playbook["follow_up_priority"] == [
        "recon.service_identify",
        "recon.web_light_discover",
        "recon.vulnerability_candidate_scan",
    ]
    assert playbook["result_generation_preference"]["preferred_function"] == (
        "recon.report_generate"
    )


def test_recon_supporting_skill_files_exist_and_reference_required_rules() -> None:
    base = Path("modules/recon_scan/skill")
    control = (base / "CONTROLLED_EXECUTION_SKILL.md").read_text(encoding="utf-8")
    strategy = (base / "SCAN_STRATEGY_SKILL.md").read_text(encoding="utf-8")
    result = (base / "FINAL_RESULT_WRITING_SKILL.md").read_text(encoding="utf-8")

    assert "get_raw_output_map" in control
    assert "Run at most one AI-gated follow-up function at a time." in control
    assert "Do not convert candidate findings into verified vulnerabilities" in control
    assert "recon.attack_surface_summarize" in strategy
    assert "recon.next_step_options" in strategy
    assert "Keep candidate findings separate from verified conclusions." in result
    assert "save_session_result" in result


def test_recon_active_functions_block_without_confirmation(tmp_path) -> None:
    functions = _recon_functions(tmp_path)
    scope = functions["recon.scope_validate"].run(
        {},
        {
            "targets": ["example.com"],
            "authorized_scope": ["example.com", "*.example.com"],
            "active_scan": True,
        },
    )
    targets = functions["recon.target_normalize"].run(
        {"results": {"recon_scope": scope.to_dict()}},
        {},
    )
    context = {"results": {"recon_scope": scope.to_dict(), "recon_targets": targets.to_dict()}}

    dns = functions["recon.dns_probe"].run(context, {})
    ports = functions["recon.port_scan"].run(context, {})

    assert scope.status == "success"
    assert scope.data["active_authorized"] is False
    assert dns.status == "success"
    assert dns.data["blocked"] is True
    assert ports.data["blocked"] is True


def test_recon_basic_collection_outputs_ai_next_step_options(tmp_path) -> None:
    functions = _recon_functions(tmp_path)
    context = _authorized_context(functions)

    dns = functions["recon.dns_probe"].run(
        context,
        {"dns_output": '{"host":"app.example.com","a":["203.0.113.10"]}\n'},
    )
    context["results"]["recon_dns"] = dns.to_dict()
    http = functions["recon.http_probe"].run(
        context,
        {
            "http_output": (
                '{"url":"https://app.example.com","status_code":200,'
                '"title":"App","tech":["nginx"]}\n'
            )
        },
    )
    context["results"]["recon_http"] = http.to_dict()
    ports = functions["recon.port_scan"].run(
        context,
        {"port_output": "app.example.com:443\n"},
    )
    context["results"]["recon_ports"] = ports.to_dict()
    surface = functions["recon.attack_surface_summarize"].run(context, {})
    context["results"]["recon_attack_surface"] = surface.to_dict()
    options = functions["recon.next_step_options"].run(context, {})
    context["results"]["recon_next_steps"] = options.to_dict()
    report = functions["recon.report_generate"].run(context, {"report_stage": "basic_collection"})

    assert "203.0.113.10" in surface.data["assets"]["addresses"]
    assert surface.data["assets"]["web_endpoints"][0]["status_code"] == 200
    assert {"host": "app.example.com", "port": "443", "service": "", "product": "", "source": "naabu"} in (
        surface.data["assets"]["services"]
    )
    option_ids = {item["function_id"] for item in options.data["options"] if item["function_id"]}
    assert {"recon.service_identify", "recon.web_light_discover", "recon.vulnerability_candidate_scan"} <= option_ids
    assert options.data["options"][0]["action"] == "Run service fingerprinting"
    assert options.data["options"][0]["priority"] == "medium"
    assert options.data["options"][0]["why_now"]
    assert report.data["final_result"]["schema_id"] == "recon_scan.final_result.v1"
    assert report.data["final_result"]["summary"]["report_stage"] == "basic_collection"
    assert report.data["final_result"]["summary"]["executive_summary"]
    assert report.data["final_result"]["summary"]["operator_conclusion"]
    assert report.data["final_result"]["summary"]["unverified_notice"]


def test_recon_dns_parser_rejects_tool_error_text(tmp_path) -> None:
    functions = _recon_functions(tmp_path)
    context = _authorized_context(functions)

    dns = functions["recon.dns_probe"].run(
        context,
        {"dns_output": "flag provided but not defined: -retries\n"},
    )

    assert dns.data["records"] == []
    assert dns.data["resolved_hosts"] == []
    assert dns.data["addresses"] == []


def test_recon_ffuf_parser_uses_json_results_only(tmp_path) -> None:
    functions = _recon_functions(tmp_path)
    context = _authorized_context(functions)
    ffuf_output = (
        "https://app.example.com/# directory-list-2.3-small.txt\n"
        '{"results":['
        '{"url":"https://app.example.com/admin","status":200,"length":42},'
        '{"url":"https://app.example.com/missing","status":404,"length":0},'
        '{"url":"https://app.example.com/# directory-list-2.3-small.txt","status":200,"length":42}'
        "]}\n"
    )

    web = functions["recon.web_light_discover"].run(
        context,
        {"content_output": ffuf_output},
    )

    assert {"url": "https://app.example.com/admin", "source": "ffuf", "status": 200, "length": 42, "words": None, "lines": None} in web.data["urls"]
    discovered_urls = {item["url"] for item in web.data["urls"]}
    assert "https://app.example.com/missing" not in discovered_urls
    assert "https://app.example.com/# directory-list-2.3-small.txt" not in discovered_urls


def test_recon_http_title_repairs_mojibake(tmp_path) -> None:
    functions = _recon_functions(tmp_path)
    context = _authorized_context(functions)
    mojibake = "\u93b5\u60e7\u57cc\u6d63\u72b5\u6b91\u6d94\u612f\u53ee"
    expected = "\u627e\u5230\u4f60\u7684\u4e50\u8da3"

    http = functions["recon.http_probe"].run(
        context,
        {
            "http_output": json.dumps(
                {
                    "url": "https://app.example.com",
                    "status_code": 200,
                    "title": mojibake,
                }
            )
            + "\n"
        },
    )
    context["results"]["recon_http"] = http.to_dict()
    surface = functions["recon.attack_surface_summarize"].run(context, {})

    assert http.data["web_endpoints"][0]["title"] == expected
    assert surface.data["assets"]["web_endpoints"][0]["title"] == expected


def test_recon_service_identify_preserves_previous_services_after_empty_warning(tmp_path) -> None:
    functions = _recon_functions(tmp_path)
    context = _authorized_context(functions)
    context["results"]["recon_ports"] = functions["recon.port_scan"].run(
        context,
        {"port_output": "app.example.com:443\n"},
    ).to_dict()
    previous = functions["recon.service_identify"].run(
        context,
        {"service_output": "Nmap scan report for app.example.com\n443/tcp open https nginx\n"},
    )
    context["results"]["recon_services"] = previous.to_dict()

    current = functions["recon.service_identify"].run(
        context,
        {"nmap_path": sys.executable, "timeout_seconds": 180},
    )

    assert current.data["services"] == previous.data["services"]
    assert any("Preserved previous non-empty nmap" in item for item in current.data["warnings"])
    assert any("capped at 100s" in item for item in current.data["warnings"])


def test_recon_nuclei_timeout_is_capped_before_mcp_deadline(tmp_path) -> None:
    functions = _recon_functions(tmp_path)
    context = _authorized_context(functions)
    context["results"]["recon_http"] = functions["recon.http_probe"].run(
        context,
        {"http_output": '{"url":"https://app.example.com","status_code":200,"title":"App"}\n'},
    ).to_dict()

    result = functions["recon.vulnerability_candidate_scan"].run(
        context,
        {"nuclei_path": sys.executable, "timeout_seconds": 180},
    )

    assert result.data["candidate_findings"] == []
    assert any("capped at 100s" in item for item in result.data["warnings"])


def test_recon_single_step_loop_updates_final_report(tmp_path) -> None:
    functions = _recon_functions(tmp_path)
    context = _authorized_context(functions)
    context["results"]["recon_http"] = functions["recon.http_probe"].run(
        context,
        {"http_output": '{"url":"https://app.example.com","status_code":200,"title":"App"}\n'},
    ).to_dict()
    context["results"]["recon_ports"] = functions["recon.port_scan"].run(
        context,
        {"port_output": "app.example.com:443\n"},
    ).to_dict()

    service = functions["recon.service_identify"].run(
        context,
        {"service_output": "Nmap scan report for app.example.com\n443/tcp open https nginx\n"},
    )
    context["results"]["recon_services"] = service.to_dict()
    web = functions["recon.web_light_discover"].run(
        context,
        {"crawl_output": '{"url":"https://app.example.com/login"}\n'},
    )
    context["results"]["recon_web"] = web.to_dict()
    vuln = functions["recon.vulnerability_candidate_scan"].run(
        context,
        {
            "vulnerability_output": (
                '{"template-id":"exposed-panel","matched-at":"https://app.example.com",'
                '"info":{"name":"Exposed Panel","severity":"high"}}\n'
            )
        },
    )
    context["results"]["recon_vuln_candidates"] = vuln.to_dict()
    surface = functions["recon.attack_surface_summarize"].run(context, {})
    context["results"]["recon_attack_surface"] = surface.to_dict()
    report = functions["recon.report_generate"].run(context, {"report_stage": "final"})

    assert surface.data["summary"]["risk_level"] == "high"
    assert surface.data["assets"]["services"][0]["service"] == "https"
    assert {"url": "https://app.example.com/login", "source": "katana"} in surface.data["assets"]["urls"]
    assert surface.data["candidate_findings"][0]["verification"] == "unverified"
    assert report.data["final_result"]["candidate_findings"][0]["title"] == "Exposed Panel"
    assert report.data["final_result"]["candidate_findings"][0]["confidence"] == "medium"
    assert report.data["final_result"]["candidate_findings"][0]["manual_verification_steps"]
    assert report.data["final_result"]["recommended_next_steps"][0]["action"]
    assert report.data["final_result"]["recommended_next_steps"][0]["priority"]
    assert report.data["final_result"]["recommended_next_steps"][0]["why_now"]


def test_recon_raw_sorting_compacts_stage_output(tmp_path) -> None:
    functions = _recon_functions(tmp_path)
    context = _authorized_context(functions)
    http = functions["recon.http_probe"].run(
        context,
        {"http_output": '{"url":"https://app.example.com","status_code":200,"title":"App"}\n'},
    )

    sorted_item = sort_raw_output_item(
        {
            "raw_output_id": "raw-001-recon_http",
            "index": 1,
            "function_id": "recon.http_probe",
            "function_name": "Recon HTTP liveness probe",
            "result_key": "recon_http",
            "status": http.status,
            "output": http.to_dict(),
        }
    )

    assert sorted_item["sort_status"] == "sorted"
    assert sorted_item["ai_payload"]["key_fields"]["counts"]["web_endpoints"] == 1
    assert "http_output" not in sorted_item["ai_payload"]
