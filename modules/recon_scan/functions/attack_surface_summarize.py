from __future__ import annotations

from typing import Any

from scan_common import (
    compact_strings,
    finding_evidence,
    merge_services,
    merge_unique_dicts,
    parse_http_output,
    parse_nmap_output,
    parse_nuclei_output,
    parse_port_output,
    repair_mojibake,
    result_data,
    result_status,
    stage_status,
    success,
)
from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ReconAttackSurfaceSummarizeFunction(AnalysisFunction):
    id = "recon.attack_surface_summarize"
    name = "Recon attack surface summarize"
    category = "recon"
    result_key = "recon_attack_surface"
    description = "Summarize collected recon outputs into AI-friendly assets, findings, and stage coverage."
    requires_results = ["recon_scope", "recon_targets"]
    recommended_before = [
        "recon.dns_probe",
        "recon.http_probe",
        "recon.port_scan",
        "recon.service_identify",
        "recon.web_light_discover",
        "recon.vulnerability_candidate_scan",
    ]
    cost = "low"
    candidate_only = True
    output_schema = {
        "assets": "Domains, hosts, addresses, live web endpoints, services, and URLs.",
        "candidate_findings": "Unverified candidate findings.",
        "next_step_candidates": "Suggested function-level next steps for AI review.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        _ = params
        scope = result_data(context, "recon_scope")
        targets = result_data(context, "recon_targets")
        dns = result_data(context, "recon_dns")
        http = result_data(context, "recon_http")
        ports = result_data(context, "recon_ports")
        services_raw = result_data(context, "recon_services")
        web = result_data(context, "recon_web")
        vulns = result_data(context, "recon_vuln_candidates")

        domains = compact_strings(list(targets.get("domains", [])))
        hosts = compact_strings(
            list(targets.get("hosts", []))
            + list(dns.get("resolved_hosts", []))
        )
        addresses = compact_strings(list(dns.get("addresses", [])))
        http_endpoints = http.get("web_endpoints") if isinstance(http.get("web_endpoints"), list) else []
        web_endpoints = merge_unique_dicts(
            parse_http_output(str(http.get("http_output") or ""))
            + [_clean_endpoint(item) for item in http_endpoints if isinstance(item, dict)],
            "url",
        )
        service_items = []
        service_items.extend(ports.get("services", []) if isinstance(ports.get("services"), list) else [])
        service_items.extend(parse_port_output(str(ports.get("port_output") or ""), "naabu"))
        service_items.extend(services_raw.get("services", []) if isinstance(services_raw.get("services"), list) else [])
        service_items.extend(parse_nmap_output(str(services_raw.get("service_output") or "")))
        services = merge_services([item for item in service_items if isinstance(item, dict)])
        urls = merge_unique_dicts(
            list(web.get("urls", []) if isinstance(web.get("urls"), list) else []),
            "url",
        )
        raw_findings = []
        raw_findings.extend(vulns.get("candidate_findings", []) if isinstance(vulns.get("candidate_findings"), list) else [])
        raw_findings.extend(parse_nuclei_output(str(vulns.get("vulnerability_output") or "")))
        candidate_findings = [self._finding(item) for item in raw_findings if isinstance(item, dict)]

        stage_coverage = {
            "scope_validate": result_status(context, "recon_scope") or "not_run",
            "target_normalize": result_status(context, "recon_targets") or "not_run",
            "dns_probe": stage_status(dns),
            "http_probe": stage_status(http),
            "port_scan": stage_status(ports),
            "service_identify": stage_status(services_raw),
            "web_light_discover": stage_status(web),
            "vulnerability_candidate_scan": stage_status(vulns),
        }
        warnings = []
        for data in [scope, dns, http, ports, services_raw, web, vulns]:
            warnings.extend(str(item) for item in data.get("warnings", []) if item)

        assets = {
            "domains": domains,
            "hosts": hosts,
            "addresses": addresses,
            "web_endpoints": web_endpoints,
            "services": services,
            "urls": urls,
        }
        return success(
            self.id,
            self.result_key,
            {
                "target_scope": {
                    "authorized": bool(scope.get("authorized")),
                    "active_authorized": bool(scope.get("active_authorized")),
                    "allowed_count": len(scope.get("allowed_targets", [])),
                    "excluded_count": len(scope.get("excluded_targets", [])),
                    "out_of_scope_count": len(scope.get("out_of_scope_targets", [])),
                    "warnings": warnings,
                    "limitations": [
                        "Automated output is recon evidence, not a verified vulnerability.",
                        "Candidate findings must be manually verified before reporting as vulnerabilities.",
                    ],
                },
                "summary": {
                    "overall": self._overall(assets, candidate_findings),
                    "risk_level": self._risk(candidate_findings),
                    "planned_only": not any(
                        data.get("sources")
                        for data in [dns, http, ports, services_raw, web, vulns]
                    ),
                    "limitations": [
                        "Missing tools produce partial coverage.",
                        "Rate limits are conservative by default.",
                    ],
                },
                "stage_coverage": stage_coverage,
                "assets": assets,
                "candidate_findings": candidate_findings,
                "next_step_candidates": self._next_steps(
                    web_endpoints,
                    services,
                    candidate_findings,
                    stage_coverage,
                ),
            },
        )

    @staticmethod
    def _finding(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "title": str(item.get("title") or "Candidate finding"),
            "severity": str(item.get("severity") or "unknown").lower(),
            "affected_asset": str(item.get("affected_asset") or ""),
            "evidence": finding_evidence(item, "recon.vulnerability_candidate_scan", "recon_vuln_candidates"),
            "verification": "unverified",
            "recommended_fix": "Verify manually, then apply the asset-specific remediation.",
        }

    @staticmethod
    def _overall(assets: dict[str, Any], findings: list[dict[str, Any]]) -> str:
        return (
            f"Collected {len(assets['domains'])} domain(s), {len(assets['hosts'])} host(s), "
            f"{len(assets['addresses'])} address(es), {len(assets['web_endpoints'])} web endpoint(s), "
            f"{len(assets['services'])} service observation(s), {len(assets['urls'])} discovered URL(s), "
            f"and {len(findings)} candidate finding(s)."
        )

    @staticmethod
    def _risk(findings: list[dict[str, Any]]) -> str:
        severities = {str(item.get("severity") or "").lower() for item in findings}
        if "critical" in severities or "high" in severities:
            return "high"
        if "medium" in severities:
            return "medium"
        if severities:
            return "low"
        return "unknown"

    @staticmethod
    def _next_steps(
        endpoints: list[dict[str, Any]],
        services: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        coverage: dict[str, str],
    ) -> list[dict[str, Any]]:
        steps: list[dict[str, Any]] = []
        if services and coverage.get("service_identify") == "not_run":
            steps.append(
                {
                    "function_id": "recon.service_identify",
                    "reason": "Open ports exist and service names/products are still unknown.",
                    "risk": "medium",
                    "requires_human_confirmation": True,
                }
            )
        if endpoints and coverage.get("web_light_discover") == "not_run":
            steps.append(
                {
                    "function_id": "recon.web_light_discover",
                    "reason": "Live web endpoints exist and lightweight crawl/TLS/content discovery has not run.",
                    "risk": "medium",
                    "requires_human_confirmation": True,
                }
            )
        if endpoints and coverage.get("vulnerability_candidate_scan") == "not_run":
            steps.append(
                {
                    "function_id": "recon.vulnerability_candidate_scan",
                    "reason": "Live web endpoints exist and candidate template scanning has not run.",
                    "risk": "high",
                    "requires_human_confirmation": True,
                }
            )
        if findings:
            steps.append(
                {
                    "function_id": "",
                    "reason": "Candidate findings exist; request manual verification evidence before making any vulnerability claim or continuing with riskier automation.",
                    "risk": "manual",
                    "requires_human_confirmation": True,
                }
            )
        if not steps:
            steps.append(
                {
                    "function_id": "recon.report_generate",
                    "reason": "No higher-value automated next step is obvious from current evidence.",
                    "risk": "low",
                    "requires_human_confirmation": False,
                }
            )
        return steps


def _clean_endpoint(item: dict[str, Any]) -> dict[str, Any]:
    cleaned = dict(item)
    cleaned["title"] = repair_mojibake(str(cleaned.get("title") or ""))
    return cleaned
