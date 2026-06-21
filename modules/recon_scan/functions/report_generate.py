from __future__ import annotations

from typing import Any

from scan_common import result_data, success
from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ReconReportGenerateFunction(AnalysisFunction):
    id = "recon.report_generate"
    name = "Recon report generate"
    category = "recon"
    result_key = "recon_final_report"
    description = "Generate the structured final report payload that can be saved with save_session_result."
    requires_results = ["recon_attack_surface"]
    recommended_before = ["recon.attack_surface_summarize", "recon.next_step_options"]
    cost = "low"
    candidate_only = True
    output_schema = {
        "final_result": "Final result payload compatible with the module final_result_schema.",
        "report_markdown": "Human-readable markdown report draft.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        stage = str(params.get("report_stage") or params.get("stage") or "current")
        surface = result_data(context, "recon_attack_surface")
        next_steps = result_data(context, "recon_next_steps")
        target = context.get("target") if isinstance(context.get("target"), dict) else {}
        sample_filename = str(context.get("filename") or "")
        session_type = str(context.get("session_type") or "sample")
        target_scope = surface.get("target_scope") if isinstance(surface.get("target_scope"), dict) else {}
        summary = surface.get("summary") if isinstance(surface.get("summary"), dict) else {}
        assets = surface.get("assets") if isinstance(surface.get("assets"), dict) else {}
        findings = surface.get("candidate_findings") if isinstance(surface.get("candidate_findings"), list) else []
        recommended = next_steps.get("options") if isinstance(next_steps.get("options"), list) else []
        if not recommended:
            recommended = surface.get("next_step_candidates") if isinstance(surface.get("next_step_candidates"), list) else []

        candidate_findings = [self._enrich_finding(item) for item in findings if isinstance(item, dict)]
        recommended_next_steps = [
            self._enrich_next_step(item)
            for item in recommended
            if isinstance(item, dict)
        ]
        executive_summary = self._executive_summary(summary, assets, candidate_findings)
        operator_conclusion = self._operator_conclusion(stage, recommended_next_steps, candidate_findings)
        unverified_notice = (
            "Candidate findings remain unverified until manual validation confirms the issue."
        )
        final_result = {
            "module_id": "recon_scan",
            "schema_id": "recon_scan.final_result.v1",
            "target": {
                "label": str(target.get("label") or ""),
                "targets": list(target.get("targets") or []),
                "authorized_scope": list(target.get("authorized_scope") or []),
                "exclude": list(target.get("exclude") or []),
            },
            "file": {
                "filename": sample_filename,
                "size": 0 if session_type == "target" else None,
                "sha256": "",
                "file_type": "target" if session_type == "target" else "",
            },
            "target_scope": {
                "authorized": bool(target_scope.get("authorized")),
                "active_authorized": bool(target_scope.get("active_authorized")),
                "scope_summary": (
                    f"{target_scope.get('allowed_count', 0)} allowed, "
                    f"{target_scope.get('excluded_count', 0)} excluded, "
                    f"{target_scope.get('out_of_scope_count', 0)} out of scope"
                ),
                "excluded": [],
                "limitations": target_scope.get("limitations", []),
            },
            "summary": {
                "overall": str(summary.get("overall") or "Recon report generated."),
                "risk_level": str(summary.get("risk_level") or "unknown"),
                "planned_only": bool(summary.get("planned_only")),
                "report_stage": stage,
                "executive_summary": executive_summary,
                "operator_conclusion": operator_conclusion,
                "unverified_notice": unverified_notice,
                "limitations": summary.get("limitations", []),
            },
            "stage_coverage": surface.get("stage_coverage", {}),
            "assets": {
                "domains": assets.get("domains", []),
                "hosts": assets.get("hosts", []),
                "addresses": assets.get("addresses", []),
                "web_endpoints": assets.get("web_endpoints", []),
                "urls": assets.get("urls", []),
                "services": assets.get("services", []),
            },
            "candidate_findings": candidate_findings,
            "recommended_next_steps": recommended_next_steps,
        }
        return success(
            self.id,
            self.result_key,
            {
                "report_stage": stage,
                "final_result": final_result,
                "report_markdown": self._markdown(final_result),
                "save_instruction": (
                    "AI should save final_result with save_session_result after the loop is complete."
                ),
            },
        )

    @staticmethod
    def _markdown(result: dict[str, Any]) -> str:
        summary = result.get("summary", {})
        assets = result.get("assets", {})
        findings = result.get("candidate_findings", [])
        lines = [
            "# Recon Scan Report",
            "",
            f"Overall: {summary.get('overall', '')}",
            f"Risk: {summary.get('risk_level', 'unknown')}",
            "",
            "## Asset Counts",
            f"- Domains: {len(assets.get('domains', []))}",
            f"- Hosts: {len(assets.get('hosts', []))}",
            f"- Addresses: {len(assets.get('addresses', []))}",
            f"- Web endpoints: {len(assets.get('web_endpoints', []))}",
            f"- Services: {len(assets.get('services', []))}",
            f"- Candidate findings: {len(findings)}",
            "",
            "## Notes",
            "- Candidate findings are unverified until manually validated.",
            "- Scope validation is syntactic and must be backed by the operator's authorization record.",
        ]
        return "\n".join(lines)

    @staticmethod
    def _executive_summary(
        summary: dict[str, Any],
        assets: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> str:
        risk = str(summary.get("risk_level") or "unknown")
        return (
            f"Authorized reconnaissance completed with {risk} assessed risk, "
            f"{len(assets.get('web_endpoints', []))} live web endpoint(s), "
            f"{len(assets.get('services', []))} service observation(s), and "
            f"{len(findings)} candidate finding(s) requiring cautious review."
        )

    @staticmethod
    def _operator_conclusion(
        stage: str,
        recommended_next_steps: list[dict[str, Any]],
        candidate_findings: list[dict[str, Any]],
    ) -> str:
        if candidate_findings:
            return (
                f"Stage {stage} collected enough candidate evidence to hand off for manual verification "
                "before making any vulnerability claim."
            )
        if recommended_next_steps and recommended_next_steps[0].get("function_id") == "recon.report_generate":
            return (
                f"Stage {stage} appears complete for automated recon; the current evidence is ready for operator review."
            )
        if recommended_next_steps:
            return (
                f"Stage {stage} is partially complete; continue with the next recommended low-noise step if it remains authorized."
            )
        return f"Stage {stage} is ready to be saved as the current operator handoff."

    @staticmethod
    def _enrich_finding(item: dict[str, Any]) -> dict[str, Any]:
        finding = dict(item)
        sources = finding.get("evidence", {}).get("sources", []) if isinstance(finding.get("evidence"), dict) else []
        severity = str(finding.get("severity") or "unknown").lower()
        if severity in {"critical", "high"} and sources:
            confidence = "medium"
        else:
            confidence = "low"
        finding["confidence"] = str(finding.get("confidence") or confidence)
        finding["manual_verification_steps"] = finding.get("manual_verification_steps") or [
            "Confirm the affected asset manually within the authorized scope.",
            "Reproduce the candidate condition with a scoped, operator-approved check.",
            "Review the original evidence source before reporting the issue as verified."
        ]
        return finding

    @staticmethod
    def _enrich_next_step(item: dict[str, Any]) -> dict[str, Any]:
        step = dict(item)
        function_id = str(step.get("function_id") or "")
        if not step.get("action"):
            step["action"] = ReconReportGenerateFunction._step_action(function_id)
        if not step.get("priority"):
            step["priority"] = ReconReportGenerateFunction._step_priority(function_id, str(step.get("risk") or ""))
        if not step.get("why_now"):
            step["why_now"] = str(step.get("reason") or ReconReportGenerateFunction._step_why_now(function_id))
        return step

    @staticmethod
    def _step_action(function_id: str) -> str:
        if function_id == "recon.service_identify":
            return "Run service fingerprinting"
        if function_id == "recon.web_light_discover":
            return "Run lightweight web discovery"
        if function_id == "recon.vulnerability_candidate_scan":
            return "Run candidate vulnerability scan"
        if function_id == "recon.report_generate":
            return "Finalize report"
        return "Request manual verification"

    @staticmethod
    def _step_priority(function_id: str, risk: str) -> str:
        if function_id == "recon.report_generate":
            return "low"
        if function_id == "recon.vulnerability_candidate_scan" or risk == "high":
            return "high"
        return "medium"

    @staticmethod
    def _step_why_now(function_id: str) -> str:
        if function_id == "recon.service_identify":
            return "Ports are open, and service fingerprints will improve exposure context."
        if function_id == "recon.web_light_discover":
            return "Live web endpoints exist, and lightweight discovery can expand the visible surface safely."
        if function_id == "recon.vulnerability_candidate_scan":
            return "Live web endpoints exist, and a scoped candidate scan may expose items for manual follow-up."
        if function_id == "recon.report_generate":
            return "No higher-value automated step remains, so the session should be finalized."
        return "Manual verification is the next safest useful step."
