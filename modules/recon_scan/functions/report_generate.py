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
        target_scope = surface.get("target_scope") if isinstance(surface.get("target_scope"), dict) else {}
        summary = surface.get("summary") if isinstance(surface.get("summary"), dict) else {}
        assets = surface.get("assets") if isinstance(surface.get("assets"), dict) else {}
        findings = surface.get("candidate_findings") if isinstance(surface.get("candidate_findings"), list) else []
        recommended = next_steps.get("options") if isinstance(next_steps.get("options"), list) else []
        if not recommended:
            recommended = surface.get("next_step_candidates") if isinstance(surface.get("next_step_candidates"), list) else []

        final_result = {
            "module_id": "recon_scan",
            "schema_id": "recon_scan.final_result.v1",
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
            "candidate_findings": findings,
            "recommended_next_steps": recommended,
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
