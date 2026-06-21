from __future__ import annotations

from typing import Any

from scan_common import result_data, success
from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ReconNextStepOptionsFunction(AnalysisFunction):
    id = "recon.next_step_options"
    name = "Recon next step options"
    category = "recon"
    result_key = "recon_next_steps"
    description = "Expose machine-readable function choices for the AI decision loop."
    requires_results = ["recon_attack_surface"]
    recommended_before = ["recon.attack_surface_summarize"]
    cost = "low"
    candidate_only = True
    output_schema = {
        "options": "Candidate next functions with reasons, risk, and params template.",
        "operator_rule": "AI chooses one option, calls run_function, analyzes ai_output, then repeats.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        _ = params
        surface = result_data(context, "recon_attack_surface")
        raw_options = surface.get("next_step_candidates")
        if not isinstance(raw_options, list):
            raw_options = []
        options = []
        for item in raw_options:
            if not isinstance(item, dict):
                continue
            function_id = str(item.get("function_id") or "")
            if not function_id:
                options.append(
                    {
                        "type": "manual_review",
                        "action": "Request manual verification",
                        "priority": "high",
                        "why_now": "Candidate findings exist and should be verified before any vulnerability claim is made.",
                        "function_id": "",
                        "params_template": {},
                        "reason": str(item.get("reason") or ""),
                        "risk": str(item.get("risk") or "manual"),
                        "requires_human_confirmation": True,
                    }
                )
                continue
            options.append(
                {
                    "type": "run_function",
                    "action": self._action(function_id),
                    "priority": self._priority(function_id),
                    "why_now": self._why_now(function_id),
                    "function_id": function_id,
                    "params_template": self._params_template(function_id),
                    "reason": str(item.get("reason") or ""),
                    "risk": str(item.get("risk") or "medium"),
                    "requires_human_confirmation": bool(item.get("requires_human_confirmation", True)),
                }
            )
        return success(
            self.id,
            self.result_key,
            {
                "operator_rule": (
                    "After the basic workflow, AI should inspect ai_output, choose one option, "
                    "call run_function on the same session, analyze the returned ai_output_item, "
                    "then rerun recon.attack_surface_summarize and recon.next_step_options."
                ),
                "options": options,
                "completion_condition": (
                    "Generate final report when no useful low or medium risk step remains, "
                    "or when candidate findings require manual validation outside this module."
                ),
            },
        )

    @staticmethod
    def _params_template(function_id: str) -> dict[str, Any]:
        if function_id == "recon.service_identify":
            return {"timeout_seconds": 90}
        if function_id == "recon.web_light_discover":
            return {"crawl_depth": 1, "rate_limit": "low", "timeout_seconds": 180}
        if function_id == "recon.vulnerability_candidate_scan":
            return {
                "nuclei_severity": ["critical", "high", "medium"],
                "rate_limit": "low",
                "timeout_seconds": 90,
            }
        if function_id == "recon.report_generate":
            return {"report_stage": "final"}
        return {}

    @staticmethod
    def _action(function_id: str) -> str:
        if function_id == "recon.service_identify":
            return "Run service fingerprinting"
        if function_id == "recon.web_light_discover":
            return "Run lightweight web discovery"
        if function_id == "recon.vulnerability_candidate_scan":
            return "Run candidate vulnerability scan"
        if function_id == "recon.report_generate":
            return "Finalize report"
        return "Run selected follow-up"

    @staticmethod
    def _priority(function_id: str) -> str:
        if function_id == "recon.vulnerability_candidate_scan":
            return "high"
        if function_id == "recon.report_generate":
            return "low"
        return "medium"

    @staticmethod
    def _why_now(function_id: str) -> str:
        if function_id == "recon.service_identify":
            return "Open ports are present, and service fingerprints will clarify exposure."
        if function_id == "recon.web_light_discover":
            return "Live web endpoints exist, and lightweight discovery can expand the visible attack surface."
        if function_id == "recon.vulnerability_candidate_scan":
            return "Live web targets exist, and a scoped candidate scan can surface items for manual verification."
        if function_id == "recon.report_generate":
            return "No higher-value automated step remains, so the session is ready to be summarized."
        return "This step is currently the safest useful way to increase evidence quality."
