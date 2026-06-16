from __future__ import annotations

from typing import Any


def sort_output(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    data = _data(raw_output_item)
    result = data.get("final_result") if isinstance(data.get("final_result"), dict) else {}
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    assets = result.get("assets") if isinstance(result.get("assets"), dict) else {}
    findings = result.get("candidate_findings") if isinstance(result.get("candidate_findings"), list) else []
    return {
        "summary": str(summary.get("overall") or "Recon report draft generated."),
        "key_fields": {
            "report_stage": data.get("report_stage", ""),
            "risk_level": summary.get("risk_level", "unknown"),
            "save_instruction": data.get("save_instruction", ""),
            "counts": {
                "domains": len(_list(assets.get("domains"))),
                "hosts": len(_list(assets.get("hosts"))),
                "web_endpoints": len(_list(assets.get("web_endpoints"))),
                "services": len(_list(assets.get("services"))),
                "candidate_findings": len(findings),
            },
        },
        "evidence_hints": {
            "final_result_keys": sorted(result.keys()),
            "markdown_preview": str(data.get("report_markdown") or "")[:1200],
        },
        "warnings": [],
        "limitations": [
            "AI must save final_result with save_session_result when the loop is complete.",
            "Candidate findings remain unverified unless manual evidence is added.",
        ],
    }


def _data(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    output = raw_output_item.get("output")
    if isinstance(output, dict):
        data = output.get("data")
        if isinstance(data, dict):
            return data
    return {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
