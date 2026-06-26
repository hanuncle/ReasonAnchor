from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ValidationPlanFocusedDynamicFunction(AnalysisFunction):
    id = "validation.plan_focused_dynamic"
    name = "Plan focused dynamic validation"
    category = "validation"
    result_key = "focused_dynamic_validation_plan"
    description = (
        "Selects static behavior candidates that were not observed in broad dynamic telemetry "
        "and maps them to benign single-point validation scenarios."
    )
    cost = "low"
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    requires_results = ["static_dynamic_validation"]
    recommended_before = ["validation.compare_static_dynamic"]
    output_schema = {
        "targets": "Focused behavior validation targets selected from comparison results.",
        "counts": "Target and fixture availability counts.",
        "limitations": "Planning only; does not execute samples or connect to a VM.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        skipped_reason = _skipped_static_dynamic_validation_reason(context)
        if skipped_reason:
            return FunctionResult(
                function_id=self.id,
                result_key=self.result_key,
                status="skipped",
                data={
                    "skipped": True,
                    "skip_reason": skipped_reason,
                    "targets": [],
                    "counts": {"targets": 0, "ready": 0, "missing_fixture": 0},
                    "requires_human_confirmation": True,
                    "limitations": [
                        "Focused dynamic validation planning skipped because static/dynamic comparison was skipped.",
                        "No dynamic telemetry was available for focused validation planning.",
                    ],
                },
            )
        comparisons = _comparisons(context, params)
        if comparisons is None:
            return self._error(
                "missing_static_dynamic_validation",
                "static_dynamic_validation result or params.comparisons is required",
            )
        categories = _requested_categories(params)
        target_consistency = _target_consistency(params)
        scenarios = _load_scenarios()
        samples = _load_samples()

        targets: list[dict[str, Any]] = []
        for comparison in comparisons:
            if not isinstance(comparison, dict):
                continue
            category = str(comparison.get("category") or "")
            if not category:
                continue
            if categories and category not in categories:
                continue
            consistency = str(comparison.get("consistency") or "")
            if not categories and consistency not in target_consistency:
                continue
            targets.append(
                _target_from_comparison(
                    comparison,
                    scenarios.get(category, []),
                    samples.get(category, []),
                )
            )

        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "source": "params.comparisons" if params.get("comparisons") else "results.static_dynamic_validation",
                "targets": targets,
                "counts": {
                    "targets": len(targets),
                    "ready": sum(1 for item in targets if item["status"] == "ready"),
                    "missing_fixture": sum(
                        1 for item in targets if item["status"] == "missing_validation_sample"
                    ),
                },
                "requires_human_confirmation": True,
                "limitations": [
                    "planning only",
                    "focused validation fixture checks telemetry and mapping capability",
                    "it does not prove the original sample performed the behavior",
                ],
            },
        )

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )


def _comparisons(context: dict[str, Any], params: dict[str, Any]) -> list[Any] | None:
    if isinstance(params.get("comparisons"), list):
        return params["comparisons"]
    result = context.get("results", {}).get("static_dynamic_validation")
    if isinstance(result, dict) and result.get("status") != "error":
        data = result.get("data", {})
        if isinstance(data, dict) and isinstance(data.get("comparisons"), list):
            return data["comparisons"]
    return None


def _skipped_static_dynamic_validation_reason(context: dict[str, Any]) -> str:
    result = context.get("results", {}).get("static_dynamic_validation")
    if not isinstance(result, dict) or result.get("status") != "skipped":
        return ""
    data = result.get("data", {})
    if isinstance(data, dict):
        return str(data.get("skip_reason") or "static_dynamic_validation_skipped")
    return "static_dynamic_validation_skipped"


def _requested_categories(params: dict[str, Any]) -> set[str]:
    value = params.get("behavior_categories")
    if isinstance(value, str) and value:
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value if str(item)}
    return set()


def _target_consistency(params: dict[str, Any]) -> set[str]:
    value = params.get("target_consistency")
    if isinstance(value, str) and value:
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value if str(item)}
    return {"static_candidate_not_observed"}


def _target_from_comparison(
    comparison: dict[str, Any],
    scenarios: list[dict[str, Any]],
    samples: list[dict[str, Any]],
) -> dict[str, Any]:
    sample = samples[0] if samples else {}
    scenario = scenarios[0] if scenarios else {}
    status = "ready" if sample else "missing_validation_sample"
    return {
        "behavior_category": str(comparison.get("category") or ""),
        "consistency": str(comparison.get("consistency") or ""),
        "static_confidence": str(comparison.get("static_confidence") or ""),
        "static_score": _safe_int(comparison.get("static_score")),
        "scenario_id": str(scenario.get("scenario_id") or sample.get("scenario_id") or ""),
        "technique_id": str(sample.get("technique_id") or scenario.get("technique_id") or ""),
        "validation_sample_id": str(sample.get("sample_id") or ""),
        "validation_sample_path": str(sample.get("path") or ""),
        "expected_dynamic_events": list(
            sample.get("expected_dynamic_events")
            or scenario.get("expected_dynamic_events")
            or []
        ),
        "status": status,
        "note": (
            "Focused dynamic validation can be run with dynamic.vm_validate_behavior."
            if status == "ready"
            else "No validation sample is registered for this behavior category."
        ),
    }


def _load_scenarios() -> dict[str, list[dict[str, Any]]]:
    data = _read_json(_module_config_root() / "validation" / "validation_scenarios.json")
    scenarios = data.get("scenarios", []) if isinstance(data, dict) else []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in scenarios:
        if not isinstance(item, dict):
            continue
        category = str(item.get("behavior_category") or "")
        if category:
            grouped.setdefault(category, []).append(item)
    return grouped


def _load_samples() -> dict[str, list[dict[str, Any]]]:
    data = _read_json(_module_config_root() / "validation_samples" / "samples_manifest.json")
    samples = data.get("samples", []) if isinstance(data, dict) else []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in samples:
        if not isinstance(item, dict):
            continue
        category = str(item.get("behavior_category") or "")
        if category:
            grouped.setdefault(category, []).append(item)
    return grouped


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _module_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _module_config_root() -> Path:
    return _module_root() / "config_files"


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
