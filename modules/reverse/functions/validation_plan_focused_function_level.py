from __future__ import annotations

from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

from behavior_taxonomy import static_rules


class ValidationPlanFocusedFunctionLevelFunction(AnalysisFunction):
    id = "validation.plan_focused_function_level"
    name = "Plan focused function-level analysis"
    category = "validation"
    result_key = "focused_function_level_plan"
    description = (
        "Selects behavior categories that were not covered by function-level evidence, "
        "or were not observed dynamically, and prepares focused function-level review targets."
    )
    cost = "low"
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    requires_results = ["static_dynamic_function_validation"]
    recommended_before = ["validation.compare_static_dynamic_function"]
    output_schema = {
        "targets": "Behavior categories requiring focused function-level review.",
        "counts": "Target counts and reasons.",
        "limitations": "Planning only; does not execute external tools.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        comparisons = _comparisons(context, params)
        if comparisons is None:
            return FunctionResult(
                function_id=self.id,
                result_key=self.result_key,
                status="error",
                error={
                    "code": "missing_static_dynamic_function_validation",
                    "message": "static_dynamic_function_validation data.comparisons is required",
                },
            )
        categories = _requested_categories(params)
        target_modes = _target_modes(params)
        rules = static_rules()
        targets = []
        for comparison in comparisons:
            if not isinstance(comparison, dict):
                continue
            category = str(comparison.get("category") or "")
            if not category:
                continue
            if categories and category not in categories:
                continue
            needs_dynamic = bool(comparison.get("needs_focused_dynamic"))
            needs_function = bool(comparison.get("needs_focused_function_level"))
            if not categories and not _targeted(needs_dynamic, needs_function, target_modes):
                continue
            rule = rules.get(category, {})
            targets.append(
                {
                    "behavior_category": category,
                    "name": str(rule.get("name") or category),
                    "keywords": _string_list(rule.get("keywords"))[:40],
                    "gap": str(comparison.get("gap") or ""),
                    "needs_focused_dynamic": needs_dynamic,
                    "needs_focused_function_level": needs_function,
                    "static_confidence": str(comparison.get("static_confidence") or ""),
                    "static_score": _safe_int(comparison.get("static_score")),
                    "static_evidence": _dict_list(comparison.get("static_evidence"))[:12],
                    "existing_related_functions": _dict_list(comparison.get("related_functions"))[:12],
                    "note": "Run tool.focused_function_level_analysis for this behavior category.",
                }
            )

        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "source": "params.comparisons" if params.get("comparisons") else "results.static_dynamic_function_validation",
                "targets": targets,
                "counts": {
                    "targets": len(targets),
                    "needs_focused_dynamic": sum(1 for item in targets if item["needs_focused_dynamic"]),
                    "needs_focused_function_level": sum(
                        1 for item in targets if item["needs_focused_function_level"]
                    ),
                },
                "requires_human_confirmation": True,
                "limitations": [
                    "planning only",
                    "function-level not_found can be caused by missing or failed IDA/Ghidra configuration",
                    "focused function-level analysis reviews recovered function features and does not execute the sample",
                ],
            },
        )


def _comparisons(context: dict[str, Any], params: dict[str, Any]) -> list[Any] | None:
    if isinstance(params.get("comparisons"), list):
        return params["comparisons"]
    result = context.get("results", {}).get("static_dynamic_function_validation")
    if isinstance(result, dict) and result.get("status") != "error":
        data = result.get("data", {})
        if isinstance(data, dict) and isinstance(data.get("comparisons"), list):
            return data["comparisons"]
    return None


def _requested_categories(params: dict[str, Any]) -> set[str]:
    value = params.get("behavior_categories")
    if isinstance(value, str) and value:
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value if str(item)}
    return set()


def _target_modes(params: dict[str, Any]) -> set[str]:
    value = params.get("target_modes")
    if isinstance(value, str) and value:
        return {value}
    if isinstance(value, list):
        return {str(item) for item in value if str(item)}
    return {"dynamic", "function_level"}


def _targeted(needs_dynamic: bool, needs_function: bool, modes: set[str]) -> bool:
    return ("dynamic" in modes and needs_dynamic) or (
        "function_level" in modes and needs_function
    )


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
