from __future__ import annotations

from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ValidationCompareStaticDynamicFunctionLevelFunction(AnalysisFunction):
    id = "validation.compare_static_dynamic_function"
    name = "Static, dynamic, and function-level behavior comparison"
    category = "validation"
    result_key = "static_dynamic_function_validation"
    description = (
        "Compares static behavior candidates against broad dynamic observations and "
        "function-level evidence exported by IDA/Ghidra feature extractors."
    )
    cost = "low"
    candidate_only = True
    requires_human_confirmation = True
    requires_results = ["static_behavior_map"]
    recommended_before = [
        "behavior.map_static",
        "behavior.map_dynamic",
        "tool.ida_function_features",
        "tool.ghidra_function_features",
    ]
    output_schema = {
        "comparisons": "Per-behavior dynamic and function-level coverage.",
        "summary": "Counts for observed/found/missing behavior coverage.",
        "limitations": "Evidence comparison only; not proof of absence.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        static_data = _result_data(context, "static_behavior_map")
        static_behaviors = static_data.get("behaviors") if static_data else None
        if not isinstance(static_behaviors, list):
            return _error(self.id, self.result_key, "missing_static_behavior_map", "static_behavior_map data.behaviors is required")

        dynamic_state = _dynamic_state(context)
        function_state = _function_state(context)
        dynamic_categories = _dynamic_categories(context)
        function_categories = _function_categories(context, static_behaviors)
        max_evidence = _int_param(params, "max_evidence_per_side", 12)
        max_functions = _int_param(params, "max_functions_per_behavior", 12)

        comparisons = []
        for behavior in static_behaviors:
            if not isinstance(behavior, dict):
                continue
            category = str(behavior.get("category") or behavior.get("behavior_id") or "")
            if not category:
                continue
            dynamic_found = category in dynamic_categories
            function_matches = function_categories.get(category, [])[:max_functions]
            function_found = bool(function_matches)
            comparisons.append(
                {
                    "category": category,
                    "static_result": "candidate",
                    "dynamic_result": (
                        "skipped" if dynamic_state["status"] == "skipped" else "observed" if dynamic_found else "not_observed"
                    ),
                    "function_level_result": (
                        "skipped" if function_state["status"] == "skipped" else "found" if function_found else "not_found"
                    ),
                    "needs_focused_dynamic": not dynamic_found,
                    "needs_focused_function_level": not function_found,
                    "gap": _gap(not dynamic_found, not function_found),
                    "static_confidence": str(behavior.get("confidence") or ""),
                    "static_score": _safe_int(behavior.get("score")),
                    "static_evidence": _dict_list(behavior.get("evidence"))[:max_evidence],
                    "related_functions": function_matches,
                    "dynamic_skip_reason": dynamic_state["reason"],
                    "function_level_skip_reason": function_state["reason"],
                }
            )

        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "comparisons": comparisons,
                "summary": _summary(comparisons),
                "dynamic_state": dynamic_state,
                "function_level_state": function_state,
                "requires_human_confirmation": True,
                "limitations": [
                    "static behavior remains candidate evidence",
                    "not observed dynamically is not proof of absence",
                    "function-level not_found can mean the configured tool failed or did not recover enough function detail",
                ],
            },
        )


def _dynamic_state(context: dict[str, Any]) -> dict[str, str]:
    result = context.get("results", {}).get("dynamic_behavior_map")
    if not isinstance(result, dict):
        return {"status": "missing", "reason": "dynamic_behavior_map_missing"}
    if result.get("status") == "skipped":
        data = result.get("data", {})
        return {
            "status": "skipped",
            "reason": str((data if isinstance(data, dict) else {}).get("skip_reason") or "dynamic_behavior_map_skipped"),
        }
    if result.get("status") == "error":
        error = result.get("error", {})
        return {
            "status": "error",
            "reason": str((error if isinstance(error, dict) else {}).get("code") or "dynamic_behavior_map_error"),
        }
    return {"status": "available", "reason": ""}


def _function_state(context: dict[str, Any]) -> dict[str, str]:
    keys = ["ida_function_features", "ghidra_function_features"]
    found_any = False
    reasons = []
    for key in keys:
        result = context.get("results", {}).get(key)
        if not isinstance(result, dict):
            reasons.append(f"{key}:missing")
            continue
        if result.get("status") == "success":
            found_any = True
            continue
        error = result.get("error", {})
        reasons.append(f"{key}:{str((error if isinstance(error, dict) else {}).get('code') or result.get('status') or 'unavailable')}")
    if found_any:
        return {"status": "available", "reason": ""}
    return {"status": "skipped", "reason": "; ".join(reasons) or "function_features_unavailable"}


def _dynamic_categories(context: dict[str, Any]) -> set[str]:
    data = _result_data(context, "dynamic_behavior_map")
    return {
        str(item.get("category") or item.get("behavior_id") or "")
        for item in _dict_list(data.get("behaviors"))
        if str(item.get("category") or item.get("behavior_id") or "")
    }


def _function_categories(
    context: dict[str, Any],
    static_behaviors: list[Any],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for behavior in static_behaviors:
        if not isinstance(behavior, dict):
            continue
        category = str(behavior.get("category") or behavior.get("behavior_id") or "")
        for related in _dict_list(behavior.get("related_functions")):
            if category:
                _append_unique(grouped.setdefault(category, []), related)
    for result_key, tool in [("ida_function_features", "ida"), ("ghidra_function_features", "ghidra")]:
        data = _result_data(context, result_key)
        for function in _dict_list(data.get("functions")):
            for candidate in _dict_list(function.get("candidate_behaviors")):
                category = str(candidate.get("category") or "")
                if not category:
                    continue
                _append_unique(
                    grouped.setdefault(category, []),
                    {
                        "tool": tool,
                        "name": str(function.get("name") or "")[:300],
                        "address": str(function.get("start") or "")[:64],
                        "size": _safe_int(function.get("size")),
                        "evidence": _string_list(candidate.get("keywords"))[:10],
                    },
                )
    return grouped


def _gap(needs_dynamic: bool, needs_function: bool) -> str:
    if needs_dynamic and needs_function:
        return "needs_focused_dynamic_and_function_level"
    if needs_dynamic:
        return "needs_focused_dynamic"
    if needs_function:
        return "needs_focused_function_level"
    return "covered"


def _summary(comparisons: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "categories": len(comparisons),
        "dynamic_observed": sum(1 for item in comparisons if item.get("dynamic_result") == "observed"),
        "dynamic_not_observed": sum(1 for item in comparisons if item.get("dynamic_result") != "observed"),
        "function_level_found": sum(1 for item in comparisons if item.get("function_level_result") == "found"),
        "function_level_not_found": sum(1 for item in comparisons if item.get("function_level_result") != "found"),
        "needs_focused_dynamic": sum(1 for item in comparisons if item.get("needs_focused_dynamic")),
        "needs_focused_function_level": sum(1 for item in comparisons if item.get("needs_focused_function_level")),
    }


def _result_data(context: dict[str, Any], result_key: str) -> dict[str, Any]:
    result = context.get("results", {}).get(result_key)
    if not isinstance(result, dict) or result.get("status") == "error":
        return {}
    data = result.get("data", {})
    return data if isinstance(data, dict) else {}


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _append_unique(items: list[dict[str, Any]], item: dict[str, Any]) -> None:
    if item not in items:
        items.append(item)


def _int_param(params: dict[str, Any], key: str, default: int) -> int:
    try:
        return max(0, int(params.get(key, default)))
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _error(function_id: str, result_key: str, code: str, message: str) -> FunctionResult:
    return FunctionResult(
        function_id=function_id,
        result_key=result_key,
        status="error",
        error={"code": code, "message": message},
    )
