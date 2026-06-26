from __future__ import annotations

from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ValidationCompareStaticDynamicFunction(AnalysisFunction):
    id = "validation.compare_static_dynamic"
    name = "Static and dynamic behavior comparison"
    category = "validation"
    result_key = "static_dynamic_validation"
    description = (
        "Compares static behavior candidates with dynamic telemetry observations. "
        "This is an evidence consistency step and does not execute samples."
    )
    cost = "low"
    candidate_only = True
    requires_human_confirmation = True
    requires_results = ["static_behavior_map", "dynamic_behavior_map"]
    recommended_before = ["behavior.map_static", "behavior.map_dynamic"]
    output_schema = {
        "comparisons": "Per-behavior static candidate and dynamic observation comparison.",
        "summary": "Counts for matched, static-only, dynamic-only, and compared categories.",
        "limitations": "Not-observed dynamic behavior is not proof of absence.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        static_data = _result_data(context, "static_behavior_map")
        if not static_data:
            return self._error(
                "missing_static_behavior_map",
                "static_behavior_map result is required",
            )
        dynamic_data = _result_data(context, "dynamic_behavior_map")
        dynamic_result = context.get("results", {}).get("dynamic_behavior_map")
        if isinstance(dynamic_result, dict) and dynamic_result.get("status") == "skipped":
            data = dynamic_result.get("data", {})
            if not isinstance(data, dict):
                data = {}
            static_behaviors = static_data.get("behaviors")
            return FunctionResult(
                function_id=self.id,
                result_key=self.result_key,
                status="skipped",
                data={
                    "skipped": True,
                    "skip_reason": str(
                        data.get("skip_reason") or "dynamic_behavior_map_skipped"
                    ),
                    "comparisons": [],
                    "summary": {
                        "categories": 0,
                        "matched": 0,
                        "static_candidate_not_observed": 0,
                        "dynamic_observed_without_static_candidate": 0,
                        "static_candidates": len(static_behaviors)
                        if isinstance(static_behaviors, list)
                        else 0,
                        "dynamic_observed": 0,
                    },
                    "requires_human_confirmation": True,
                    "limitations": [
                        "Static/dynamic comparison skipped because dynamic behavior mapping was skipped.",
                        "No dynamic telemetry was available for comparison.",
                    ],
                },
            )
        if not dynamic_data:
            return self._error(
                "missing_dynamic_behavior_map",
                "dynamic_behavior_map result is required",
            )

        static_behaviors = static_data.get("behaviors")
        dynamic_behaviors = dynamic_data.get("behaviors")
        if not isinstance(static_behaviors, list):
            return self._error(
                "invalid_static_behavior_map",
                "static_behavior_map data.behaviors must be a list",
            )
        if not isinstance(dynamic_behaviors, list):
            return self._error(
                "invalid_dynamic_behavior_map",
                "dynamic_behavior_map data.behaviors must be a list",
            )

        max_evidence = _int_param(params, "max_evidence_per_side", 20)
        static_by_category = _by_category(static_behaviors)
        dynamic_by_category = _by_category(dynamic_behaviors)
        categories = sorted(set(static_by_category) | set(dynamic_by_category))
        comparisons = [
            _compare_category(
                category,
                static_by_category.get(category),
                dynamic_by_category.get(category),
                max_evidence,
            )
            for category in categories
        ]
        summary = _summary(comparisons)

        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "comparisons": comparisons,
                "summary": summary,
                "requires_human_confirmation": True,
                "limitations": [
                    "static evidence is candidate-only",
                    "dynamic not_observed means telemetry did not show it, not that behavior is absent",
                    "comparison quality depends on static and dynamic input coverage",
                    "does not execute samples",
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


def _compare_category(
    category: str,
    static_behavior: dict[str, Any] | None,
    dynamic_behavior: dict[str, Any] | None,
    max_evidence: int,
) -> dict[str, Any]:
    if static_behavior and dynamic_behavior:
        consistency = "matched"
        note = "Static candidate has supporting dynamic telemetry."
    elif static_behavior:
        consistency = "static_candidate_not_observed"
        note = "Static candidate was not observed in available dynamic telemetry."
    else:
        consistency = "dynamic_observed_without_static_candidate"
        note = "Dynamic telemetry observed behavior without a matching static candidate."

    return {
        "category": category,
        "static_result": "candidate" if static_behavior else "not_present",
        "dynamic_result": "observed" if dynamic_behavior else "not_observed",
        "consistency": consistency,
        "note": note,
        "static_confidence": str((static_behavior or {}).get("confidence", "")),
        "dynamic_confidence": str((dynamic_behavior or {}).get("confidence", "")),
        "static_score": _safe_int((static_behavior or {}).get("score")),
        "dynamic_score": _safe_int((dynamic_behavior or {}).get("score")),
        "static_evidence": _evidence(static_behavior, max_evidence),
        "dynamic_evidence": _evidence(dynamic_behavior, max_evidence),
    }


def _summary(comparisons: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {
        "categories": len(comparisons),
        "matched": 0,
        "static_candidate_not_observed": 0,
        "dynamic_observed_without_static_candidate": 0,
    }
    for item in comparisons:
        consistency = str(item.get("consistency", ""))
        if consistency in counts:
            counts[consistency] += 1
    counts["static_candidates"] = sum(
        1 for item in comparisons if item.get("static_result") == "candidate"
    )
    counts["dynamic_observed"] = sum(
        1 for item in comparisons if item.get("dynamic_result") == "observed"
    )
    return counts


def _by_category(behaviors: list[Any]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for behavior in behaviors:
        if not isinstance(behavior, dict):
            continue
        category = str(behavior.get("category") or behavior.get("behavior_id") or "")
        if not category:
            continue
        current = grouped.get(category)
        if current is None:
            grouped[category] = {
                **behavior,
                "score": _safe_int(behavior.get("score")),
                "evidence": _list(behavior.get("evidence")),
            }
            continue
        current["score"] = _safe_int(current.get("score")) + _safe_int(
            behavior.get("score")
        )
        current["confidence"] = _merge_confidence(
            str(current.get("confidence", "low")),
            str(behavior.get("confidence", "low")),
        )
        for evidence in _list(behavior.get("evidence")):
            if evidence not in current["evidence"]:
                current["evidence"].append(evidence)
    return grouped


def _result_data(context: dict[str, Any], result_key: str) -> dict[str, Any]:
    result = context.get("results", {}).get(result_key)
    if not isinstance(result, dict) or result.get("status") == "error":
        return {}
    data = result.get("data", {})
    return data if isinstance(data, dict) else {}


def _evidence(behavior: dict[str, Any] | None, limit: int) -> list[dict[str, Any]]:
    if not behavior:
        return []
    return [
        item
        for item in _list(behavior.get("evidence"))[: max(0, limit)]
        if isinstance(item, dict)
    ]


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _merge_confidence(current: str, incoming: str) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    return incoming if order.get(incoming, 1) > order.get(current, 1) else current


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
