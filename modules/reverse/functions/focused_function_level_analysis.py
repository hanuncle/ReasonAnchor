from __future__ import annotations

from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class FocusedFunctionLevelAnalysisFunction(AnalysisFunction):
    id = "tool.focused_function_level_analysis"
    name = "Focused function-level behavior analysis"
    category = "tool"
    result_key = "focused_function_level_analysis"
    description = (
        "Reviews recovered IDA/Ghidra function features for focused behavior targets "
        "and reports matching functions, APIs, strings, and remaining gaps."
    )
    cost = "low"
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    requires_results = ["focused_function_level_plan"]
    recommended_before = ["validation.plan_focused_function_level"]
    output_schema = {
        "targets": "Focused behavior categories and matching function evidence.",
        "summary": "Coverage counts for focused function-level review.",
        "limitations": "Uses already recovered function features; it does not execute samples.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        targets = _targets(context, params)
        if targets is None:
            return FunctionResult(
                function_id=self.id,
                result_key=self.result_key,
                status="error",
                error={
                    "code": "missing_focused_function_level_plan",
                    "message": "focused_function_level_plan data.targets or params.targets is required",
                },
            )
        functions = _function_features(context)
        if not functions:
            return FunctionResult(
                function_id=self.id,
                result_key=self.result_key,
                status="skipped",
                data={
                    "skipped": True,
                    "skip_reason": "function_level_features_unavailable",
                    "targets": [],
                    "summary": {"targets": len(targets), "found": 0, "not_found": len(targets)},
                    "requires_human_confirmation": True,
                    "limitations": [
                        "No successful IDA or Ghidra function feature output was available.",
                        "Focused function-level analysis could not inspect recovered function features.",
                    ],
                },
            )

        max_matches = _int_param(params, "max_matches_per_target", 20)
        reviewed = [
            _review_target(target, functions, max_matches)
            for target in targets
            if isinstance(target, dict)
        ]
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "targets": reviewed,
                "summary": {
                    "targets": len(reviewed),
                    "found": sum(1 for item in reviewed if item.get("status") == "found"),
                    "not_found": sum(1 for item in reviewed if item.get("status") == "not_found"),
                    "matching_functions": sum(len(item.get("matching_functions", [])) for item in reviewed),
                },
                "requires_human_confirmation": True,
                "limitations": [
                    "reviews existing function-level feature output only",
                    "not_found means no recovered function matched the focused keywords",
                    "does not execute the sample",
                ],
            },
        )


def _targets(context: dict[str, Any], params: dict[str, Any]) -> list[Any] | None:
    if isinstance(params.get("targets"), list):
        return params["targets"]
    result = context.get("results", {}).get("focused_function_level_plan")
    if isinstance(result, dict) and result.get("status") != "error":
        data = result.get("data", {})
        if isinstance(data, dict) and isinstance(data.get("targets"), list):
            return data["targets"]
    return None


def _function_features(context: dict[str, Any]) -> list[dict[str, Any]]:
    features = []
    for result_key, tool in [("ida_function_features", "ida"), ("ghidra_function_features", "ghidra")]:
        result = context.get("results", {}).get(result_key)
        if not isinstance(result, dict) or result.get("status") != "success":
            continue
        data = result.get("data", {})
        if not isinstance(data, dict):
            continue
        for function in _dict_list(data.get("functions")):
            item = dict(function)
            item["tool"] = tool
            features.append(item)
    return features


def _review_target(
    target: dict[str, Any],
    functions: list[dict[str, Any]],
    max_matches: int,
) -> dict[str, Any]:
    category = str(target.get("behavior_category") or "")
    keywords = _lower_keywords(target)
    matches = []
    for function in functions:
        score, evidence = _match_function(function, category, keywords)
        if score <= 0:
            continue
        matches.append(
            {
                "tool": str(function.get("tool") or ""),
                "name": str(function.get("name") or "")[:300],
                "address": str(function.get("start") or "")[:64],
                "size": _safe_int(function.get("size")),
                "score": score,
                "evidence": evidence[:20],
            }
        )
    matches.sort(key=lambda item: (-_safe_int(item.get("score")), str(item.get("name") or "")))
    return {
        "behavior_category": category,
        "gap": str(target.get("gap") or ""),
        "status": "found" if matches else "not_found",
        "matching_functions": matches[:max(0, max_matches)],
        "static_evidence": _dict_list(target.get("static_evidence"))[:12],
        "note": (
            "Focused function-level review found matching recovered functions."
            if matches
            else "No recovered function matched this behavior target."
        ),
    }


def _lower_keywords(target: dict[str, Any]) -> list[str]:
    values = _string_list(target.get("keywords"))
    for evidence in _dict_list(target.get("static_evidence")):
        values.append(str(evidence.get("value") or ""))
        values.append(str(evidence.get("reason") or ""))
    result = []
    seen = set()
    for value in values:
        lowered = value.lower().strip()
        if len(lowered) < 3 or lowered in seen:
            continue
        seen.add(lowered)
        result.append(lowered)
    return result[:80]


def _match_function(
    function: dict[str, Any],
    category: str,
    keywords: list[str],
) -> tuple[int, list[str]]:
    evidence = []
    score = 0
    for candidate in _dict_list(function.get("candidate_behaviors")):
        if str(candidate.get("category") or "") != category:
            continue
        hits = _string_list(candidate.get("keywords"))[:20]
        evidence.extend([f"candidate_behavior:{hit}" for hit in hits] or [f"candidate_behavior:{category}"])
        score += 5
    haystack_values = _string_list(function.get("api_calls")) + _string_list(function.get("strings"))
    haystack = [value.lower() for value in haystack_values]
    for keyword in keywords:
        if any(keyword in value for value in haystack):
            evidence.append(f"keyword:{keyword}")
            score += 1
    return score, _unique(evidence)


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]


def _unique(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


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
