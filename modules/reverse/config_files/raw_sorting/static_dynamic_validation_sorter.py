from __future__ import annotations

from typing import Any


def sort_output(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    data = _data(raw_output_item)
    status = str(raw_output_item.get("status") or "")
    error = _error(raw_output_item)
    if status == "error" or error:
        return {
            "summary": f"Static/dynamic validation failed: {str(error.get('code') or 'error')}.",
            "key_fields": {
                "failed": True,
                "error": error,
                "required_next_step": _required_next_step(error),
                "summary": {},
                "matched_categories": [],
                "static_not_observed": [],
                "dynamic_only": [],
            },
            "evidence_hints": [],
            "warnings": ["Validation did not run; do not interpret this as zero differences."],
            "limitations": _limitations(data),
        }
    comparisons = data.get("comparisons", [])
    if not isinstance(comparisons, list):
        comparisons = []
    summary = data.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    if status == "skipped":
        return {
            "summary": (
                "Static/dynamic validation was skipped: "
                f"{str(data.get('skip_reason') or 'upstream_skipped')[:160]}."
            ),
            "key_fields": {
                "summary": summary,
                "skipped": True,
                "skip_reason": str(data.get("skip_reason") or ""),
            },
            "evidence_hints": [],
            "warnings": ["Static/dynamic validation skipped because dynamic evidence was unavailable."],
            "limitations": _limitations(data),
        }
    return {
        "summary": (
            "Static/dynamic validation compared "
            f"{summary.get('categories', len(comparisons))} behavior categories."
        ),
        "key_fields": {
            "summary": summary,
            "matched_categories": _categories_by_consistency(comparisons, "matched"),
            "static_not_observed": _categories_by_consistency(
                comparisons,
                "static_candidate_not_observed",
            ),
            "dynamic_only": _categories_by_consistency(
                comparisons,
                "dynamic_observed_without_static_candidate",
            ),
        },
        "evidence_hints": _comparison_hints(comparisons, limit=30),
        "warnings": _warnings(comparisons),
        "limitations": _limitations(data),
    }


def _data(raw_output_item: dict[str, Any]) -> dict[str, Any]:
    output = raw_output_item.get("output", {})
    if isinstance(output, dict):
        data = output.get("data", {})
        if isinstance(data, dict):
            return data
    return {}


def _error(raw_output_item: dict[str, Any]) -> dict[str, str]:
    output = raw_output_item.get("output", {})
    if isinstance(output, dict) and isinstance(output.get("error"), dict):
        error = output["error"]
        return {
            "code": str(error.get("code") or ""),
            "message": str(error.get("message") or "")[:500],
        }
    return {}


def _required_next_step(error: dict[str, str]) -> str:
    code = error.get("code", "")
    if code == "missing_dynamic_behavior_map":
        return "Run dynamic telemetry collection and dynamic behavior mapping first."
    if code == "missing_static_behavior_map":
        return "Run static behavior mapping first."
    return "Resolve the validation prerequisite error and rerun comparison."


def _categories_by_consistency(comparisons: list[Any], consistency: str) -> list[str]:
    return [
        str(item.get("category"))
        for item in comparisons
        if isinstance(item, dict) and item.get("consistency") == consistency
    ]


def _comparison_hints(comparisons: list[Any], limit: int) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    for item in comparisons:
        if len(hints) >= limit:
            return hints
        if not isinstance(item, dict):
            continue
        hints.append(
            {
                "category": str(item.get("category", "")),
                "consistency": str(item.get("consistency", "")),
                "static_result": str(item.get("static_result", "")),
                "dynamic_result": str(item.get("dynamic_result", "")),
                "note": str(item.get("note", ""))[:300],
                "static_evidence_count": len(_list(item.get("static_evidence"))),
                "dynamic_evidence_count": len(_list(item.get("dynamic_evidence"))),
            }
        )
    return hints


def _warnings(comparisons: list[Any]) -> list[str]:
    warnings: list[str] = []
    if any(
        isinstance(item, dict)
        and item.get("consistency") == "static_candidate_not_observed"
        for item in comparisons
    ):
        warnings.append("Some static candidates were not observed in available telemetry.")
    if any(
        isinstance(item, dict)
        and item.get("consistency") == "dynamic_observed_without_static_candidate"
        for item in comparisons
    ):
        warnings.append("Some dynamic observations had no matching static candidate.")
    return warnings


def _limitations(data: dict[str, Any]) -> list[str]:
    limitations = data.get("limitations", [])
    if isinstance(limitations, list):
        return [str(item)[:300] for item in limitations[:8]]
    return []


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
