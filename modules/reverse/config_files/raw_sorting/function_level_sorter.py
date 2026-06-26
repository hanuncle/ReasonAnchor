from __future__ import annotations

from typing import Any


def sort_output(item: dict[str, Any]) -> dict[str, Any]:
    result_key = str(item.get("result_key") or "")
    output = item.get("output") if isinstance(item.get("output"), dict) else {}
    if output.get("status") == "error":
        return {
            "summary": f"{result_key} returned an error.",
            "error": output.get("error", {}),
            "limitations": ["Sorter returned compact error view."],
        }
    data = output.get("data") if isinstance(output.get("data"), dict) else {}

    if result_key == "ida_function_analysis":
        functions = _function_list(data)
        return {
            "summary": f"IDA recovered {len(functions)} functions.",
            "key_fields": {
                "tool": data.get("tool", "ida"),
                "status": data.get("status", ""),
                "counts": data.get("counts", {}),
                "warnings": data.get("warnings", []),
            },
            "largest_functions": _largest_functions(functions),
            "entry_like_functions": _named_samples(functions, ["main", "start", "program", "winmain"]),
            "stdout_excerpt": data.get("stdout_excerpt", ""),
            "stderr_excerpt": data.get("stderr_excerpt", ""),
            "limitations": _string_list(data.get("limitations")),
        }

    if result_key == "ida_function_features":
        functions = _function_list(data)
        candidate_functions = [
            fn for fn in functions
            if isinstance(fn.get("candidate_behaviors"), list) and fn.get("candidate_behaviors")
        ]
        return {
            "summary": (
                f"IDA function features collected for {len(functions)} functions; "
                f"candidate_behavior_functions={len(candidate_functions)}."
            ),
            "key_fields": {
                "tool": data.get("tool", "ida"),
                "status": data.get("status", ""),
                "counts": data.get("counts", {}),
                "warnings": data.get("warnings", []),
            },
            "candidate_behavior_functions": [
                {
                    "name": fn.get("name", ""),
                    "start": fn.get("start", ""),
                    "size": fn.get("size", 0),
                    "api_calls": _string_list(fn.get("api_calls"))[:15],
                    "strings": _string_list(fn.get("strings"))[:10],
                    "candidate_behaviors": fn.get("candidate_behaviors", []),
                }
                for fn in candidate_functions[:20]
            ],
            "largest_functions": _largest_functions(functions),
            "warnings": [
                "If candidate_behavior_functions is zero for a .NET sample, IDA may have recovered managed method names but not useful API/string references.",
            ],
            "stdout_excerpt": data.get("stdout_excerpt", ""),
            "stderr_excerpt": data.get("stderr_excerpt", ""),
            "limitations": _string_list(data.get("limitations")),
        }

    if result_key == "static_dynamic_function_validation":
        comparisons = [item for item in data.get("comparisons", []) if isinstance(item, dict)]
        return {
            "summary": (
                f"Static/dynamic/function comparison covered {len(comparisons)} categories; "
                f"dynamic_state={data.get('dynamic_state', {}).get('status', '') if isinstance(data.get('dynamic_state'), dict) else ''}."
            ),
            "comparisons": [
                {
                    "category": item.get("category", ""),
                    "static_result": item.get("static_result", ""),
                    "dynamic_result": item.get("dynamic_result", ""),
                    "function_level_result": item.get("function_level_result", ""),
                    "gap": item.get("gap", ""),
                    "needs_focused_dynamic": bool(item.get("needs_focused_dynamic")),
                    "needs_focused_function_level": bool(item.get("needs_focused_function_level")),
                    "static_confidence": item.get("static_confidence", ""),
                    "static_score": item.get("static_score", 0),
                    "dynamic_skip_reason": item.get("dynamic_skip_reason", ""),
                    "function_level_skip_reason": item.get("function_level_skip_reason", ""),
                    "static_evidence_sample": _evidence_sample(item.get("static_evidence"), 8),
                }
                for item in comparisons[:30]
            ],
            "key_fields": {
                "summary": data.get("summary", {}),
                "dynamic_state": data.get("dynamic_state", {}),
                "function_level_state": data.get("function_level_state", {}),
                "requires_human_confirmation": bool(data.get("requires_human_confirmation")),
            },
            "limitations": _string_list(data.get("limitations")),
        }

    if result_key == "focused_function_level_plan":
        targets = [item for item in data.get("targets", []) if isinstance(item, dict)]
        return {
            "summary": f"Focused function-level plan created {len(targets)} targets.",
            "targets": [
                {
                    "behavior_category": item.get("behavior_category", ""),
                    "gap": item.get("gap", ""),
                    "needs_focused_dynamic": bool(item.get("needs_focused_dynamic")),
                    "needs_focused_function_level": bool(item.get("needs_focused_function_level")),
                    "static_confidence": item.get("static_confidence", ""),
                    "static_score": item.get("static_score", 0),
                    "keywords": _string_list(item.get("keywords"))[:20],
                    "existing_related_functions": item.get("existing_related_functions", []),
                    "note": item.get("note", ""),
                }
                for item in targets[:30]
            ],
            "key_fields": {
                "source": data.get("source", ""),
                "counts": data.get("counts", {}),
                "requires_human_confirmation": bool(data.get("requires_human_confirmation")),
            },
            "limitations": _string_list(data.get("limitations")),
        }

    if result_key == "focused_function_level_analysis":
        targets = [item for item in data.get("targets", []) if isinstance(item, dict)]
        return {
            "summary": (
                f"Focused function-level analysis checked {len(targets)} targets; "
                f"found={data.get('summary', {}).get('found', 0) if isinstance(data.get('summary'), dict) else 0}."
            ),
            "targets": [
                {
                    "behavior_category": item.get("behavior_category", ""),
                    "gap": item.get("gap", ""),
                    "status": item.get("status", ""),
                    "matching_functions": item.get("matching_functions", [])[:20] if isinstance(item.get("matching_functions"), list) else [],
                    "static_evidence_sample": _evidence_sample(item.get("static_evidence"), 8),
                    "note": item.get("note", ""),
                }
                for item in targets[:30]
            ],
            "key_fields": {
                "summary": data.get("summary", {}),
                "requires_human_confirmation": bool(data.get("requires_human_confirmation")),
            },
            "limitations": _string_list(data.get("limitations")),
        }

    return {
        "summary": f"Function-level output for {result_key}.",
        "key_fields": data,
        "limitations": ["No specialized branch matched this result_key."],
    }


def _function_list(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [item for item in data.get("functions", []) if isinstance(item, dict)]


def _largest_functions(functions: list[dict[str, Any]], limit: int = 15) -> list[dict[str, Any]]:
    sorted_functions = sorted(functions, key=lambda item: int(item.get("size") or 0), reverse=True)
    return [
        {
            "name": item.get("name", ""),
            "start": item.get("start", ""),
            "end": item.get("end", ""),
            "size": item.get("size", 0),
        }
        for item in sorted_functions[:limit]
    ]


def _named_samples(functions: list[dict[str, Any]], needles: list[str], limit: int = 15) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in functions:
        name = str(item.get("name") or "")
        lowered = name.lower()
        if not any(needle in lowered for needle in needles):
            continue
        result.append(
            {
                "name": name,
                "start": item.get("start", ""),
                "end": item.get("end", ""),
                "size": item.get("size", 0),
            }
        )
        if len(result) >= limit:
            break
    return result


def _evidence_sample(value: Any, limit: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        result.append(
            {
                "source_result": item.get("source_result", ""),
                "field": item.get("field", ""),
                "value": str(item.get("value", ""))[:200],
                "reason": item.get("reason", ""),
            }
        )
        if len(result) >= limit:
            break
    return result


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []
