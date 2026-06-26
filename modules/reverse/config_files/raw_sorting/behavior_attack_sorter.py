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

    if result_key == "static_behavior_map":
        behaviors = [item for item in data.get("behaviors", []) if isinstance(item, dict)]
        return {
            "summary": f"Static behavior mapping produced {len(behaviors)} candidate behavior categories.",
            "behaviors": [
                {
                    "behavior_id": behavior.get("behavior_id", behavior.get("category", "")),
                    "category": behavior.get("category", ""),
                    "name": behavior.get("name", ""),
                    "confidence": behavior.get("confidence", "low"),
                    "score": behavior.get("score", 0),
                    "verification": behavior.get("verification", "candidate_static_only"),
                    "evidence_sample": _evidence_sample(behavior.get("evidence"), 12),
                    "evidence_count": len(behavior.get("evidence", [])) if isinstance(behavior.get("evidence"), list) else 0,
                    "related_functions_count": len(behavior.get("related_functions", [])) if isinstance(behavior.get("related_functions"), list) else 0,
                }
                for behavior in behaviors
            ],
            "quality_hints": _quality_hints(behaviors),
            "key_fields": {
                "counts": data.get("counts", {}),
                "requires_human_confirmation": bool(data.get("requires_human_confirmation")),
            },
            "limitations": _string_list(data.get("limitations")),
        }

    if result_key == "attack_mapping":
        techniques = [item for item in data.get("techniques", []) if isinstance(item, dict)]
        return {
            "summary": f"Static ATT&CK mapping produced {len(techniques)} candidate techniques.",
            "techniques": [
                {
                    "technique_id": technique.get("technique_id", ""),
                    "name": technique.get("name", ""),
                    "tactic": technique.get("tactic", []),
                    "behavior_categories": technique.get("behavior_categories", []),
                    "confidence": technique.get("confidence", "low"),
                    "score": technique.get("score", 0),
                    "verification": technique.get("verification", "candidate_static_only"),
                    "source": technique.get("source", ""),
                    "evidence_sample": _evidence_sample(technique.get("evidence"), 12),
                    "evidence_count": len(technique.get("evidence", [])) if isinstance(technique.get("evidence"), list) else 0,
                }
                for technique in techniques
            ],
            "quality_hints": _quality_hints(techniques),
            "key_fields": {
                "unmapped_behaviors": data.get("unmapped_behaviors", []),
                "counts": data.get("counts", {}),
                "knowledge_sources": data.get("knowledge_sources", []),
                "requires_human_confirmation": bool(data.get("requires_human_confirmation")),
            },
            "limitations": _string_list(data.get("limitations")),
        }

    return {
        "summary": f"Behavior/ATT&CK output for {result_key}.",
        "key_fields": data,
        "limitations": ["No specialized branch matched this result_key."],
    }


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


def _quality_hints(items: list[dict[str, Any]]) -> list[str]:
    hints: list[str] = []
    for item in items:
        evidence = item.get("evidence") if isinstance(item.get("evidence"), list) else []
        weak_ioc = [
            ev
            for ev in evidence
            if isinstance(ev, dict)
            and ev.get("source_result") == "ioc_extractor"
            and str(ev.get("reason")) in {"network_ioc", "network_ioc_weak"}
        ]
        if weak_ioc and len(weak_ioc) == len(evidence):
            hints.append(
                f"{item.get('category') or item.get('technique_id')}: evidence is IOC-only; require dynamic, import, or function-level corroboration."
            )
        if str(item.get("verification", "")).startswith("candidate"):
            hints.append(
                f"{item.get('category') or item.get('technique_id')}: candidate only, not confirmed runtime behavior."
            )
    return _unique(hints)[:10]


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []
