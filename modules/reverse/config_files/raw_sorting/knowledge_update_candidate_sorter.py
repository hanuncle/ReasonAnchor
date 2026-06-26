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
    target = data.get("target") if isinstance(data.get("target"), dict) else {}
    candidate = data.get("candidate") if isinstance(data.get("candidate"), dict) else {}
    return {
        "summary": (
            "Knowledge update candidate created: "
            f"target={target.get('key', '')}, "
            f"type={data.get('update_type', '')}, "
            f"status={data.get('review_status', '')}."
        ),
        "key_fields": {
            "candidate_id": data.get("candidate_id", ""),
            "candidate_path": data.get("candidate_path", ""),
            "target": target,
            "update_type": data.get("update_type", ""),
            "review_status": data.get("review_status", ""),
            "official_knowledge_modified": bool(data.get("official_knowledge_modified")),
            "requires_human_review": bool(data.get("requires_human_review")),
            "dry_run": bool(data.get("dry_run")),
            "confidence": candidate.get("confidence", ""),
            "behavior_category": candidate.get("behavior_category", ""),
            "technique_id": candidate.get("technique_id", ""),
            "source_raw_output_ids": candidate.get("source_raw_output_ids", []),
            "source_result_keys": candidate.get("source_result_keys", []),
        },
        "warnings": [
            "This is a pending candidate only; official knowledge files were not modified.",
            "Human review is required before applying the proposed change.",
        ],
        "limitations": _string_list(data.get("limitations")),
    }


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []
