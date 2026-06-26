from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

_DEFAULT_EVENT_GROUPS = [
    "process_events",
    "file_events",
    "registry_events",
    "network_events",
    "service_events",
    "scheduled_task_events",
    "module_load_events",
]


@lru_cache(maxsize=1)
def load_behavior_taxonomy() -> dict[str, Any]:
    path = Path(__file__).resolve().parents[1] / "knowledge" / "behavior_taxonomy.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"event_groups": _DEFAULT_EVENT_GROUPS, "categories": []}
    return data if isinstance(data, dict) else {"event_groups": _DEFAULT_EVENT_GROUPS, "categories": []}


def event_groups() -> list[str]:
    groups = load_behavior_taxonomy().get("event_groups", [])
    if not isinstance(groups, list):
        return list(_DEFAULT_EVENT_GROUPS)
    return [str(item) for item in groups if str(item)] or list(_DEFAULT_EVENT_GROUPS)


def static_rules() -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for category in _categories():
        category_id = str(category.get("id") or "")
        if not category_id:
            continue
        static = category.get("static", {})
        if not isinstance(static, dict):
            static = {}
        rules[category_id] = {
            "name": str(category.get("name") or category_id),
            "keywords": _string_list(static.get("keywords")),
        }
    return rules


def dynamic_rules() -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for category in _categories():
        category_id = str(category.get("id") or "")
        if not category_id:
            continue
        dynamic = category.get("dynamic", {})
        if not isinstance(dynamic, dict):
            dynamic = {}
        rules[category_id] = {
            "name": str(category.get("name") or category_id),
            "event_groups": _string_list(dynamic.get("event_groups")),
            "event_types": _string_list(dynamic.get("event_types")),
            "keywords": _string_list(dynamic.get("keywords")),
        }
    return rules


def keyword_group_map() -> dict[str, str]:
    mapping: dict[str, str] = {}
    for category in _categories():
        category_id = str(category.get("id") or "")
        static = category.get("static", {})
        if not category_id or not isinstance(static, dict):
            continue
        for group in _string_list(static.get("keyword_groups")):
            mapping[group] = category_id
    return mapping


def boundary_patterns() -> dict[str, list[tuple[str, re.Pattern[str]]]]:
    patterns: dict[str, list[tuple[str, re.Pattern[str]]]] = {}
    for category in _categories():
        category_id = str(category.get("id") or "")
        static = category.get("static", {})
        if not category_id or not isinstance(static, dict):
            continue
        for keyword in _string_list(static.get("boundary_keywords")):
            patterns.setdefault(category_id, []).append(
                (
                    keyword,
                    re.compile(
                        rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])",
                        re.IGNORECASE,
                    ),
                )
            )
    return patterns


def _categories() -> list[dict[str, Any]]:
    categories = load_behavior_taxonomy().get("categories", [])
    if not isinstance(categories, list):
        return []
    return [item for item in categories if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item)]
