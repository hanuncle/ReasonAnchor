from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_FALLBACK_TECHNIQUES: dict[str, dict[str, Any]] = {
    "network_communication": {
        "technique_id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": ["Command and Control"],
        "source": "builtin_fallback",
    },
    "file_write": {
        "technique_id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": ["Command and Control"],
        "source": "builtin_fallback",
    },
    "registry_persistence": {
        "technique_id": "T1547.001",
        "name": "Registry Run Keys / Startup Folder",
        "tactic": ["Persistence", "Privilege Escalation"],
        "source": "builtin_fallback",
    },
    "credential_access": {
        "technique_id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": ["Credential Access"],
        "source": "builtin_fallback",
    },
    "anti_analysis": {
        "technique_id": "T1497",
        "name": "Virtualization/Sandbox Evasion",
        "tactic": ["Defense Evasion", "Discovery"],
        "source": "builtin_fallback",
    },
    "anti_vm_sandbox_evasion": {
        "technique_id": "T1497",
        "name": "Virtualization/Sandbox Evasion",
        "tactic": ["Defense Evasion", "Discovery"],
        "source": "builtin_fallback",
    },
    "system_discovery": {
        "technique_id": "T1082",
        "name": "System Information Discovery",
        "tactic": ["Discovery"],
        "source": "builtin_fallback",
    },
    "privilege_discovery": {
        "technique_id": "T1069",
        "name": "Permission Groups Discovery",
        "tactic": ["Discovery"],
        "source": "builtin_fallback",
    },
    "file_directory_discovery": {
        "technique_id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": ["Discovery"],
        "source": "builtin_fallback",
    },
    "trace_setting_modification": {
        "technique_id": "T1112",
        "name": "Modify Registry",
        "tactic": ["Defense Evasion"],
        "source": "builtin_fallback",
    },
    "packer_or_obfuscation": {
        "technique_id": "T1027",
        "name": "Obfuscated Files or Information",
        "tactic": ["Defense Evasion"],
        "source": "builtin_fallback",
    },
    "service_creation": {
        "technique_id": "T1543.003",
        "name": "Windows Service",
        "tactic": ["Persistence", "Privilege Escalation"],
        "source": "builtin_fallback",
    },
    "scheduled_task": {
        "technique_id": "T1053.005",
        "name": "Scheduled Task",
        "tactic": ["Execution", "Persistence", "Privilege Escalation"],
        "source": "builtin_fallback",
    },
}


class AttackMapStaticFunction(AnalysisFunction):
    id = "attack.map_static"
    name = "Static ATT&CK mapping"
    category = "static"
    result_key = "attack_mapping"
    description = (
        "Maps static behavior candidates to ATT&CK technique candidates using the "
        "reverse module knowledge base plus a small local fallback map."
    )
    cost = "low"
    candidate_only = True
    requires_human_confirmation = True
    requires_results = ["static_behavior_map"]
    recommended_before = ["behavior.map_static"]
    output_schema = {
        "techniques": "ATT&CK technique candidates mapped from static behavior evidence.",
        "unmapped_behaviors": "Behavior categories without a static ATT&CK mapping.",
        "limitations": "Candidate mapping only; not confirmed behavior.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        behavior_data = _result_data(context, "static_behavior_map")
        if not behavior_data:
            return self._error(
                "missing_behavior_map",
                "static_behavior_map result is required",
            )
        behaviors = behavior_data.get("behaviors")
        if not isinstance(behaviors, list):
            return self._error(
                "invalid_behavior_map",
                "static_behavior_map data.behaviors must be a list",
            )

        max_evidence = _int_param(params, "max_evidence_per_technique", 80)
        max_related = _int_param(params, "max_related_functions", 80)
        knowledge = _load_attack_knowledge()
        mapped = _map_behaviors(behaviors, knowledge, max_evidence, max_related)
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "techniques": mapped["techniques"],
                "unmapped_behaviors": mapped["unmapped_behaviors"],
                "counts": {
                    "techniques": len(mapped["techniques"]),
                    "unmapped_behaviors": len(mapped["unmapped_behaviors"]),
                },
                "knowledge_sources": mapped["knowledge_sources"],
                "requires_human_confirmation": True,
                "limitations": [
                    "static ATT&CK mapping only",
                    "candidate techniques require human confirmation",
                    "does not execute sample",
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


def _map_behaviors(
    behaviors: list[Any],
    knowledge: dict[str, list[dict[str, Any]]],
    max_evidence: int,
    max_related: int,
) -> dict[str, Any]:
    by_technique: dict[str, dict[str, Any]] = {}
    unmapped: list[str] = []
    sources: set[str] = set()

    for behavior in behaviors:
        if not isinstance(behavior, dict):
            continue
        category = str(behavior.get("category") or behavior.get("behavior_id") or "")
        if not category:
            continue
        technique_defs = knowledge.get(category) or []
        if not technique_defs and category in _FALLBACK_TECHNIQUES:
            fallback = dict(_FALLBACK_TECHNIQUES[category])
            fallback["behavior_categories"] = [category]
            technique_defs = [fallback]
        if not technique_defs:
            unmapped.append(category)
            continue

        for technique in technique_defs:
            technique_id = str(technique.get("technique_id", ""))
            if not technique_id:
                continue
            source = str(technique.get("source", "module_knowledge"))
            sources.add(source)
            entry = by_technique.setdefault(
                technique_id,
                {
                    "technique_id": technique_id,
                    "name": str(technique.get("name", "")),
                    "tactic": _string_list(technique.get("tactic")),
                    "behavior_categories": [],
                    "confidence": "low",
                    "score": 0,
                    "evidence": [],
                    "related_functions": [],
                    "source": source,
                    "recommended_functions": _string_list(
                        technique.get("recommended_functions")
                    ),
                    "verification": "candidate_static_only",
                },
            )
            _append_unique(entry["behavior_categories"], category)
            score = _safe_int(behavior.get("score"))
            entry["score"] += score
            entry["confidence"] = _merge_confidence(
                str(entry["confidence"]),
                str(behavior.get("confidence", "low")),
            )
            for evidence in behavior.get("evidence", []):
                if isinstance(evidence, dict):
                    _append_limited(entry["evidence"], evidence, max_evidence)
            for related in behavior.get("related_functions", []):
                if isinstance(related, dict):
                    _append_limited(entry["related_functions"], related, max_related)

    techniques = list(by_technique.values())
    techniques.sort(key=lambda item: (-int(item["score"]), str(item["technique_id"])))
    return {
        "techniques": techniques,
        "unmapped_behaviors": _unique(unmapped),
        "knowledge_sources": sorted(sources),
    }


def _load_attack_knowledge() -> dict[str, list[dict[str, Any]]]:
    path = Path(__file__).resolve().parents[1] / "knowledge" / "attack" / "techniques.json"
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        parsed = {}
    techniques = parsed.get("techniques", []) if isinstance(parsed, dict) else []
    by_behavior: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(techniques, list):
        return by_behavior
    for technique in techniques:
        if not isinstance(technique, dict):
            continue
        item = dict(technique)
        item["source"] = "module_knowledge"
        for category in _string_list(item.get("behavior_categories")):
            by_behavior.setdefault(category, []).append(item)
    return by_behavior


def _result_data(context: dict[str, Any], result_key: str) -> dict[str, Any]:
    result = context.get("results", {}).get(result_key)
    if not isinstance(result, dict) or result.get("status") == "error":
        return {}
    data = result.get("data", {})
    return data if isinstance(data, dict) else {}


def _merge_confidence(current: str, incoming: str) -> str:
    order = {"low": 1, "medium": 2, "high": 3}
    return incoming if order.get(incoming, 1) > order.get(current, 1) else current


def _append_limited(values: list[Any], item: Any, limit: int) -> None:
    if item in values or len(values) >= max(0, limit):
        return
    values.append(item)


def _append_unique(values: list[str], item: str) -> None:
    if item not in values:
        values.append(item)


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None]


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
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
