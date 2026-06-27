from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from tools.knowledge_importers.import_attack_sources import _technique_sort_key
except ModuleNotFoundError:  # pragma: no cover - supports direct script execution.
    from import_attack_sources import _technique_sort_key


DEFAULT_MODULE_ROOT = Path("modules/malware_analysis")
DEFAULT_OUTPUT = DEFAULT_MODULE_ROOT / "knowledge" / "behavior_attack_view.json"


def build_view(module_root: Path | str = DEFAULT_MODULE_ROOT) -> dict[str, Any]:
    module_root = Path(module_root)
    behavior_data = _read_json(module_root / "knowledge" / "behavior_taxonomy.json", {})
    attack_data = _read_json(module_root / "knowledge" / "attack" / "techniques.json", [])
    rules_data = _read_json(module_root / "knowledge" / "behavior_rules.json", [])
    external_attack = _read_json(module_root / "knowledge" / "candidates" / "external_attack_candidates.json", {})
    external_behavior = _read_json(module_root / "knowledge" / "candidates" / "external_behavior_candidates.json", {})
    external_detection = _read_json(module_root / "knowledge" / "candidates" / "external_detection_candidates.json", {})

    categories = behavior_data.get("categories", []) if isinstance(behavior_data, dict) else []
    attack_items = attack_data.get("techniques", []) if isinstance(attack_data, dict) else attack_data
    rules = rules_data.get("rules", []) if isinstance(rules_data, dict) else rules_data
    attack_by_id = {
        str(item.get("technique_id")): item
        for item in attack_items
        if isinstance(item, dict) and item.get("technique_id")
    }
    external_attack_by_id = {
        str(item.get("technique_id")): item
        for item in external_attack.get("techniques", [])
        if isinstance(item, dict) and item.get("technique_id")
    }
    rules_by_behavior = _group_rules_by_behavior(rules)
    detection_by_technique = _group_external_rules_by_technique(external_detection.get("rules", []))
    mbc_by_technique = _group_mbc_by_technique(external_behavior.get("behaviors", []))

    behaviors = []
    missing_attack_refs: set[str] = set()
    for category in categories:
        if not isinstance(category, dict):
            continue
        behavior_id = str(category.get("id") or "")
        attack_refs = [str(item) for item in category.get("attack_techniques", [])]
        attack_techniques = []
        detection_summary = _detection_summary(attack_refs, detection_by_technique)
        mbc_candidates = _mbc_summary(attack_refs, mbc_by_technique)
        for technique_id in attack_refs:
            official = attack_by_id.get(technique_id)
            external = external_attack_by_id.get(technique_id)
            if not official and not external:
                missing_attack_refs.add(technique_id)
            attack_techniques.append(_technique_view(technique_id, official, external))
        behaviors.append(
            {
                "behavior_id": behavior_id,
                "name": str(category.get("name") or ""),
                "verification_rule": str(category.get("verification_rule") or ""),
                "attack_techniques": attack_techniques,
                "rules": [_rule_summary(item) for item in rules_by_behavior.get(behavior_id, [])],
                "external_detection_candidates": detection_summary,
                "external_mbc_candidates": mbc_candidates,
            }
        )

    behavior_ids = {item["behavior_id"] for item in behaviors}
    attack_behavior_refs = sorted(
        {
            behavior_id
            for item in attack_by_id.values()
            for behavior_id in item.get("behavior_categories", [])
            if behavior_id not in behavior_ids
        }
    )
    rules_behavior_refs = sorted(
        {
            str(item.get("behavior_id"))
            for item in rules
            if isinstance(item, dict) and item.get("behavior_id") and str(item.get("behavior_id")) not in behavior_ids
        }
    )
    known_attack_ids = set(attack_by_id) | set(external_attack_by_id)
    rules_attack_refs = sorted(
        {
            tech["technique_id"]
            for item in rules
            if isinstance(item, dict)
            for tech in item.get("attack_techniques", [])
            if isinstance(tech, dict)
            and tech.get("technique_id")
            and tech["technique_id"] not in known_attack_ids
        },
        key=_technique_sort_key,
    )
    return {
        "schema_version": "1",
        "generated_at": _now(),
        "generated_from": {
            "behavior_taxonomy": "knowledge/behavior_taxonomy.json",
            "attack_techniques": "knowledge/attack/techniques.json",
            "behavior_rules": "knowledge/behavior_rules.json",
            "external_attack_candidates": "knowledge/candidates/external_attack_candidates.json",
            "external_behavior_candidates": "knowledge/candidates/external_behavior_candidates.json",
            "external_detection_candidates": "knowledge/candidates/external_detection_candidates.json",
        },
        "official_knowledge_modified": False,
        "behaviors": behaviors,
        "unmapped": {
            "behavior_attack_refs": sorted(missing_attack_refs, key=_technique_sort_key),
            "attack_behavior_refs": attack_behavior_refs,
            "rules_behavior_refs": rules_behavior_refs,
            "rules_attack_refs": rules_attack_refs,
        },
        "counts": {
            "behaviors": len(behaviors),
            "official_attack_techniques": len(attack_by_id),
            "external_attack_candidates": len(external_attack_by_id),
            "official_behavior_rules": len(rules) if isinstance(rules, list) else 0,
            "external_detection_candidates": len(external_detection.get("rules", [])),
            "external_mbc_candidates": len(external_behavior.get("behaviors", [])),
        },
    }


def _technique_view(technique_id: str, official: dict[str, Any] | None, external: dict[str, Any] | None) -> dict[str, Any]:
    if official:
        name = str(official.get("name") or "")
        tactic = str(official.get("tactic") or "")
        analysis_methods = _string_list(official.get("analysis_methods"))
        detection_methods = _string_list(official.get("detection_methods"))
        validation_samples = _string_list(official.get("validation_samples"))
        source_status = "official"
    elif external:
        name = str(external.get("name") or "")
        tactic = ", ".join(_string_list(external.get("tactics")))
        analysis_methods = []
        detection_methods = []
        validation_samples = []
        source_status = "candidate_external"
    else:
        name = ""
        tactic = ""
        analysis_methods = []
        detection_methods = []
        validation_samples = []
        source_status = "missing_reference"
    return {
        "technique_id": technique_id,
        "name": name,
        "tactic": tactic,
        "source_status": source_status,
        "analysis_methods": analysis_methods,
        "detection_methods": detection_methods,
        "candidate_detection_guidance": str((external or {}).get("detection_guidance") or ""),
        "candidate_data_sources": _string_list((external or {}).get("data_sources")),
        "validation_samples": validation_samples,
    }


def _group_rules_by_behavior(rules: Any) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(rules, list):
        return out
    for rule in rules:
        if isinstance(rule, dict) and rule.get("behavior_id"):
            out.setdefault(str(rule["behavior_id"]), []).append(rule)
    return out


def _group_external_rules_by_technique(rules: Any) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(rules, list):
        return out
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        for technique_id in rule.get("attack_technique_ids", []):
            out.setdefault(str(technique_id), []).append(rule)
    return out


def _group_mbc_by_technique(behaviors: Any) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(behaviors, list):
        return out
    for behavior in behaviors:
        if not isinstance(behavior, dict):
            continue
        for technique_id in behavior.get("attack_technique_ids", []):
            out.setdefault(str(technique_id), []).append(behavior)
    return out


def _detection_summary(attack_refs: list[str], detection_by_technique: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    rules = _rules_for_attack_refs(attack_refs, detection_by_technique)
    sigma = [item for item in rules if item.get("rule_source") == "sigma"]
    capa = [item for item in rules if item.get("rule_source") == "capa"]
    examples = [
        {
            "rule_source": str(item.get("rule_source") or ""),
            "name": str(item.get("name") or ""),
            "attack_technique_ids": item.get("attack_technique_ids", []),
            "source_path": str((item.get("source") or {}).get("path") or ""),
        }
        for item in rules[:12]
    ]
    return {
        "sigma_rule_count": len(sigma),
        "capa_rule_count": len(capa),
        "examples": examples,
    }


def _mbc_summary(attack_refs: list[str], mbc_by_technique: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    items = _rules_for_attack_refs(attack_refs, mbc_by_technique)
    examples = [
        {
            "mbc_id": str(item.get("mbc_id") or ""),
            "name": str(item.get("name") or ""),
            "objectives": str(item.get("objectives") or ""),
            "attack_technique_ids": item.get("attack_technique_ids", []),
        }
        for item in items[:8]
    ]
    return {"count": len(items), "examples": examples}


def _rules_for_attack_refs(attack_refs: list[str], grouped: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for attack_ref in attack_refs:
        parent = attack_ref.split(".")[0]
        for technique_id, items in grouped.items():
            if technique_id == attack_ref or technique_id.split(".")[0] == parent:
                for item in items:
                    key = str(item.get("candidate_id") or item.get("rule_id") or item.get("name") or id(item))
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(item)
    return out


def _rule_summary(rule: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_id": str(rule.get("rule_id") or ""),
        "name": str(rule.get("name") or ""),
        "event_type": rule.get("event_type", []),
        "attack_technique_ids": [
            str(item.get("technique_id"))
            for item in rule.get("attack_techniques", [])
            if isinstance(item, dict) and item.get("technique_id")
        ],
        "required_attribution": rule.get("required_attribution", []),
        "status_when_matched": str(rule.get("status_when_matched") or ""),
        "confidence": str(rule.get("confidence") or ""),
    }


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str) and value:
        return [value]
    return []


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_view(module_root: Path | str = DEFAULT_MODULE_ROOT, output: Path | str = DEFAULT_OUTPUT) -> dict[str, Any]:
    view = build_view(module_root)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(view, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return view


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the malware behavior-to-ATT&CK AI view.")
    parser.add_argument("--module-root", default=str(DEFAULT_MODULE_ROOT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    view = write_view(args.module_root, args.output)
    print(json.dumps({"output": args.output, "counts": view["counts"], "unmapped": view["unmapped"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
