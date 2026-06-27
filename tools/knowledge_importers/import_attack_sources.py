from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from tools.knowledge_importers.check_attack_sources import (
        DEFAULT_SOURCE_ROOT,
        check_sources,
        select_latest_attack_file,
    )
except ModuleNotFoundError:  # pragma: no cover - supports direct script execution.
    from check_attack_sources import DEFAULT_SOURCE_ROOT, check_sources, select_latest_attack_file


DEFAULT_MODULE_ROOT = Path("modules/malware_analysis")
DEFAULT_OUTPUT_DIR = DEFAULT_MODULE_ROOT / "knowledge" / "candidates"
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


def run_import(
    source_root: Path | str = DEFAULT_SOURCE_ROOT,
    module_root: Path | str = DEFAULT_MODULE_ROOT,
    output_dir: Path | str | None = None,
) -> dict[str, Any]:
    source_root = Path(source_root)
    module_root = Path(module_root)
    output_dir = Path(output_dir) if output_dir else module_root / "knowledge" / "candidates"
    output_dir.mkdir(parents=True, exist_ok=True)

    official = _load_official_knowledge(module_root)
    attack_candidates = _extract_attack_candidates(source_root, official)
    behavior_candidates = _extract_mbc_behavior_candidates(source_root, official)
    detection_candidates = _extract_detection_candidates(source_root)
    summary = {
        "schema_version": "1",
        "generated_at": _now(),
        "source_root": str(source_root),
        "module_root": str(module_root),
        "official_knowledge_modified": False,
        "review_model": "candidate_only_until_malware.knowledge_review_approval",
        "source_check": check_sources(source_root),
        "outputs": {
            "external_attack_candidates": len(attack_candidates["techniques"]),
            "external_behavior_candidates": len(behavior_candidates["behaviors"]),
            "external_detection_candidates": len(detection_candidates["rules"]),
            "sigma_rules": detection_candidates["counts"]["sigma_rules"],
            "capa_rules": detection_candidates["counts"]["capa_rules"],
        },
        "files": {
            "external_attack_candidates": "knowledge/candidates/external_attack_candidates.json",
            "external_behavior_candidates": "knowledge/candidates/external_behavior_candidates.json",
            "external_detection_candidates": "knowledge/candidates/external_detection_candidates.json",
        },
    }

    _write_json(output_dir / "external_attack_candidates.json", attack_candidates)
    _write_json(output_dir / "external_behavior_candidates.json", behavior_candidates)
    _write_json(output_dir / "external_detection_candidates.json", detection_candidates)
    _write_json(output_dir / "external_import_summary.json", summary)
    return summary


def _extract_attack_candidates(source_root: Path, official: dict[str, Any]) -> dict[str, Any]:
    attack_file = select_latest_attack_file(source_root)
    objects: list[dict[str, Any]] = []
    if attack_file and attack_file.is_file():
        data = json.loads(attack_file.read_text(encoding="utf-8"))
        objects = [item for item in data.get("objects", []) if isinstance(item, dict)]
    official_by_id = official["attack_by_id"]
    behavior_by_attack = official["behavior_by_attack"]
    techniques: list[dict[str, Any]] = []
    for item in objects:
        if item.get("type") != "attack-pattern" or item.get("revoked") or item.get("x_mitre_deprecated"):
            continue
        technique_id = _external_attack_id(item)
        if not technique_id:
            continue
        official_item = official_by_id.get(technique_id, {})
        related_behaviors = set(official_item.get("behavior_categories", []))
        related_behaviors.update(_behaviors_for_technique(behavior_by_attack, technique_id))
        techniques.append(
            {
                "candidate_id": f"attack:{technique_id}",
                "candidate_type": "attack_technique_enrichment" if technique_id in official_by_id else "new_attack_technique",
                "technique_id": technique_id,
                "name": str(item.get("name") or ""),
                "current_module_status": "existing" if technique_id in official_by_id else "missing",
                "related_behavior_ids": sorted(related_behaviors),
                "tactics": _kill_chain_tactics(item),
                "platforms": _string_list(item.get("x_mitre_platforms")),
                "data_sources": _string_list(item.get("x_mitre_data_sources")),
                "detection_guidance": _compact_text(item.get("x_mitre_detection"), limit=900),
                "description": _compact_text(item.get("description"), limit=700),
                "is_subtechnique": bool(item.get("x_mitre_is_subtechnique")),
                "external_references": _external_refs(item),
                "source": {
                    "name": "MITRE ATT&CK STIX",
                    "path": _relative_to(attack_file, source_root) if attack_file else "",
                },
                "review_status": "candidate_external",
            }
        )
    techniques.sort(key=lambda item: _technique_sort_key(item["technique_id"]))
    return {
        "schema_version": "1",
        "generated_at": _now(),
        "source": {
            "name": "MITRE ATT&CK STIX",
            "path": _relative_to(attack_file, source_root) if attack_file else "",
        },
        "official_knowledge_modified": False,
        "techniques": techniques,
        "counts": {
            "techniques": len(techniques),
            "existing_module_techniques": sum(1 for item in techniques if item["current_module_status"] == "existing"),
            "new_module_candidates": sum(1 for item in techniques if item["current_module_status"] == "missing"),
        },
    }


def _extract_mbc_behavior_candidates(source_root: Path, official: dict[str, Any]) -> dict[str, Any]:
    summary_path = source_root / "mbc-markdown" / "mbc_summary.md"
    if not summary_path.is_file():
        return _empty_behavior_candidates(source_root)
    text = summary_path.read_text(encoding="utf-8", errors="replace")
    behavior_by_attack = official["behavior_by_attack"]
    behaviors: list[dict[str, Any]] = []
    for row in _markdown_table_rows(text, "## Malware Behaviors"):
        if len(row) < 4 or not re.match(r"^B\d{4}$", row[0]):
            continue
        name, link = _markdown_link(row[1])
        technique_ids = sorted(set(_technique_ids(row[3])), key=_technique_sort_key)
        related_behavior_ids = sorted(
            {
                behavior_id
                for technique_id in technique_ids
                for behavior_id in _behaviors_for_technique(behavior_by_attack, technique_id)
            }
        )
        behaviors.append(
            {
                "candidate_id": f"mbc:{row[0]}",
                "candidate_type": "behavior_taxonomy_enrichment",
                "mbc_id": row[0],
                "name": name,
                "objectives": _clean_cell(row[2]),
                "attack_technique_ids": technique_ids,
                "related_behavior_ids": related_behavior_ids,
                "confidence": "medium" if technique_ids else "low",
                "source": {
                    "name": "Malware Behavior Catalog",
                    "path": _relative_to(summary_path, source_root),
                    "link": link,
                },
                "review_status": "candidate_external",
            }
        )
    return {
        "schema_version": "1",
        "generated_at": _now(),
        "source": {"name": "Malware Behavior Catalog", "path": _relative_to(summary_path, source_root)},
        "official_knowledge_modified": False,
        "behaviors": behaviors,
        "counts": {
            "behaviors": len(behaviors),
            "with_attack_mapping": sum(1 for item in behaviors if item["attack_technique_ids"]),
            "mapped_to_existing_behavior": sum(1 for item in behaviors if item["related_behavior_ids"]),
        },
    }


def _extract_detection_candidates(source_root: Path) -> dict[str, Any]:
    sigma_rules = _extract_sigma_rules(source_root)
    capa_rules = _extract_capa_rules(source_root)
    rules = sorted(sigma_rules + capa_rules, key=lambda item: (item["rule_source"], item["name"].lower()))
    by_technique: dict[str, dict[str, int]] = {}
    for rule in rules:
        for technique_id in rule["attack_technique_ids"]:
            by_technique.setdefault(technique_id, {"sigma": 0, "capa": 0})
            by_technique[technique_id][rule["rule_source"]] += 1
    return {
        "schema_version": "1",
        "generated_at": _now(),
        "official_knowledge_modified": False,
        "review_status": "candidate_external",
        "rules": rules,
        "by_technique": by_technique,
        "counts": {
            "rules": len(rules),
            "sigma_rules": len(sigma_rules),
            "capa_rules": len(capa_rules),
            "techniques_with_rules": len(by_technique),
        },
    }


def _extract_sigma_rules(source_root: Path) -> list[dict[str, Any]]:
    rules_root = source_root / "sigma" / "rules"
    out: list[dict[str, Any]] = []
    for path in sorted(rules_root.rglob("*.yml")) + sorted(rules_root.rglob("*.yaml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        tags = _block_list(text, "tags")
        technique_ids = sorted(set(_technique_ids(" ".join(tags))), key=_technique_sort_key)
        if not technique_ids:
            continue
        title = _scalar(text, "title") or path.stem.replace("_", " ")
        out.append(
            {
                "candidate_id": f"sigma:{_scalar(text, 'id') or path.stem}",
                "candidate_type": "detection_rule_reference",
                "rule_source": "sigma",
                "name": title,
                "rule_id": _scalar(text, "id"),
                "status": _scalar(text, "status"),
                "level": _scalar(text, "level"),
                "attack_technique_ids": technique_ids,
                "logsource": _block_mapping(text, "logsource"),
                "source": {"name": "SigmaHQ sigma", "path": _relative_to(path, source_root)},
                "review_status": "candidate_external",
            }
        )
    return out


def _extract_capa_rules(source_root: Path) -> list[dict[str, Any]]:
    rules_root = source_root / "capa-rules"
    out: list[dict[str, Any]] = []
    for path in sorted(rules_root.rglob("*.yml")) + sorted(rules_root.rglob("*.yaml")):
        relative_parts = set(path.relative_to(rules_root).parts)
        if relative_parts & {".github", "doc", "internal"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        attack_lines = _block_list(text, "att&ck")
        technique_ids = sorted(set(_technique_ids(" ".join(attack_lines))), key=_technique_sort_key)
        if not technique_ids:
            continue
        name = _scalar(text, "name") or path.stem.replace("-", " ")
        namespace = _scalar(text, "namespace")
        out.append(
            {
                "candidate_id": f"capa:{_relative_to(path, rules_root).replace('/', ':')}",
                "candidate_type": "capability_rule_reference",
                "rule_source": "capa",
                "name": name,
                "namespace": namespace,
                "maturity": "nursery" if "nursery" in relative_parts else "stable",
                "attack_technique_ids": technique_ids,
                "source": {"name": "mandiant capa-rules", "path": _relative_to(path, source_root)},
                "review_status": "candidate_external",
            }
        )
    return out


def _load_official_knowledge(module_root: Path) -> dict[str, Any]:
    behavior_data = _read_json(module_root / "knowledge" / "behavior_taxonomy.json", {})
    attack_data = _read_json(module_root / "knowledge" / "attack" / "techniques.json", [])
    categories = behavior_data.get("categories", []) if isinstance(behavior_data, dict) else []
    techniques = attack_data.get("techniques", []) if isinstance(attack_data, dict) else attack_data
    attack_by_id = {
        str(item.get("technique_id")): item
        for item in techniques
        if isinstance(item, dict) and item.get("technique_id")
    }
    behavior_by_attack: dict[str, set[str]] = {}
    for category in categories:
        if not isinstance(category, dict):
            continue
        behavior_id = str(category.get("id") or "")
        for technique_id in _string_list(category.get("attack_techniques")):
            behavior_by_attack.setdefault(technique_id, set()).add(behavior_id)
    for technique_id, item in attack_by_id.items():
        for behavior_id in _string_list(item.get("behavior_categories")):
            behavior_by_attack.setdefault(technique_id, set()).add(behavior_id)
    return {
        "attack_by_id": attack_by_id,
        "behavior_by_attack": behavior_by_attack,
    }


def _external_attack_id(item: dict[str, Any]) -> str:
    for ref in item.get("external_references", []):
        if not isinstance(ref, dict):
            continue
        if ref.get("source_name") == "mitre-attack":
            value = str(ref.get("external_id") or "").upper()
            if TECHNIQUE_RE.fullmatch(value):
                return value
    return ""


def _external_refs(item: dict[str, Any]) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    for ref in item.get("external_references", []):
        if not isinstance(ref, dict):
            continue
        refs.append(
            {
                "source_name": str(ref.get("source_name") or ""),
                "external_id": str(ref.get("external_id") or ""),
                "url": str(ref.get("url") or ""),
            }
        )
    return refs[:12]


def _kill_chain_tactics(item: dict[str, Any]) -> list[str]:
    tactics: list[str] = []
    for phase in item.get("kill_chain_phases", []):
        if isinstance(phase, dict) and phase.get("phase_name"):
            tactics.append(str(phase["phase_name"]))
    return sorted(set(tactics))


def _markdown_table_rows(text: str, heading: str) -> list[list[str]]:
    rows: list[list[str]] = []
    in_section = False
    for line in text.splitlines():
        if line.strip().startswith("## "):
            if in_section:
                break
            in_section = line.strip() == heading
            continue
        if not in_section or not line.startswith("|"):
            continue
        raw = [part.strip() for part in line.strip().strip("|").split("|")]
        if not raw or raw[0].lower() == "id" or set(raw[0]) <= {"-", ":"}:
            continue
        rows.append(raw)
    return rows


def _markdown_link(value: str) -> tuple[str, str]:
    match = re.search(r"\[([^\]]+)\]\(([^)]+)\)", value)
    if match:
        return _strip_markdown(match.group(1)), match.group(2)
    return _strip_markdown(value), ""


def _clean_cell(value: str) -> str:
    return re.sub(r"\s+", " ", _strip_markdown(value)).strip()


def _strip_markdown(value: str) -> str:
    value = re.sub(r"\*\*", "", value)
    value = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", value)
    value = value.replace("<br>", ", ")
    return value.strip()


def _scalar(text: str, key: str) -> str:
    pattern = re.compile(rf"(?m)^\s*{re.escape(key)}:\s*(.*?)\s*$")
    match = pattern.search(text)
    if not match:
        return ""
    value = match.group(1).strip()
    if value in {"|", ">"}:
        return ""
    return value.strip("'\"")


def _block_list(text: str, key: str) -> list[str]:
    lines = text.splitlines()
    out: list[str] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith(f"{key}:"):
            continue
        rest = stripped[len(key) + 1 :].strip()
        if rest.startswith("[") and rest.endswith("]"):
            return [item.strip().strip("'\"") for item in rest.strip("[]").split(",") if item.strip()]
        base_indent = _indent(line)
        for child in lines[index + 1 :]:
            child_stripped = child.strip()
            if not child_stripped:
                continue
            if _indent(child) <= base_indent and not child_stripped.startswith("-"):
                break
            if child_stripped.startswith("-"):
                out.append(child_stripped[1:].strip().strip("'\""))
        return out
    return out


def _block_mapping(text: str, key: str) -> dict[str, str]:
    lines = text.splitlines()
    out: dict[str, str] = {}
    for index, line in enumerate(lines):
        if line.strip() != f"{key}:":
            continue
        base_indent = _indent(line)
        for child in lines[index + 1 :]:
            child_stripped = child.strip()
            if not child_stripped:
                continue
            if _indent(child) <= base_indent:
                break
            if ":" in child_stripped and not child_stripped.startswith("-"):
                child_key, child_value = child_stripped.split(":", 1)
                out[child_key.strip()] = child_value.strip().strip("'\"")
        return out
    return out


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _technique_ids(value: str) -> list[str]:
    return [match.group(0).upper() for match in TECHNIQUE_RE.finditer(value or "")]


def _technique_sort_key(value: str) -> tuple[int, int]:
    match = re.match(r"T(\d{4})(?:\.(\d{3}))?$", value)
    if not match:
        return (99999, 999)
    return (int(match.group(1)), int(match.group(2) or 0))


def _behaviors_for_technique(behavior_by_attack: dict[str, set[str]], technique_id: str) -> list[str]:
    out: set[str] = set()
    parent = technique_id.split(".")[0]
    for known_id, behavior_ids in behavior_by_attack.items():
        known_parent = known_id.split(".")[0]
        if known_id == technique_id or known_parent == parent:
            out.update(behavior_ids)
    return sorted(out)


def _string_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, str) and value:
        return [value]
    return []


def _compact_text(value: Any, limit: int) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _relative_to(path: Path | None, root: Path) -> str:
    if not path:
        return ""
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _empty_behavior_candidates(source_root: Path) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "generated_at": _now(),
        "source": {"name": "Malware Behavior Catalog", "path": _relative_to(source_root / "mbc-markdown", source_root)},
        "official_knowledge_modified": False,
        "behaviors": [],
        "counts": {"behaviors": 0, "with_attack_mapping": 0, "mapped_to_existing_behavior": 0},
    }


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Import external malware knowledge as candidate JSON assets.")
    parser.add_argument("--source-root", default=str(DEFAULT_SOURCE_ROOT))
    parser.add_argument("--module-root", default=str(DEFAULT_MODULE_ROOT))
    parser.add_argument("--output-dir", default="")
    args = parser.parse_args()

    summary = run_import(
        source_root=args.source_root,
        module_root=args.module_root,
        output_dir=args.output_dir or None,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
