from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


DEFAULT_SOURCE_ROOT = Path(r"D:\secure_tools\attack")
ENTERPRISE_ATTACK_RE = re.compile(r"enterprise-attack-(\d+(?:\.\d+)*)\.json$", re.IGNORECASE)


def select_latest_attack_file(source_root: Path | str = DEFAULT_SOURCE_ROOT) -> Path | None:
    root = Path(source_root)
    enterprise_root = root / "attack-stix-data" / "enterprise-attack"
    numbered: list[tuple[tuple[int, ...], Path]] = []
    for path in enterprise_root.glob("enterprise-attack-*.json"):
        match = ENTERPRISE_ATTACK_RE.match(path.name)
        if not match:
            continue
        numbered.append((tuple(int(part) for part in match.group(1).split(".")), path))
    if numbered:
        return max(numbered, key=lambda item: item[0])[1]
    alias = enterprise_root / "enterprise-attack.json"
    return alias if alias.is_file() else None


def check_sources(source_root: Path | str = DEFAULT_SOURCE_ROOT) -> dict[str, Any]:
    root = Path(source_root)
    latest_attack = select_latest_attack_file(root)
    sources = [
        _source_status(root, "attack-stix-data", latest_attack),
        _source_status(root, "mbc-markdown", root / "mbc-markdown" / "mbc_summary.md"),
        _source_status(root, "sigma", root / "sigma" / "rules"),
        _source_status(root, "capa-rules", root / "capa-rules"),
    ]
    ready = all(item["exists"] and item["usable"] for item in sources)
    return {
        "schema_version": "1",
        "source_root": str(root),
        "ready": ready,
        "sources": sources,
        "missing": [item["name"] for item in sources if not item["usable"]],
    }


def _source_status(root: Path, name: str, primary_path: Path | None) -> dict[str, Any]:
    path = root / name
    status: dict[str, Any] = {
        "name": name,
        "path": str(path),
        "exists": path.exists(),
        "is_git_checkout": (path / ".git").exists(),
        "files_count": _count_files(path, "*"),
        "usable": False,
        "primary_path": str(primary_path) if primary_path else "",
        "primary_exists": bool(primary_path and primary_path.exists()),
    }
    if name == "attack-stix-data":
        attack_count, object_count = _attack_counts(primary_path)
        status.update(
            {
                "enterprise_attack_files_count": _count_files(path / "enterprise-attack", "enterprise-attack*.json"),
                "attack_pattern_count": attack_count,
                "stix_object_count": object_count,
                "usable": bool(primary_path and primary_path.is_file() and attack_count > 0),
            }
        )
    elif name == "mbc-markdown":
        markdown_count = _count_files(path, "*.md")
        status.update(
            {
                "markdown_files_count": markdown_count,
                "usable": bool(primary_path and primary_path.is_file() and markdown_count > 0),
            }
        )
    elif name == "sigma":
        rules_count = _count_files(path / "rules", "*.yml") + _count_files(path / "rules", "*.yaml")
        status.update({"rules_count": rules_count, "usable": rules_count > 0})
    elif name == "capa-rules":
        rules_count = _count_files(path, "*.yml") + _count_files(path, "*.yaml")
        status.update({"rules_count": rules_count, "usable": rules_count > 0})
    return status


def _count_files(root: Path, pattern: str) -> int:
    if not root.exists():
        return 0
    try:
        return sum(1 for item in root.rglob(pattern) if item.is_file())
    except OSError:
        return 0


def _attack_counts(path: Path | None) -> tuple[int, int]:
    if not path or not path.is_file():
        return 0, 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0, 0
    objects = data.get("objects", []) if isinstance(data, dict) else []
    if not isinstance(objects, list):
        return 0, 0
    attack_patterns = [
        item
        for item in objects
        if isinstance(item, dict)
        and item.get("type") == "attack-pattern"
        and not item.get("revoked")
        and not item.get("x_mitre_deprecated")
    ]
    return len(attack_patterns), len(objects)


def main() -> int:
    parser = argparse.ArgumentParser(description="Check local ATT&CK/MBC/Sigma/capa source completeness.")
    parser.add_argument("--source-root", default=str(DEFAULT_SOURCE_ROOT))
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when any source is missing or unusable.")
    args = parser.parse_args()

    status = check_sources(args.source_root)
    print(json.dumps(status, ensure_ascii=False, indent=2))
    return 1 if args.strict and not status["ready"] else 0


if __name__ == "__main__":
    sys.exit(main())
