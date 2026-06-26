from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_TARGETS: dict[str, str] = {
    "behavior_taxonomy": "modules/reverse/knowledge/behavior_taxonomy.json",
    "attack_techniques": "modules/reverse/knowledge/attack/techniques.json",
    "validation_scenarios": "modules/reverse/config_files/validation/validation_scenarios.json",
    "validation_samples": "modules/reverse/config_files/validation_samples/samples_manifest.json",
    "raw_sorting": "modules/reverse/config_files/raw_sorting/raw_sorting_index.json",
    "module_skill": "modules/reverse/skill/SKILL.md",
    "other": "",
}

_SECRET_RE = re.compile(
    r"(api[_-]?key|auth[_-]?key|token|password|secret|credential)",
    re.IGNORECASE,
)


class KnowledgeUpdateCandidateFunction(AnalysisFunction):
    id = "knowledge.update_candidate"
    name = "Knowledge update candidate"
    category = "knowledge"
    result_key = "knowledge_update_candidate"
    description = (
        "Stores a pending reverse-module knowledge update candidate for human review. "
        "It does not modify official knowledge files."
    )
    cost = "low"
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    output_schema = {
        "candidate_id": "Stable id for the pending knowledge update candidate.",
        "target": "Knowledge target key and resolved official target path.",
        "candidate_path": "Local JSON file containing the pending candidate.",
        "review_status": "Always pending_review when created.",
        "official_knowledge_modified": "Always false; this function only writes candidates.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        target_key = str(params.get("target") or "other")
        if target_key not in _TARGETS:
            return self._error(
                "invalid_target",
                "target must be one of: " + ", ".join(sorted(_TARGETS)),
            )
        proposed_change = params.get("proposed_change", {})
        if proposed_change in ({}, [], "", None):
            return self._error("missing_proposed_change", "proposed_change is required")

        now = datetime.now(timezone.utc)
        candidate_id = _candidate_id(now, str(params.get("title") or target_key))
        candidate = {
            "schema_version": "1",
            "candidate_id": candidate_id,
            "module_id": "reverse",
            "created_at": now.isoformat(),
            "session_id": str(context.get("session_id") or ""),
            "review_status": "pending_review",
            "requires_human_review": True,
            "official_knowledge_modified": False,
            "title": str(params.get("title") or "Untitled knowledge update"),
            "target": {
                "key": target_key,
                "official_path": _TARGETS[target_key],
            },
            "update_type": str(params.get("update_type") or "other"),
            "confidence": _confidence(params.get("confidence")),
            "behavior_category": str(params.get("behavior_category") or ""),
            "technique_id": str(params.get("technique_id") or ""),
            "rationale": str(params.get("rationale") or ""),
            "source_raw_output_ids": _string_list(params.get("source_raw_output_ids")),
            "source_result_keys": _string_list(params.get("source_result_keys")),
            "proposed_change": _redact_secrets(proposed_change),
            "safety_notes": _string_list(params.get("safety_notes")),
        }

        dry_run = bool(params.get("dry_run", False))
        candidate_path = ""
        if not dry_run:
            output_dir = _candidate_dir(context)
            output_dir.mkdir(parents=True, exist_ok=True)
            path = output_dir / f"{candidate_id}.json"
            path.write_text(
                json.dumps(candidate, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            candidate_path = _display_path(path, _workspace_root(context))

        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "candidate_id": candidate_id,
                "target": candidate["target"],
                "update_type": candidate["update_type"],
                "review_status": candidate["review_status"],
                "candidate_path": candidate_path,
                "dry_run": dry_run,
                "official_knowledge_modified": False,
                "requires_human_review": True,
                "candidate": candidate,
                "limitations": [
                    "candidate proposal only",
                    "official knowledge files are not modified",
                    "human review is required before applying the change",
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


def _candidate_id(now: datetime, title: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40]
    if not slug:
        slug = "knowledge-update"
    return f"ku-{now.strftime('%Y%m%dT%H%M%SZ')}-{slug}-{uuid.uuid4().hex[:8]}"


def _candidate_dir(context: dict[str, Any]) -> Path:
    session_base = Path(str(context.get("session_base_dir") or "data/sessions"))
    return session_base.parent / "knowledge_candidates" / "reverse"


def _workspace_root(context: dict[str, Any]) -> Path:
    value = str(context.get("workspace_root") or "")
    return Path(value).resolve() if value else Path.cwd().resolve()


def _display_path(path: Path, workspace: Path) -> str:
    resolved = path.resolve(strict=False)
    try:
        return str(resolved.relative_to(workspace))
    except ValueError:
        return str(resolved)


def _confidence(value: Any) -> str:
    text = str(value or "low").lower()
    return text if text in {"low", "medium", "high"} else "low"


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []


def _redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            text_key = str(key)
            if _SECRET_RE.search(text_key):
                redacted[text_key] = "<redacted>"
            else:
                redacted[text_key] = _redact_secrets(item)
        return redacted
    if isinstance(value, list):
        return [_redact_secrets(item) for item in value]
    return value
