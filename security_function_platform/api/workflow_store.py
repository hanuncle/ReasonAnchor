from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_function_platform.api.session_store import SessionStore
from security_function_platform.core.workflow import WorkflowDefinition

_SECRET_KEYS = {"api_key", "auth_key", "auth-key", "token"}
_WORKFLOW_METADATA_DEFAULTS = {
    "description": "",
    "tags": [],
    "risk": "low",
    "network": False,
    "config_required": False,
    "default_safe": False,
}


class WorkflowStore:
    def __init__(self, store_path: str | Path = "data/workflows/workflows.json") -> None:
        self.store_path = Path(store_path)

    def list_workflows(self) -> dict[str, Any]:
        data = self._load()
        return {
            "workflows": [
                {
                    "workflow_id": item["workflow_id"],
                    "name": item["name"],
                    "created_at": item["created_at"],
                    "updated_at": item["updated_at"],
                    "steps_count": len(item.get("workflow", {}).get("steps", [])),
                    **self._metadata(item),
                }
                for item in data["workflows"]
            ]
        }

    def get_workflow(self, workflow_id: str) -> dict[str, Any]:
        for item in self._load()["workflows"]:
            if item["workflow_id"] == workflow_id:
                return {**item, **self._metadata(item)}
        raise KeyError(workflow_id)

    def save_workflow_template(
        self,
        name: str,
        workflow: WorkflowDefinition,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        data = self._load()
        now = self._now()
        workflow_name = name or workflow.name or "unnamed_workflow"
        workflow_metadata = self._metadata(metadata or {})
        item = {
            "workflow_id": str(uuid.uuid4()),
            "name": workflow_name,
            "created_at": now,
            "updated_at": now,
            "workflow": self._sanitize(workflow.to_dict()),
            **workflow_metadata,
        }
        data["workflows"].append(item)
        self._save(data)
        return item

    def update_workflow_template(
        self,
        workflow_id: str,
        name: str,
        workflow: WorkflowDefinition,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        data = self._load()
        for index, item in enumerate(data["workflows"]):
            if item["workflow_id"] != workflow_id:
                continue
            updated = {
                "workflow_id": workflow_id,
                "name": name or workflow.name or item["name"],
                "created_at": item["created_at"],
                "updated_at": self._now(),
                "workflow": self._sanitize(workflow.to_dict()),
                **self._metadata(metadata or item),
            }
            data["workflows"][index] = updated
            self._save(data)
            return updated
        raise KeyError(workflow_id)

    def delete_workflow_template(self, workflow_id: str) -> dict[str, Any]:
        data = self._load()
        remaining = [item for item in data["workflows"] if item["workflow_id"] != workflow_id]
        if len(remaining) == len(data["workflows"]):
            raise KeyError(workflow_id)
        data["workflows"] = remaining
        self._save(data)
        return {"workflow_id": workflow_id, "deleted": True}

    def apply_workflow_to_session(
        self,
        session_id: str,
        workflow_id: str,
        session_store: SessionStore,
    ) -> dict[str, Any]:
        item = self.get_workflow(workflow_id)
        session = session_store.get_session(session_id)
        session["workflow"] = item["workflow"]
        return session_store.save_session(session)

    def _load(self) -> dict[str, Any]:
        if not self.store_path.is_file():
            return {"workflows": []}
        try:
            data = json.loads(self.store_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"workflows": []}
        workflows = data.get("workflows") if isinstance(data, dict) else []
        return {"workflows": workflows if isinstance(workflows, list) else []}

    def _save(self, data: dict[str, Any]) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    @staticmethod
    def _sanitize(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: WorkflowStore._sanitize(item)
                for key, item in value.items()
                if str(key).lower() not in _SECRET_KEYS
            }
        if isinstance(value, list):
            return [WorkflowStore._sanitize(item) for item in value]
        return value

    @staticmethod
    def _metadata(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "description": str(item.get("description") or _WORKFLOW_METADATA_DEFAULTS["description"]),
            "tags": list(item.get("tags") or _WORKFLOW_METADATA_DEFAULTS["tags"]),
            "risk": str(item.get("risk") or _WORKFLOW_METADATA_DEFAULTS["risk"]),
            "network": bool(item.get("network", _WORKFLOW_METADATA_DEFAULTS["network"])),
            "config_required": bool(
                item.get("config_required", _WORKFLOW_METADATA_DEFAULTS["config_required"])
            ),
            "default_safe": bool(
                item.get("default_safe", _WORKFLOW_METADATA_DEFAULTS["default_safe"])
            ),
        }

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()
