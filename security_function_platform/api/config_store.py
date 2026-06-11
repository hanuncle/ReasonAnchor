from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class ConfigStore:
    def __init__(
        self,
        config_path: str | Path = "config/local_config.json",
    ) -> None:
        self.config_path = Path(config_path)

    def load_config(self) -> dict[str, Any]:
        if not self.config_path.is_file():
            return {}
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def save_config(self, config: dict[str, Any]) -> dict[str, Any]:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        self.config_path.write_text(
            json.dumps(config, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return config

    def get_redacted_config(self, extra_fields: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        config = self.load_config()
        fields = []
        for field in self._all_fields(extra_fields):
            path = str(field["path"])
            value = self._get_path(config, path)
            configured = value is not None and value != ""
            fields.append(
                {
                    "path": path,
                    "label": field["label"],
                    "secret": field["secret"],
                    "configured": configured,
                    "value": None if field["secret"] else value,
                }
            )
        return {"fields": fields}

    def set_config_value(
        self,
        path: str,
        value: Any,
        extra_fields: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        self._validate_path(path, extra_fields)
        config = self.load_config()
        current: dict[str, Any] = config
        parts = path.split(".")
        for part in parts[:-1]:
            nested = current.setdefault(part, {})
            if not isinstance(nested, dict):
                nested = {}
                current[part] = nested
            current = nested
        current[parts[-1]] = value
        self.save_config(config)
        return self.get_redacted_config(extra_fields)

    def delete_config_value(
        self,
        path: str,
        extra_fields: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        self._validate_path(path, extra_fields)
        config = self.load_config()
        current: Any = config
        parts = path.split(".")
        for part in parts[:-1]:
            current = current.get(part) if isinstance(current, dict) else None
            if current is None:
                self.save_config(config)
                return self.get_redacted_config(extra_fields)
        if isinstance(current, dict):
            current.pop(parts[-1], None)
        self.save_config(config)
        return self.get_redacted_config(extra_fields)

    @staticmethod
    def _get_path(config: dict[str, Any], path: str) -> Any:
        current: Any = config
        for part in path.split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    def _all_fields(self, extra_fields: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        return list(extra_fields or [])

    def _validate_path(
        self,
        path: str,
        extra_fields: list[dict[str, Any]] | None = None,
    ) -> None:
        allowed_paths = {str(field["path"]) for field in self._all_fields(extra_fields)}
        if path not in allowed_paths:
            raise ValueError(f"unknown config path: {path}")

    @staticmethod
    def _valid_field(field: Any) -> bool:
        if not isinstance(field, dict):
            return False
        required = {"function_id", "path", "label", "secret"}
        if not required <= set(field):
            return False
        if not isinstance(field.get("path"), str) or not field["path"]:
            return False
        if any(part in {"", ".."} for part in field["path"].split(".")):
            return False
        return isinstance(field.get("secret"), bool)
