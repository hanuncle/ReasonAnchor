from __future__ import annotations

import importlib.util
import json
import hashlib
import sys
import zipfile
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction

_DEFAULT_REQUIREMENTS = {
    "network": False,
    "active_scan": False,
    "requires_authorization": False,
    "sample_execution": False,
    "external_tools": [],
}
_MODULE_TEMPLATE_VERSION = "1"
_MODULE_TEMPLATE_DIRECTORIES = (
    "functions",
    "workflows",
    "knowledge",
    "config_fields",
    "skill",
    "config_files",
)
_ALLOWED_PACKAGE_EXTENSIONS = {
    ".json",
    ".md",
    ".txt",
    ".py",
    ".ps1",
    ".yar",
    ".yara",
}
_DENIED_PACKAGE_PARTS = {
    "__pycache__",
    ".git",
    ".venv",
    ".env",
    "data",
    "local_config.json",
}


class ModuleStore:
    def __init__(
        self,
        modules_dir: str | Path = "modules",
        registry_path: str | Path = "data/modules/loaded_modules.json",
        installed_modules_dir: str | Path = "data/modules_installed",
        packages_dir: str | Path = "data/module_packages",
    ) -> None:
        self.modules_dir = Path(modules_dir)
        self.registry_path = Path(registry_path)
        self.installed_modules_dir = Path(installed_modules_dir)
        self.packages_dir = Path(packages_dir)

    def list_modules(self) -> dict[str, Any]:
        return {
            "modules": [
                {
                    **self._module_summary(manifest),
                    "loaded": True,
                    "usable": True,
                }
                for manifest in self._discover_manifests()
            ]
        }

    def get_module_template(self) -> dict[str, Any]:
        return {
            "template_version": _MODULE_TEMPLATE_VERSION,
            "directories": list(_MODULE_TEMPLATE_DIRECTORIES),
            "module_json": {
                "template_version": _MODULE_TEMPLATE_VERSION,
                "module_id": "<module_id>",
                "name": "<display name>",
                "version": "0.1.0",
                "description": "",
                "requirements": {**_DEFAULT_REQUIREMENTS, "external_tools": []},
                "functions": [
                    {
                        "function_id": "<module_id>.<function_name>",
                        "path": "functions/<function_file>.py",
                        "class_name": "<FunctionClassName>",
                    }
                ],
                "workflows": ["workflows/<workflow_id>.json"],
                "knowledge": [
                    {
                        "type": "<knowledge_type>",
                        "path": "knowledge/<knowledge_file>.json",
                    }
                ],
                "config_fields": ["config_fields/<fields_file>.json"],
                "skill": {
                    "skill_file": "skill/SKILL.md",
                    "playbook_file": "skill/playbook.json",
                    "final_result_schema_file": "skill/final_result_schema.json",
                },
            },
            "default_files": {
                "module.json": "Module manifest and declarations.",
                "skill/SKILL.md": "Module-specific AI usage instructions.",
                "skill/playbook.json": "Machine-readable module playbook.",
                "skill/final_result_schema.json": "Module-specific final summary output structure.",
            },
            "mutable_paths": {
                "functions": "Reusable module function code.",
                "workflows": "Reusable workflow templates.",
                "knowledge": "Module knowledge assets.",
                "config_fields": "User-configurable field declarations.",
                "skill": "Module skill and playbook.",
                "config_files": "Module-owned resources such as raw_sorting and function data files.",
            },
            "create_with": "create_module",
        }

    def load_module(self, module_id: str) -> dict[str, Any]:
        manifest = self.get_module(module_id)
        return {**self._module_summary(manifest), "loaded": True, "usable": True}

    def create_module(
        self,
        module_id: str,
        name: str = "",
        version: str = "0.1.0",
        description: str = "",
        requirements: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        module_id = self._validate_module_id(module_id)
        if self._module_id_exists(module_id):
            raise ValueError("module_already_exists")

        module_root = self.modules_dir / module_id
        module_root.mkdir(parents=True, exist_ok=False)
        for dirname in _MODULE_TEMPLATE_DIRECTORIES:
            (module_root / dirname).mkdir()

        manifest = {
            "template_version": _MODULE_TEMPLATE_VERSION,
            "module_id": module_id,
            "name": name or module_id,
            "version": version or "0.1.0",
            "description": description or "",
            "requirements": self._requirements(requirements or {}),
            "functions": [],
            "workflows": [],
            "knowledge": [],
            "config_fields": [],
            "skill": {
                "skill_file": "skill/SKILL.md",
                "playbook_file": "skill/playbook.json",
                "final_result_schema_file": "skill/final_result_schema.json",
            },
        }
        (module_root / "module.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (module_root / "skill" / "SKILL.md").write_text(
            f"# {manifest['name']}\n\nLocal module skill notes.\n",
            encoding="utf-8",
        )
        (module_root / "skill" / "playbook.json").write_text(
            json.dumps({"module_id": module_id, "notes": []}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        (module_root / "skill" / "final_result_schema.json").write_text(
            json.dumps(
                self._default_final_result_schema(module_id),
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        created = self.get_module(module_id)
        return {**self._module_summary(created), "created": True, "loaded": True, "usable": True}

    def validate_module(self, module_id: str) -> dict[str, Any]:
        manifest = self.get_module(module_id)
        module_root = self._module_root(manifest)
        errors: list[dict[str, Any]] = []

        for dirname in _MODULE_TEMPLATE_DIRECTORIES:
            if not (module_root / dirname).is_dir():
                errors.append(
                    {
                        "code": "missing_template_directory",
                        "path": dirname,
                        "message": f"Missing module template directory: {dirname}",
                    }
                )

        for field in ("functions", "workflows", "knowledge", "config_fields"):
            value = manifest.get(field, [])
            if not isinstance(value, list):
                errors.append(
                    {
                        "code": "invalid_manifest_field",
                        "field": field,
                        "message": f"Module manifest field must be a list: {field}",
                    }
                )

        skill_info = manifest.get("skill", {})
        if skill_info and not isinstance(skill_info, dict):
            errors.append(
                {
                    "code": "invalid_manifest_field",
                    "field": "skill",
                    "message": "Module manifest field must be an object: skill",
                }
            )
            skill_info = {}

        self._validate_function_entries(manifest, module_root, errors)
        self._validate_path_list(manifest, module_root, "workflows", {".json"}, errors)
        self._validate_path_list(manifest, module_root, "config_fields", {".json"}, errors)
        self._validate_knowledge_entries(manifest, module_root, errors)
        self._validate_skill_paths(skill_info, module_root, errors)

        return {
            "module_id": manifest["module_id"],
            "valid": not errors,
            "errors": errors,
        }

    def get_module_detail(self, module_id: str) -> dict[str, Any]:
        manifest = self.get_module(module_id)
        return {
            **self._module_summary(manifest),
            "loaded": True,
            "usable": True,
            "validation": self.validate_module(module_id),
            "functions": [
                item
                for item in manifest.get("functions", [])
                if isinstance(item, dict)
            ],
            "workflows": [
                self._workflow_summary(item)
                for item in self._workflows_for_manifest(manifest)
            ],
            "knowledge": [
                item
                for item in manifest.get("knowledge", [])
                if isinstance(item, dict)
            ],
            "config_fields": [
                str(item)
                for item in manifest.get("config_fields", [])
                if isinstance(item, str)
            ],
            "skill": manifest.get("skill", {}) if isinstance(manifest.get("skill"), dict) else {},
        }

    def get_module_skill(self, module_id: str) -> dict[str, Any]:
        manifest = self.get_module(module_id)
        return self._skill_context_for_manifest(manifest)

    def package_module(self, module_id: str) -> dict[str, Any]:
        manifest = self.get_module(module_id)
        module_root = self._module_root(manifest)
        archive_name = self._archive_name(manifest)
        archive_path = self.packages_dir / archive_name
        self.packages_dir.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(module_root.rglob("*")):
                if not path.is_file():
                    continue
                relative = path.relative_to(module_root)
                if not self._allowed_package_member(relative):
                    continue
                archive.write(path, f"{manifest['module_id']}/{relative.as_posix()}")

        data = archive_path.read_bytes()
        return {
            "module_id": manifest["module_id"],
            "version": str(manifest.get("version") or "0.0.0"),
            "archive": str(archive_path),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def import_module_archive(self, archive_path: str | Path) -> dict[str, Any]:
        archive_path = Path(archive_path)
        if not archive_path.is_file():
            raise FileNotFoundError(archive_path)
        if archive_path.suffix.lower() not in {".zip", ".sfpmod"} and not archive_path.name.endswith(
            ".sfpmod.zip"
        ):
            raise ValueError("invalid_archive_extension")

        members = self._safe_archive_members(archive_path)
        roots = {member.parts[0] for member in members}
        if len(roots) != 1:
            raise ValueError("archive_must_contain_single_module_root")
        module_id = next(iter(roots))
        manifest_member = Path(module_id) / "module.json"
        if manifest_member not in members:
            raise ValueError("module_json_missing")

        target_root = self.installed_modules_dir / module_id
        with zipfile.ZipFile(archive_path) as archive:
            try:
                manifest = json.loads(
                    archive.read(manifest_member.as_posix()).decode("utf-8")
                )
            except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("module_json_invalid") from exc
        if not isinstance(manifest, dict) or not self._valid_manifest(manifest, target_root):
            raise ValueError("module_json_invalid")

        if target_root.exists() or self._module_id_exists(module_id):
            raise ValueError("module_already_exists")

        self.installed_modules_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive_path) as archive:
            for member in members:
                target = (self.installed_modules_dir / member).resolve()
                install_root = self.installed_modules_dir.resolve()
                if install_root not in target.parents:
                    raise ValueError("archive_path_not_allowed")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member.as_posix()) as source:
                    target.write_bytes(source.read())

        manifest = self.get_module(module_id)
        return {
            **self._module_summary(manifest),
            "installed": True,
            "loaded": True,
            "usable": True,
        }

    def list_loaded_modules(self) -> list[dict[str, Any]]:
        return [
            {**self._module_summary(manifest), "loaded": True, "usable": True}
            for manifest in self._discover_manifests()
        ]

    def get_module(self, module_id: str) -> dict[str, Any]:
        for manifest in self._discover_manifests():
            if manifest["module_id"] == module_id:
                return manifest
        raise KeyError(module_id)

    def list_workflows(self) -> dict[str, Any]:
        return {"workflows": [self._workflow_summary(item) for item in self._loaded_workflows()]}

    def get_workflow(self, workflow_id: str) -> dict[str, Any]:
        for item in self._loaded_workflows():
            if item["workflow_id"] == workflow_id:
                return item
        raise KeyError(workflow_id)

    def list_module_workflows(self, module_id: str) -> list[dict[str, Any]]:
        manifest = self.get_module(module_id)
        return self._workflows_for_manifest(manifest)

    def load_function_instances(
        self,
        module_id: str | None = None,
        exclude_module_id: str | None = None,
    ) -> list[AnalysisFunction]:
        manifests = [self.get_module(module_id)] if module_id else self._loaded_manifests()
        functions: list[AnalysisFunction] = []
        for manifest in manifests:
            if manifest["module_id"] == exclude_module_id:
                continue
            functions.extend(self._functions_for_manifest(manifest))
        return functions

    def list_knowledge(self) -> dict[str, Any]:
        entries: list[dict[str, Any]] = []
        for manifest in self._loaded_manifests():
            module_root = self._module_root(manifest)
            for item in manifest.get("knowledge", []):
                if not isinstance(item, dict):
                    continue
                path = self._safe_join(module_root, str(item.get("path", "")))
                entries.append(
                    {
                        "module_id": manifest["module_id"],
                        "type": str(item.get("type") or "knowledge"),
                        "path": str(item.get("path") or ""),
                        "items_count": self._count_json_items(path),
                    }
                )
        return {"knowledge": entries}

    def load_config_fields(self) -> list[dict[str, Any]]:
        fields: list[dict[str, Any]] = []
        for manifest in self._loaded_manifests():
            module_root = self._module_root(manifest)
            for relative_path in manifest.get("config_fields", []):
                path = self._safe_join(module_root, str(relative_path))
                fields.extend(self._read_config_fields(path))
        return fields

    def loaded_skill_context(self) -> list[dict[str, Any]]:
        return [
            self._skill_context_for_manifest(manifest)
            for manifest in self._loaded_manifests()
        ]

    def _skill_context_for_manifest(self, manifest: dict[str, Any]) -> dict[str, Any]:
        module_root = self._module_root(manifest)
        skill_info = manifest.get("skill") if isinstance(manifest.get("skill"), dict) else {}
        skill_path = self._safe_join(module_root, str(skill_info.get("skill_file", "")))
        playbook_path = self._safe_join(module_root, str(skill_info.get("playbook_file", "")))
        final_result_schema_path = self._safe_join(
            module_root,
            str(skill_info.get("final_result_schema_file", "")),
        )
        return {
            **self._module_summary(manifest),
            "loaded": True,
            "usable": True,
            "skill_paths": {
                "skill_file": str(skill_info.get("skill_file") or ""),
                "playbook_file": str(skill_info.get("playbook_file") or ""),
                "final_result_schema_file": str(
                    skill_info.get("final_result_schema_file") or ""
                ),
            },
            "skill": self._read_text_if_exists(skill_path),
            "playbook": self._read_json_if_exists(playbook_path),
            "final_result_schema": self._read_json_if_exists(final_result_schema_path),
            "knowledge": [
                {
                    "type": str(item.get("type") or "knowledge"),
                    "path": str(item.get("path") or ""),
                }
                for item in manifest.get("knowledge", [])
                if isinstance(item, dict)
            ],
        }

    def _loaded_workflows(self) -> list[dict[str, Any]]:
        workflows: list[dict[str, Any]] = []
        for manifest in self._loaded_manifests():
            workflows.extend(self._workflows_for_manifest(manifest))
        return workflows

    def _workflows_for_manifest(self, manifest: dict[str, Any]) -> list[dict[str, Any]]:
        workflows: list[dict[str, Any]] = []
        module_root = self._module_root(manifest)
        for relative_path in manifest.get("workflows", []):
            path = self._safe_join(module_root, str(relative_path))
            item = self._read_json_if_exists(path)
            if not isinstance(item, dict):
                continue
            workflow_id = str(item.get("workflow_id") or path.stem)
            workflows.append(
                {
                    "workflow_id": f"module:{manifest['module_id']}:{workflow_id}",
                    "name": str(item.get("name") or workflow_id),
                    "description": str(item.get("description") or ""),
                    "tags": list(item.get("tags") or []),
                    "risk": str(item.get("risk") or "low"),
                    "network": bool(item.get("network", False)),
                    "config_required": bool(item.get("config_required", False)),
                    "default_safe": bool(item.get("default_safe", False)),
                    "created_at": "",
                    "updated_at": "",
                    "source": "module",
                    "module_id": manifest["module_id"],
                    "workflow": item.get("workflow", {"name": item.get("name", ""), "steps": []}),
                }
            )
        return workflows

    def _functions_for_manifest(self, manifest: dict[str, Any]) -> list[AnalysisFunction]:
        functions: list[AnalysisFunction] = []
        module_root = self._module_root(manifest)
        for item in manifest.get("functions", []):
            if not isinstance(item, dict):
                continue
            function_id = str(item.get("function_id") or "")
            relative_path = str(item.get("path") or item.get("module") or "")
            class_name = str(item.get("class_name") or item.get("class") or "")
            path = self._safe_join(module_root, relative_path)
            if not function_id or not class_name or path.suffix.lower() != ".py":
                raise ValueError("invalid_module_function")
            fn = self._load_function_class(
                manifest["module_id"],
                function_id,
                path,
                class_name,
            )
            functions.append(fn)
        return functions

    def _loaded_manifests(self) -> list[dict[str, Any]]:
        return self._discover_manifests()

    def _discover_manifests(self) -> list[dict[str, Any]]:
        manifests: list[dict[str, Any]] = []
        seen: set[str] = set()
        for base_dir, source in [
            (self.modules_dir, "builtin"),
            (self.installed_modules_dir, "installed"),
        ]:
            if not base_dir.is_dir():
                continue
            for path in sorted(base_dir.glob("*/module.json")):
                manifest = self._read_json_if_exists(path)
                if not isinstance(manifest, dict) or not self._valid_manifest(manifest, path.parent):
                    continue
                if manifest["module_id"] in seen:
                    continue
                manifest["_module_root"] = str(path.parent)
                manifest["_module_source"] = source
                manifests.append(manifest)
                seen.add(manifest["module_id"])
        return manifests

    def _load_registry(self) -> list[str]:
        if not self.registry_path.is_file():
            return []
        data = self._read_json_if_exists(self.registry_path)
        modules = data.get("loaded_modules") if isinstance(data, dict) else []
        return [str(module_id) for module_id in modules] if isinstance(modules, list) else []

    def _save_registry(self, loaded_modules: list[str]) -> None:
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.registry_path.write_text(
            json.dumps({"loaded_modules": loaded_modules}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    @staticmethod
    def _valid_manifest(manifest: dict[str, Any], module_root: Path) -> bool:
        module_id = manifest.get("module_id")
        if not isinstance(module_id, str) or not module_id:
            return False
        if any(part in {"", ".", ".."} for part in module_id.split("/")):
            return False
        if ModuleStore._safe_name(module_id) != module_id:
            return False
        if module_root.name != module_id:
            return False
        return True

    @staticmethod
    def _module_summary(manifest: dict[str, Any]) -> dict[str, Any]:
        return {
            "module_id": manifest["module_id"],
            "template_version": str(manifest.get("template_version") or _MODULE_TEMPLATE_VERSION),
            "name": str(manifest.get("name") or manifest["module_id"]),
            "version": str(manifest.get("version") or "0.0.0"),
            "description": str(manifest.get("description") or ""),
            "source": str(manifest.get("_module_source") or "builtin"),
            "requirements": ModuleStore._requirements(manifest.get("requirements")),
            "workflows_count": len(manifest.get("workflows", [])),
            "knowledge_count": len(manifest.get("knowledge", [])),
            "functions_count": len(manifest.get("functions", [])),
        }

    @staticmethod
    def _requirements(value: Any) -> dict[str, Any]:
        requirements = value if isinstance(value, dict) else {}
        return {
            **_DEFAULT_REQUIREMENTS,
            **requirements,
            "external_tools": list(requirements.get("external_tools") or []),
        }

    @staticmethod
    def _workflow_summary(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "workflow_id": item["workflow_id"],
            "name": item["name"],
            "created_at": item["created_at"],
            "updated_at": item["updated_at"],
            "steps_count": len(item.get("workflow", {}).get("steps", [])),
            "description": item["description"],
            "tags": item["tags"],
            "risk": item["risk"],
            "network": item["network"],
            "config_required": item["config_required"],
            "default_safe": item["default_safe"],
            "source": item["source"],
            "module_id": item["module_id"],
        }

    @staticmethod
    def _module_root(manifest: dict[str, Any]) -> Path:
        return Path(str(manifest.get("_module_root", "")))

    @staticmethod
    def _safe_join(root: Path, relative_path: str) -> Path:
        if not relative_path:
            return root / "__missing__"
        path = Path(relative_path)
        if path.is_absolute() or ".." in path.parts:
            return root / "__invalid__"
        target = (root / path).resolve()
        root_resolved = root.resolve()
        if target != root_resolved and root_resolved not in target.parents:
            return root / "__invalid__"
        return target

    @staticmethod
    def _read_json_if_exists(path: Path) -> Any:
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    @staticmethod
    def _read_text_if_exists(path: Path) -> str:
        if not path.is_file():
            return ""
        try:
            return path.read_text(encoding="utf-8")
        except OSError:
            return ""

    @classmethod
    def _read_config_fields(cls, path: Path) -> list[dict[str, Any]]:
        data = cls._read_json_if_exists(path)
        fields = data.get("fields") if isinstance(data, dict) else []
        if not isinstance(fields, list):
            return []
        return [field for field in fields if cls._valid_config_field(field)]

    @staticmethod
    def _valid_config_field(field: Any) -> bool:
        if not isinstance(field, dict):
            return False
        required = {"function_id", "path", "label", "secret"}
        if not required <= set(field):
            return False
        if not isinstance(field.get("path"), str) or not field["path"]:
            return False
        return isinstance(field.get("secret"), bool)

    @classmethod
    def _count_json_items(cls, path: Path) -> int:
        data = cls._read_json_if_exists(path)
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            for key in ("items", "techniques", "entries"):
                if isinstance(data.get(key), list):
                    return len(data[key])
            return 1
        return 0

    @staticmethod
    def _load_function_class(
        module_id: str,
        function_id: str,
        path: Path,
        class_name: str,
    ) -> AnalysisFunction:
        if not path.is_file():
            raise ValueError("module_function_not_found")
        module_name = (
            f"sfp_module_{ModuleStore._safe_name(module_id)}_"
            f"{ModuleStore._safe_name(function_id)}"
        ).replace(".", "_")
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise ValueError("module_function_import_failed")
        module = importlib.util.module_from_spec(spec)
        module_dir = str(path.parent)
        inserted = False
        if module_dir not in sys.path:
            sys.path.insert(0, module_dir)
            inserted = True
        try:
            spec.loader.exec_module(module)
        finally:
            if inserted:
                try:
                    sys.path.remove(module_dir)
                except ValueError:
                    pass
        candidate = getattr(module, class_name, None)
        if not isinstance(candidate, type) or not issubclass(candidate, AnalysisFunction):
            raise ValueError("module_function_class_invalid")
        instance = candidate()
        if instance.id != function_id:
            raise ValueError("module_function_id_mismatch")
        instance.source = "module"
        instance.module_id = module_id
        return instance

    def _module_id_exists(self, module_id: str) -> bool:
        return any(manifest["module_id"] == module_id for manifest in self._discover_manifests())

    @classmethod
    def _validate_function_entries(
        cls,
        manifest: dict[str, Any],
        module_root: Path,
        errors: list[dict[str, Any]],
    ) -> None:
        functions = manifest.get("functions", [])
        if not isinstance(functions, list):
            return
        for index, item in enumerate(functions):
            if not isinstance(item, dict):
                errors.append(cls._entry_error("invalid_manifest_item", "functions", index))
                continue
            function_id = str(item.get("function_id") or "")
            relative_path = str(item.get("path") or item.get("module") or "")
            class_name = str(item.get("class_name") or item.get("class") or "")
            if not function_id or not class_name:
                errors.append(cls._entry_error("missing_function_metadata", "functions", index))
            path = cls._safe_join(module_root, relative_path)
            cls._validate_existing_path(path, relative_path, "functions", index, {".py"}, errors)

    @classmethod
    def _validate_path_list(
        cls,
        manifest: dict[str, Any],
        module_root: Path,
        field: str,
        suffixes: set[str],
        errors: list[dict[str, Any]],
    ) -> None:
        values = manifest.get(field, [])
        if not isinstance(values, list):
            return
        for index, value in enumerate(values):
            relative_path = str(value or "")
            path = cls._safe_join(module_root, relative_path)
            cls._validate_existing_path(path, relative_path, field, index, suffixes, errors)

    @classmethod
    def _validate_knowledge_entries(
        cls,
        manifest: dict[str, Any],
        module_root: Path,
        errors: list[dict[str, Any]],
    ) -> None:
        knowledge = manifest.get("knowledge", [])
        if not isinstance(knowledge, list):
            return
        for index, item in enumerate(knowledge):
            if not isinstance(item, dict):
                errors.append(cls._entry_error("invalid_manifest_item", "knowledge", index))
                continue
            relative_path = str(item.get("path") or "")
            path = cls._safe_join(module_root, relative_path)
            cls._validate_existing_path(
                path,
                relative_path,
                "knowledge",
                index,
                _ALLOWED_PACKAGE_EXTENSIONS,
                errors,
            )

    @classmethod
    def _validate_skill_paths(
        cls,
        skill_info: dict[str, Any],
        module_root: Path,
        errors: list[dict[str, Any]],
    ) -> None:
        for key, suffixes in [
            ("skill_file", {".md"}),
            ("playbook_file", {".json"}),
            ("final_result_schema_file", {".json"}),
        ]:
            relative_path = str(skill_info.get(key) or "")
            if not relative_path:
                continue
            path = cls._safe_join(module_root, relative_path)
            cls._validate_existing_path(path, relative_path, "skill", key, suffixes, errors)

    @classmethod
    def _validate_existing_path(
        cls,
        path: Path,
        relative_path: str,
        field: str,
        index: int | str,
        suffixes: set[str],
        errors: list[dict[str, Any]],
    ) -> None:
        if path.name in {"__invalid__", "__missing__"}:
            errors.append(cls._entry_error("invalid_module_path", field, index, relative_path))
            return
        if path.suffix.lower() not in suffixes:
            errors.append(cls._entry_error("invalid_module_file_type", field, index, relative_path))
            return
        if not path.is_file():
            errors.append(cls._entry_error("module_file_not_found", field, index, relative_path))

    @staticmethod
    def _entry_error(
        code: str,
        field: str,
        index: int | str,
        path: str = "",
    ) -> dict[str, Any]:
        error: dict[str, Any] = {
            "code": code,
            "field": field,
            "index": index,
            "message": f"{code}: {field}[{index}]",
        }
        if path:
            error["path"] = path
        return error

    @staticmethod
    def _validate_module_id(module_id: str) -> str:
        module_id = str(module_id).strip()
        path = Path(module_id)
        if (
            not module_id
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or "\\" in module_id
            or "/" in module_id
        ):
            raise ValueError("invalid_module_id")
        safe = ModuleStore._safe_name(module_id)
        if safe != module_id:
            raise ValueError("invalid_module_id")
        return module_id

    @staticmethod
    def _archive_name(manifest: dict[str, Any]) -> str:
        module_id = ModuleStore._safe_name(str(manifest["module_id"]))
        version = ModuleStore._safe_name(str(manifest.get("version") or "0.0.0"))
        return f"{module_id}-{version}.sfpmod.zip"

    @staticmethod
    def _safe_name(value: str) -> str:
        return "".join(char if char.isalnum() or char in {"_", "-", "."} else "_" for char in value)

    @staticmethod
    def _default_final_result_schema(module_id: str) -> dict[str, Any]:
        return {
            "schema_id": f"{module_id}.final_result.v1",
            "module_id": module_id,
            "description": "Default final AI summary output saved by save_session_result.",
            "write_target": "data/sessions/<session_id>/result/result.json",
            "required_top_level_fields": [
                "session_id",
                "file",
                "summary",
                "behaviors",
            ],
            "output": {
                "session_id": "string",
                "file": {
                    "filename": "string",
                    "size": "number",
                    "sha256": "string",
                    "file_type": "string",
                },
                "summary": {
                    "overall": "string",
                    "risk_level": "unknown|low|medium|high",
                    "limitations": ["string"],
                },
                "behaviors": [
                    {
                        "behavior": "string",
                        "evidence": {
                            "summary": "string",
                            "sources": [
                                {
                                    "source_type": "ai_output|raw_output|manual",
                                    "raw_output_id": "string",
                                    "function_id": "string",
                                    "result_key": "string",
                                    "description": "string",
                                }
                            ],
                        },
                        "verification": "verified|unverified",
                        "function_level_source": {
                            "tool": "string",
                            "function_name": "string",
                            "address": "string",
                            "source_raw_output_id": "string",
                            "note": "string",
                        },
                    }
                ],
            },
            "rules": [
                "Save the final output with save_session_result.",
                "Use ai_output first and include raw_output_id sources when possible.",
                "Do not include secrets.",
                "Do not treat candidate evidence as confirmed behavior unless verified.",
            ],
        }

    @staticmethod
    def _allowed_package_member(relative: Path) -> bool:
        parts = {part.lower() for part in relative.parts}
        if parts & _DENIED_PACKAGE_PARTS:
            return False
        if relative.name.lower() in _DENIED_PACKAGE_PARTS:
            return False
        return relative.suffix.lower() in _ALLOWED_PACKAGE_EXTENSIONS

    @classmethod
    def _safe_archive_members(cls, archive_path: Path) -> list[Path]:
        members: list[Path] = []
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                member = Path(info.filename)
                if member.is_absolute() or ".." in member.parts:
                    raise ValueError("archive_path_not_allowed")
                if len(member.parts) < 2:
                    raise ValueError("archive_must_contain_single_module_root")
                if not cls._allowed_package_member(Path(*member.parts[1:])):
                    raise ValueError("archive_member_not_allowed")
                members.append(member)
        if not members:
            raise ValueError("archive_empty")
        return members
