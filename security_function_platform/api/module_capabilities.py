from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_function_platform.module_system import ModuleStore


class ModuleCapabilityCache:
    def __init__(self, cache_dir: str | Path = "data/module_capabilities") -> None:
        self.cache_dir = Path(cache_dir)

    def get_capabilities(
        self,
        module_store: ModuleStore,
        module_id: str,
        functions: list[dict[str, Any]],
        workflows: list[dict[str, Any]],
        *,
        refresh: bool = False,
    ) -> dict[str, Any]:
        detail = module_store.get_module_detail(module_id)
        skill = module_store.get_module_skill(module_id)
        knowledge = module_store.list_knowledge().get("knowledge", [])
        source = _source_payload(detail, skill, functions, workflows, knowledge)
        source_hash = _stable_hash(source)
        cache_path = self._cache_path(module_id)

        if not refresh:
            cached = self._read_cache(cache_path)
            if cached and cached.get("generated_from", {}).get("source_hash") == source_hash:
                cached["cache"] = {
                    "hit": True,
                    "path": str(cache_path),
                    "refreshed": False,
                }
                return cached

        generated = _build_capabilities(detail, skill, functions, workflows, knowledge)
        generated["generated_from"] = {
            "source_hash": source_hash,
            "module_id": module_id,
            "functions_count": len(generated["capability_summary"]["functions"]),
            "workflows_count": len(generated["capability_summary"]["workflows"]),
            "knowledge_count": len(generated["capability_summary"]["knowledge_assets"]),
        }
        generated["generated_at"] = datetime.now(timezone.utc).isoformat()
        generated["cache"] = {
            "hit": False,
            "path": str(cache_path),
            "refreshed": bool(refresh),
        }
        self._write_cache(cache_path, generated)
        return generated

    def _cache_path(self, module_id: str) -> Path:
        safe = "".join(char if char.isalnum() or char in {"_", "-", "."} else "_" for char in module_id)
        return self.cache_dir / f"{safe or 'module'}.json"

    @staticmethod
    def _read_cache(path: Path) -> dict[str, Any] | None:
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    @staticmethod
    def _write_cache(path: Path, capabilities: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        saved = dict(capabilities)
        saved.pop("cache", None)
        path.write_text(json.dumps(saved, ensure_ascii=False, indent=2), encoding="utf-8")


def _build_capabilities(
    detail: dict[str, Any],
    skill: dict[str, Any],
    functions: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    knowledge: list[dict[str, Any]],
) -> dict[str, Any]:
    module_id = str(detail.get("module_id") or "")
    module_functions = _module_functions(functions, module_id)
    module_workflows = _module_workflows(workflows, module_id)
    module_knowledge = _module_knowledge(knowledge, module_id)
    function_groups = _function_groups(module_functions)
    config_requirements = sorted(
        {
            str(item)
            for function in module_functions
            for item in function.get("config_requirements", [])
            if str(item)
        }
    )
    final_schema = skill.get("final_result_schema")
    if not isinstance(final_schema, dict):
        final_schema = {}

    display_sections = [
        {
            "title": "模块用途",
            "items": [
                str(detail.get("description") or "未声明模块用途。"),
                _requirement_sentence(detail.get("requirements")),
            ],
        },
        {
            "title": "能力概览",
            "items": [
                f"函数数量：{len(module_functions)}",
                f"流程数量：{len(module_workflows)}",
                f"知识库数量：{len(module_knowledge)}",
                f"配置需求数量：{len(config_requirements)}",
            ],
        },
        {
            "title": "主要能力分组",
            "items": [
                f"{group['category']}：{group['count']} 个函数"
                for group in function_groups
            ]
            or ["暂无函数分组。"],
        },
        {
            "title": "可用流程",
            "items": [
                f"{workflow['name']}：{workflow.get('description') or '未声明说明'}"
                for workflow in module_workflows
            ]
            or ["暂无流程。"],
        },
        {
            "title": "配置需求",
            "items": config_requirements or ["暂无函数级配置需求。"],
        },
        {
            "title": "知识库页面",
            "items": [
                f"{page.get('title') or page.get('page_id')}（{page.get('knowledge_type')}）"
                for page in detail.get("ui", {}).get("pages", [])
                if isinstance(page, dict)
            ]
            or ["暂无知识库页面。"],
        },
    ]

    return {
        "schema_id": "module.capabilities.v1",
        "module_id": module_id,
        "name": str(detail.get("name") or module_id),
        "version": str(detail.get("version") or ""),
        "description": str(detail.get("description") or ""),
        "capability_summary": {
            "requirements": detail.get("requirements") if isinstance(detail.get("requirements"), dict) else {},
            "functions": module_functions,
            "function_groups": function_groups,
            "workflows": module_workflows,
            "knowledge_assets": module_knowledge,
            "ui_pages": detail.get("ui", {}).get("pages", []),
            "config_requirements": config_requirements,
            "final_result_schema": {
                "schema_id": str(final_schema.get("schema_id") or ""),
                "module_id": str(final_schema.get("module_id") or module_id),
                "required_top_level_fields": final_schema.get("required_top_level_fields", []),
                "description": str(final_schema.get("description") or ""),
            },
        },
        "display_sections": display_sections,
    }


def _source_payload(
    detail: dict[str, Any],
    skill: dict[str, Any],
    functions: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
    knowledge: list[dict[str, Any]],
) -> dict[str, Any]:
    module_id = str(detail.get("module_id") or "")
    return {
        "detail": detail,
        "playbook": skill.get("playbook", {}),
        "final_result_schema": skill.get("final_result_schema", {}),
        "skill_paths": skill.get("skill_paths", {}),
        "functions": _module_functions(functions, module_id),
        "workflows": _module_workflows(workflows, module_id),
        "knowledge": _module_knowledge(knowledge, module_id),
    }


def _module_functions(functions: list[dict[str, Any]], module_id: str) -> list[dict[str, Any]]:
    items = [
        {
            "id": str(function.get("id") or ""),
            "name": str(function.get("name") or ""),
            "category": str(function.get("category") or ""),
            "result_key": str(function.get("result_key") or ""),
            "description": str(function.get("description") or ""),
            "requires_results": _string_list(function.get("requires_results")),
            "recommended_before": _string_list(function.get("recommended_before")),
            "cost": str(function.get("cost") or ""),
            "network": bool(function.get("network")),
            "external": bool(function.get("external")),
            "external_tool": bool(function.get("external_tool")),
            "config_required": bool(function.get("config_required")),
            "config_requirements": _string_list(function.get("config_requirements")),
            "optional": bool(function.get("optional")),
            "candidate_only": bool(function.get("candidate_only")),
            "requires_human_confirmation": bool(function.get("requires_human_confirmation")),
            "output_fields": sorted((function.get("output_schema") or {}).keys())
            if isinstance(function.get("output_schema"), dict)
            else [],
        }
        for function in functions
        if isinstance(function, dict) and str(function.get("module_id") or "") == module_id
    ]
    return sorted(items, key=lambda item: item["id"])


def _module_workflows(workflows: list[dict[str, Any]], module_id: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for workflow in workflows:
        if not isinstance(workflow, dict):
            continue
        tags = _string_list(workflow.get("tags"))
        workflow_id = str(workflow.get("workflow_id") or "")
        if (
            str(workflow.get("module_id") or "") != module_id
            and module_id not in tags
            and not workflow_id.startswith(f"module:{module_id}:")
        ):
            continue
        items.append(
            {
                "workflow_id": workflow_id,
                "name": str(workflow.get("name") or ""),
                "description": str(workflow.get("description") or ""),
                "steps_count": _safe_int(workflow.get("steps_count")),
                "risk": str(workflow.get("risk") or ""),
                "network": bool(workflow.get("network")),
                "config_required": bool(workflow.get("config_required")),
                "default_safe": bool(workflow.get("default_safe")),
                "tags": tags,
                "source": str(workflow.get("source") or ""),
            }
        )
    return sorted(items, key=lambda item: item["workflow_id"])


def _module_knowledge(knowledge: list[dict[str, Any]], module_id: str) -> list[dict[str, Any]]:
    items = [
        {
            "type": str(item.get("type") or ""),
            "path": str(item.get("path") or ""),
            "items_count": _safe_int(item.get("items_count")),
        }
        for item in knowledge
        if isinstance(item, dict) and str(item.get("module_id") or "") == module_id
    ]
    return sorted(items, key=lambda item: item["type"])


def _function_groups(functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for function in functions:
        category = function.get("category") or "uncategorized"
        group = groups.setdefault(
            str(category),
            {
                "category": str(category),
                "count": 0,
                "functions": [],
                "requires_config_count": 0,
                "network_count": 0,
                "candidate_only_count": 0,
            },
        )
        group["count"] += 1
        group["functions"].append(function["id"])
        if function.get("config_required"):
            group["requires_config_count"] += 1
        if function.get("network"):
            group["network_count"] += 1
        if function.get("candidate_only"):
            group["candidate_only_count"] += 1
    return sorted(groups.values(), key=lambda item: item["category"])


def _requirement_sentence(requirements: Any) -> str:
    if not isinstance(requirements, dict):
        return "模块未声明运行需求。"
    parts = []
    if requirements.get("network"):
        parts.append("包含网络能力")
    if requirements.get("active_scan"):
        parts.append("包含主动扫描能力")
    if requirements.get("requires_authorization"):
        parts.append("需要授权范围")
    if requirements.get("sample_execution"):
        parts.append("支持样本执行")
    tools = requirements.get("external_tools")
    if isinstance(tools, list) and tools:
        parts.append("外部工具：" + ", ".join(str(tool) for tool in tools))
    return "；".join(parts) if parts else "模块未声明额外运行需求。"


def _stable_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
