from __future__ import annotations

from typing import Any


def build_platform_actions(modules: list[dict[str, Any]]) -> dict[str, Any]:
    default_module_id = _default_module_id(modules)
    return {
        "schema_id": "platform.actions.v1",
        "scope": "platform",
        "default_module_id": default_module_id,
        "primary_action_id": "platform.select_module",
        "actions": [
            _action(
                1,
                "platform.select_module",
                "选择模块",
                "列出可用模块并进入模块通用菜单。",
                {"type": "select_module"},
            ),
            _action(
                2,
                "platform.create_module",
                "创建模块",
                "基于平台模板创建新的模块骨架。",
                {"type": "create_module"},
            ),
            _action(
                3,
                "platform.enter_default_module",
                f"进入默认模块{f' {default_module_id}' if default_module_id else ''}",
                "直接进入默认模块。",
                {"type": "enter_module", "module_id": default_module_id},
                enabled=bool(default_module_id),
                disabled_reason="尚未发现可用默认模块。",
            ),
            _action(
                4,
                "platform.import_module",
                "导入模块",
                "导入可信本地模块包。",
                {"type": "open_page", "path": "/modules.html", "intent": "import_module"},
            ),
            _action(
                5,
                "platform.export_module",
                "导出 / 打包模块",
                "打包或导出现有模块。",
                {"type": "open_page", "path": "/modules.html", "intent": "export_module"},
            ),
            _action(
                6,
                "platform.load_validate_module",
                "加载 / 校验模块",
                "加载模块并校验函数、流程、知识库和 UI 声明。",
                {"type": "open_page", "path": "/modules.html", "intent": "load_module"},
            ),
            _action(
                7,
                "platform.manage_modules",
                "管理已有模块",
                "查看模块、流程模板和模块知识页面。",
                {"type": "open_page", "path": "/modules.html", "intent": "manage_modules"},
            ),
            _action(
                8,
                "platform.resume_session",
                "继续已有任务 / Session",
                "选择已有 session 并继续工作。",
                {"type": "focus", "target": "session-select"},
            ),
            _action(
                9,
                "platform.batch_jobs",
                "查看批处理任务",
                "查看长任务和批量流程状态。",
                {"type": "focus", "target": "batch-job-status"},
            ),
            _action(
                10,
                "platform.reports",
                "查看历史报告",
                "查看已保存的跨样本报告。",
                {"type": "focus", "target": "report-list"},
            ),
            _action(
                11,
                "platform.config",
                "平台配置",
                "打开平台配置页面。",
                {"type": "open_page", "path": "/config.html"},
            ),
        ],
    }


def build_module_actions(module_detail: dict[str, Any]) -> dict[str, Any]:
    module_id = str(module_detail.get("module_id") or "")
    requirements = module_detail.get("requirements")
    if not isinstance(requirements, dict):
        requirements = {}
    session_kind = "sample" if requirements.get("sample_execution") else "target"
    if not requirements.get("sample_execution") and not requirements.get("active_scan"):
        session_kind = "generic"

    return {
        "schema_id": "module.actions.v1",
        "scope": "module",
        "module_id": module_id,
        "name": str(module_detail.get("name") or module_id),
        "primary_action_id": "module.view_capabilities",
        "actions": [
            _action(
                0,
                "module.view_capabilities",
                "查看模块功能",
                "查看平台自动生成并缓存的模块能力说明。",
                {"type": "view_module_capabilities", "module_id": module_id},
                source="platform_module_default",
            ),
            _action(
                1,
                "module.start_task",
                "开始一个新任务",
                "按模块类型创建新的分析 session。",
                {
                    "type": "create_session",
                    "module_id": module_id,
                    "session_kind": session_kind,
                },
                source="platform_module_default",
            ),
            _action(
                2,
                "module.resume_session",
                "继续该模块已有任务",
                "从已有 session 中选择一个继续。",
                {"type": "focus", "target": "session-select", "module_id": module_id},
                source="platform_module_default",
            ),
            _action(
                3,
                "module.view_workflows",
                "查看流程",
                "查看当前模块可用 workflow。",
                {"type": "focus", "target": "workflow-select", "module_id": module_id},
                source="platform_module_default",
            ),
            _action(
                4,
                "module.create_workflow",
                "创建流程",
                "打开流程模板编辑页面。",
                {
                    "type": "open_page",
                    "path": f"/modules.html?module={module_id}",
                    "intent": "create_workflow",
                },
                source="platform_module_default",
            ),
            _action(
                5,
                "module.apply_run_workflow",
                "应用 / 运行流程",
                "为当前 session 应用并运行选中的 workflow。",
                {"type": "focus", "target": "workflow-select", "module_id": module_id},
                source="platform_module_default",
            ),
            _action(
                6,
                "module.run_function",
                "运行单个函数",
                "选择一个模块函数并在当前 session 中执行。",
                {"type": "run_function_picker", "module_id": module_id},
                source="platform_module_default",
            ),
            _action(
                7,
                "module.view_functions",
                "查看模块函数",
                "查看模块函数、依赖、配置、成本和输出字段。",
                {"type": "view_functions", "module_id": module_id},
                source="platform_module_default",
            ),
            _action(
                8,
                "module.configure",
                "查看 / 修改模块配置",
                "打开配置中心并查看当前模块配置字段。",
                {
                    "type": "open_page",
                    "path": f"/config.html?module={module_id}",
                    "intent": "configure_module",
                },
                source="platform_module_default",
            ),
            _action(
                9,
                "module.view_knowledge",
                "查看模块知识库页面",
                "查看模块声明的知识库页面。",
                {"type": "view_module_knowledge", "module_id": module_id},
                source="platform_module_default",
            ),
            _action(
                10,
                "module.reports_batches",
                "查看模块报告和批处理",
                "查看相关报告与批处理任务。",
                {"type": "focus", "target": "report-list", "module_id": module_id},
                source="platform_module_default",
            ),
            _action(
                11,
                "module.back_to_platform",
                "返回平台主菜单",
                "返回平台级操作菜单。",
                {"type": "focus", "target": "platform-action-list"},
                source="platform_module_default",
            ),
        ],
    }


def _default_module_id(modules: list[dict[str, Any]]) -> str:
    module_ids = [str(item.get("module_id") or "") for item in modules if isinstance(item, dict)]
    if "reverse" in module_ids:
        return "reverse"
    return next((module_id for module_id in module_ids if module_id), "")


def _action(
    menu_index: int,
    action_id: str,
    label: str,
    description: str,
    action: dict[str, Any],
    *,
    enabled: bool = True,
    disabled_reason: str = "",
    source: str = "platform_default",
) -> dict[str, Any]:
    return {
        "id": action_id,
        "menu_index": menu_index,
        "label": label,
        "description": description,
        "source": source,
        "enabled": enabled,
        "disabled_reason": "" if enabled else disabled_reason,
        "action": action,
    }
