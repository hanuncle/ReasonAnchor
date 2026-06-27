from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class MCPToolSpec:
    name: str
    group: str
    purpose: str
    side_effect: str
    inputs: dict[str, Any]
    returns: dict[str, Any]
    safety: str = ""


_TOOL_SPECS: tuple[MCPToolSpec, ...] = (
    MCPToolSpec(
        "get_platform_skill",
        "skill",
        "Return the platform Skill, default playbook, and module loading contract.",
        "read",
        {},
        {"skill": "markdown", "playbook": "object", "module_loading": "object"},
    ),
    MCPToolSpec(
        "list_mcp_tools",
        "skill",
        "Return the MCP tool registry with groups, input contracts, return contracts, and side-effect hints.",
        "read",
        {},
        {"schema_id": "string", "tools": "list"},
    ),
    MCPToolSpec(
        "upload_sample",
        "session",
        "Upload one sample and create a sample-backed session.",
        "write",
        {"file_path": "string"},
        {"session_id": "string"},
        "Only upload samples when the selected module workflow and user request allow it.",
    ),
    MCPToolSpec(
        "upload_samples",
        "session",
        "Upload multiple samples and create sample-backed sessions.",
        "write",
        {"file_paths": "list[string]"},
        {"sessions": "list", "count": "integer"},
        "Only upload samples when the selected module workflow and user request allow it.",
    ),
    MCPToolSpec(
        "create_target_session",
        "session",
        "Create a target-backed session with explicit authorized scope.",
        "write",
        {
            "targets": "list[string]",
            "authorized_scope": "list[string]",
            "module_id": "string optional",
            "exclude": "list[string] optional",
            "label": "string optional",
            "notes": "string optional",
        },
        {"session_id": "string"},
        "Use only for authorized targets.",
    ),
    MCPToolSpec("list_sessions", "session", "List sessions.", "read", {}, {"sessions": "list"}),
    MCPToolSpec(
        "get_session",
        "session",
        "Fetch one session by id.",
        "read",
        {"session_id": "string"},
        {"session": "object"},
    ),
    MCPToolSpec("list_functions", "function", "List platform/module primitive functions.", "read", {}, {"functions": "list"}),
    MCPToolSpec(
        "run_function",
        "function",
        "Run one primitive function against a session.",
        "execute",
        {"session_id": "string", "function_id": "string", "params": "object optional"},
        {"summary": "object", "ai_output_item": "object optional"},
        "Prefer action/workflow tools unless direct primitive execution is intentional.",
    ),
    MCPToolSpec("get_platform_actions", "action", "List platform actions.", "read", {}, {"actions": "list"}),
    MCPToolSpec(
        "get_module_actions",
        "action",
        "List actions declared by one module.",
        "read",
        {"module_id": "string"},
        {"actions": "list"},
    ),
    MCPToolSpec(
        "preview_action",
        "action",
        "Preview an action execution plan and validation state without running it.",
        "read",
        {"module_id": "string", "action_id": "string", "session_id": "string optional"},
        {"ready": "bool", "execution_plan": "object", "validation_errors": "list"},
    ),
    MCPToolSpec(
        "list_runner_flows",
        "runner",
        "List module-declared flows that can be compiled into a Go runner plan.",
        "read",
        {"module_id": "string"},
        {"flows": "list", "runner": "object"},
    ),
    MCPToolSpec(
        "preview_runner_flow",
        "runner",
        "Compile one module flow into a Go runner plan without executing it.",
        "read",
        {
            "module_id": "string",
            "flow_id": "string",
            "session_id": "string optional",
            "params": "object optional",
        },
        {"ready": "bool", "runner_plan": "object", "validation_errors": "list"},
        "Preview only; it must not execute samples or mutate VM state.",
    ),
    MCPToolSpec(
        "run_action",
        "action",
        "Run one module action and return compact outputs plus the execution plan.",
        "execute",
        {
            "session_id": "string",
            "module_id": "string",
            "action_id": "string",
            "params": "object optional",
            "approvals": "object optional",
        },
        {
            "status": "string",
            "summary": "object",
            "execution_plan": "object",
            "raw_output_items": "list",
            "ai_output_items": "list",
            "allowed_next_actions": "list",
        },
        "Run only after preview and required approvals/configuration are satisfied.",
    ),
    MCPToolSpec("save_custom_workflow", "workflow", "Save a custom workflow template.", "write", {"name": "string", "workflow": "object"}, {"workflow_id": "string"}),
    MCPToolSpec("list_custom_workflows", "workflow", "List saved custom workflow templates.", "read", {}, {"workflows": "list"}),
    MCPToolSpec("select_custom_workflow", "workflow", "Attach a custom workflow template to a session.", "write", {"session_id": "string", "workflow_id": "string"}, {"session_id": "string"}),
    MCPToolSpec("run_workflow", "workflow", "Run the selected workflow for one session.", "execute", {"session_id": "string"}, {"summary": "object", "ai_output": "object"}),
    MCPToolSpec("run_batch_workflow", "workflow", "Run a workflow for multiple sessions synchronously.", "execute", {"session_ids": "list[string]", "workflow_id": "string optional", "create_report": "bool optional"}, {"batch_id": "string", "report_id": "string optional"}),
    MCPToolSpec("submit_batch_workflow_job", "workflow", "Submit an asynchronous batch workflow job.", "execute", {"session_ids": "list[string]", "workflow_id": "string optional", "create_report": "bool optional"}, {"job_id": "string", "status": "string"}),
    MCPToolSpec("list_batch_jobs", "workflow", "List asynchronous batch jobs.", "read", {}, {"jobs": "list"}),
    MCPToolSpec("get_batch_job", "workflow", "Fetch one asynchronous batch job.", "read", {"job_id": "string"}, {"job_id": "string", "status": "string"}),
    MCPToolSpec("list_modules", "module", "List available modules.", "read", {}, {"modules": "list"}),
    MCPToolSpec("get_module_template", "module", "Return the module creation template.", "read", {}, {"template": "object"}),
    MCPToolSpec("get_module_detail", "module", "Return one module detail.", "read", {"module_id": "string"}, {"module": "object"}),
    MCPToolSpec("get_module_capabilities", "module", "Return one module capability catalog.", "read", {"module_id": "string"}, {"capabilities": "object"}),
    MCPToolSpec("refresh_module_capabilities", "module", "Refresh one module capability catalog.", "write", {"module_id": "string"}, {"capabilities": "object"}),
    MCPToolSpec("get_module_skill", "module", "Return one selected module Skill/playbook/schema.", "read", {"module_id": "string"}, {"skill": "markdown", "playbook": "object"}),
    MCPToolSpec("get_module_ui", "module", "Return one module UI declaration.", "read", {"module_id": "string"}, {"pages": "list"}),
    MCPToolSpec("get_module_knowledge", "module", "Return one declared module knowledge asset.", "read", {"module_id": "string", "knowledge_type": "string"}, {"items": "list"}),
    MCPToolSpec("create_module", "module", "Create a module scaffold.", "write", {"module_id": "string", "name": "string optional", "version": "string optional", "description": "string optional", "requirements": "object optional"}, {"module_id": "string"}),
    MCPToolSpec("load_module", "module", "Load or enable one module.", "write", {"module_id": "string"}, {"module_id": "string"}),
    MCPToolSpec("package_module", "module", "Package one module.", "write", {"module_id": "string"}, {"archive_path": "string"}),
    MCPToolSpec("export_module", "module", "Export one module package.", "write", {"module_id": "string"}, {"archive_path": "string"}),
    MCPToolSpec("import_module_archive", "module", "Import one module archive.", "write", {"archive_path": "string"}, {"module_id": "string"}),
    MCPToolSpec("list_module_knowledge", "module", "List module knowledge declarations.", "read", {}, {"knowledge": "list"}),
    MCPToolSpec("upsert_module_ui_page", "module", "Create or replace one module UI page declaration.", "write", {"module_id": "string", "page_id": "string", "title": "string", "page_type": "string", "knowledge_type": "string", "description": "string optional", "columns": "list[string] optional"}, {"page": "object"}),
    MCPToolSpec("get_ai_output", "result", "Return compact AI-facing output for a session.", "read", {"session_id": "string"}, {"items": "list"}),
    MCPToolSpec("get_ai_output_by_raw_id", "result", "Return AI-facing output linked to one raw output id.", "read", {"session_id": "string", "raw_output_id": "string"}, {"item": "object"}),
    MCPToolSpec("get_raw_output_map", "result", "Return raw output ids and metadata before fetching raw detail.", "read", {"session_id": "string"}, {"items": "list"}),
    MCPToolSpec("get_session_execution_status", "result", "Return the latest lightweight execution progress for a session.", "read", {"session_id": "string"}, {"status": "string", "current_step": "object", "last_completed_step": "object", "failed_step": "object"}),
    MCPToolSpec("get_raw_output_by_id", "result", "Fetch one raw output by id.", "read", {"session_id": "string", "raw_output_id": "string"}, {"raw_output": "object"}),
    MCPToolSpec("list_sample_set_reports", "result", "List sample-set reports.", "read", {}, {"reports": "list"}),
    MCPToolSpec("get_sample_set_report", "result", "Fetch one sample-set report.", "read", {"report_id": "string"}, {"report": "object"}),
    MCPToolSpec("save_session_result", "result", "Save final structured session result.", "write", {"session_id": "string", "result": "object"}, {"session_id": "string"}),
    MCPToolSpec("get_mcp_file_access_policy", "file", "Return allowed MCP file access policy.", "read", {}, {"policy": "object"}),
    MCPToolSpec("inspect_allowed_files", "file", "Inspect an allowed file or directory.", "read", {"path": "string", "include_content": "bool optional"}, {"path": "string", "items": "list optional", "content": "string optional"}),
    MCPToolSpec("write_allowed_file", "file", "Write an allowed platform file.", "write", {"path": "string", "content": "string"}, {"path": "string", "sha256": "string"}),
)


MCP_TOOL_NAMES: tuple[str, ...] = tuple(spec.name for spec in _TOOL_SPECS)


def mcp_tool_specs() -> list[dict[str, Any]]:
    return [asdict(spec) for spec in _TOOL_SPECS]
