from __future__ import annotations

import json
import mimetypes
import os
import hashlib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from security_function_platform.module_system import ModuleStore

API_BASE = os.environ.get(
    "SECURITY_FUNCTION_PLATFORM_API_BASE",
    "http://127.0.0.1:8111",
).rstrip("/")
PROJECT_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = PROJECT_ROOT / "config" / "mcp_file_access.json"
PLATFORM_SKILL_PATH = PROJECT_ROOT / "config_files" / "codex_skill" / "SKILL.md"
PLATFORM_PLAYBOOK_PATH = (
    PROJECT_ROOT / "config_files" / "codex_skill" / "default_analysis_playbook.json"
)
MODULE_STORE = ModuleStore(
    PROJECT_ROOT / "modules",
    PROJECT_ROOT / "data" / "modules" / "loaded_modules.json",
    PROJECT_ROOT / "data" / "modules_installed",
    PROJECT_ROOT / "data" / "module_packages",
)

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:

    class FastMCP:  # type: ignore[no-redef]
        def __init__(self, name: str) -> None:
            self.name = name
            self._tools: dict[str, Callable[..., Any]] = {}

        def tool(self) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
            def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
                self._tools[fn.__name__] = fn
                return fn

            return decorator

        def run(self, transport: str = "stdio") -> None:
            raise RuntimeError("mcp package is not installed")


mcp = FastMCP(
    "security-function-platform: before analyzing a sample, call get_platform_skill first"
)


@mcp.tool()
def upload_sample(file_path: str) -> dict[str, Any]:
    path = Path(file_path)
    if not path.is_file():
        return {"status": "error", "error": {"code": "file_not_found", "message": "file not found"}}
    return _upload_file("/api/sessions/upload", path)


@mcp.tool()
def upload_samples(file_paths: list[str]) -> dict[str, Any]:
    paths = [Path(file_path) for file_path in file_paths]
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        return {
            "status": "error",
            "error": {
                "code": "file_not_found",
                "message": "one or more files were not found",
                "missing": missing,
            },
        }
    return _upload_files("/api/sessions/upload-multiple", paths)


@mcp.tool()
def list_functions() -> dict[str, Any]:
    return _request_json("GET", "/api/functions")


@mcp.tool()
def save_custom_workflow(name: str, workflow: dict[str, Any]) -> dict[str, Any]:
    return _request_json("POST", "/api/workflows", {"name": name, "workflow": workflow})


@mcp.tool()
def list_custom_workflows() -> dict[str, Any]:
    return _request_json("GET", "/api/workflows")


@mcp.tool()
def list_modules() -> dict[str, Any]:
    return _request_json("GET", "/api/modules")


@mcp.tool()
def get_module_template() -> dict[str, Any]:
    return _request_json("GET", "/api/modules/template")


@mcp.tool()
def get_module_detail(module_id: str) -> dict[str, Any]:
    return _request_json("GET", f"/api/modules/{_quote(module_id)}")


@mcp.tool()
def get_module_skill(module_id: str) -> dict[str, Any]:
    return _request_json("GET", f"/api/modules/{_quote(module_id)}/skill")


@mcp.tool()
def get_module_ui(module_id: str) -> dict[str, Any]:
    return _request_json("GET", f"/api/modules/{_quote(module_id)}/ui")


@mcp.tool()
def get_module_knowledge(module_id: str, knowledge_type: str) -> dict[str, Any]:
    return _request_json(
        "GET",
        f"/api/modules/{_quote(module_id)}/knowledge/{_quote(knowledge_type)}",
    )


@mcp.tool()
def create_module(
    module_id: str,
    name: str = "",
    version: str = "0.1.0",
    description: str = "",
    requirements: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _request_json(
        "POST",
        "/api/modules",
        {
            "module_id": module_id,
            "name": name,
            "version": version,
            "description": description,
            "requirements": requirements or {},
        },
    )


@mcp.tool()
def load_module(module_id: str) -> dict[str, Any]:
    return _request_json("POST", f"/api/modules/{_quote(module_id)}/load")


@mcp.tool()
def package_module(module_id: str) -> dict[str, Any]:
    return _request_json("POST", f"/api/modules/{_quote(module_id)}/package")


@mcp.tool()
def export_module(module_id: str) -> dict[str, Any]:
    return _request_json("POST", f"/api/modules/{_quote(module_id)}/export")


@mcp.tool()
def import_module_archive(archive_path: str) -> dict[str, Any]:
    return _request_json("POST", "/api/modules/import", {"archive_path": archive_path})


@mcp.tool()
def list_module_knowledge() -> dict[str, Any]:
    return _request_json("GET", "/api/modules/knowledge")


@mcp.tool()
def upsert_module_ui_page(
    module_id: str,
    page_id: str,
    title: str = "",
    page_type: str = "knowledge_table",
    knowledge_type: str = "",
    description: str = "",
    columns: list[str] | None = None,
) -> dict[str, Any]:
    return _request_json(
        "PUT",
        f"/api/modules/{_quote(module_id)}/ui/pages/{_quote(page_id)}",
        {
            "title": title,
            "type": page_type,
            "knowledge_type": knowledge_type,
            "description": description,
            "columns": columns or [],
        },
    )


@mcp.tool()
def select_custom_workflow(session_id: str, workflow_id: str) -> dict[str, Any]:
    return _request_json(
        "POST",
        f"/api/sessions/{session_id}/workflow-template",
        {"workflow_id": workflow_id},
    )


@mcp.tool()
def run_workflow(session_id: str) -> dict[str, Any]:
    response = _request_json("POST", f"/api/sessions/{session_id}/run")
    return {
        "session_id": response.get("session_id", session_id),
        "summary": response.get("summary", {}),
        "ai_output": response.get("ai_output", {"session_id": session_id, "items": []}),
    }


@mcp.tool()
def run_batch_workflow(
    session_ids: list[str],
    workflow_id: str = "",
    create_report: bool = True,
) -> dict[str, Any]:
    return _request_json(
        "POST",
        "/api/batches/run",
        {
            "session_ids": session_ids,
            "workflow_id": workflow_id,
            "create_report": create_report,
        },
    )


@mcp.tool()
def submit_batch_workflow_job(
    session_ids: list[str],
    workflow_id: str = "",
    create_report: bool = True,
) -> dict[str, Any]:
    return _request_json(
        "POST",
        "/api/batches/jobs",
        {
            "session_ids": session_ids,
            "workflow_id": workflow_id,
            "create_report": create_report,
        },
    )


@mcp.tool()
def list_batch_jobs() -> dict[str, Any]:
    return _request_json("GET", "/api/batches/jobs")


@mcp.tool()
def get_batch_job(job_id: str) -> dict[str, Any]:
    return _request_json("GET", f"/api/batches/jobs/{_quote(job_id)}")


@mcp.tool()
def list_sample_set_reports() -> dict[str, Any]:
    return _request_json("GET", "/api/reports")


@mcp.tool()
def get_sample_set_report(report_id: str) -> dict[str, Any]:
    return _request_json("GET", f"/api/reports/{_quote(report_id)}")


@mcp.tool()
def get_raw_output_map(session_id: str) -> dict[str, Any]:
    return _request_json("GET", f"/api/sessions/{_quote(session_id)}/raw-output-map")


@mcp.tool()
def get_raw_output_by_id(session_id: str, raw_output_id: str) -> dict[str, Any]:
    return _request_json(
        "GET",
        f"/api/sessions/{_quote(session_id)}/raw-output/{_quote(raw_output_id)}",
    )


@mcp.tool()
def run_function(
    session_id: str,
    function_id: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response = _request_json(
        "POST",
        f"/api/sessions/{_quote(session_id)}/functions/run",
        {"function_id": function_id, "params": params or {}},
    )
    return {
        "session_id": session_id,
        "summary": response.get("summary", {}),
        "ai_output_item": response.get("ai_output_item"),
    }


@mcp.tool()
def get_ai_output(session_id: str) -> dict[str, Any]:
    return _request_json("GET", f"/api/sessions/{_quote(session_id)}/ai-output")


@mcp.tool()
def get_ai_output_by_raw_id(session_id: str, raw_output_id: str) -> dict[str, Any]:
    return _request_json(
        "GET",
        f"/api/sessions/{_quote(session_id)}/ai-output/{_quote(raw_output_id)}",
    )


@mcp.tool()
def get_mcp_file_access_policy() -> dict[str, Any]:
    try:
        return _load_policy()
    except FileNotFoundError:
        return {
            "status": "error",
            "error": {"code": "policy_not_found", "message": "MCP file access policy not found"},
        }


@mcp.tool()
def inspect_allowed_files(path: str, include_content: bool = False) -> dict[str, Any]:
    try:
        policy = _load_policy()
        target = _resolve_allowed_path(path, policy, must_exist=True)
    except ValueError as exc:
        return _policy_error(str(exc))
    except FileNotFoundError:
        return _policy_error("file_not_found")

    if target.is_dir():
        return {
            "path": _relative(target),
            "type": "directory",
            "items": [
                {
                    "path": _relative(item),
                    "type": "directory" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else 0,
                }
                for item in sorted(target.rglob("*"))
                if _is_allowed_existing(item, policy)
            ],
        }

    size = target.stat().st_size
    result: dict[str, Any] = {"path": _relative(target), "type": "file", "size": size}
    if include_content:
        max_read_bytes = int(policy.get("max_read_bytes", 200000))
        if size > max_read_bytes:
            return _policy_error("file_too_large")
        result["content"] = target.read_text(encoding="utf-8")
    return result


@mcp.tool()
def write_allowed_file(path: str, content: str) -> dict[str, Any]:
    try:
        policy = _load_policy()
        target = _resolve_allowed_path(path, policy, must_exist=False)
        max_write_bytes = int(policy.get("max_write_bytes", 200000))
        content_bytes = content.encode("utf-8")
        if len(content_bytes) > max_write_bytes:
            return _policy_error("content_too_large")
    except ValueError as exc:
        return _policy_error(str(exc))
    except FileNotFoundError:
        return _policy_error("policy_not_found")

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    written = target.read_bytes()
    return {
        "path": _relative(target),
        "size": len(written),
        "sha256": hashlib.sha256(written).hexdigest(),
    }


@mcp.tool()
def get_platform_skill() -> dict[str, Any]:
    if not PLATFORM_SKILL_PATH.is_file():
        return {
            "status": "error",
            "error": {"code": "skill_not_found", "message": "Platform skill file not found"},
        }
    if not PLATFORM_PLAYBOOK_PATH.is_file():
        return {
            "status": "error",
            "error": {"code": "playbook_not_found", "message": "Platform playbook file not found"},
        }
    try:
        playbook = json.loads(PLATFORM_PLAYBOOK_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {
            "status": "error",
            "error": {"code": "playbook_parse_failed", "message": "Platform playbook is invalid"},
        }
    return {
        "skill": PLATFORM_SKILL_PATH.read_text(encoding="utf-8"),
        "playbook": playbook,
        "module_loading": {
            "rule": "Call list_modules first, ask or infer the selected module, then call get_module_skill(module_id) only for the selected module skill, playbook, and final_result_schema.",
            "list_modules_tool": "list_modules",
            "module_skill_tool": "get_module_skill",
            "module_detail_tool": "get_module_detail",
            "module_template_tool": "get_module_template",
            "create_module_tool": "create_module",
            "module_ui_tool": "get_module_ui",
            "module_knowledge_tool": "get_module_knowledge",
            "module_ui_page_upsert_tool": "upsert_module_ui_page",
        },
    }


@mcp.tool()
def save_session_result(session_id: str, result: dict[str, Any]) -> dict[str, Any]:
    return _request_json(
        "POST",
        f"/api/sessions/{_quote(session_id)}/result",
        result,
    )


def _request_json(
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        f"{API_BASE}{path}",
        data=data,
        headers=headers,
        method=method,
    )
    return _open_json(request)


def _upload_file(path: str, file_path: Path) -> dict[str, Any]:
    return _upload_files(path, [file_path], field_name="file")


def _upload_files(
    path: str,
    file_paths: list[Path],
    field_name: str = "files",
) -> dict[str, Any]:
    boundary = "security-function-platform-boundary"
    parts: list[bytes] = []
    for file_path in file_paths:
        filename = file_path.name
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        parts.extend(
            [
                f"--{boundary}\r\n".encode("utf-8"),
                (
                    f'Content-Disposition: form-data; name="{field_name}"; '
                    f'filename="{filename}"\r\n'
                ).encode("utf-8"),
                f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"),
                file_path.read_bytes(),
                b"\r\n",
            ]
        )
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    body = b"".join(parts)
    request = urllib.request.Request(
        f"{API_BASE}{path}",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST",
    )
    return _open_json(request)


def _open_json(request: urllib.request.Request) -> dict[str, Any]:
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode("utf-8")
        return {
            "status": "error",
            "status_code": exc.code,
            "response": _loads(payload),
        }
    except urllib.error.URLError as exc:
        return {
            "status": "error",
            "error": {"code": "request_failed", "message": str(exc.reason)},
        }
    return _loads(payload)


def _loads(payload: str) -> dict[str, Any]:
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return {"status": "error", "error": {"code": "parse_failed", "message": "invalid JSON"}}
    return data if isinstance(data, dict) else {"items": data}


def _quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _load_policy() -> dict[str, Any]:
    if not POLICY_PATH.is_file():
        raise FileNotFoundError(POLICY_PATH)
    data = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _resolve_allowed_path(path: str, policy: dict[str, Any], must_exist: bool) -> Path:
    if not path or Path(path).is_absolute():
        raise ValueError("path_not_allowed")
    if ".." in Path(path).parts:
        raise ValueError("path_not_allowed")

    target = (PROJECT_ROOT / path).resolve()
    if not _is_allowed_target(target, policy):
        raise ValueError("path_not_allowed")
    if _matches_deny_policy(target, policy):
        raise ValueError("path_denied")
    if must_exist and not target.exists():
        raise FileNotFoundError(target)
    if target.suffix and target.suffix.lower() not in policy.get("allowed_extensions", []):
        if target.exists() and target.is_file():
            raise ValueError("extension_not_allowed")
    if not target.exists() and target.suffix.lower() not in policy.get("allowed_extensions", []):
        raise ValueError("extension_not_allowed")
    return target


def _under_allowed_root(target: Path, policy: dict[str, Any]) -> bool:
    for root in policy.get("allowed_roots", []):
        allowed_root = (PROJECT_ROOT / str(root)).resolve()
        if target == allowed_root or allowed_root in target.parents:
            return True
    return False


def _is_allowed_file(target: Path, policy: dict[str, Any]) -> bool:
    for file_path in policy.get("allowed_files", []):
        allowed_file = (PROJECT_ROOT / str(file_path)).resolve()
        if target == allowed_file:
            return True
    return False


def _is_allowed_target(target: Path, policy: dict[str, Any]) -> bool:
    return _under_allowed_root(target, policy) or _is_allowed_file(target, policy)


def _matches_deny_policy(target: Path, policy: dict[str, Any]) -> bool:
    relative = _relative(target).replace("\\", "/").lower()
    parts = {part.lower() for part in Path(relative).parts}
    for pattern in policy.get("deny_patterns", []):
        value = str(pattern).lower()
        if value in parts or value in relative:
            return True
    return False


def _is_allowed_existing(path: Path, policy: dict[str, Any]) -> bool:
    if _matches_deny_policy(path, policy):
        return False
    if path.is_file() and path.suffix.lower() not in policy.get("allowed_extensions", []):
        return False
    return _is_allowed_target(path.resolve(), policy)


def _relative(path: Path) -> str:
    return path.resolve().relative_to(PROJECT_ROOT).as_posix()


def _policy_error(code: str) -> dict[str, Any]:
    return {"status": "error", "error": {"code": code, "message": code}}


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
