from __future__ import annotations

from pathlib import Path
from typing import Any
import uuid

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from security_function_platform.api.builtin_registry import create_builtin_registry
from security_function_platform.api.config_store import ConfigStore
from security_function_platform.api.session_store import SessionStore
from security_function_platform.api.workflow_store import WorkflowStore
from security_function_platform.core.function_registry import FunctionRegistry
from security_function_platform.core.workflow import WorkflowDefinition, WorkflowRunner
from security_function_platform.module_system import ModuleStore
from security_function_platform.raw_sorting.sorter import sort_raw_output_item, sort_raw_outputs

store = SessionStore()
config_store = ConfigStore()
workflow_store = WorkflowStore()
module_store = ModuleStore()
runner = WorkflowRunner()

app = FastAPI(title="SecurityFunctionPlatform")

_WEB_DIR = Path(__file__).resolve().parents[2] / "web"
if _WEB_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(_WEB_DIR)), name="static")


@app.get("/")
def index() -> FileResponse:
    return _web_file("index.html")


@app.get("/modules.html")
def modules_page() -> FileResponse:
    return _web_file("modules.html")


@app.get("/config.html")
def config_page() -> FileResponse:
    return _web_file("config.html")


@app.get("/platform.html")
def platform_page() -> FileResponse:
    return _web_file("platform.html")


@app.get("/raw-data.html")
def raw_data_page() -> FileResponse:
    return _web_file("raw-data.html")


@app.get("/raw-output.html")
def raw_output_page() -> FileResponse:
    return _web_file("raw-output.html")


@app.get("/result.html")
def result_page() -> FileResponse:
    return _web_file("result.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/functions")
def list_functions() -> list[dict[str, Any]]:
    return _current_registry().list_functions()


@app.get("/api/workflows")
def list_workflows() -> dict[str, Any]:
    workflows = [
        *workflow_store.list_workflows()["workflows"],
        *module_store.list_workflows()["workflows"],
    ]
    return {"workflows": workflows}


@app.get("/api/workflows/{workflow_id}")
def get_workflow_template(workflow_id: str) -> dict[str, Any]:
    try:
        return workflow_store.get_workflow(workflow_id)
    except KeyError:
        try:
            return module_store.get_workflow(workflow_id)
        except KeyError:
            raise HTTPException(
                status_code=404,
                detail={"code": "workflow_not_found", "message": "Workflow was not found"},
            ) from None


@app.post("/api/workflows")
def save_workflow_template(body: dict[str, Any]) -> dict[str, Any]:
    registry = _current_registry()
    workflow = WorkflowDefinition.from_dict(body.get("workflow", {}))
    validation_errors = runner.validate(registry, workflow)
    if validation_errors:
        raise HTTPException(status_code=400, detail={"errors": validation_errors})
    metadata = {
        "description": body.get("description", ""),
        "tags": body.get("tags", []),
        "risk": body.get("risk", "low"),
        "network": body.get("network", False),
        "config_required": body.get("config_required", False),
        "default_safe": body.get("default_safe", False),
    }
    return workflow_store.save_workflow_template(
        str(body.get("name") or workflow.name),
        workflow,
        metadata,
    )


@app.put("/api/workflows/{workflow_id}")
def update_workflow_template(workflow_id: str, body: dict[str, Any]) -> dict[str, Any]:
    registry = _current_registry()
    workflow = WorkflowDefinition.from_dict(body.get("workflow", {}))
    validation_errors = runner.validate(registry, workflow)
    if validation_errors:
        raise HTTPException(status_code=400, detail={"errors": validation_errors})
    metadata = {
        "description": body.get("description", ""),
        "tags": body.get("tags", []),
        "risk": body.get("risk", "low"),
        "network": body.get("network", False),
        "config_required": body.get("config_required", False),
        "default_safe": body.get("default_safe", False),
    }
    try:
        return workflow_store.update_workflow_template(
            workflow_id,
            str(body.get("name") or workflow.name),
            workflow,
            metadata,
        )
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "workflow_not_found", "message": "Workflow was not found"},
        ) from None


@app.delete("/api/workflows/{workflow_id}")
def delete_workflow_template(workflow_id: str) -> dict[str, Any]:
    try:
        return workflow_store.delete_workflow_template(workflow_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "workflow_not_found", "message": "Workflow was not found"},
        ) from None


@app.get("/api/config")
def get_config() -> dict[str, Any]:
    return config_store.get_redacted_config(module_store.load_config_fields())


@app.post("/api/config/value")
def set_config_value(body: dict[str, Any]) -> dict[str, Any]:
    try:
        return config_store.set_config_value(
            str(body.get("path", "")),
            body.get("value"),
            module_store.load_config_fields(),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_config_path", "message": str(exc)},
        ) from None


@app.post("/api/config/delete")
def delete_config_value(body: dict[str, Any]) -> dict[str, Any]:
    try:
        return config_store.delete_config_value(
            str(body.get("path", "")),
            module_store.load_config_fields(),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_config_path", "message": str(exc)},
        ) from None


@app.post("/api/sessions/upload")
async def upload_session(file: UploadFile = File(...)) -> dict[str, Any]:
    content = await file.read()
    return store.create_session_from_upload(file.filename or "sample.bin", content)


@app.post("/api/sessions/upload-multiple")
async def upload_sessions(files: list[UploadFile] = File(...)) -> dict[str, Any]:
    sessions: list[dict[str, Any]] = []
    for file in files:
        content = await file.read()
        sessions.append(store.create_session_from_upload(file.filename or "sample.bin", content))
    return {
        "sessions": sessions,
        "count": len(sessions),
    }


@app.get("/api/sessions")
def list_sessions() -> dict[str, Any]:
    return store.list_sessions()


@app.get("/api/sessions/{session_id}")
def get_session(session_id: str) -> dict[str, Any]:
    return _get_session_or_404(session_id)


@app.post("/api/sessions/{session_id}/workflow")
def set_workflow(session_id: str, body: dict[str, Any]) -> dict[str, Any]:
    registry = _current_registry()
    _get_session_or_404(session_id)
    workflow = WorkflowDefinition.from_dict(body)
    validation_errors = runner.validate(registry, workflow)
    if validation_errors:
        raise HTTPException(status_code=400, detail={"errors": validation_errors})
    return store.set_workflow(session_id, workflow)


@app.post("/api/sessions/{session_id}/workflow-template")
def apply_workflow_template(session_id: str, body: dict[str, Any]) -> dict[str, Any]:
    _get_session_or_404(session_id)
    try:
        return workflow_store.apply_workflow_to_session(
            session_id,
            str(body.get("workflow_id", "")),
            store,
        )
    except KeyError:
        try:
            workflow = WorkflowDefinition.from_dict(
                module_store.get_workflow(str(body.get("workflow_id", "")))["workflow"]
            )
            return store.set_workflow(session_id, workflow)
        except KeyError:
            raise HTTPException(
                status_code=404,
                detail={"code": "workflow_not_found", "message": "Workflow was not found"},
            ) from None


@app.get("/api/modules")
def list_modules() -> dict[str, Any]:
    return module_store.list_modules()


@app.post("/api/modules")
def create_module(body: dict[str, Any]) -> dict[str, Any]:
    try:
        return module_store.create_module(
            str(body.get("module_id", "")),
            str(body.get("name") or ""),
            str(body.get("version") or "0.1.0"),
            str(body.get("description") or ""),
            body.get("requirements") if isinstance(body.get("requirements"), dict) else {},
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": str(exc), "message": str(exc)},
        ) from None


@app.get("/api/modules/template")
def get_module_template() -> dict[str, Any]:
    return module_store.get_module_template()


@app.post("/api/modules/{module_id}/load")
def load_module(module_id: str) -> dict[str, Any]:
    try:
        module = module_store.get_module(module_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "module_not_found", "message": "Module was not found"},
        ) from None

    _ = module
    registry = _current_registry(exclude_module_id=module_id)
    try:
        for fn in module_store.load_function_instances(module_id):
            registry.register(fn)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": str(exc), "message": str(exc)},
        ) from None
    for workflow in module_store.list_module_workflows(module_id):
        errors = runner.validate(registry, WorkflowDefinition.from_dict(workflow["workflow"]))
        if errors:
            raise HTTPException(status_code=400, detail={"errors": errors})
    return module_store.load_module(module_id)


@app.post("/api/modules/{module_id}/package")
def package_module(module_id: str) -> dict[str, Any]:
    try:
        return module_store.package_module(module_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "module_not_found", "message": "Module was not found"},
        ) from None


@app.post("/api/modules/{module_id}/export")
def export_module(module_id: str) -> dict[str, Any]:
    return package_module(module_id)


@app.get("/api/modules/{module_id}/download")
def download_module(module_id: str) -> FileResponse:
    packaged = package_module(module_id)
    archive_path = Path(packaged["archive"])
    return FileResponse(
        archive_path,
        media_type="application/zip",
        filename=archive_path.name,
    )


@app.post("/api/modules/import")
def import_module_archive(body: dict[str, Any]) -> dict[str, Any]:
    try:
        return module_store.import_module_archive(str(body.get("archive_path", "")))
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={"code": "archive_not_found", "message": "Module archive was not found"},
        ) from None
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": str(exc), "message": str(exc)},
        ) from None


@app.post("/api/modules/import-file")
async def import_module_file(file: UploadFile = File(...)) -> dict[str, Any]:
    filename = _safe_upload_filename(file.filename or "module.sfpmod.zip")
    temp_dir = module_store.packages_dir / "_imports"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / f"{uuid.uuid4().hex}-{filename}"
    content = await file.read()
    temp_path.write_bytes(content)
    try:
        return module_store.import_module_archive(temp_path)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={"code": "archive_not_found", "message": "Module archive was not found"},
        ) from None
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": str(exc), "message": str(exc)},
        ) from None
    finally:
        temp_path.unlink(missing_ok=True)


@app.get("/api/modules/knowledge")
def list_module_knowledge() -> dict[str, Any]:
    return module_store.list_knowledge()


@app.get("/api/modules/{module_id}/skill")
def get_module_skill(module_id: str) -> dict[str, Any]:
    try:
        return module_store.get_module_skill(module_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "module_not_found", "message": "Module was not found"},
        ) from None


@app.get("/api/modules/{module_id}")
def get_module_detail(module_id: str) -> dict[str, Any]:
    try:
        return module_store.get_module_detail(module_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "module_not_found", "message": "Module was not found"},
        ) from None


@app.post("/api/sessions/{session_id}/run")
def run_workflow(session_id: str) -> dict[str, Any]:
    registry = _current_registry()
    session = _get_session_or_404(session_id)
    if session.get("workflow") is None:
        raise HTTPException(
            status_code=400,
            detail={"code": "missing_workflow", "message": "Session workflow is not configured"},
        )

    workflow = WorkflowDefinition.from_dict(session["workflow"])
    context = {
        "sample_path": session["sample"]["stored_path"],
        "filename": session["sample"]["filename"],
        "results": {},
        "config": config_store.load_config(),
    }
    store.clear_raw_output(session_id)
    store.clear_ai_output(session_id)

    function_names = {item["id"]: item["name"] for item in registry.list_functions()}
    runner.run(
        registry,
        workflow,
        context,
        on_step_result=lambda index, result: store.append_raw_output_step(
            session_id,
            index,
            result.to_dict(),
            function_names.get(result.function_id, result.function_id),
        ),
    )
    session = store.save_run_outputs(session_id, context)
    ai_output = sort_raw_outputs(store.get_raw_output(session_id))
    store.save_ai_output(session_id, ai_output)
    session["ai_output"] = ai_output
    return session


@app.get("/api/sessions/{session_id}/raw-output")
def get_raw_output(session_id: str) -> dict[str, Any]:
    _get_session_or_404(session_id)
    return store.get_raw_output(session_id)


@app.get("/api/sessions/{session_id}/raw-output-map")
def get_raw_output_map(session_id: str) -> dict[str, Any]:
    _get_session_or_404(session_id)
    return store.get_raw_output_map(session_id)


@app.get("/api/sessions/{session_id}/raw-output/{raw_output_id}")
def get_raw_output_by_id(session_id: str, raw_output_id: str) -> dict[str, Any]:
    _get_session_or_404(session_id)
    try:
        return store.get_raw_output_item(session_id, raw_output_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "raw_output_not_found", "message": "Raw output was not found"},
        ) from None


@app.post("/api/sessions/{session_id}/functions/run")
def run_session_function(session_id: str, body: dict[str, Any]) -> dict[str, Any]:
    registry = _current_registry()
    session = _get_session_or_404(session_id)
    function_id = str(body.get("function_id", ""))
    try:
        function_info = registry.get(function_id).info()
    except KeyError:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "unknown_function",
                "function_id": function_id,
                "message": f"Unknown function: {function_id}",
            },
        ) from None

    context = {
        "sample_path": session["sample"]["stored_path"],
        "filename": session["sample"]["filename"],
        "results": dict(session.get("raw_outputs") or {}),
        "config": config_store.load_config(),
    }
    result = registry.run(function_id, context, dict(body.get("params") or {}))
    result_dict = result.to_dict()
    context.setdefault("results", {})[result.result_key] = result_dict
    next_index = len(store.get_raw_output(session_id).get("items", [])) + 1
    raw_output = store.append_raw_output_step(
        session_id,
        next_index,
        result_dict,
        str(function_info.get("name") or function_id),
    )
    raw_output_item = raw_output["items"][-1]
    ai_output_item = sort_raw_output_item(raw_output_item)
    store.append_ai_output_item(session_id, ai_output_item)
    session = store.save_run_outputs(session_id, context)
    return {
        "result": result_dict,
        "summary": session["summary"],
        "ai_output_item": ai_output_item,
    }


@app.get("/api/sessions/{session_id}/result")
def get_session_result(session_id: str) -> dict[str, Any]:
    _get_session_or_404(session_id)
    return store.get_session_result(session_id)


@app.post("/api/sessions/{session_id}/result")
def save_session_result(session_id: str, body: dict[str, Any]) -> dict[str, Any]:
    _get_session_or_404(session_id)
    return store.save_session_result(session_id, body)


@app.get("/api/sessions/{session_id}/ai-output")
def get_ai_output(session_id: str) -> dict[str, Any]:
    _get_session_or_404(session_id)
    return store.get_ai_output(session_id)


@app.get("/api/sessions/{session_id}/ai-output/{raw_output_id}")
def get_ai_output_by_raw_id(session_id: str, raw_output_id: str) -> dict[str, Any]:
    _get_session_or_404(session_id)
    try:
        return store.get_ai_output_item(session_id, raw_output_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "ai_output_not_found", "message": "AI output was not found"},
        ) from None


def _get_session_or_404(session_id: str) -> dict[str, Any]:
    try:
        return store.get_session(session_id)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={"code": "session_not_found", "message": "Session was not found"},
        ) from None


def _current_registry(exclude_module_id: str | None = None) -> FunctionRegistry:
    registry = create_builtin_registry()
    for fn in module_store.load_function_instances(exclude_module_id=exclude_module_id):
        registry.register(fn)
    return registry


def _safe_upload_filename(filename: str) -> str:
    name = Path(filename).name
    safe = "".join(char if char.isalnum() or char in {"_", "-", "."} else "_" for char in name)
    return safe or "module.sfpmod.zip"


def _web_file(filename: str) -> FileResponse:
    path = _WEB_DIR / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail={"code": "web_not_found"})
    return FileResponse(path)
