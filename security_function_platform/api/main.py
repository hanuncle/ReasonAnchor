from __future__ import annotations

from pathlib import Path
from typing import Any
import threading
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


@app.get("/module-page.html")
def module_page() -> FileResponse:
    return _web_file("module-page.html")


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
    metadata = _workflow_metadata_from_body(body)
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
    metadata = _workflow_metadata_from_body(body)
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


def _workflow_metadata_from_body(body: dict[str, Any]) -> dict[str, Any]:
    workflow_body = body.get("workflow", {})
    if not isinstance(workflow_body, dict):
        workflow_body = {}
    return {
        "description": body.get("description", workflow_body.get("description", "")),
        "tags": body.get("tags", workflow_body.get("tags", [])),
        "risk": body.get("risk", workflow_body.get("risk", "low")),
        "network": body.get("network", workflow_body.get("network", False)),
        "config_required": body.get(
            "config_required",
            workflow_body.get("config_required", False),
        ),
        "default_safe": body.get("default_safe", workflow_body.get("default_safe", False)),
    }


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


@app.get("/api/modules/{module_id}/ui")
def get_module_ui(module_id: str) -> dict[str, Any]:
    try:
        return module_store.get_module_ui(module_id)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "module_not_found", "message": "Module was not found"},
        ) from None


@app.get("/api/modules/{module_id}/knowledge/{knowledge_type}")
def get_module_knowledge(module_id: str, knowledge_type: str) -> dict[str, Any]:
    try:
        return module_store.get_module_knowledge(module_id, knowledge_type)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "module_not_found", "message": "Module was not found"},
        ) from None
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "knowledge_file_not_found",
                "message": "Module knowledge file was not found",
            },
        ) from None
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail={"code": str(exc), "message": str(exc)},
        ) from None


@app.put("/api/modules/{module_id}/ui/pages/{page_id}")
def upsert_module_ui_page(module_id: str, page_id: str, body: dict[str, Any]) -> dict[str, Any]:
    try:
        return module_store.upsert_module_ui_page(
            module_id,
            page_id,
            str(body.get("title") or ""),
            str(body.get("type") or "knowledge_table"),
            str(body.get("knowledge_type") or ""),
            str(body.get("description") or ""),
            body.get("columns") if isinstance(body.get("columns"), list) else [],
        )
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "module_not_found", "message": "Module was not found"},
        ) from None
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={"code": "module_json_not_found", "message": "Module manifest was not found"},
        ) from None
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": str(exc), "message": str(exc)},
        ) from None


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
    return _run_session_workflow(session_id, registry)


@app.post("/api/batches/run")
def run_batch_workflow(body: dict[str, Any]) -> dict[str, Any]:
    create_report = bool(body.get("create_report", True))
    session_ids, workflow_id, workflow, registry = _prepare_batch_request(body)
    return _run_batch_workflow_sync(
        session_ids,
        workflow_id,
        workflow,
        registry,
        create_report,
        str(uuid.uuid4()),
    )


@app.post("/api/batches/jobs")
def submit_batch_workflow_job(body: dict[str, Any]) -> dict[str, Any]:
    create_report = bool(body.get("create_report", True))
    session_ids, workflow_id, _workflow, _registry = _prepare_batch_request(body)
    job = store.create_batch_job(session_ids, workflow_id, create_report)
    thread = threading.Thread(
        target=_run_batch_job_worker,
        args=(str(job["job_id"]),),
        name=f"sfp-batch-{job['job_id']}",
        daemon=True,
    )
    thread.start()
    return store.get_batch_job(str(job["job_id"]))


@app.get("/api/batches/jobs")
def list_batch_jobs() -> dict[str, Any]:
    return store.list_batch_jobs()


@app.get("/api/batches/jobs/{job_id}")
def get_batch_job(job_id: str) -> dict[str, Any]:
    try:
        return store.get_batch_job(job_id)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={"code": "batch_job_not_found", "message": "Batch job was not found"},
        ) from None


@app.get("/api/reports")
def list_sample_set_reports() -> dict[str, Any]:
    return store.list_sample_set_reports()


@app.get("/api/reports/{report_id}")
def get_sample_set_report(report_id: str) -> dict[str, Any]:
    try:
        return store.get_sample_set_report(report_id)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={"code": "report_not_found", "message": "Report was not found"},
        ) from None


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


def _prepare_batch_request(
    body: dict[str, Any],
) -> tuple[list[str], str, WorkflowDefinition | None, FunctionRegistry]:
    session_ids = _string_list(body.get("session_ids"))
    if not session_ids:
        raise HTTPException(
            status_code=400,
            detail={"code": "missing_session_ids", "message": "session_ids is required"},
        )

    workflow_id = str(body.get("workflow_id") or "")
    workflow = _workflow_from_template(workflow_id) if workflow_id else None
    registry = _current_registry()
    if workflow is not None:
        validation_errors = runner.validate(registry, workflow)
        if validation_errors:
            raise HTTPException(status_code=400, detail={"errors": validation_errors})
    return session_ids, workflow_id, workflow, registry


def _run_batch_workflow_sync(
    session_ids: list[str],
    workflow_id: str,
    workflow: WorkflowDefinition | None,
    registry: FunctionRegistry,
    create_report: bool,
    batch_id: str,
) -> dict[str, Any]:
    items = [
        _run_batch_session_item(session_id, workflow, registry, batch_index=index)
        for index, session_id in enumerate(session_ids)
    ]
    report = _build_sample_set_report(batch_id, session_ids, workflow_id, items)
    saved_report = store.save_sample_set_report(report) if create_report else report
    return {
        "batch_id": batch_id,
        "status": "completed",
        "count": len(items),
        "items": items,
        "report_id": saved_report.get("report_id", ""),
        "report": saved_report,
    }


def _run_batch_session_item(
    session_id: str,
    workflow: WorkflowDefinition | None,
    registry: FunctionRegistry,
    batch_index: int | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {"session_id": session_id}
    try:
        if workflow is not None:
            store.set_workflow(session_id, workflow)
        completed = _run_session_workflow(session_id, registry, batch_index=batch_index)
        item.update(
            {
                "status": str(completed.get("summary", {}).get("status") or "completed"),
                "sample": completed.get("sample", {}),
                "summary": completed.get("summary", {}),
            }
        )
    except HTTPException as exc:
        item.update(
            {
                "status": "error",
                "error": exc.detail
                if isinstance(exc.detail, dict)
                else {"code": "run_failed", "message": str(exc.detail)},
            }
        )
    except Exception as exc:  # pragma: no cover - defensive job isolation
        item.update(
            {
                "status": "error",
                "error": {"code": "run_failed", "message": str(exc)},
            }
        )
    return item


def _run_batch_job_worker(job_id: str) -> None:
    try:
        job = store.get_batch_job(job_id)
        job["status"] = "running"
        job["started_at"] = SessionStore._now()
        job["current_session_id"] = ""
        job = store.save_batch_job(job)

        session_ids = _string_list(job.get("session_ids"))
        workflow_id = str(job.get("workflow_id") or "")
        workflow = _workflow_from_template(workflow_id) if workflow_id else None
        registry = _current_registry()

        for index, session_id in enumerate(session_ids):
            job = store.get_batch_job(job_id)
            job["status"] = "running"
            job["current_session_id"] = session_id
            _replace_batch_job_item(
                job,
                session_id,
                {"session_id": session_id, "status": "running"},
            )
            store.save_batch_job(job)

            item = _run_batch_session_item(session_id, workflow, registry, batch_index=index)
            job = store.get_batch_job(job_id)
            _replace_batch_job_item(job, session_id, item)
            _update_batch_job_counts(job)
            store.save_batch_job(job)

        job = store.get_batch_job(job_id)
        report = _build_sample_set_report(job_id, session_ids, workflow_id, job.get("items", []))
        create_report = bool(job.get("create_report", True))
        saved_report = store.save_sample_set_report(report) if create_report else report
        job["status"] = "completed"
        job["current_session_id"] = ""
        job["completed_at"] = SessionStore._now()
        job["report_id"] = str(saved_report.get("report_id") or "")
        job["report"] = saved_report
        _update_batch_job_counts(job)
        store.save_batch_job(job)
    except Exception as exc:  # pragma: no cover - keeps background failures observable
        try:
            job = store.get_batch_job(job_id)
        except FileNotFoundError:
            job = {"job_id": job_id, "batch_id": job_id}
        job["status"] = "error"
        job["current_session_id"] = ""
        job["completed_at"] = SessionStore._now()
        job["error"] = {"code": "batch_job_failed", "message": str(exc)}
        store.save_batch_job(job)


def _replace_batch_job_item(job: dict[str, Any], session_id: str, item: dict[str, Any]) -> None:
    items = job.get("items")
    if not isinstance(items, list):
        items = []
        job["items"] = items
    for index, existing in enumerate(items):
        if isinstance(existing, dict) and existing.get("session_id") == session_id:
            merged = dict(existing)
            merged.update(item)
            items[index] = merged
            return
    items.append(item)


def _update_batch_job_counts(job: dict[str, Any]) -> None:
    items = [item for item in job.get("items", []) if isinstance(item, dict)]
    job["count"] = len(items)
    job["completed_count"] = sum(1 for item in items if item.get("status") == "completed")
    job["failed_count"] = sum(1 for item in items if item.get("status") == "error")


def _run_session_workflow(
    session_id: str,
    registry: FunctionRegistry,
    batch_index: int | None = None,
) -> dict[str, Any]:
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
    if batch_index is not None:
        context["batch_index"] = batch_index
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
    completed = store.save_run_outputs(session_id, context)
    ai_output = sort_raw_outputs(store.get_raw_output(session_id))
    store.save_ai_output(session_id, ai_output)
    completed["ai_output"] = ai_output
    return completed


def _workflow_from_template(workflow_id: str) -> WorkflowDefinition:
    try:
        data = workflow_store.get_workflow(workflow_id)
    except KeyError:
        try:
            data = module_store.get_workflow(workflow_id)
        except KeyError:
            raise HTTPException(
                status_code=404,
                detail={"code": "workflow_not_found", "message": "Workflow was not found"},
            ) from None
    return WorkflowDefinition.from_dict(data["workflow"])


def _build_sample_set_report(
    batch_id: str,
    session_ids: list[str],
    workflow_id: str,
    batch_items: list[dict[str, Any]],
) -> dict[str, Any]:
    samples = [_sample_report_item(item) for item in batch_items]
    completed_samples = [sample for sample in samples if sample.get("status") == "completed"]
    sample_facts = [_sample_fact(sample) for sample in samples]
    completed_facts = [fact for fact in sample_facts if fact.get("status") == "completed"]
    behavior_catalog = _behavior_taxonomy_catalog()
    attack_catalog = _attack_knowledge_catalog()
    behavior_matrix = _behavior_matrix(completed_facts, behavior_catalog, attack_catalog)
    attack_matrix = _attack_matrix(completed_facts, attack_catalog)
    validation_status = _validation_status(completed_facts)
    knowledge_links = _reverse_knowledge_links()
    behavior_counts = _count_values(
        behavior["category_id"]
        for behavior in behavior_matrix
        for _sample in behavior.get("samples", [])
    )
    technique_counts = _count_values(
        technique["technique_id"]
        for technique in attack_matrix
        for _sample in technique.get("samples", [])
    )
    report = {
        "report_id": str(uuid.uuid4()),
        "schema_id": "sample_set.report.v2",
        "batch_id": batch_id,
        "created_at": SessionStore._now(),
        "workflow_id": workflow_id,
        "session_ids": session_ids,
        "knowledge_links": knowledge_links,
        "summary": {
            "sample_count": len(samples),
            "completed": len(completed_samples),
            "failed": sum(1 for sample in samples if sample.get("status") == "error"),
            "behavior_categories": sorted(behavior_counts),
            "behavior_category_count": len(behavior_counts),
            "common_behavior_categories": sorted(
                category
                for category, count in behavior_counts.items()
                if completed_samples and count == len(completed_samples)
            ),
            "repeated_behavior_categories": sorted(
                category for category, count in behavior_counts.items() if count >= 2
            ),
            "attack_techniques": sorted(technique_counts),
            "attack_technique_count": len(technique_counts),
            "validation_status": validation_status,
            "knowledge_links": knowledge_links,
        },
        "common_analysis_points": _common_analysis_points(
            workflow_id,
            behavior_matrix,
            len(completed_samples),
        ),
        "differential_analysis_points": _differential_analysis_points(
            sample_facts,
            behavior_counts,
            technique_counts,
        ),
        "sample_facts": sample_facts,
        "behavior_matrix": behavior_matrix,
        "attack_matrix": attack_matrix,
        "samples": samples,
    }
    report["markdown"] = _sample_set_report_markdown(report)
    return report


def _sample_report_item(batch_item: dict[str, Any]) -> dict[str, Any]:
    session_id = str(batch_item.get("session_id") or "")
    if batch_item.get("status") == "error":
        return {
            "session_id": session_id,
            "status": "error",
            "error": batch_item.get("error", {}),
            "behavior_categories": [],
            "attack_techniques": [],
        }

    try:
        session = store.get_session(session_id)
    except FileNotFoundError:
        return {
            "session_id": session_id,
            "status": "error",
            "error": {"code": "session_not_found"},
            "behavior_categories": [],
            "attack_techniques": [],
        }

    final_result = store.get_session_result(session_id)
    raw_outputs = session.get("raw_outputs") if isinstance(session.get("raw_outputs"), dict) else {}
    final_behaviors = final_result.get("behaviors", [])
    behavior_categories = _behavior_categories_from_final(final_behaviors)
    if not behavior_categories:
        behavior_categories = _behavior_categories_from_raw(raw_outputs)
    attack_techniques = _attack_techniques_from_final(final_behaviors)
    if not attack_techniques:
        attack_techniques = _attack_techniques_from_raw(raw_outputs)
    iocs = _iocs_from_raw(raw_outputs)
    evidence_sources = _behavior_evidence_sources(final_behaviors, raw_outputs)
    file_info = dict(final_result.get("file") if isinstance(final_result.get("file"), dict) else {})
    file_info.setdefault("filename", session.get("sample", {}).get("filename", ""))
    file_info.setdefault("size", session.get("sample", {}).get("size", 0))
    hash_result = raw_outputs.get("hash") if isinstance(raw_outputs, dict) else {}
    hash_data = hash_result.get("data", {}) if isinstance(hash_result, dict) else {}
    if isinstance(hash_data, dict):
        file_info.setdefault("sha256", hash_data.get("sha256", ""))

    return {
        "session_id": session_id,
        "status": str(session.get("summary", {}).get("status") or "unknown"),
        "file": file_info,
        "summary": session.get("summary", {}),
        "final_result_available": bool(final_behaviors),
        "behavior_categories": sorted(set(behavior_categories)),
        "behaviors": _compact_behaviors(final_behaviors, raw_outputs),
        "attack_techniques": attack_techniques,
        "iocs": iocs,
        "evidence_sources": evidence_sources,
        "validation_status": _sample_validation_status(final_behaviors, raw_outputs),
        "result_keys": _string_list(session.get("summary", {}).get("result_keys")),
        "error_count": _safe_int(session.get("summary", {}).get("error_count")),
    }


def _sample_fact(sample: dict[str, Any]) -> dict[str, Any]:
    file_info = sample.get("file") if isinstance(sample.get("file"), dict) else {}
    techniques = [
        str(item.get("technique_id") or "")
        for item in sample.get("attack_techniques", [])
        if isinstance(item, dict) and str(item.get("technique_id") or "")
    ]
    return {
        "session_id": str(sample.get("session_id") or ""),
        "status": str(sample.get("status") or ""),
        "filename": str(file_info.get("filename") or ""),
        "sha256": str(file_info.get("sha256") or ""),
        "size": file_info.get("size", 0),
        "behavior_categories": _string_list(sample.get("behavior_categories")),
        "attack_techniques": sorted(set(techniques)),
        "iocs": sample.get("iocs", {}) if isinstance(sample.get("iocs"), dict) else {},
        "evidence_sources": (
            sample.get("evidence_sources")
            if isinstance(sample.get("evidence_sources"), dict)
            else {}
        ),
        "validation_status": str(sample.get("validation_status") or "not_run"),
        "result_keys": _string_list(sample.get("result_keys")),
        "error_count": _safe_int(sample.get("error_count")),
    }


def _behavior_categories_from_final(behaviors: Any) -> list[str]:
    if not isinstance(behaviors, list):
        return []
    return [
        str(item.get("category") or item.get("behavior") or "")
        for item in behaviors
        if isinstance(item, dict) and str(item.get("category") or item.get("behavior") or "")
    ]


def _behavior_categories_from_raw(raw_outputs: Any) -> list[str]:
    if not isinstance(raw_outputs, dict):
        return []
    categories: list[str] = []
    for key in ["static_behavior_map", "dynamic_behavior_map"]:
        result = raw_outputs.get(key)
        data = result.get("data", {}) if isinstance(result, dict) else {}
        behaviors = data.get("behaviors", []) if isinstance(data, dict) else []
        if isinstance(behaviors, list):
            categories.extend(
                str(item.get("category") or item.get("behavior_id") or "")
                for item in behaviors
                if isinstance(item, dict)
                and str(item.get("category") or item.get("behavior_id") or "")
            )
    return categories


def _attack_techniques_from_final(behaviors: Any) -> list[dict[str, str]]:
    if not isinstance(behaviors, list):
        return []
    techniques: dict[str, dict[str, str]] = {}
    for behavior in behaviors:
        if not isinstance(behavior, dict):
            continue
        for technique in behavior.get("attack_techniques", []):
            if not isinstance(technique, dict):
                continue
            technique_id = str(technique.get("technique_id") or "")
            if not technique_id:
                continue
            techniques.setdefault(
                technique_id,
                {
                    "technique_id": technique_id,
                    "technique_name": str(technique.get("technique_name") or ""),
                    "tactic": str(technique.get("tactic") or ""),
                },
            )
    return sorted(techniques.values(), key=lambda item: item["technique_id"])


def _attack_techniques_from_raw(raw_outputs: Any) -> list[dict[str, str]]:
    if not isinstance(raw_outputs, dict):
        return []
    result = raw_outputs.get("attack_mapping")
    data = result.get("data", {}) if isinstance(result, dict) else {}
    techniques = data.get("techniques", []) if isinstance(data, dict) else []
    if not isinstance(techniques, list):
        return []
    by_id: dict[str, dict[str, str]] = {}
    for item in techniques:
        if not isinstance(item, dict):
            continue
        technique_id = str(item.get("technique_id") or "")
        if not technique_id:
            continue
        tactic = item.get("tactic", [])
        by_id.setdefault(
            technique_id,
            {
                "technique_id": technique_id,
                "technique_name": str(item.get("name") or ""),
                "tactic": ", ".join(_string_list(tactic)),
            },
        )
    return sorted(by_id.values(), key=lambda item: item["technique_id"])


def _compact_behaviors(behaviors: Any, raw_outputs: Any) -> list[dict[str, Any]]:
    if isinstance(behaviors, list) and behaviors:
        return [
            {
                "behavior": str(item.get("behavior") or ""),
                "category": str(item.get("category") or ""),
                "confidence": str(item.get("confidence") or ""),
                "verification": str(item.get("verification") or ""),
            }
            for item in behaviors
            if isinstance(item, dict)
        ]
    if not isinstance(raw_outputs, dict):
        return []
    compact: list[dict[str, Any]] = []
    for key in ["static_behavior_map", "dynamic_behavior_map"]:
        result = raw_outputs.get(key)
        data = result.get("data", {}) if isinstance(result, dict) else {}
        raw_behaviors = data.get("behaviors", []) if isinstance(data, dict) else []
        if not isinstance(raw_behaviors, list):
            continue
        for item in raw_behaviors:
            if not isinstance(item, dict):
                continue
            compact.append(
                {
                    "behavior": str(item.get("name") or ""),
                    "category": str(item.get("category") or item.get("behavior_id") or ""),
                    "confidence": str(item.get("confidence") or ""),
                    "verification": str(item.get("verification") or ""),
                    "source_result": key,
                }
            )
    return compact


def _iocs_from_raw(raw_outputs: Any) -> dict[str, list[str]]:
    if not isinstance(raw_outputs, dict):
        return {}
    result = raw_outputs.get("ioc_extractor")
    data = result.get("data", {}) if isinstance(result, dict) else {}
    if not isinstance(data, dict):
        return {}
    return {
        "urls": sorted(set(_string_list(data.get("urls")))),
        "domains": sorted(set(_string_list(data.get("domains")))),
        "ipv4": sorted(set(_string_list(data.get("ipv4")))),
        "registry_keys": sorted(set(_string_list(data.get("registry_keys")))),
        "windows_paths": sorted(set(_string_list(data.get("windows_paths")))),
    }


def _behavior_evidence_sources(behaviors: Any, raw_outputs: Any) -> dict[str, list[str]]:
    sources: dict[str, set[str]] = {}
    if isinstance(behaviors, list):
        for behavior in behaviors:
            if not isinstance(behavior, dict):
                continue
            category = str(behavior.get("category") or behavior.get("behavior") or "")
            if not category:
                continue
            sources.setdefault(category, set()).add("final_result")
            evidence = behavior.get("evidence", {})
            evidence_sources = evidence.get("sources", []) if isinstance(evidence, dict) else []
            if isinstance(evidence_sources, list):
                for item in evidence_sources:
                    if isinstance(item, dict):
                        function_id = str(item.get("function_id") or item.get("result_key") or "")
                        if function_id:
                            sources[category].add(function_id)
    if isinstance(raw_outputs, dict):
        for result_key in ["static_behavior_map", "dynamic_behavior_map"]:
            result = raw_outputs.get(result_key)
            data = result.get("data", {}) if isinstance(result, dict) else {}
            behaviors_from_raw = data.get("behaviors", []) if isinstance(data, dict) else []
            if not isinstance(behaviors_from_raw, list):
                continue
            for behavior in behaviors_from_raw:
                if not isinstance(behavior, dict):
                    continue
                category = str(behavior.get("category") or behavior.get("behavior_id") or "")
                if category:
                    sources.setdefault(category, set()).add(result_key)
    return {category: sorted(values) for category, values in sorted(sources.items())}


def _sample_validation_status(behaviors: Any, raw_outputs: Any) -> str:
    if isinstance(raw_outputs, dict) and _raw_behavior_count(raw_outputs, "dynamic_behavior_map"):
        return "dynamic_confirmed"
    if isinstance(behaviors, list):
        values = {
            str(item.get("verification") or "")
            for item in behaviors
            if isinstance(item, dict) and item.get("verification")
        }
        if any("dynamic" in value and "confirm" in value for value in values):
            return "dynamic_confirmed"
        if any("contradict" in value or "mismatch" in value for value in values):
            return "dynamic_contradicted"
        if values:
            return "static_only"
    if isinstance(raw_outputs, dict) and _raw_behavior_count(raw_outputs, "static_behavior_map"):
        return "static_only"
    return "not_run"


def _raw_behavior_count(raw_outputs: dict[str, Any], result_key: str) -> int:
    result = raw_outputs.get(result_key)
    data = result.get("data", {}) if isinstance(result, dict) else {}
    behaviors = data.get("behaviors", []) if isinstance(data, dict) else []
    return len(behaviors) if isinstance(behaviors, list) else 0


def _behavior_taxonomy_catalog() -> dict[str, dict[str, Any]]:
    try:
        knowledge = module_store.get_module_knowledge("reverse", "behavior_taxonomy")
    except (KeyError, FileNotFoundError, ValueError):
        return {}
    data = knowledge.get("data", {})
    categories = data.get("categories", []) if isinstance(data, dict) else []
    catalog: dict[str, dict[str, Any]] = {}
    if not isinstance(categories, list):
        return catalog
    for item in categories:
        if not isinstance(item, dict):
            continue
        category_id = str(item.get("id") or "")
        if not category_id:
            continue
        catalog[category_id] = {
            "category_id": category_id,
            "name": str(item.get("name") or category_id),
            "description": str(item.get("description") or ""),
            "attack_techniques": _string_list(item.get("attack_techniques")),
        }
    return catalog


def _attack_knowledge_catalog() -> dict[str, dict[str, Any]]:
    try:
        knowledge = module_store.get_module_knowledge("reverse", "attack_techniques")
    except (KeyError, FileNotFoundError, ValueError):
        return {}
    data = knowledge.get("data", {})
    techniques = data.get("techniques", []) if isinstance(data, dict) else []
    catalog: dict[str, dict[str, Any]] = {}
    if not isinstance(techniques, list):
        return catalog
    for item in techniques:
        if not isinstance(item, dict):
            continue
        technique_id = str(item.get("technique_id") or "")
        if not technique_id:
            continue
        catalog[technique_id] = {
            "technique_id": technique_id,
            "name": str(item.get("name") or technique_id),
            "tactic": _string_list(item.get("tactic")),
            "behavior_categories": _string_list(item.get("behavior_categories")),
            "analysis_methods": _string_list(item.get("analysis_methods")),
            "detection_methods": _string_list(item.get("detection_methods")),
            "validation_samples": _string_list(item.get("validation_samples")),
        }
    return catalog


def _behavior_matrix(
    sample_facts: list[dict[str, Any]],
    behavior_catalog: dict[str, dict[str, Any]],
    attack_catalog: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    completed_count = len(sample_facts)
    for fact in sample_facts:
        for category in _string_list(fact.get("behavior_categories")):
            catalog_item = behavior_catalog.get(category, {})
            row = rows.setdefault(
                category,
                {
                    "category_id": category,
                    "name": str(catalog_item.get("name") or category),
                    "description": str(catalog_item.get("description") or ""),
                    "sample_count": 0,
                    "sample_ratio": 0.0,
                    "samples": [],
                    "attack_techniques": set(_string_list(catalog_item.get("attack_techniques"))),
                    "evidence_summary": {
                        "static": 0,
                        "dynamic": 0,
                        "final": 0,
                        "unknown": 0,
                    },
                    "representative_evidence": [],
                    "knowledge_link": _module_page_url("behavior_taxonomy"),
                },
            )
            row["sample_count"] += 1
            sources = _string_list(
                fact.get("evidence_sources", {}).get(category)
                if isinstance(fact.get("evidence_sources"), dict)
                else []
            )
            source_kind = _source_kind(sources)
            row["evidence_summary"][source_kind] = row["evidence_summary"].get(source_kind, 0) + 1
            for technique_id in _string_list(fact.get("attack_techniques")):
                technique = attack_catalog.get(technique_id, {})
                if category in _string_list(technique.get("behavior_categories")):
                    row["attack_techniques"].add(technique_id)
            row["samples"].append(
                {
                    "session_id": fact.get("session_id", ""),
                    "filename": fact.get("filename", ""),
                    "sha256": fact.get("sha256", ""),
                    "validation_status": fact.get("validation_status", "not_run"),
                    "evidence_sources": sources,
                    "iocs": fact.get("iocs", {}),
                }
            )
            if len(row["representative_evidence"]) < 3:
                row["representative_evidence"].append(
                    {
                        "session_id": fact.get("session_id", ""),
                        "filename": fact.get("filename", ""),
                        "sources": sources,
                        "validation_status": fact.get("validation_status", "not_run"),
                    }
                )
    normalized: list[dict[str, Any]] = []
    for row in rows.values():
        row["sample_ratio"] = round(
            row["sample_count"] / completed_count,
            4,
        ) if completed_count else 0.0
        row["attack_techniques"] = [
            _attack_ref(technique_id, attack_catalog)
            for technique_id in sorted(row["attack_techniques"])
        ]
        normalized.append(row)
    return sorted(
        normalized,
        key=lambda item: (-int(item["sample_count"]), str(item["category_id"])),
    )


def _attack_matrix(
    sample_facts: list[dict[str, Any]],
    attack_catalog: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for fact in sample_facts:
        for technique_id in _string_list(fact.get("attack_techniques")):
            catalog_item = attack_catalog.get(technique_id, {})
            row = rows.setdefault(
                technique_id,
                {
                    "technique_id": technique_id,
                    "name": str(catalog_item.get("name") or technique_id),
                    "tactic": _string_list(catalog_item.get("tactic")),
                    "behavior_categories": set(
                        _string_list(catalog_item.get("behavior_categories"))
                    ),
                    "analysis_methods": _string_list(catalog_item.get("analysis_methods")),
                    "detection_methods": _string_list(catalog_item.get("detection_methods")),
                    "validation_samples": _string_list(catalog_item.get("validation_samples")),
                    "sample_count": 0,
                    "samples": [],
                    "knowledge_link": _module_page_url("attack_knowledge"),
                },
            )
            row["sample_count"] += 1
            for category in _string_list(fact.get("behavior_categories")):
                row["behavior_categories"].add(category)
            row["samples"].append(
                {
                    "session_id": fact.get("session_id", ""),
                    "filename": fact.get("filename", ""),
                    "sha256": fact.get("sha256", ""),
                    "validation_status": fact.get("validation_status", "not_run"),
                }
            )
    normalized: list[dict[str, Any]] = []
    for row in rows.values():
        row["behavior_categories"] = sorted(row["behavior_categories"])
        normalized.append(row)
    return sorted(
        normalized,
        key=lambda item: (-int(item["sample_count"]), str(item["technique_id"])),
    )


def _attack_ref(technique_id: str, attack_catalog: dict[str, dict[str, Any]]) -> dict[str, Any]:
    item = attack_catalog.get(technique_id, {})
    return {
        "technique_id": technique_id,
        "name": str(item.get("name") or technique_id),
        "tactic": _string_list(item.get("tactic")),
        "knowledge_link": _module_page_url("attack_knowledge"),
    }


def _validation_status(sample_facts: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "static_only": 0,
        "dynamic_confirmed": 0,
        "dynamic_contradicted": 0,
        "not_run": 0,
    }
    for fact in sample_facts:
        status = str(fact.get("validation_status") or "not_run")
        if status not in counts:
            status = "not_run"
        counts[status] += 1
    return counts


def _source_kind(sources: list[str]) -> str:
    lowered = " ".join(sources).lower()
    if "dynamic" in lowered:
        return "dynamic"
    if "static" in lowered or "strings" in lowered or "ioc" in lowered:
        return "static"
    if "final_result" in lowered:
        return "final"
    return "unknown"


def _common_analysis_points(
    workflow_id: str,
    behavior_matrix: list[dict[str, Any]],
    completed_count: int,
) -> list[str]:
    points = [
        "Use the same workflow and final-result schema across the sample set before comparing behavior categories.",
        "Treat static behavior and ATT&CK mappings as candidates until corroborated by dynamic telemetry or manual review.",
    ]
    if workflow_id:
        points.append(f"Batch workflow template: {workflow_id}.")
    behavior_counts = {
        str(item.get("category_id") or ""): _safe_int(item.get("sample_count"))
        for item in behavior_matrix
    }
    common = sorted(
        category
        for category, count in behavior_counts.items()
        if completed_count and count == completed_count
    )
    if common:
        points.append("Common behavior categories across all completed samples: " + ", ".join(common))
    repeated = sorted(category for category, count in behavior_counts.items() if count >= 2)
    if repeated and repeated != common:
        points.append("Repeated behavior categories across multiple samples: " + ", ".join(repeated))
    top_behaviors = [
        f"{item['category_id']}({item['sample_count']})"
        for item in behavior_matrix[:5]
        if item.get("category_id")
    ]
    if top_behaviors:
        points.append("Prioritize review by behavior frequency: " + ", ".join(top_behaviors))
    return points


def _differential_analysis_points(
    samples: list[dict[str, Any]],
    behavior_counts: dict[str, int],
    technique_counts: dict[str, int],
) -> list[dict[str, Any]]:
    points: list[dict[str, Any]] = []
    for sample in samples:
        categories = _string_list(sample.get("behavior_categories"))
        unique_categories = sorted(
            category for category in categories if behavior_counts.get(category) == 1
        )
        techniques = _string_list(sample.get("attack_techniques"))
        unique_techniques = sorted(
            technique for technique in techniques if technique_counts.get(technique) == 1
        )
        points.append(
            {
                "session_id": sample.get("session_id", ""),
                "filename": sample.get("filename", ""),
                "status": sample.get("status", ""),
                "unique_behavior_categories": unique_categories,
                "unique_attack_techniques": unique_techniques,
                "validation_status": sample.get("validation_status", "not_run"),
                "analysis_focus": _analysis_focus(
                    unique_categories,
                    unique_techniques,
                    sample,
                ),
            }
        )
    return points


def _analysis_focus(
    unique_categories: list[str],
    unique_techniques: list[str],
    sample: dict[str, Any],
) -> list[str]:
    if sample.get("status") == "error":
        return ["Fix the session workflow or input error before comparing this sample."]
    focus: list[str] = []
    if unique_categories:
        focus.extend(
            [
            "Review evidence for unique behavior categories: " + ", ".join(unique_categories),
            "Check whether unique categories are true sample behavior or analysis noise.",
            ]
        )
    if unique_techniques:
        focus.append("Review unique ATT&CK candidates: " + ", ".join(unique_techniques))
    if sample.get("validation_status") != "dynamic_confirmed":
        focus.append("Dynamic validation is not confirmed for this sample.")
    return focus or ["No unique behavior category was found in the current report inputs."]


def _reverse_knowledge_links() -> dict[str, str]:
    return {
        "behavior_taxonomy": _module_page_url("behavior_taxonomy"),
        "attack_knowledge": _module_page_url("attack_knowledge"),
        "validation_samples": _module_page_url("validation_samples"),
    }


def _module_page_url(page_id: str) -> str:
    return f"/module-page.html?module=reverse&page={page_id}"


def _sample_set_report_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    lines = [
        f"# Cross-sample Report {report.get('report_id', '')}",
        "",
        f"- Schema: {report.get('schema_id', '')}",
        f"- Workflow: {report.get('workflow_id', '')}",
        f"- Samples: {summary.get('sample_count', 0)}",
        f"- Completed: {summary.get('completed', 0)}",
        f"- Failed: {summary.get('failed', 0)}",
        f"- Behavior categories: {summary.get('behavior_category_count', 0)}",
        f"- ATT&CK techniques: {summary.get('attack_technique_count', 0)}",
        "",
        "## Common Analysis Points",
    ]
    lines.extend(f"- {point}" for point in _string_list(report.get("common_analysis_points")))
    lines.extend(["", "## Behavior Matrix"])
    for row in report.get("behavior_matrix", []):
        if not isinstance(row, dict):
            continue
        techniques = [
            str(item.get("technique_id") or "")
            for item in row.get("attack_techniques", [])
            if isinstance(item, dict)
        ]
        lines.append(
            f"- {row.get('category_id', '')}: {row.get('sample_count', 0)} samples; "
            f"ATT&CK: {', '.join(techniques)}"
        )
    lines.extend(["", "## Differential Analysis Points"])
    for point in report.get("differential_analysis_points", []):
        if not isinstance(point, dict):
            continue
        lines.append(
            f"- {point.get('filename') or point.get('session_id')}: "
            f"unique behaviors={', '.join(_string_list(point.get('unique_behavior_categories')))}; "
            f"unique ATT&CK={', '.join(_string_list(point.get('unique_attack_techniques')))}"
        )
    return "\n".join(lines) + "\n"


def _count_values(values: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        text = str(value or "")
        if not text:
            continue
        counts[text] = counts.get(text, 0) + 1
    return counts


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
