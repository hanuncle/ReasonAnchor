from security_function_platform.mcp_server import server


EXPECTED_TOOLS = {
    "upload_sample",
    "upload_samples",
    "list_functions",
    "save_custom_workflow",
    "list_custom_workflows",
    "list_modules",
    "get_module_template",
    "get_module_detail",
    "get_module_skill",
    "get_module_ui",
    "get_module_knowledge",
    "create_module",
    "load_module",
    "package_module",
    "export_module",
    "import_module_archive",
    "list_module_knowledge",
    "upsert_module_ui_page",
    "select_custom_workflow",
    "run_workflow",
    "run_batch_workflow",
    "submit_batch_workflow_job",
    "list_batch_jobs",
    "get_batch_job",
    "list_sample_set_reports",
    "get_sample_set_report",
    "get_raw_output_map",
    "get_raw_output_by_id",
    "get_ai_output",
    "get_ai_output_by_raw_id",
    "get_platform_skill",
    "run_function",
    "get_mcp_file_access_policy",
    "inspect_allowed_files",
    "write_allowed_file",
    "save_session_result",
}


def test_mcp_server_imports_and_exposes_tool_functions() -> None:
    assert {name for name in EXPECTED_TOOLS if hasattr(server, name)} == EXPECTED_TOOLS
    if hasattr(server.mcp, "_tools"):
        assert set(server.mcp._tools) == EXPECTED_TOOLS


def test_mcp_tools_call_http_helpers(monkeypatch, tmp_path) -> None:
    calls = []

    def fake_request(method, path, body=None):
        calls.append((method, path, body))
        if path.endswith("/functions/run"):
            return {
                "summary": {"status": "completed"},
                "ai_output_item": {"raw_output_id": "raw-002-hash"},
            }
        if path == "/api/batches/run":
            return {
                "batch_id": "batch",
                "items": [],
                "report_id": "report",
                "report": {"report_id": "report"},
            }
        if path == "/api/batches/jobs":
            return {"job_id": "job", "status": "queued"}
        if path == "/api/batches/jobs/job":
            return {"job_id": "job", "status": "completed"}
        if path.endswith("/run"):
            return {
                "session_id": "session",
                "summary": {"status": "completed"},
                "ai_output": {"session_id": "session", "items": [{"raw_output_id": "raw-001-hash"}]},
            }
        return {"ok": True, "path": path}

    def fake_upload(path, file_path):
        calls.append(("UPLOAD", path, file_path.name))
        return {"session_id": "demo"}

    def fake_uploads(path, file_paths):
        calls.append(("UPLOADS", path, [file_path.name for file_path in file_paths]))
        return {"sessions": [{"session_id": "demo-1"}, {"session_id": "demo-2"}], "count": 2}

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello")
    sample_two = tmp_path / "sample2.bin"
    sample_two.write_bytes(b"world")
    monkeypatch.setattr(server, "_request_json", fake_request)
    monkeypatch.setattr(server, "_upload_file", fake_upload)
    monkeypatch.setattr(server, "_upload_files", fake_uploads)

    assert server.upload_sample(str(sample)) == {"session_id": "demo"}
    assert server.upload_samples([str(sample), str(sample_two)])["count"] == 2
    assert server.list_functions()["path"] == "/api/functions"
    assert server.save_custom_workflow("basic", {"name": "basic", "steps": []})["ok"] is True
    assert server.list_custom_workflows()["path"] == "/api/workflows"
    assert server.list_modules()["path"] == "/api/modules"
    assert server.get_module_template()["path"] == "/api/modules/template"
    assert server.get_module_detail("reverse")["path"] == "/api/modules/reverse"
    assert server.get_module_skill("reverse")["path"] == "/api/modules/reverse/skill"
    assert server.get_module_ui("reverse")["path"] == "/api/modules/reverse/ui"
    assert server.get_module_knowledge("reverse", "attack_techniques")["path"] == (
        "/api/modules/reverse/knowledge/attack_techniques"
    )
    assert server.create_module("demo", "Demo", "0.1.0", "desc", {})["path"] == "/api/modules"
    assert server.load_module("reverse")["path"] == "/api/modules/reverse/load"
    assert server.package_module("reverse")["path"] == "/api/modules/reverse/package"
    assert server.export_module("reverse")["path"] == "/api/modules/reverse/export"
    assert server.import_module_archive("demo.sfpmod.zip")["path"] == "/api/modules/import"
    assert server.list_module_knowledge()["path"] == "/api/modules/knowledge"
    assert server.upsert_module_ui_page(
        "reverse",
        "attack_knowledge",
        "ATT&CK Knowledge",
        "knowledge_table",
        "attack_techniques",
        "ATT&CK mapped knowledge.",
        ["technique_id", "name"],
    )["path"] == "/api/modules/reverse/ui/pages/attack_knowledge"
    assert server.select_custom_workflow("session", "workflow")["path"] == (
        "/api/sessions/session/workflow-template"
    )
    assert server.run_workflow("session")["ai_output"]["items"][0]["raw_output_id"] == "raw-001-hash"
    assert server.run_batch_workflow(["session"], "workflow")["report_id"] == "report"
    assert server.submit_batch_workflow_job(["session"], "workflow")["job_id"] == "job"
    assert server.list_batch_jobs()["job_id"] == "job"
    assert server.get_batch_job("job")["status"] == "completed"
    assert server.list_sample_set_reports()["path"] == "/api/reports"
    assert server.get_sample_set_report("report")["path"] == "/api/reports/report"
    assert server.get_raw_output_map("session")["path"] == "/api/sessions/session/raw-output-map"
    assert server.get_raw_output_by_id("session", "raw-001-hash")["path"] == (
        "/api/sessions/session/raw-output/raw-001-hash"
    )
    assert server.get_ai_output("session")["path"] == "/api/sessions/session/ai-output"
    assert server.get_ai_output_by_raw_id("session", "raw-001-hash")["path"] == (
        "/api/sessions/session/ai-output/raw-001-hash"
    )
    assert server.run_function("session", "hash.compute", {})["ai_output_item"]["raw_output_id"] == "raw-002-hash"
    assert server.save_session_result("session", {"session_id": "session"})["path"] == (
        "/api/sessions/session/result"
    )

    assert calls == [
        ("UPLOAD", "/api/sessions/upload", "sample.bin"),
        ("UPLOADS", "/api/sessions/upload-multiple", ["sample.bin", "sample2.bin"]),
        ("GET", "/api/functions", None),
        ("POST", "/api/workflows", {"name": "basic", "workflow": {"name": "basic", "steps": []}}),
        ("GET", "/api/workflows", None),
        ("GET", "/api/modules", None),
        ("GET", "/api/modules/template", None),
        ("GET", "/api/modules/reverse", None),
        ("GET", "/api/modules/reverse/skill", None),
        ("GET", "/api/modules/reverse/ui", None),
        ("GET", "/api/modules/reverse/knowledge/attack_techniques", None),
        (
            "POST",
            "/api/modules",
            {
                "module_id": "demo",
                "name": "Demo",
                "version": "0.1.0",
                "description": "desc",
                "requirements": {},
            },
        ),
        ("POST", "/api/modules/reverse/load", None),
        ("POST", "/api/modules/reverse/package", None),
        ("POST", "/api/modules/reverse/export", None),
        ("POST", "/api/modules/import", {"archive_path": "demo.sfpmod.zip"}),
        ("GET", "/api/modules/knowledge", None),
        (
            "PUT",
            "/api/modules/reverse/ui/pages/attack_knowledge",
            {
                "title": "ATT&CK Knowledge",
                "type": "knowledge_table",
                "knowledge_type": "attack_techniques",
                "description": "ATT&CK mapped knowledge.",
                "columns": ["technique_id", "name"],
            },
        ),
        ("POST", "/api/sessions/session/workflow-template", {"workflow_id": "workflow"}),
        ("POST", "/api/sessions/session/run", None),
        (
            "POST",
            "/api/batches/run",
            {
                "session_ids": ["session"],
                "workflow_id": "workflow",
                "create_report": True,
            },
        ),
        (
            "POST",
            "/api/batches/jobs",
            {
                "session_ids": ["session"],
                "workflow_id": "workflow",
                "create_report": True,
            },
        ),
        ("GET", "/api/batches/jobs", None),
        ("GET", "/api/batches/jobs/job", None),
        ("GET", "/api/reports", None),
        ("GET", "/api/reports/report", None),
        ("GET", "/api/sessions/session/raw-output-map", None),
        ("GET", "/api/sessions/session/raw-output/raw-001-hash", None),
        ("GET", "/api/sessions/session/ai-output", None),
        ("GET", "/api/sessions/session/ai-output/raw-001-hash", None),
        (
            "POST",
            "/api/sessions/session/functions/run",
            {"function_id": "hash.compute", "params": {}},
        ),
        ("POST", "/api/sessions/session/result", {"session_id": "session"}),
    ]


def test_upload_sample_missing_file_returns_structured_error(tmp_path) -> None:
    result = server.upload_sample(str(tmp_path / "missing.bin"))

    assert result["status"] == "error"
    assert result["error"]["code"] == "file_not_found"


def test_upload_samples_missing_file_returns_structured_error(tmp_path) -> None:
    result = server.upload_samples([str(tmp_path / "missing.bin")])

    assert result["status"] == "error"
    assert result["error"]["code"] == "file_not_found"
