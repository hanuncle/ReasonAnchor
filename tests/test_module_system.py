import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from security_function_platform.api import main
from security_function_platform.api.session_store import SessionStore
from security_function_platform.module_system import ModuleStore

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVERSE_MODULE = PROJECT_ROOT / "modules" / "reverse" / "module.json"
VULN_SCAN_MODULE = PROJECT_ROOT / "modules" / "vuln_scan" / "module.json"
requires_local_example_modules = pytest.mark.skipif(
    not REVERSE_MODULE.is_file() or not VULN_SCAN_MODULE.is_file(),
    reason="local example modules are not included in this platform-only checkout",
)


@requires_local_example_modules
def test_module_store_discovers_modules_as_usable_by_default(tmp_path) -> None:
    store = ModuleStore("modules", tmp_path / "data" / "modules" / "loaded_modules.json")

    modules = store.list_modules()["modules"]
    module_ids = {item["module_id"] for item in modules}
    assert {"reverse", "vuln_scan"} <= module_ids
    assert all(item["loaded"] is True for item in modules)
    assert all(item["usable"] is True for item in modules)

    loaded = store.load_module("reverse")
    assert loaded["module_id"] == "reverse"
    assert loaded["loaded"] is True
    assert loaded["usable"] is True
    assert {"reverse", "vuln_scan"} <= {
        item["module_id"] for item in store.list_loaded_modules()
    }


@requires_local_example_modules
def test_loaded_module_workflows_are_exposed_and_selectable(tmp_path, monkeypatch) -> None:
    module_store = ModuleStore("modules", tmp_path / "data" / "modules" / "loaded_modules.json")
    session_store = SessionStore(tmp_path / "data" / "sessions")
    monkeypatch.setattr(main, "module_store", module_store)
    monkeypatch.setattr(main, "store", session_store)
    client = TestClient(main.app)

    workflows = client.get("/api/workflows").json()["workflows"]
    workflow_ids = {item["workflow_id"] for item in workflows}
    assert "module:reverse:reverse_basic" in workflow_ids

    workflow_response = client.get("/api/workflows/module:reverse:reverse_basic")
    assert workflow_response.status_code == 200
    assert workflow_response.json()["source"] == "module"
    assert workflow_response.json()["module_id"] == "reverse"

    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello")},
    ).json()
    apply_response = client.post(
        f"/api/sessions/{session['session_id']}/workflow-template",
        json={"workflow_id": "module:reverse:reverse_basic"},
    )
    assert apply_response.status_code == 200
    assert apply_response.json()["workflow"]["name"] == "reverse_basic"


@requires_local_example_modules
def test_loaded_module_config_fields_and_knowledge_are_exposed(tmp_path, monkeypatch) -> None:
    module_store = ModuleStore("modules", tmp_path / "data" / "modules" / "loaded_modules.json")
    monkeypatch.setattr(main, "module_store", module_store)
    client = TestClient(main.app)

    config_fields = client.get("/api/config").json()["fields"]
    assert "vuln_scan.scope" in {field["path"] for field in config_fields}

    knowledge = client.get("/api/modules/knowledge").json()["knowledge"]
    assert {
        ("vuln_scan", "vulnerability_knowledge"),
    } <= {(item["module_id"], item["type"]) for item in knowledge}


@requires_local_example_modules
def test_module_store_returns_template_and_module_skill_on_demand(tmp_path) -> None:
    module_store = ModuleStore("modules", tmp_path / "data" / "modules" / "loaded_modules.json")

    template = module_store.get_module_template()
    context = module_store.get_module_skill("reverse")

    assert template["create_with"] == "create_module"
    assert "config_files" in template["directories"]
    assert template["module_json"]["skill"]["skill_file"] == "skill/SKILL.md"
    assert template["module_json"]["skill"]["final_result_schema_file"] == (
        "skill/final_result_schema.json"
    )
    assert "Reverse Module Skill" in context["skill"]
    assert context["playbook"]["module_id"] == "reverse"
    assert context["final_result_schema"]["schema_id"] == "reverse.final_result.v1"
    assert context["skill_paths"]["playbook_file"] == "skill/playbook.json"
    assert context["skill_paths"]["final_result_schema_file"] == "skill/final_result_schema.json"


def test_module_store_can_create_module_skeleton(tmp_path) -> None:
    module_store = ModuleStore(
        tmp_path / "modules",
        tmp_path / "data" / "modules" / "loaded_modules.json",
        tmp_path / "data" / "modules_installed",
        tmp_path / "data" / "module_packages",
    )

    created = module_store.create_module(
        "demo_module",
        "Demo Module",
        "0.1.0",
        "Demo description",
        {"network": True},
    )

    assert created["module_id"] == "demo_module"
    assert created["template_version"] == "1"
    assert created["created"] is True
    assert created["usable"] is True
    assert created["requirements"]["network"] is True
    assert (tmp_path / "modules" / "demo_module" / "module.json").is_file()
    assert (tmp_path / "modules" / "demo_module" / "skill" / "SKILL.md").is_file()
    assert (tmp_path / "modules" / "demo_module" / "config_files").is_dir()
    assert (
        tmp_path / "modules" / "demo_module" / "skill" / "final_result_schema.json"
    ).is_file()
    assert module_store.validate_module("demo_module")["valid"] is True


@requires_local_example_modules
def test_module_validation_accepts_current_template_modules(tmp_path) -> None:
    module_store = ModuleStore("modules", tmp_path / "data" / "modules" / "loaded_modules.json")

    assert module_store.validate_module("reverse")["valid"] is True
    assert module_store.validate_module("vuln_scan")["valid"] is True


@requires_local_example_modules
def test_reverse_module_declares_all_reverse_functions_and_config_fields(tmp_path) -> None:
    module_store = ModuleStore("modules", tmp_path / "data" / "modules" / "loaded_modules.json")

    detail = module_store.get_module_detail("reverse")
    function_ids = {item["function_id"] for item in detail["functions"]}
    config_paths = {field["path"] for field in module_store.load_config_fields()}

    assert {
        "hash.compute",
        "file.type_detect",
        "file.multi_format_parse",
        "file.byte_stats",
        "pe.deep_parse",
        "strings.extract",
        "strings.enhanced_extract",
        "ioc.extract",
        "packer.detect_enhanced",
        "yara.scan_local",
        "tool.detect_it_easy",
        "tool.capa_analyze",
        "tool.floss_extract",
        "file.lief_parse",
        "tool.ida_function_analyze",
        "tool.ida_function_features",
        "tool.ghidra_function_analyze",
        "tool.ghidra_function_features",
        "tool.binaryninja_function_analyze",
        "behavior.map_static",
        "attack.map_static",
        "behavior.map_dynamic",
        "validation.compare_static_dynamic",
        "validation.plan_focused_dynamic",
        "dynamic.vm_status",
        "dynamic.vm_restore_snapshot",
        "dynamic.vm_upload_sample",
        "dynamic.vm_run_sample",
        "dynamic.vm_collect_sysmon",
        "dynamic.vm_validate_behavior",
        "dynamic.vm_save_snapshot",
        "ti.virustotal.hash_lookup",
        "ti.virustotal.behaviour_summary",
        "ti.malwarebazaar.hash_lookup",
    } <= function_ids
    assert {
        "virustotal.api_key",
        "virustotal.endpoint",
        "virustotal.behaviour_endpoint",
        "virustotal.timeout_seconds",
        "malwarebazaar.auth_key",
        "malwarebazaar.endpoint",
        "malwarebazaar.timeout_seconds",
        "ida.path",
        "ghidra.analyze_headless_path",
        "binaryninja.path",
        "binaryninja.python_path",
        "vmware.vmrun_path",
        "vmware.vmx_path",
        "vmware.vm_password",
        "vmware.guest_user",
        "vmware.guest_password",
        "vmware.ready_snapshot",
        "vmware.host_output_dir",
    } <= config_paths
    assert detail["functions_count"] >= 34


def test_module_validation_reports_basic_template_errors(tmp_path) -> None:
    module_root = tmp_path / "modules"
    bad = module_root / "bad"
    bad.mkdir(parents=True)
    (bad / "module.json").write_text(
        json.dumps(
            {
                "module_id": "bad",
                "name": "Bad Module",
                "version": "1.0.0",
                "workflows": ["workflows/missing.json"],
                "knowledge": [],
                "config_fields": [],
            }
        ),
        encoding="utf-8",
    )
    module_store = ModuleStore(
        module_root,
        tmp_path / "data" / "modules" / "loaded_modules.json",
    )

    validation = module_store.validate_module("bad")

    assert validation["valid"] is False
    codes = {error["code"] for error in validation["errors"]}
    assert "missing_template_directory" in codes
    assert "module_file_not_found" in codes


def test_create_module_api_uses_module_store(tmp_path, monkeypatch) -> None:
    module_store = ModuleStore(
        tmp_path / "modules",
        tmp_path / "data" / "modules" / "loaded_modules.json",
        tmp_path / "data" / "modules_installed",
        tmp_path / "data" / "module_packages",
    )
    monkeypatch.setattr(main, "module_store", module_store)
    client = TestClient(main.app)

    response = client.post(
        "/api/modules",
        json={
            "module_id": "api_demo",
            "name": "API Demo",
            "version": "0.1.0",
            "description": "Created from API",
        },
    )

    assert response.status_code == 200
    assert response.json()["module_id"] == "api_demo"
    assert response.json()["created"] is True
    assert client.get("/api/modules").json()["modules"][0]["module_id"] == "api_demo"


@requires_local_example_modules
def test_module_detail_api_returns_manifest_summary_and_validation(tmp_path, monkeypatch) -> None:
    module_store = ModuleStore("modules", tmp_path / "data" / "modules" / "loaded_modules.json")
    monkeypatch.setattr(main, "module_store", module_store)
    client = TestClient(main.app)

    response = client.get("/api/modules/reverse")

    assert response.status_code == 200
    detail = response.json()
    assert detail["module_id"] == "reverse"
    assert detail["usable"] is True
    assert detail["validation"]["valid"] is True
    assert detail["workflows"][0]["workflow_id"] == "module:reverse:reverse_basic"


@requires_local_example_modules
def test_module_template_and_skill_api(tmp_path, monkeypatch) -> None:
    module_store = ModuleStore("modules", tmp_path / "data" / "modules" / "loaded_modules.json")
    monkeypatch.setattr(main, "module_store", module_store)
    client = TestClient(main.app)

    template_response = client.get("/api/modules/template")
    skill_response = client.get("/api/modules/reverse/skill")

    assert template_response.status_code == 200
    assert template_response.json()["create_with"] == "create_module"
    assert "config_files" in template_response.json()["directories"]
    assert skill_response.status_code == 200
    assert skill_response.json()["module_id"] == "reverse"
    assert skill_response.json()["playbook"]["module_id"] == "reverse"
    assert skill_response.json()["final_result_schema"]["schema_id"] == "reverse.final_result.v1"


def test_module_package_and_import_archive(tmp_path) -> None:
    source_modules = tmp_path / "source_modules"
    demo = source_modules / "demo"
    (demo / "workflows").mkdir(parents=True)
    (demo / "module.json").write_text(
        json.dumps(
            {
                "module_id": "demo",
                "name": "Demo Module",
                "version": "1.0.0",
                "workflows": ["workflows/demo.json"],
                "knowledge": [],
                "config_fields": [],
            }
        ),
        encoding="utf-8",
    )
    (demo / "workflows" / "demo.json").write_text(
        json.dumps(
            {
                "workflow_id": "demo",
                "name": "demo",
                "workflow": {"name": "demo", "steps": []},
            }
        ),
        encoding="utf-8",
    )
    package_store = ModuleStore(
        source_modules,
        tmp_path / "registry" / "loaded.json",
        tmp_path / "installed_source",
        tmp_path / "packages",
    )

    packaged = package_store.package_module("demo")

    assert packaged["module_id"] == "demo"
    assert packaged["archive"].endswith(".sfpmod.zip")

    import_store = ModuleStore(
        tmp_path / "empty_modules",
        tmp_path / "target" / "loaded.json",
        tmp_path / "installed",
        tmp_path / "target_packages",
    )
    imported = import_store.import_module_archive(packaged["archive"])

    assert imported["module_id"] == "demo"
    assert imported["installed"] is True
    assert import_store.get_module("demo")["module_id"] == "demo"
    assert import_store.list_module_workflows("demo")[0]["workflow_id"] == "module:demo:demo"


def test_import_module_archive_rejects_path_traversal(tmp_path) -> None:
    archive_path = tmp_path / "bad.sfpmod.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("bad/../module.json", "{}")

    store = ModuleStore(
        tmp_path / "empty_modules",
        tmp_path / "loaded.json",
        tmp_path / "installed",
        tmp_path / "packages",
    )

    try:
        store.import_module_archive(archive_path)
    except ValueError as exc:
        assert str(exc) == "archive_path_not_allowed"
    else:
        raise AssertionError("path traversal archive was accepted")


@requires_local_example_modules
def test_module_package_and_import_api(tmp_path, monkeypatch) -> None:
    module_store = ModuleStore(
        "modules",
        tmp_path / "data" / "modules" / "loaded_modules.json",
        tmp_path / "data" / "modules_installed",
        tmp_path / "data" / "module_packages",
    )
    monkeypatch.setattr(main, "module_store", module_store)
    client = TestClient(main.app)

    package_response = client.post("/api/modules/reverse/package")

    assert package_response.status_code == 200
    assert package_response.json()["module_id"] == "reverse"

    export_response = client.post("/api/modules/reverse/export")
    assert export_response.status_code == 200
    assert export_response.json()["module_id"] == "reverse"

    import_response = client.post(
        "/api/modules/import",
        json={"archive_path": package_response.json()["archive"]},
    )
    assert import_response.status_code == 400
    assert import_response.json()["detail"]["code"] == "module_already_exists"


def test_module_download_and_import_file_api(tmp_path, monkeypatch) -> None:
    source_modules = tmp_path / "source_modules"
    demo = source_modules / "demo"
    (demo / "workflows").mkdir(parents=True)
    (demo / "module.json").write_text(
        json.dumps(
            {
                "module_id": "demo",
                "name": "Demo Module",
                "version": "1.0.0",
                "workflows": ["workflows/demo.json"],
                "knowledge": [],
                "config_fields": [],
            }
        ),
        encoding="utf-8",
    )
    (demo / "workflows" / "demo.json").write_text(
        json.dumps(
            {
                "workflow_id": "demo",
                "name": "demo",
                "workflow": {"name": "demo", "steps": []},
            }
        ),
        encoding="utf-8",
    )
    package_store = ModuleStore(
        source_modules,
        tmp_path / "source" / "loaded.json",
        tmp_path / "source_installed",
        tmp_path / "source_packages",
    )
    archive_path = package_store.package_module("demo")["archive"]

    module_store = ModuleStore(
        tmp_path / "empty_modules",
        tmp_path / "data" / "modules" / "loaded_modules.json",
        tmp_path / "data" / "modules_installed",
        tmp_path / "data" / "module_packages",
    )
    monkeypatch.setattr(main, "module_store", module_store)
    client = TestClient(main.app)

    import_response = client.post(
        "/api/modules/import-file",
        files={
            "file": (
                "demo.sfpmod.zip",
                Path(archive_path).read_bytes(),
                "application/zip",
            )
        },
    )

    assert import_response.status_code == 200
    assert import_response.json()["module_id"] == "demo"

    download_response = client.get("/api/modules/demo/download")
    assert download_response.status_code == 200
    assert "demo-1.0.0.sfpmod.zip" in download_response.headers["content-disposition"]
    assert download_response.content.startswith(b"PK")


def test_module_function_is_registered_by_default(tmp_path, monkeypatch) -> None:
    module_root = tmp_path / "modules"
    _write_demo_function_module(module_root, "demo", "demo.fn")
    module_store = ModuleStore(
        module_root,
        tmp_path / "data" / "modules" / "loaded_modules.json",
        tmp_path / "data" / "modules_installed",
        tmp_path / "data" / "module_packages",
    )
    monkeypatch.setattr(main, "module_store", module_store)
    monkeypatch.setattr(main, "store", SessionStore(tmp_path / "data" / "sessions"))
    client = TestClient(main.app)

    functions = client.get("/api/functions").json()
    by_id = {item["id"]: item for item in functions}
    assert "demo.fn" in by_id
    assert by_id["demo.fn"]["source"] == "module"
    assert by_id["demo.fn"]["module_id"] == "demo"

    session = client.post(
        "/api/sessions/upload",
        files={"file": ("sample.bin", b"hello")},
    ).json()
    response = client.post(
        f"/api/sessions/{session['session_id']}/functions/run",
        json={"function_id": "demo.fn", "params": {"value": "ok"}},
    )

    assert response.status_code == 200
    assert response.json()["result"]["data"]["value"] == "ok"


@requires_local_example_modules
def test_module_load_rejects_function_id_conflict(tmp_path, monkeypatch) -> None:
    installed_root = tmp_path / "data" / "modules_installed"
    _write_demo_function_module(installed_root, "conflict", "hash.compute")
    module_store = ModuleStore(
        "modules",
        tmp_path / "data" / "modules" / "loaded_modules.json",
        installed_root,
        tmp_path / "data" / "module_packages",
    )
    monkeypatch.setattr(main, "module_store", module_store)
    client = TestClient(main.app)

    response = client.post("/api/modules/conflict/load")

    assert response.status_code == 400
    assert "already registered" in response.json()["detail"]["code"]


def test_module_load_rejects_invalid_function_path(tmp_path, monkeypatch) -> None:
    module_root = tmp_path / "modules"
    bad = module_root / "bad"
    bad.mkdir(parents=True)
    (bad / "module.json").write_text(
        json.dumps(
            {
                "module_id": "bad",
                "name": "Bad Module",
                "version": "1.0.0",
                "functions": [
                    {
                        "function_id": "bad.fn",
                        "path": "../bad.py",
                        "class_name": "BadFunction",
                    }
                ],
                "workflows": [],
                "knowledge": [],
                "config_fields": [],
            }
        ),
        encoding="utf-8",
    )
    module_store = ModuleStore(
        module_root,
        tmp_path / "data" / "modules" / "loaded_modules.json",
        tmp_path / "data" / "modules_installed",
        tmp_path / "data" / "module_packages",
    )
    monkeypatch.setattr(main, "module_store", module_store)
    client = TestClient(main.app)

    response = client.post("/api/modules/bad/load")

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_module_function"


def test_index_page_exposes_minimal_module_controls() -> None:
    client = TestClient(main.app)

    response = client.get("/")

    assert response.status_code == 200
    assert "分析工作台" in response.text
    assert "sample-file" in response.text
    assert "session-select" in response.text
    assert "workflow-select" in response.text
    assert "open-result-button" in response.text
    assert "final-result" in response.text
    assert "type=\"file\" multiple" in response.text


def test_module_management_page_exposes_module_and_workflow_controls() -> None:
    client = TestClient(main.app)

    response = client.get("/modules.html")

    assert response.status_code == 200
    assert "模块与流程管理" in response.text
    assert "module-import-file" in response.text
    assert "module-list" in response.text
    assert "导入模块" in response.text
    assert "流程模板配置" in response.text
    assert "delete-workflow-button" in response.text


def test_navigation_pages_are_available() -> None:
    client = TestClient(main.app)

    for path, expected in [
        ("/config.html", "配置中心"),
        ("/platform.html", "平台与模块说明"),
        ("/raw-data.html", "原始数据查询"),
    ]:
        response = client.get(path)
        assert response.status_code == 200
        assert expected in response.text


def _write_demo_function_module(module_root, module_id: str, function_id: str) -> None:
    demo = module_root / module_id
    (demo / "functions").mkdir(parents=True)
    (demo / "workflows").mkdir()
    class_name = "DemoModuleFunction"
    (demo / "module.json").write_text(
        json.dumps(
            {
                "module_id": module_id,
                "name": "Demo Function Module",
                "version": "1.0.0",
                "functions": [
                    {
                        "function_id": function_id,
                        "path": "functions/demo_function.py",
                        "class_name": class_name,
                    }
                ],
                "workflows": ["workflows/demo.json"],
                "knowledge": [],
                "config_fields": [],
            }
        ),
        encoding="utf-8",
    )
    (demo / "functions" / "demo_function.py").write_text(
        "from typing import Any\n"
        "from security_function_platform.core.function_base import AnalysisFunction\n"
        "from security_function_platform.core.function_result import FunctionResult\n\n"
        f"class {class_name}(AnalysisFunction):\n"
        f"    id = {function_id!r}\n"
        "    name = 'Demo module function'\n"
        "    category = 'module_test'\n"
        "    result_key = 'demo_module'\n"
        "    description = 'Test module function.'\n\n"
        "    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:\n"
        "        return FunctionResult(\n"
        "            function_id=self.id,\n"
        "            result_key=self.result_key,\n"
        "            data={'value': params.get('value', 'demo')},\n"
        "        )\n",
        encoding="utf-8",
    )
    (demo / "workflows" / "demo.json").write_text(
        json.dumps(
            {
                "workflow_id": "demo",
                "name": "demo",
                "workflow": {
                    "name": "demo",
                    "steps": [{"function_id": function_id, "params": {}}],
                },
            }
        ),
        encoding="utf-8",
    )
