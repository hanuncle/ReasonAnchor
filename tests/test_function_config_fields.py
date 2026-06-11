import json

from fastapi.testclient import TestClient

from security_function_platform.api import main
from security_function_platform.api.config_store import ConfigStore
from security_function_platform.mcp_server import server


def field_by_path(redacted, path):
    return next(field for field in redacted["fields"] if field["path"] == path)


def write_policy(tmp_path):
    policy = {
        "allowed_roots": ["config_files", "modules"],
        "allowed_extensions": [".py", ".json", ".yar", ".yara", ".md", ".txt", ".ps1"],
        "deny_patterns": [
            "__pycache__",
            ".pyc",
            ".pyo",
            ".env",
            "local_config.json",
            "data",
            ".git",
            ".venv",
        ],
        "max_read_bytes": 200000,
        "max_write_bytes": 200000,
    }
    policy_path = tmp_path / "config" / "mcp_file_access.json"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    return policy_path


def test_config_store_uses_supplied_config_fields(tmp_path) -> None:
    fields = [
        {
            "function_id": "tool.example",
            "path": "tool_example.path",
            "label": "Example tool path",
            "secret": False,
        }
    ]
    store = ConfigStore(tmp_path / "config" / "local_config.json")

    initial = store.get_redacted_config(fields)
    saved = store.set_config_value("tool_example.path", "example.exe", fields)

    assert field_by_path(initial, "tool_example.path")["configured"] is False
    assert field_by_path(saved, "tool_example.path")["configured"] is True
    assert field_by_path(saved, "tool_example.path")["value"] == "example.exe"


def test_config_api_returns_and_redacts_extra_fields(tmp_path, monkeypatch) -> None:
    class ModuleFields:
        @staticmethod
        def load_config_fields():
            return [
                {
                    "function_id": "ti.example_lookup",
                    "path": "example_provider.api_key",
                    "label": "Example Provider API key",
                    "secret": True,
                }
            ]

    store = ConfigStore(tmp_path / "config" / "local_config.json")
    monkeypatch.setattr(main, "config_store", store)
    monkeypatch.setattr(main, "module_store", ModuleFields())
    client = TestClient(main.app)

    initial = client.get("/api/config").json()
    assert field_by_path(initial, "example_provider.api_key")["configured"] is False

    saved = client.post(
        "/api/config/value",
        json={"path": "example_provider.api_key", "value": "test-secret"},
    ).json()
    field = field_by_path(saved, "example_provider.api_key")

    assert field["secret"] is True
    assert field["configured"] is True
    assert field["value"] is None
    assert "test-secret" not in json.dumps(saved)


def test_mcp_can_read_and_write_module_config_fields(tmp_path, monkeypatch) -> None:
    policy_path = write_policy(tmp_path)
    target = tmp_path / "modules" / "reverse" / "config_fields" / "function_config_fields.json"
    target.parent.mkdir(parents=True)
    target.write_text('{"fields":[]}', encoding="utf-8")
    monkeypatch.setattr(server, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(server, "POLICY_PATH", policy_path)

    read = server.inspect_allowed_files(
        "modules/reverse/config_fields/function_config_fields.json",
        True,
    )
    written = server.write_allowed_file(
        "modules/reverse/config_fields/function_config_fields.json",
        '{"fields":[{"function_id":"tool.example","path":"tool_example.path","label":"Example","secret":false}]}',
    )

    assert read["content"] == '{"fields":[]}'
    assert written["path"] == "modules/reverse/config_fields/function_config_fields.json"
    assert len(written["sha256"]) == 64


def test_mcp_still_rejects_local_config_traversal_and_unlisted_config_files(
    tmp_path,
    monkeypatch,
) -> None:
    policy_path = write_policy(tmp_path)
    monkeypatch.setattr(server, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(server, "POLICY_PATH", policy_path)

    read_local = server.inspect_allowed_files("config/local_config.json", True)
    write_local = server.write_allowed_file("config/local_config.json", "{}")
    traversal = server.inspect_allowed_files(
        "../modules/reverse/config_fields/function_config_fields.json",
        True,
    )
    unlisted = server.write_allowed_file("config/other_fields.json", "{}")

    assert read_local["status"] == "error"
    assert write_local["status"] == "error"
    assert traversal["status"] == "error"
    assert unlisted["status"] == "error"
