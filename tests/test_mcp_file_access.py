import json

from security_function_platform.mcp_server import server


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
    policy_path.parent.mkdir(parents=True)
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    return policy_path


def test_policy_file_exists_and_parses() -> None:
    assert server.POLICY_PATH.is_file()
    assert "allowed_roots" in json.loads(server.POLICY_PATH.read_text(encoding="utf-8"))


def test_inspect_allowed_files_lists_and_reads_allowed_paths(tmp_path, monkeypatch) -> None:
    policy_path = write_policy(tmp_path)
    skill_file = tmp_path / "config_files" / "codex_skill" / "SKILL.md"
    fn_file = tmp_path / "modules" / "reverse" / "functions" / "ioc_extract.py"
    skill_file.parent.mkdir(parents=True)
    fn_file.parent.mkdir(parents=True)
    skill_file.write_text("# Skill\n", encoding="utf-8")
    fn_file.write_text("VALUE = 1\n", encoding="utf-8")
    monkeypatch.setattr(server, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(server, "POLICY_PATH", policy_path)

    listed = server.inspect_allowed_files("config_files", include_content=False)
    read = server.inspect_allowed_files(
        "modules/reverse/functions/ioc_extract.py",
        include_content=True,
    )

    assert listed["type"] == "directory"
    assert "config_files/codex_skill" in {item["path"] for item in listed["items"]}
    assert read["content"] == "VALUE = 1\n"


def test_inspect_allowed_files_rejects_local_config_and_traversal(tmp_path, monkeypatch) -> None:
    policy_path = write_policy(tmp_path)
    monkeypatch.setattr(server, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(server, "POLICY_PATH", policy_path)

    local_config = server.inspect_allowed_files("config/local_config.json", True)
    traversal = server.inspect_allowed_files("../config_files/demo.yar", True)

    assert local_config["status"] == "error"
    assert traversal["status"] == "error"


def test_write_allowed_file_allows_policy_path_and_rejects_unsafe_paths(tmp_path, monkeypatch) -> None:
    policy_path = write_policy(tmp_path)
    monkeypatch.setattr(server, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(server, "POLICY_PATH", policy_path)

    written = server.write_allowed_file(
        "modules/reverse/config_files/yara_rules/default/custom_rule.yar",
        "rule CustomRule { condition: true }\n",
    )
    module_written = server.write_allowed_file(
        "modules/reverse/functions/demo.py",
        "VALUE = 1\n",
    )
    outside = server.write_allowed_file("README.md", "bad")
    local_config = server.write_allowed_file("config/local_config.json", "{}")

    assert written["path"] == "modules/reverse/config_files/yara_rules/default/custom_rule.yar"
    assert module_written["path"] == "modules/reverse/functions/demo.py"
    assert len(written["sha256"]) == 64
    assert outside["status"] == "error"
    assert local_config["status"] == "error"
