from security_function_platform.api.config_store import ConfigStore
from security_function_platform.module_system import ModuleStore


def reverse_config_fields():
    return ModuleStore("modules").load_config_fields()


def field_by_path(redacted, path):
    return next(field for field in redacted["fields"] if field["path"] == path)


def test_load_config_returns_empty_dict_when_file_missing(tmp_path) -> None:
    store = ConfigStore(tmp_path / "config" / "local_config.json")

    assert store.load_config() == {}


def test_set_config_value_writes_nested_field(tmp_path) -> None:
    store = ConfigStore(tmp_path / "config" / "local_config.json")

    store.set_config_value("yara.rules_dir", r"E:\rules\yara", reverse_config_fields())

    assert store.load_config() == {"yara": {"rules_dir": r"E:\rules\yara"}}


def test_delete_config_value_removes_field(tmp_path) -> None:
    store = ConfigStore(tmp_path / "config" / "local_config.json")
    store.set_config_value(
        "virustotal.endpoint",
        "https://example.test/{hash}",
        reverse_config_fields(),
    )

    store.delete_config_value("virustotal.endpoint", reverse_config_fields())

    assert store.load_config() == {"virustotal": {}}


def test_get_redacted_config_hides_secret_values(tmp_path) -> None:
    store = ConfigStore(tmp_path / "config" / "local_config.json")
    fields = reverse_config_fields()
    store.set_config_value("virustotal.api_key", "test-secret", fields)
    store.set_config_value("yara.rules_dir", r"E:\rules\yara", fields)

    redacted = store.get_redacted_config(fields)
    api_key = field_by_path(redacted, "virustotal.api_key")
    rules_dir = field_by_path(redacted, "yara.rules_dir")

    assert api_key["configured"] is True
    assert api_key["value"] is None
    assert rules_dir["configured"] is True
    assert rules_dir["value"] == r"E:\rules\yara"
