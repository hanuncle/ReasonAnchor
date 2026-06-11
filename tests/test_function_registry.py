import pytest

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_registry import FunctionRegistry
from security_function_platform.core.function_result import FunctionResult


class DemoFunction(AnalysisFunction):
    id = "demo.fn"
    name = "Demo"
    category = "test"
    result_key = "demo"

    def run(self, context, params):
        return FunctionResult(function_id=self.id, result_key=self.result_key, data={"ok": True})


class ErrorFunction(AnalysisFunction):
    id = "demo.error"
    name = "Error"
    category = "test"
    result_key = "error"

    def run(self, context, params):
        raise RuntimeError("boom")


class EmptyIdFunction(AnalysisFunction):
    id = ""


def test_register_list_and_get_function() -> None:
    registry = FunctionRegistry()
    fn = DemoFunction()

    registry.register(fn)

    assert registry.list_functions() == [fn.info()]
    assert registry.get("demo.fn") is fn


def test_duplicate_registration_raises_value_error() -> None:
    registry = FunctionRegistry()
    registry.register(DemoFunction())

    with pytest.raises(ValueError):
        registry.register(DemoFunction())


def test_empty_function_id_raises_value_error() -> None:
    registry = FunctionRegistry()

    with pytest.raises(ValueError):
        registry.register(EmptyIdFunction())


def test_missing_function_id_raises_key_error() -> None:
    registry = FunctionRegistry()

    with pytest.raises(KeyError):
        registry.get("missing")


def test_registry_run_executes_function() -> None:
    registry = FunctionRegistry()
    registry.register(DemoFunction())

    result = registry.run("demo.fn", {}, params={})

    assert result.status == "success"
    assert result.data == {"ok": True}


def test_registry_run_catches_function_exception() -> None:
    registry = FunctionRegistry()
    registry.register(ErrorFunction())

    result = registry.run("demo.error", {}, params={})

    assert result.status == "error"
    assert result.error == {"type": "RuntimeError", "message": "boom"}
