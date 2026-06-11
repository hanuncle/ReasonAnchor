from security_function_platform.core.function_result import FunctionResult


def test_function_result_to_dict_has_only_five_fields() -> None:
    result = FunctionResult(function_id="demo.fn", result_key="demo")

    assert result.to_dict() == {
        "function_id": "demo.fn",
        "result_key": "demo",
        "status": "success",
        "data": {},
        "error": None,
    }


def test_function_result_defaults() -> None:
    result = FunctionResult(function_id="demo.fn", result_key="demo")

    assert result.status == "success"
    assert result.data == {}
    assert result.error is None
