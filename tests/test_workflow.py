import hashlib

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_registry import FunctionRegistry
from security_function_platform.core.function_result import FunctionResult
from security_function_platform.core.workflow import (
    WorkflowDefinition,
    WorkflowRunner,
    WorkflowStep,
)

from tests.module_function_helpers import reverse_function_class

FileTypeDetectFunction = reverse_function_class(
    "file_type_detect.py",
    "FileTypeDetectFunction",
)
HashComputeFunction = reverse_function_class("hash_compute.py", "HashComputeFunction")
StringsExtractFunction = reverse_function_class("strings_extract.py", "StringsExtractFunction")


class MarkerFunction(AnalysisFunction):
    id = "marker.fn"
    name = "Marker"
    category = "test"
    result_key = "marker"

    def run(self, context, params):
        context["marker_executed"] = True
        return FunctionResult(function_id=self.id, result_key=self.result_key)


class ActivateSampleFunction(AnalysisFunction):
    id = "sample.activate"
    name = "Activate Sample"
    category = "test"
    result_key = "sample_activation"

    def run(self, context, params):
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "activate_sample_path": True,
                "provider": "test",
                "sample_path": params["sample_path"],
                "filename": "downloaded.exe",
                "sha256": params.get("sha256", ""),
                "quarantine_dir": params.get("quarantine_dir", ""),
                "cleanup": {"delete_after_analysis": True},
            },
        )


def build_registry() -> FunctionRegistry:
    registry = FunctionRegistry()
    registry.register(HashComputeFunction())
    registry.register(FileTypeDetectFunction())
    registry.register(StringsExtractFunction())
    return registry


def test_workflow_step_to_dict() -> None:
    step = WorkflowStep(
        function_id="strings.extract",
        params={"min_length": 4, "max_strings": 2000},
    )

    assert step.to_dict() == {
        "function_id": "strings.extract",
        "params": {"min_length": 4, "max_strings": 2000},
    }


def test_workflow_definition_to_dict() -> None:
    workflow = WorkflowDefinition(
        name="basic_static_analysis",
        steps=[
            WorkflowStep("hash.compute"),
            WorkflowStep("file.type_detect"),
            WorkflowStep("strings.extract", {"min_length": 4}),
        ],
    )

    assert workflow.to_dict() == {
        "name": "basic_static_analysis",
        "steps": [
            {"function_id": "hash.compute", "params": {}},
            {"function_id": "file.type_detect", "params": {}},
            {"function_id": "strings.extract", "params": {"min_length": 4}},
        ],
    }


def test_workflow_definition_from_dict() -> None:
    workflow = WorkflowDefinition.from_dict(
        {
            "name": "basic_static_analysis",
            "steps": [
                {"function_id": "hash.compute"},
                {"function_id": "strings.extract", "params": {"min_length": 4}},
            ],
        }
    )

    assert workflow.name == "basic_static_analysis"
    assert workflow.steps == [
        WorkflowStep("hash.compute"),
        WorkflowStep("strings.extract", {"min_length": 4}),
    ]


def test_workflow_definition_from_dict_defaults_empty_name() -> None:
    workflow = WorkflowDefinition.from_dict({"name": "", "steps": []})

    assert workflow.name == "unnamed_workflow"
    assert workflow.steps == []


def test_workflow_runner_validate_registered_functions_returns_empty_list() -> None:
    workflow = WorkflowDefinition(
        name="basic_static_analysis",
        steps=[WorkflowStep("hash.compute"), WorkflowStep("file.type_detect")],
    )

    assert WorkflowRunner().validate(build_registry(), workflow) == []


def test_workflow_runner_validate_unknown_function_returns_error() -> None:
    workflow = WorkflowDefinition(
        name="invalid",
        steps=[WorkflowStep("unknown.fn")],
    )

    assert WorkflowRunner().validate(build_registry(), workflow) == [
        {
            "code": "unknown_function",
            "function_id": "unknown.fn",
            "message": "Unknown function: unknown.fn",
        }
    ]


def test_workflow_runner_run_executes_steps_and_collects_results(tmp_path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x00hello world\x00http://example.test/a\x00")
    workflow = WorkflowDefinition(
        name="basic_static_analysis",
        steps=[
            WorkflowStep("hash.compute"),
            WorkflowStep("file.type_detect"),
            WorkflowStep("strings.extract", {"min_length": 4}),
        ],
    )
    context = {
        "sample_path": str(sample),
        "filename": "sample.exe",
        "config": {},
    }

    result_context = WorkflowRunner().run(build_registry(), workflow, context)

    assert result_context is context
    assert set(context["results"]) == {"hash", "file_type", "strings"}
    assert context["results"]["hash"]["result_key"] == "hash"
    assert context["results"]["file_type"]["result_key"] == "file_type"
    assert context["results"]["strings"]["result_key"] == "strings"


def test_workflow_runner_collects_results_without_function_writing_results(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello world")
    context = {"sample_path": str(sample), "results": {}}
    workflow = WorkflowDefinition(name="hash_only", steps=[WorkflowStep("hash.compute")])

    WorkflowRunner().run(build_registry(), workflow, context)

    assert set(context["results"]) == {"hash"}


def test_workflow_runner_activates_downloaded_sample_path(tmp_path) -> None:
    original = tmp_path / "original.exe"
    downloaded = tmp_path / "downloaded.exe"
    original.write_bytes(b"original")
    downloaded.write_bytes(b"downloaded sample")
    expected_sha256 = hashlib.sha256(downloaded.read_bytes()).hexdigest()
    registry = build_registry()
    registry.register(ActivateSampleFunction())
    workflow = WorkflowDefinition(
        name="download_then_hash",
        steps=[
            WorkflowStep(
                "sample.activate",
                {"sample_path": str(downloaded), "sha256": expected_sha256},
            ),
            WorkflowStep("hash.compute"),
        ],
    )
    context = {
        "sample_path": str(original),
        "filename": "original.exe",
        "config": {},
    }

    WorkflowRunner().run(registry, workflow, context)

    assert context["sample_path"] == str(downloaded)
    assert context["filename"] == "downloaded.exe"
    assert context["downloaded_sample"]["sha256"] == expected_sha256
    assert context["results"]["hash"]["data"]["sha256"] == expected_sha256


def test_workflow_runner_run_empty_steps_returns_context_without_error() -> None:
    context = {"sample_path": "sample.exe"}
    workflow = WorkflowDefinition(name="empty", steps=[])

    result_context = WorkflowRunner().run(build_registry(), workflow, context)

    assert result_context is context
    assert "results" not in context
    assert "validation_errors" not in context


def test_workflow_runner_run_unknown_function_records_error_and_does_not_execute() -> None:
    registry = build_registry()
    registry.register(MarkerFunction())
    context = {}
    workflow = WorkflowDefinition(
        name="invalid",
        steps=[WorkflowStep("unknown.fn"), WorkflowStep("marker.fn")],
    )

    WorkflowRunner().run(registry, workflow, context)

    assert context["validation_errors"] == [
        {
            "code": "unknown_function",
            "function_id": "unknown.fn",
            "message": "Unknown function: unknown.fn",
        }
    ]
    assert "results" not in context
    assert "marker_executed" not in context
