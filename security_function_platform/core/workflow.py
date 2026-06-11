from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class WorkflowStep:
    function_id: str
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "params": self.params,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WorkflowStep":
        return cls(
            function_id=str(data.get("function_id", "")),
            params=dict(data.get("params") or {}),
        )


@dataclass
class WorkflowDefinition:
    name: str = "unnamed_workflow"
    steps: list[WorkflowStep] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name:
            self.name = "unnamed_workflow"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "steps": [step.to_dict() for step in self.steps],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WorkflowDefinition":
        return cls(
            name=str(data.get("name") or "unnamed_workflow"),
            steps=[WorkflowStep.from_dict(step) for step in data.get("steps", [])],
        )


class WorkflowRunner:
    def validate(self, registry: Any, workflow: WorkflowDefinition) -> list[dict[str, str]]:
        errors: list[dict[str, str]] = []
        for step in workflow.steps:
            try:
                registry.get(step.function_id)
            except KeyError:
                errors.append(
                    {
                        "code": "unknown_function",
                        "function_id": step.function_id,
                        "message": f"Unknown function: {step.function_id}",
                    }
                )
        return errors

    def run(
        self,
        registry: Any,
        workflow: WorkflowDefinition,
        context: dict[str, Any],
        on_step_result: Callable[[int, Any], None] | None = None,
    ) -> dict[str, Any]:
        validation_errors = self.validate(registry, workflow)
        if validation_errors:
            context["validation_errors"] = validation_errors
            return context

        for index, step in enumerate(workflow.steps, start=1):
            result = registry.run(step.function_id, context, step.params)
            context.setdefault("results", {})[result.result_key] = result.to_dict()
            if on_step_result is not None:
                on_step_result(index, result)
        return context
