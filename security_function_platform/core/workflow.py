from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


@dataclass
class WorkflowStep:
    function_id: str
    params: dict[str, Any] = field(default_factory=dict)
    step_id: str = ""
    depends_on: list[str] = field(default_factory=list)
    requires_results: list[str] = field(default_factory=list)
    stop_on_error: bool = False
    timeout_seconds: int = 0
    when: dict[str, Any] = field(default_factory=dict)
    resource_locks: list[str] = field(default_factory=list)
    parallel_safe: bool = False
    estimated_duration_seconds: int = 0

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "function_id": self.function_id,
            "params": self.params,
        }
        if self.step_id:
            data["step_id"] = self.step_id
        if self.depends_on:
            data["depends_on"] = self.depends_on
        if self.requires_results:
            data["requires_results"] = self.requires_results
        if self.stop_on_error:
            data["stop_on_error"] = True
        if self.timeout_seconds > 0:
            data["timeout_seconds"] = self.timeout_seconds
        if self.when:
            data["when"] = self.when
        if self.resource_locks:
            data["resource_locks"] = self.resource_locks
        if self.parallel_safe:
            data["parallel_safe"] = True
        if self.estimated_duration_seconds > 0:
            data["estimated_duration_seconds"] = self.estimated_duration_seconds
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WorkflowStep":
        return cls(
            function_id=str(data.get("function_id", "")),
            params=dict(data.get("params") or {}),
            step_id=str(data.get("step_id") or data.get("id") or ""),
            depends_on=_string_list(data.get("depends_on")),
            requires_results=_string_list(data.get("requires_results")),
            stop_on_error=bool(data.get("stop_on_error", False)),
            timeout_seconds=_positive_int(data.get("timeout_seconds")),
            when=data.get("when") if isinstance(data.get("when"), dict) else {},
            resource_locks=_string_list(data.get("resource_locks")),
            parallel_safe=bool(data.get("parallel_safe", False)),
            estimated_duration_seconds=_positive_int(data.get("estimated_duration_seconds")),
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


@dataclass
class ExecutionPlanNode:
    node_id: str
    function_id: str
    params: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    requires_results: list[str] = field(default_factory=list)
    stop_on_error: bool = False
    source_index: int = 0
    timeout_seconds: int = 0
    when: dict[str, Any] = field(default_factory=dict)
    resource_locks: list[str] = field(default_factory=list)
    parallel_safe: bool = False
    estimated_duration_seconds: int = 0

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "node_id": self.node_id,
            "function_id": self.function_id,
            "params": self.params,
            "depends_on": self.depends_on,
            "requires_results": self.requires_results,
            "stop_on_error": self.stop_on_error,
            "source_index": self.source_index,
        }
        if self.timeout_seconds > 0:
            data["timeout_seconds"] = self.timeout_seconds
        if self.when:
            data["when"] = self.when
        if self.resource_locks:
            data["resource_locks"] = self.resource_locks
        if self.parallel_safe:
            data["parallel_safe"] = True
        if self.estimated_duration_seconds > 0:
            data["estimated_duration_seconds"] = self.estimated_duration_seconds
        return data


@dataclass
class ExecutionPlan:
    name: str = "unnamed_plan"
    nodes: list[ExecutionPlanNode] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "nodes": [node.to_dict() for node in self.nodes],
        }


class WorkflowRunner:
    def validate(self, registry: Any, workflow: WorkflowDefinition) -> list[dict[str, str]]:
        return self.validate_plan(registry, self.to_execution_plan(workflow))

    def validate_plan(self, registry: Any, plan: ExecutionPlan) -> list[dict[str, str]]:
        errors: list[dict[str, str]] = []
        node_ids: set[str] = set()
        for node in plan.nodes:
            if node.node_id in node_ids:
                errors.append(
                    {
                        "code": "duplicate_node",
                        "node_id": node.node_id,
                        "message": f"Duplicate execution node: {node.node_id}",
                    }
                )
            node_ids.add(node.node_id)
            try:
                registry.get(node.function_id)
            except KeyError:
                errors.append(
                    {
                        "code": "unknown_function",
                        "function_id": node.function_id,
                        "message": f"Unknown function: {node.function_id}",
                    }
                )
        for node in plan.nodes:
            for dependency in node.depends_on:
                if dependency not in node_ids:
                    errors.append(
                        {
                            "code": "unknown_dependency",
                            "node_id": node.node_id,
                            "dependency": dependency,
                            "message": f"Unknown dependency for {node.node_id}: {dependency}",
                        }
                    )
        cycle = _find_cycle(plan.nodes)
        if cycle:
            errors.append(
                {
                    "code": "dependency_cycle",
                    "node_id": cycle[0],
                    "message": "Execution plan contains a dependency cycle: "
                    + " -> ".join(cycle),
                }
            )
        return errors

    def to_execution_plan(self, workflow: WorkflowDefinition) -> ExecutionPlan:
        nodes: list[ExecutionPlanNode] = []
        for index, step in enumerate(workflow.steps, start=1):
            node_id = step.step_id or _default_node_id(index, step.function_id)
            nodes.append(
                ExecutionPlanNode(
                    node_id=node_id,
                    function_id=step.function_id,
                    params=dict(step.params),
                    depends_on=list(step.depends_on),
                    requires_results=list(step.requires_results),
                    stop_on_error=step.stop_on_error,
                    source_index=index,
                    timeout_seconds=step.timeout_seconds,
                    when=dict(step.when),
                    resource_locks=list(step.resource_locks),
                    parallel_safe=step.parallel_safe,
                    estimated_duration_seconds=step.estimated_duration_seconds,
                )
            )
        return ExecutionPlan(name=workflow.name, nodes=nodes)

    def run(
        self,
        registry: Any,
        workflow: WorkflowDefinition,
        context: dict[str, Any],
        on_step_start: Callable[[int, ExecutionPlanNode], None] | None = None,
        on_step_result: Callable[[int, Any], None] | None = None,
    ) -> dict[str, Any]:
        return self.run_plan(
            registry,
            self.to_execution_plan(workflow),
            context,
            on_step_start=on_step_start,
            on_step_result=on_step_result,
        )

    def run_plan(
        self,
        registry: Any,
        plan: ExecutionPlan,
        context: dict[str, Any],
        on_step_start: Callable[[int, ExecutionPlanNode], None] | None = None,
        on_step_result: Callable[[int, Any], None] | None = None,
    ) -> dict[str, Any]:
        validation_errors = self.validate_plan(registry, plan)
        if validation_errors:
            context["validation_errors"] = validation_errors
            return context

        execution = {
            "plan_name": plan.name,
            "status": "running",
            "total_nodes": len(plan.nodes),
            "nodes": {},
            "order": [],
            "current_node": {},
            "last_completed_node": {},
            "failed_node": {},
            "stopped_reason": "",
        }
        context["execution_plan"] = execution

        for index, node in enumerate(_topological_nodes(plan.nodes), start=1):
            execution["current_node"] = _execution_node_status(node, "running")
            if on_step_start is not None:
                on_step_start(index, node)
            missing_results = [
                result_key
                for result_key in node.requires_results
                if result_key not in context.get("results", {})
            ]
            if missing_results:
                result = _missing_results_result(node, missing_results)
            else:
                result = registry.run(node.function_id, context, node.params)
            result_data = result.to_dict()
            context.setdefault("results", {})[result.result_key] = result_data
            execution["order"].append(node.node_id)
            execution["nodes"][node.node_id] = {
                "node_id": node.node_id,
                "function_id": node.function_id,
                "result_key": result.result_key,
                "status": result_data.get("status", ""),
                "depends_on": list(node.depends_on),
                "requires_results": list(node.requires_results),
            }
            completed_node = _execution_node_status(
                node,
                str(result_data.get("status") or ""),
                result_key=result.result_key,
                error=result_data.get("error") if isinstance(result_data.get("error"), dict) else {},
            )
            execution["last_completed_node"] = completed_node
            execution["current_node"] = {}
            _activate_sample_path(context, result_data)
            if on_step_result is not None:
                on_step_result(index, result)
            if node.stop_on_error and result_data.get("status") == "error":
                execution["status"] = "stopped"
                execution["failed_node"] = completed_node
                execution["stopped_reason"] = "stop_on_error"
                break
        else:
            execution["status"] = "completed"
        return context


def _activate_sample_path(context: dict[str, Any], result: dict[str, Any]) -> None:
    if result.get("status") != "success":
        return
    data = result.get("data")
    if not isinstance(data, dict) or data.get("activate_sample_path") is not True:
        return
    sample_path = str(data.get("sample_path") or "")
    if not sample_path:
        return
    path = Path(sample_path)
    if not path.is_file():
        return
    context["sample_path"] = str(path)
    context["filename"] = str(data.get("filename") or path.name)
    context["downloaded_sample"] = {
        "provider": str(data.get("provider") or ""),
        "sha256": str(data.get("sha256") or ""),
        "sample_path": str(path),
        "quarantine_dir": str(data.get("quarantine_dir") or ""),
        "cleanup": data.get("cleanup", {}),
    }


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []


def _positive_int(value: Any) -> int:
    try:
        integer = int(value)
    except (TypeError, ValueError):
        return 0
    return integer if integer > 0 else 0


def _default_node_id(index: int, function_id: str) -> str:
    safe = "".join(char if char.isalnum() or char in {"_", "-", "."} else "_" for char in function_id)
    safe = safe.strip("._-") or "step"
    return f"step-{index:03d}-{safe}"


def _execution_node_status(
    node: ExecutionPlanNode,
    status: str,
    result_key: str = "",
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "node_id": node.node_id,
        "function_id": node.function_id,
        "status": status,
        "source_index": node.source_index,
        "depends_on": list(node.depends_on),
        "requires_results": list(node.requires_results),
    }
    if node.timeout_seconds > 0:
        data["timeout_seconds"] = node.timeout_seconds
    if node.resource_locks:
        data["resource_locks"] = list(node.resource_locks)
    if result_key:
        data["result_key"] = result_key
    if error:
        data["error"] = error
    return data


def _topological_nodes(nodes: list[ExecutionPlanNode]) -> list[ExecutionPlanNode]:
    by_id = {node.node_id: node for node in nodes}
    indegree = {node.node_id: 0 for node in nodes}
    dependents: dict[str, list[str]] = {node.node_id: [] for node in nodes}
    for node in nodes:
        for dependency in node.depends_on:
            if dependency not in by_id:
                continue
            indegree[node.node_id] += 1
            dependents[dependency].append(node.node_id)

    ready = [node.node_id for node in nodes if indegree[node.node_id] == 0]
    ordered: list[ExecutionPlanNode] = []
    while ready:
        node_id = ready.pop(0)
        ordered.append(by_id[node_id])
        for dependent in dependents[node_id]:
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                ready.append(dependent)
    return ordered


def _find_cycle(nodes: list[ExecutionPlanNode]) -> list[str]:
    ordered_ids = {node.node_id for node in _topological_nodes(nodes)}
    all_ids = {node.node_id for node in nodes}
    unresolved = sorted(all_ids - ordered_ids)
    return unresolved


def _missing_results_result(node: ExecutionPlanNode, missing_results: list[str]) -> Any:
    from security_function_platform.core.function_result import FunctionResult

    return FunctionResult(
        function_id=node.function_id,
        result_key=f"{node.node_id}_blocked",
        status="error",
        error={
            "type": "MissingRequiredResults",
            "message": "Missing required result keys: " + ", ".join(missing_results),
            "missing_results": missing_results,
        },
    )
