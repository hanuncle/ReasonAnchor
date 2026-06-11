from typing import Any

from security_function_platform.core.function_result import FunctionResult


class AnalysisFunction:
    id: str = ""
    name: str = ""
    category: str = "general"
    result_key: str = ""
    source: str = "builtin"
    module_id: str = ""
    description: str = ""
    requires: list[str] = []
    requires_results: list[str] = []
    recommended_before: list[str] = []
    cost: str = "low"
    network: bool = False
    external: bool = False
    external_tool: bool = False
    config_required: bool = False
    config_requirements: list[str] = []
    optional: bool = False
    candidate_only: bool = False
    requires_human_confirmation: bool = False
    output_schema: dict[str, Any] = {}

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        raise NotImplementedError

    def info(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "result_key": self.result_key,
            "source": getattr(self, "source", "builtin"),
            "module_id": getattr(self, "module_id", ""),
            "description": getattr(self, "description", ""),
            "requires": list(getattr(self, "requires", [])),
            "requires_results": list(getattr(self, "requires_results", [])),
            "recommended_before": list(getattr(self, "recommended_before", [])),
            "cost": getattr(self, "cost", "low"),
            "network": bool(getattr(self, "network", False)),
            "external": bool(getattr(self, "external", False)),
            "external_tool": bool(getattr(self, "external_tool", False)),
            "config_required": bool(getattr(self, "config_required", False)),
            "config_requirements": list(getattr(self, "config_requirements", [])),
            "optional": bool(getattr(self, "optional", False)),
            "candidate_only": bool(getattr(self, "candidate_only", False)),
            "requires_human_confirmation": bool(
                getattr(self, "requires_human_confirmation", False)
            ),
            "output_schema": dict(getattr(self, "output_schema", {})),
        }
