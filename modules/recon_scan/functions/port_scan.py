from __future__ import annotations

from typing import Any

from scan_common import (
    active_scope_authorized,
    host_targets,
    parse_port_output,
    rate_limit_value,
    rate_number,
    resolve_tool,
    run_tool_with_input_file,
    selected_targets,
    success,
)
from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ReconPortScanFunction(AnalysisFunction):
    id = "recon.port_scan"
    name = "Recon low-rate port scan"
    category = "recon"
    result_key = "recon_ports"
    description = "Run or ingest naabu output for authorized scoped hosts."
    requires_results = ["recon_scope", "recon_targets"]
    recommended_before = ["recon.dns_probe"]
    cost = "high"
    network = True
    external_tool = True
    optional = True
    requires_human_confirmation = True
    output_schema = {
        "port_output": "Raw naabu output.",
        "services": "Parsed host and open-port observations.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        provided = str(params.get("port_output") or params.get("naabu_output") or "")
        if provided:
            return self._result(False, [], provided, [], ["provided.port_output"])
        if not active_scope_authorized(context):
            return self._result(
                False,
                [],
                "",
                ["Port scanning is blocked until active scan authorization is confirmed."],
                [],
                blocked=True,
            )

        hosts = host_targets(selected_targets(context, params))
        naabu = resolve_tool(context, params, "naabu")
        if not naabu:
            return self._result(False, hosts, "", ["naabu was not found; port scan was skipped."], [])
        rate_limit = rate_limit_value(context, params)
        ports = str(params.get("ports") or params.get("port_profile") or "top-1000")
        argv = [naabu, "-list", "__INPUT__", "-json", "-rate", rate_number(rate_limit, "naabu")]
        if ports == "top-1000":
            argv.extend(["-top-ports", "1000"])
        elif ports == "quick":
            argv.extend(["-p", "80,443,8080,8443,22,25,53,110,143,993,995,3306,5432,6379"])
        elif ports:
            argv.extend(["-p", ports])
        command = run_tool_with_input_file(argv, "__INPUT__", hosts, context, params)
        warnings = [] if command["status"] == "completed" else [f"naabu returned {command['status']}."]
        return self._result(True, hosts, str(command["stdout"]), warnings, ["naabu"], [command])

    def _result(
        self,
        executes: bool,
        input_hosts: list[str],
        output: str,
        warnings: list[str],
        sources: list[str],
        commands: list[dict[str, Any]] | None = None,
        blocked: bool = False,
    ) -> FunctionResult:
        return success(
            self.id,
            self.result_key,
            {
                "blocked": blocked,
                "executes": executes,
                "input_hosts": input_hosts,
                "port_output": output,
                "services": parse_port_output(output, "naabu"),
                "commands": commands or [],
                "warnings": warnings,
                "sources": sources,
            },
        )
