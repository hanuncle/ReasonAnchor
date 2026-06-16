from __future__ import annotations

from typing import Any

from scan_common import (
    active_scope_authorized,
    host_targets,
    parse_nmap_output,
    parse_port_output,
    resolve_tool,
    result_data,
    run_tool_with_input_file,
    selected_targets,
    success,
    timeout_seconds,
)
from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ReconServiceIdentifyFunction(AnalysisFunction):
    id = "recon.service_identify"
    name = "Recon service identify"
    category = "recon"
    result_key = "recon_services"
    description = "Run or ingest low-speed nmap service fingerprint output after AI reviews open ports."
    requires_results = ["recon_scope", "recon_targets", "recon_ports"]
    recommended_before = ["recon.port_scan"]
    cost = "high"
    network = True
    external_tool = True
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    output_schema = {
        "service_output": "Raw nmap output.",
        "services": "Parsed service names and product hints.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        provided = str(params.get("service_output") or params.get("nmap_output") or "")
        if provided:
            return self._result(False, [], provided, [], ["provided.service_output"])
        if not active_scope_authorized(context):
            return self._result(
                False,
                [],
                "",
                ["Service identification is blocked until active scan authorization is confirmed."],
                [],
                blocked=True,
            )

        port_data = result_data(context, "recon_ports")
        port_services = port_data.get("services")
        if not isinstance(port_services, list):
            port_services = parse_port_output(str(port_data.get("port_output") or ""))
        hosts = sorted({str(item.get("host") or "") for item in port_services if isinstance(item, dict) and item.get("host")})
        ports = sorted({str(item.get("port") or "") for item in port_services if isinstance(item, dict) and item.get("port")})
        if not hosts:
            hosts = host_targets(selected_targets(context, params))
        if not hosts:
            return self._result(False, [], "", ["No hosts were available for service identification."], [])

        nmap = resolve_tool(context, params, "nmap")
        if not nmap:
            return self._result(False, hosts, "", ["nmap was not found; service identification was skipped."], [])
        requested_timeout = timeout_seconds(context, params, 90)
        tool_timeout = min(requested_timeout, 100)
        warnings: list[str] = []
        if requested_timeout > tool_timeout:
            warnings.append(
                f"nmap execution timeout was capped at {tool_timeout}s to return before the MCP call deadline."
            )
        argv = [nmap, "-sV", "--version-light", "-T2", "-oN", "-", "-iL", "__INPUT__"]
        if params.get("default_scripts") is True:
            argv[1:1] = ["-sC"]
        if ports:
            argv[1:1] = ["-p", ",".join(ports[:200])]
        command = run_tool_with_input_file(argv, "__INPUT__", hosts, context, params, timeout=tool_timeout)
        if command["status"] != "completed":
            warnings.append(f"nmap returned {command['status']}.")
        parsed_services = parse_nmap_output(command["stdout"])
        previous_services = _previous_services(context)
        if not parsed_services and command["status"] != "completed" and previous_services:
            parsed_services = previous_services
            warnings.append("Preserved previous non-empty nmap service observations after this run returned no parsed services.")
        return self._result(True, hosts, str(command["stdout"]), warnings, ["nmap"], [command], services=parsed_services)

    def _result(
        self,
        executes: bool,
        input_hosts: list[str],
        output: str,
        warnings: list[str],
        sources: list[str],
        commands: list[dict[str, Any]] | None = None,
        blocked: bool = False,
        services: list[dict[str, Any]] | None = None,
    ) -> FunctionResult:
        return success(
            self.id,
            self.result_key,
            {
                "blocked": blocked,
                "executes": executes,
                "input_hosts": input_hosts,
                "service_output": output,
                "services": services if services is not None else parse_nmap_output(output),
                "commands": commands or [],
                "warnings": warnings,
                "sources": sources,
            },
        )


def _previous_services(context: dict[str, Any]) -> list[dict[str, Any]]:
    existing = result_data(context, "recon_services")
    services = existing.get("services")
    if not isinstance(services, list):
        return []
    return [item for item in services if isinstance(item, dict)]
