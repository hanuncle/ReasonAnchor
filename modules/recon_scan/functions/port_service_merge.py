from __future__ import annotations

from typing import Any

from scan_common import merge_services, parse_nmap_output, parse_port_output, result_data, success
from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ReconPortServiceMergeFunction(AnalysisFunction):
    id = "recon.port_service_merge"
    name = "Recon port service merge"
    category = "recon"
    result_key = "recon_port_service_merge"
    description = "Merge host:port, naabu, and nmap-style service observations into one compact table."
    cost = "low"
    optional = True
    output_schema = {
        "services": "Merged host, port, service, product, and source rows.",
        "open_ports_by_host": "Open ports grouped by host.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        services: list[dict[str, Any]] = []
        sources: list[str] = []

        for item in params.get("ports") or []:
            if isinstance(item, dict):
                services.append(item)
        if params.get("ports"):
            sources.append("params.ports")

        port_output = str(params.get("port_output") or "")
        if port_output:
            services.extend(parse_port_output(port_output))
            sources.append("params.port_output")

        service_output = str(params.get("service_output") or params.get("nmap_output") or "")
        if service_output:
            services.extend(parse_nmap_output(service_output))
            sources.append("params.service_output")

        existing_ports = result_data(context, "recon_ports")
        existing_port_services = existing_ports.get("services")
        if isinstance(existing_port_services, list):
            services.extend(item for item in existing_port_services if isinstance(item, dict))
            sources.append("context.recon_ports")

        existing_services = result_data(context, "recon_services")
        existing_nmap_services = existing_services.get("services")
        if isinstance(existing_nmap_services, list):
            services.extend(item for item in existing_nmap_services if isinstance(item, dict))
            sources.append("context.recon_services")

        merged = merge_services(services)
        return success(
            self.id,
            self.result_key,
            {
                "services": merged,
                "open_ports_by_host": _open_ports_by_host(merged),
                "counts": {
                    "services": len(merged),
                    "hosts": len({str(item.get("host") or "") for item in merged if item.get("host")}),
                },
                "sources": sorted(set(sources)),
            },
        )


def _open_ports_by_host(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, set[str]] = {}
    for item in services:
        host = str(item.get("host") or "")
        port = str(item.get("port") or "")
        if host and port:
            grouped.setdefault(host, set()).add(port)
    return [
        {"host": host, "ports": sorted(ports, key=_port_sort_key)}
        for host, ports in sorted(grouped.items())
    ]


def _port_sort_key(port: str) -> tuple[int, str]:
    return (int(port), "") if port.isdigit() else (999999, port)
