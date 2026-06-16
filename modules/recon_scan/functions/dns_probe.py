from __future__ import annotations

from typing import Any

from scan_common import (
    active_scope_authorized,
    host_targets,
    parse_dns_output,
    rate_limit_value,
    rate_number,
    resolve_tool,
    run_tool_with_input_file,
    selected_targets,
    success,
)
from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ReconDnsProbeFunction(AnalysisFunction):
    id = "recon.dns_probe"
    name = "Recon DNS probe"
    category = "recon"
    result_key = "recon_dns"
    description = "Run or ingest dnsx output for authorized scoped targets."
    requires_results = ["recon_scope", "recon_targets"]
    recommended_before = ["recon.scope_validate", "recon.target_normalize"]
    cost = "medium"
    network = True
    external_tool = True
    optional = True
    requires_human_confirmation = True
    output_schema = {
        "dns_output": "Raw dnsx output or supplied DNS output.",
        "records": "Parsed DNS records and resolved values.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        provided = str(params.get("dns_output") or params.get("dnsx_output") or "")
        if provided:
            return self._result(False, [], provided, [], ["provided.dns_output"])
        if not active_scope_authorized(context):
            return self._result(
                False,
                [],
                "",
                ["DNS probing is blocked until active scan authorization is confirmed."],
                [],
                blocked=True,
            )

        hosts = host_targets(selected_targets(context, params))
        dnsx = resolve_tool(context, params, "dnsx")
        if not dnsx:
            return self._result(False, hosts, "", ["dnsx was not found; DNS probing was skipped."], [])
        rate_limit = rate_limit_value(context, params)
        command = run_tool_with_input_file(
            [
                dnsx,
                "-json",
                "-a",
                "-aaaa",
                "-cname",
                "-retry",
                "1",
                "-rl",
                rate_number(rate_limit, "dnsx"),
                "-l",
                "__INPUT__",
            ],
            "__INPUT__",
            hosts,
            context,
            params,
        )
        warnings = []
        output = str(command["stdout"])
        if command["status"] != "completed":
            output = ""
            detail = str(command.get("stderr") or command.get("stdout") or "").strip().splitlines()
            message = f"dnsx returned {command['status']}."
            if detail:
                message = f"{message} First line: {detail[0]}"
            warnings.append(message)
        return self._result(True, hosts, output, warnings, ["dnsx"], [command])

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
        parsed = parse_dns_output(output)
        return success(
            self.id,
            self.result_key,
            {
                "blocked": blocked,
                "executes": executes,
                "input_hosts": input_hosts,
                "dns_output": output,
                "records": parsed["records"],
                "resolved_hosts": parsed["hosts"],
                "addresses": parsed["addresses"],
                "commands": commands or [],
                "warnings": warnings,
                "sources": sources,
            },
        )
