from __future__ import annotations

from typing import Any

from scan_common import (
    active_scope_authorized,
    parse_http_output,
    rate_limit_value,
    rate_number,
    resolve_tool,
    run_tool_with_input_file,
    selected_targets,
    success,
    url_targets,
)
from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ReconHttpProbeFunction(AnalysisFunction):
    id = "recon.http_probe"
    name = "Recon HTTP liveness probe"
    category = "recon"
    result_key = "recon_http"
    description = "Run or ingest httpx output for authorized scoped web targets."
    requires_results = ["recon_scope", "recon_targets"]
    recommended_before = ["recon.dns_probe"]
    cost = "medium"
    network = True
    external_tool = True
    optional = True
    requires_human_confirmation = True
    output_schema = {
        "http_output": "Raw httpx output.",
        "web_endpoints": "Parsed live HTTP endpoints.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        provided = str(params.get("http_output") or params.get("httpx_output") or "")
        if provided:
            return self._result(False, [], provided, [], ["provided.http_output"])
        if not active_scope_authorized(context):
            return self._result(
                False,
                [],
                "",
                ["HTTP probing is blocked until active scan authorization is confirmed."],
                [],
                blocked=True,
            )

        urls = url_targets(selected_targets(context, params))
        httpx = resolve_tool(context, params, "httpx")
        if not httpx:
            return self._result(False, urls, "", ["httpx was not found; HTTP probing was skipped."], [])
        rate_limit = rate_limit_value(context, params)
        command = run_tool_with_input_file(
            [
                httpx,
                "-json",
                "-status-code",
                "-title",
                "-tech-detect",
                "-follow-redirects",
                "-rl",
                rate_number(rate_limit, "httpx"),
                "-l",
                "__INPUT__",
            ],
            "__INPUT__",
            urls,
            context,
            params,
        )
        warnings = [] if command["status"] == "completed" else [f"httpx returned {command['status']}."]
        return self._result(True, urls, str(command["stdout"]), warnings, ["httpx"], [command])

    def _result(
        self,
        executes: bool,
        input_urls: list[str],
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
                "input_urls": input_urls,
                "http_output": output,
                "web_endpoints": parse_http_output(output),
                "commands": commands or [],
                "warnings": warnings,
                "sources": sources,
            },
        )
