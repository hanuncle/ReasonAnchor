from __future__ import annotations

from pathlib import Path
from typing import Any

from scan_common import (
    active_scope_authorized,
    config_or_param,
    host_targets,
    parse_http_output,
    parse_urls,
    rate_limit_value,
    rate_number,
    resolve_tool,
    result_data,
    run_tool,
    run_tool_with_input_file,
    selected_targets,
    success,
    url_targets,
)
from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ReconWebLightDiscoverFunction(AnalysisFunction):
    id = "recon.web_light_discover"
    name = "Recon web light discover"
    category = "recon"
    result_key = "recon_web"
    description = "Run or ingest tlsx, katana, and optional ffuf output after AI reviews live HTTP endpoints."
    requires_results = ["recon_scope", "recon_targets", "recon_http"]
    recommended_before = ["recon.http_probe"]
    cost = "high"
    network = True
    external_tool = True
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    output_schema = {
        "tls_output": "Raw tlsx output.",
        "crawl_output": "Raw katana output.",
        "content_output": "Raw ffuf output.",
        "urls": "Parsed discovered URLs.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        provided = {
            "tls_output": str(params.get("tls_output") or params.get("tlsx_output") or ""),
            "crawl_output": str(params.get("crawl_output") or params.get("katana_output") or ""),
            "content_output": str(params.get("content_output") or params.get("ffuf_output") or ""),
        }
        if any(provided.values()):
            return self._result(False, [], provided, [], ["provided.web_output"])
        if not active_scope_authorized(context):
            return self._result(
                False,
                [],
                {"tls_output": "", "crawl_output": "", "content_output": ""},
                ["Web discovery is blocked until active scan authorization is confirmed."],
                [],
                blocked=True,
            )

        http_data = result_data(context, "recon_http")
        endpoints = http_data.get("web_endpoints")
        if not isinstance(endpoints, list):
            endpoints = parse_http_output(str(http_data.get("http_output") or ""))
        urls = [str(item.get("url")) for item in endpoints if isinstance(item, dict) and item.get("url")]
        if not urls:
            urls = url_targets(selected_targets(context, params))
        hosts = host_targets(selected_targets(context, params))
        rate_limit = rate_limit_value(context, params)
        commands: list[dict[str, Any]] = []
        warnings: list[str] = []
        outputs = {"tls_output": "", "crawl_output": "", "content_output": ""}

        tlsx = resolve_tool(context, params, "tlsx")
        if tlsx and hosts:
            command = run_tool_with_input_file([tlsx, "-json", "-l", "__INPUT__"], "__INPUT__", hosts, context, params)
            commands.append(command)
            outputs["tls_output"] = str(command["stdout"])
        elif hosts:
            warnings.append("tlsx was not found; TLS discovery was skipped.")

        katana = resolve_tool(context, params, "katana")
        if katana and urls:
            depth = str(params.get("crawl_depth") or "1")
            command = run_tool_with_input_file(
                [katana, "-json", "-depth", depth, "-list", "__INPUT__"],
                "__INPUT__",
                urls,
                context,
                params,
            )
            commands.append(command)
            outputs["crawl_output"] = str(command["stdout"])
        elif urls:
            warnings.append("katana was not found; crawl discovery was skipped.")

        ffuf = resolve_tool(context, params, "ffuf")
        wordlist = str(
            config_or_param(
                context,
                params,
                "wordlist_path",
                params.get("content_wordlist_path") or "",
            )
            or ""
        )
        if ffuf and wordlist and Path(wordlist).is_file() and urls:
            chunks = []
            for url in urls[:10]:
                command = run_tool(
                    [
                        ffuf,
                        "-json",
                        "-ac",
                        "-rate",
                        rate_number(rate_limit, "ffuf"),
                        "-w",
                        wordlist,
                        "-u",
                        url.rstrip("/") + "/FUZZ",
                    ],
                    context,
                    params,
                )
                commands.append(command)
                if command["stdout"]:
                    chunks.append(str(command["stdout"]))
            outputs["content_output"] = "\n".join(chunks)
        elif urls:
            warnings.append("ffuf was skipped because ffuf or wordlist_path is missing.")

        sources = [command["command"].split()[0] for command in commands]
        return self._result(True, urls, outputs, warnings, sources, commands)

    def _result(
        self,
        executes: bool,
        seed_urls: list[str],
        outputs: dict[str, str],
        warnings: list[str],
        sources: list[str],
        commands: list[dict[str, Any]] | None = None,
        blocked: bool = False,
    ) -> FunctionResult:
        urls = []
        urls.extend(parse_urls(outputs.get("crawl_output", ""), "katana"))
        urls.extend(parse_urls(outputs.get("content_output", ""), "ffuf"))
        return success(
            self.id,
            self.result_key,
            {
                "blocked": blocked,
                "executes": executes,
                "seed_urls": seed_urls,
                "tls_output": outputs.get("tls_output", ""),
                "crawl_output": outputs.get("crawl_output", ""),
                "content_output": outputs.get("content_output", ""),
                "urls": urls,
                "commands": commands or [],
                "warnings": warnings,
                "sources": sources,
            },
        )
