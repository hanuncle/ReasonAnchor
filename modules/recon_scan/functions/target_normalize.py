from __future__ import annotations

from typing import Any

from scan_common import (
    as_list,
    domain_targets,
    error,
    host_targets,
    normalize_many,
    result_data,
    success,
    url_targets,
)
from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ReconTargetNormalizeFunction(AnalysisFunction):
    id = "recon.target_normalize"
    name = "Recon target normalize"
    category = "recon"
    result_key = "recon_targets"
    description = "Normalize allowed scope targets into host, domain, and URL seed lists."
    requires_results = ["recon_scope"]
    recommended_before = ["recon.scope_validate"]
    cost = "low"
    output_schema = {
        "targets": "Normalized in-scope target objects.",
        "hosts": "Host-like values for DNS, HTTP, and port probing.",
        "urls": "URL seeds for HTTP probing and light web discovery.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        explicit = as_list(params.get("targets"))
        if explicit:
            targets, invalid = normalize_many(explicit)
            if invalid:
                return error(self.id, self.result_key, "invalid_targets", "one or more targets are invalid")
        else:
            targets = [
                item
                for item in result_data(context, "recon_scope").get("allowed_targets", [])
                if isinstance(item, dict)
            ]
        if not targets:
            return error(self.id, self.result_key, "missing_allowed_targets", "no allowed targets are available")

        domains = domain_targets(targets)
        hosts = host_targets(targets)
        urls = url_targets(targets)
        return success(
            self.id,
            self.result_key,
            {
                "targets": targets,
                "domains": domains,
                "hosts": hosts,
                "urls": urls,
                "counts": {
                    "targets": len(targets),
                    "domains": len(domains),
                    "hosts": len(hosts),
                    "urls": len(urls),
                },
            },
        )
