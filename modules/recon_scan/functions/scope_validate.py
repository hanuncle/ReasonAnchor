from __future__ import annotations

from typing import Any

from scan_common import (
    AUTHORIZATION_TOKEN,
    as_list,
    config_or_param,
    error,
    normalize_many,
    success,
    target_matches_scope,
)
from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class ReconScopeValidateFunction(AnalysisFunction):
    id = "recon.scope_validate"
    name = "Recon scope validate"
    category = "recon"
    result_key = "recon_scope"
    description = "Validate user supplied targets against explicit authorized scope."
    cost = "low"
    output_schema = {
        "allowed_targets": "Normalized targets inside authorized scope and not excluded.",
        "active_authorized": "True only when active scanning is requested and explicitly confirmed.",
        "out_of_scope_targets": "Targets rejected before any scanning step.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        targets = as_list(params.get("targets") or context.get("targets"))
        if not targets:
            targets = as_list(config_or_param(context, params, "targets"))
        authorized_scope = as_list(
            params.get("authorized_scope")
            or context.get("authorized_scope")
            or config_or_param(context, params, "authorized_scope")
        )
        exclude = as_list(
            params.get("exclude")
            or context.get("exclude")
            or config_or_param(context, params, "exclude")
        )
        active_scan = bool(params.get("active_scan", False))
        confirm_authorized = str(
            params.get("confirm_authorized")
            or context.get("confirm_authorized")
            or config_or_param(context, params, "confirm_authorized", "")
            or ""
        )

        if not targets:
            return error(self.id, self.result_key, "missing_targets", "targets are required")
        if not authorized_scope:
            return error(self.id, self.result_key, "missing_authorized_scope", "authorized_scope is required")

        normalized_targets, invalid_targets = normalize_many(targets)
        normalized_scope, invalid_scope = normalize_many(authorized_scope)
        normalized_exclude, invalid_exclude = normalize_many(exclude)
        if invalid_targets:
            return error(self.id, self.result_key, "invalid_targets", "one or more targets are invalid")
        if invalid_scope:
            return error(
                self.id,
                self.result_key,
                "invalid_authorized_scope",
                "one or more authorized_scope entries are invalid",
            )

        allowed: list[dict[str, Any]] = []
        excluded: list[dict[str, Any]] = []
        out_of_scope: list[dict[str, Any]] = []
        for target in normalized_targets:
            if target_matches_scope(target, exclude):
                excluded.append(target)
                continue
            if target_matches_scope(target, authorized_scope):
                allowed.append(target)
            else:
                out_of_scope.append(target)

        active_authorized = (
            active_scan and confirm_authorized == AUTHORIZATION_TOKEN and bool(allowed)
        )
        warnings: list[str] = []
        if out_of_scope:
            warnings.append("Some targets are outside authorized scope and were excluded.")
        if excluded:
            warnings.append("Some targets matched exclude rules and were excluded.")
        if active_scan and not active_authorized:
            warnings.append(
                "Active scanning is blocked until confirm_authorized=I_CONFIRM_AUTHORIZED_ACTIVE_RECON."
            )

        return success(
            self.id,
            self.result_key,
            {
                "authorized": bool(allowed) and not out_of_scope,
                "active_scan_requested": active_scan,
                "active_authorized": active_authorized,
                "confirmation_required": active_scan and not active_authorized,
                "targets": normalized_targets,
                "authorized_scope": normalized_scope,
                "exclude": normalized_exclude,
                "allowed_targets": allowed,
                "excluded_targets": excluded,
                "out_of_scope_targets": out_of_scope,
                "invalid_exclude": invalid_exclude,
                "warnings": warnings,
                "limitations": [
                    "Scope validation is syntactic and does not prove legal authorization.",
                    "Active functions remain blocked without explicit confirmation.",
                ],
            },
        )
