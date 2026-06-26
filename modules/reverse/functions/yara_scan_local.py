from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult


class YaraScanLocalFunction(AnalysisFunction):
    id = "yara.scan_local"
    name = "YARA 本地扫描"
    category = "tool"
    result_key = "yara_scan"
    description = (
        "Local YARA scan that depends on configured rule files. Rule matches depend "
        "on rule quality and are candidate evidence, not final malicious conclusions "
        "or verified behavior."
    )
    config_required = True
    config_requirements = ["yara.rules_dir"]
    optional = True
    candidate_only = True
    requires_human_confirmation = True
    output_schema = {
        "matched_rules": "Matched YARA rules; candidate evidence only.",
        "rule_source": "The rule file or rule source if available.",
        "confidence": "Rule-dependent confidence; should not be treated as confirmed.",
        "verification": "Should remain unverified unless manually confirmed.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        rules_dir_value = params.get("rules_dir") or context.get("config", {}).get("yara", {}).get(
            "rules_dir"
        )
        if not rules_dir_value:
            return self._error("missing_rules_dir", "YARA rules_dir is required")
        rules_dir = Path(str(rules_dir_value))
        if not rules_dir.is_dir():
            return self._error("rules_dir_not_found", "YARA rules_dir was not found")
        sample_path = context.get("sample_path")
        if not sample_path:
            return self._error("missing_sample_path", "context.sample_path is required")
        if not Path(str(sample_path)).is_file():
            return self._error("file_not_found", "sample file was not found")

        try:
            yara = importlib.import_module("yara")
        except ImportError:
            return self._error("dependency_missing", "Python yara package is not installed")

        rule_files = sorted(
            path for path in rules_dir.iterdir() if path.suffix.lower() in {".yar", ".yara"}
        )
        if not rule_files:
            return FunctionResult(
                function_id=self.id,
                result_key=self.result_key,
                data=self._data("completed", rules_dir, 0, [], []),
            )

        try:
            compiled = yara.compile(
                filepaths={path.stem: str(path) for path in rule_files}
            )
            matches = compiled.match(str(sample_path))
        except Exception as exc:
            return self._error("scan_failed", f"YARA scan failed: {type(exc).__name__}")

        match_names = [str(match.rule) for match in matches]
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data=self._data(
                "completed",
                rules_dir,
                len(rule_files),
                [{"rule": name} for name in match_names],
                match_names,
            ),
        )

    @staticmethod
    def _data(
        status: str,
        rules_dir: Path,
        rule_files_loaded: int,
        matches: list[dict[str, Any]],
        matched_rules: list[str],
    ) -> dict[str, Any]:
        return {
            "status": status,
            "rules_dir": rules_dir.name,
            "rule_files_loaded": rule_files_loaded,
            "matches": matches,
            "matched_rules": matched_rules,
            "counts": {
                "matches": len(matches),
                "rule_files_loaded": rule_files_loaded,
            },
            "limitations": ["local YARA rule scan only", "does not execute sample"],
        }

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )
