from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

_CONFIRM_DELETE = "I_UNDERSTAND_DELETE_LOCAL_SAMPLE_COPY"


class LocalSampleCleanupFunction(AnalysisFunction):
    id = "sample.cleanup_local"
    name = "Local sample cleanup"
    category = "cleanup"
    result_key = "local_sample_cleanup"
    description = (
        "Deletes local quarantined sample copies after explicit confirmation. "
        "It only permits paths inside data/quarantine or data/sessions."
    )
    cost = "low"
    candidate_only = False
    requires_human_confirmation = True
    output_schema = {
        "deleted": "Local sample or quarantine paths deleted.",
        "missing": "Expected cleanup paths that were already absent.",
        "refused": "Paths refused because they are outside allowed cleanup roots.",
        "limitations": "Host cleanup only; it does not remove files from a guest VM.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        if params.get("confirm_delete") != _CONFIRM_DELETE:
            return self._error(
                "delete_not_confirmed",
                f"Set confirm_delete to {_CONFIRM_DELETE} to delete local sample copies.",
            )
        dry_run = bool(params.get("dry_run", False))
        include_session_sample = bool(params.get("include_session_sample", True))
        include_download_cleanup = bool(params.get("include_download_cleanup", True))

        workspace = _context_path(context, "workspace_root", Path.cwd()).resolve()
        allowed_roots = _unique_paths(
            [
                _context_path(context, "quarantine_dir", workspace / "data" / "quarantine"),
                _context_path(context, "session_base_dir", workspace / "data" / "sessions"),
                workspace / "data" / "quarantine",
                workspace / "data" / "sessions",
            ]
        )
        candidates = _cleanup_candidates(
            context,
            include_session_sample=include_session_sample,
            include_download_cleanup=include_download_cleanup,
        )
        deleted: list[str] = []
        missing: list[str] = []
        refused: list[dict[str, str]] = []

        for candidate in candidates:
            path = _resolve_workspace_path(candidate, workspace)
            display_path = _display_path(path, workspace)
            if not _inside_allowed_root(path, allowed_roots):
                refused.append({"path": display_path, "reason": "outside_allowed_cleanup_roots"})
                continue
            if not path.exists():
                missing.append(display_path)
                continue
            if not dry_run:
                try:
                    if path.is_dir():
                        shutil.rmtree(path)
                    else:
                        path.unlink()
                except OSError as exc:
                    refused.append({"path": display_path, "reason": f"delete_failed:{exc}"})
                    continue
            deleted.append(display_path)

        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "dry_run": dry_run,
                "deleted": deleted,
                "missing": missing,
                "refused": refused,
                "counts": {
                    "deleted": len(deleted),
                    "missing": len(missing),
                    "refused": len(refused),
                },
                "requires_human_confirmation": True,
                "limitations": [
                    "host cleanup only",
                    "does not remove guest VM files",
                    "only deletes paths under data/quarantine or data/sessions",
                ],
            },
        )

    def _error(self, code: str, message: str) -> FunctionResult:
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            status="error",
            error={"code": code, "message": message},
        )


def _cleanup_candidates(
    context: dict[str, Any],
    include_session_sample: bool,
    include_download_cleanup: bool,
) -> list[str]:
    candidates: list[str] = []
    if include_download_cleanup:
        download = _result_data(context, "malwarebazaar_download")
        cleanup = download.get("cleanup") if isinstance(download.get("cleanup"), dict) else {}
        candidates.extend(_string_list(cleanup.get("paths")))
    if include_session_sample:
        sample_path = str(context.get("sample_path") or "")
        if sample_path:
            candidates.append(sample_path)
    return _unique(candidates)


def _result_data(context: dict[str, Any], result_key: str) -> dict[str, Any]:
    result = context.get("results", {}).get(result_key)
    if not isinstance(result, dict) or result.get("status") == "error":
        return {}
    data = result.get("data", {})
    return data if isinstance(data, dict) else {}


def _resolve_workspace_path(value: str, workspace: Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = workspace / path
    return path.resolve(strict=False)


def _context_path(context: dict[str, Any], key: str, default: Path) -> Path:
    value = str(context.get(key) or "")
    return Path(value) if value else default


def _unique_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    result: list[Path] = []
    for path in paths:
        resolved = path.resolve(strict=False)
        key = str(resolved).casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(resolved)
    return result


def _inside_allowed_root(path: Path, allowed_roots: list[Path]) -> bool:
    return any(path == root or root in path.parents for root in allowed_roots)


def _display_path(path: Path, workspace: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result
