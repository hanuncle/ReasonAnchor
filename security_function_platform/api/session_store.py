from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_function_platform.core.workflow import WorkflowDefinition

_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
_SAFE_RAW_OUTPUT_ID_RE = re.compile(r"[^A-Za-z0-9_-]+")
_SENSITIVE_KEYS = {"api_key", "auth_key", "auth-key", "token"}
_VERIFICATION_VALUES = {"已验证", "未验证", "verified", "unverified"}


class SessionStore:
    def __init__(self, base_dir: str | Path = "data/sessions") -> None:
        self.base_dir = Path(base_dir)
        self.reports_dir = self.base_dir.parent / "reports"
        self.batch_jobs_dir = self.base_dir.parent / "batch_jobs"

    def create_session_from_upload(self, filename: str, content: bytes) -> dict[str, Any]:
        session_id = str(uuid.uuid4())
        now = self._now()
        safe_filename = self._safe_filename(filename)
        session_dir = self._session_dir(session_id)
        sample_dir = session_dir / "sample"
        sample_dir.mkdir(parents=True, exist_ok=False)

        stored_path = sample_dir / safe_filename
        stored_path.write_bytes(content)

        session = {
            "session_id": session_id,
            "session_type": "sample",
            "created_at": now,
            "updated_at": now,
            "sample": {
                "filename": safe_filename,
                "stored_path": str(stored_path),
                "size": len(content),
                "uploaded_at": now,
            },
            "workflow": None,
            "summary": {
                "status": "created",
                "functions_run": 0,
                "result_keys": [],
                "error_count": 0,
            },
            "raw_outputs": {},
        }
        self._write_session(session)
        return session

    def create_target_session(
        self,
        targets: Any,
        authorized_scope: Any,
        exclude: Any = None,
        module_id: str = "",
        label: str = "",
        notes: str = "",
    ) -> dict[str, Any]:
        target_values = self._string_list(targets)
        scope_values = self._string_list(authorized_scope)
        if not target_values:
            raise ValueError("missing_targets")
        if not scope_values:
            raise ValueError("missing_authorized_scope")

        session_id = str(uuid.uuid4())
        now = self._now()
        display_name = label.strip() or target_values[0]
        safe_filename = self._safe_filename(f"target-{display_name}.json")
        session = {
            "session_id": session_id,
            "session_type": "target",
            "created_at": now,
            "updated_at": now,
            "sample": {
                "filename": safe_filename,
                "stored_path": "",
                "size": 0,
                "uploaded_at": now,
            },
            "target": {
                "label": display_name,
                "targets": target_values,
                "authorized_scope": scope_values,
                "exclude": self._string_list(exclude),
                "module_id": module_id.strip(),
                "notes": notes.strip(),
                "created_at": now,
            },
            "workflow": None,
            "summary": {
                "status": "created",
                "functions_run": 0,
                "result_keys": [],
                "error_count": 0,
            },
            "raw_outputs": {},
        }
        self._write_session(session)
        return session

    def get_session(self, session_id: str) -> dict[str, Any]:
        path = self._session_file(session_id)
        if not path.is_file():
            raise FileNotFoundError(session_id)
        return json.loads(path.read_text(encoding="utf-8"))

    def list_sessions(self) -> dict[str, Any]:
        sessions: list[dict[str, Any]] = []
        if not self.base_dir.is_dir():
            return {"sessions": sessions, "count": 0}
        for session_file in sorted(
            self.base_dir.glob("*/session.json"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        ):
            try:
                session = json.loads(session_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(session, dict):
                continue
            sessions.append(
                {
                    "session_id": str(session.get("session_id") or session_file.parent.name),
                    "session_type": str(session.get("session_type") or "sample"),
                    "created_at": str(session.get("created_at") or ""),
                    "updated_at": str(session.get("updated_at") or ""),
                    "sample": session.get("sample") if isinstance(session.get("sample"), dict) else {},
                    "target": session.get("target") if isinstance(session.get("target"), dict) else {},
                    "summary": (
                        session.get("summary") if isinstance(session.get("summary"), dict) else {}
                    ),
                    "workflow": (
                        session.get("workflow") if isinstance(session.get("workflow"), dict) else None
                    ),
                }
            )
        return {"sessions": sessions, "count": len(sessions)}

    def save_session(self, session: dict[str, Any]) -> dict[str, Any]:
        session["updated_at"] = self._now()
        self._write_session(session)
        return session

    def set_workflow(self, session_id: str, workflow: WorkflowDefinition) -> dict[str, Any]:
        session = self.get_session(session_id)
        session["workflow"] = workflow.to_dict()
        return self.save_session(session)

    def save_run_outputs(self, session_id: str, context: dict[str, Any]) -> dict[str, Any]:
        session = self.get_session(session_id)
        raw_outputs = dict(context.get("results") or {})
        result_keys = list(raw_outputs.keys())
        session["raw_outputs"] = raw_outputs
        session["summary"] = {
            "status": "completed",
            "functions_run": len(raw_outputs),
            "result_keys": result_keys,
            "error_count": sum(
                1 for result in raw_outputs.values() if result.get("status") == "error"
            ),
        }
        return self.save_session(session)

    def clear_raw_output(self, session_id: str) -> None:
        raw_output = {
            "session_id": session_id,
            "items": [],
        }
        self._write_raw_output(session_id, raw_output)

    def append_raw_output_step(
        self,
        session_id: str,
        index: int,
        result: dict[str, Any],
        function_name: str | None = None,
    ) -> dict[str, Any]:
        raw_output = self.get_raw_output(session_id)
        result_key = str(result.get("result_key", "output"))
        raw_output["items"].append(
            {
                "raw_output_id": self._raw_output_id(index, result_key),
                "index": index,
                "function_id": result.get("function_id", ""),
                "function_name": function_name or result.get("function_id", ""),
                "result_key": result.get("result_key", ""),
                "status": result.get("status", ""),
                "output": result,
            }
        )
        self._write_raw_output(session_id, raw_output)
        return raw_output

    def get_raw_output_map(self, session_id: str) -> dict[str, Any]:
        raw_output = self.get_raw_output(session_id)
        return {
            "session_id": raw_output["session_id"],
            "items": [
                {
                    "raw_output_id": item.get("raw_output_id", ""),
                    "index": item.get("index", 0),
                    "function_id": item.get("function_id", ""),
                    "function_name": item.get("function_name", item.get("function_id", "")),
                    "result_key": item.get("result_key", ""),
                    "status": item.get("status", ""),
                }
                for item in raw_output.get("items", [])
            ],
        }

    def get_raw_output_item(self, session_id: str, raw_output_id: str) -> dict[str, Any]:
        raw_output = self.get_raw_output(session_id)
        for item in raw_output.get("items", []):
            if item.get("raw_output_id") == raw_output_id:
                return {
                    "session_id": session_id,
                    "item": item,
                }
        raise KeyError(raw_output_id)

    def save_session_result(self, session_id: str, result: dict[str, Any]) -> dict[str, Any]:
        saved_result = self._normalize_result(session_id, result)
        path = self._result_file(session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(saved_result, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return saved_result

    def get_session_result(self, session_id: str) -> dict[str, Any]:
        path = self._result_file(session_id)
        if not path.is_file():
            return self._default_result(session_id)
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return self._default_result(session_id)
        return self._normalize_result(session_id, data)

    def save_sample_set_report(self, report: dict[str, Any]) -> dict[str, Any]:
        saved_report = self._sanitize_result(dict(report))
        markdown = str(saved_report.pop("markdown", "") or "")
        report_id = str(saved_report.get("report_id") or uuid.uuid4())
        self._validate_report_id(report_id)
        saved_report["report_id"] = report_id
        saved_report.setdefault("created_at", self._now())
        saved_report.setdefault("schema_id", "sample_set.report.v2")
        saved_report.setdefault(
            "artifacts",
            {"json": "report.json", "markdown": "report.md" if markdown else ""},
        )
        path = self._report_file(report_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(saved_report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        if markdown:
            (path.parent / "report.md").write_text(markdown, encoding="utf-8")
        return saved_report

    def get_sample_set_report(self, report_id: str) -> dict[str, Any]:
        path = self._report_file(report_id)
        if not path.is_file():
            raise FileNotFoundError(report_id)
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise FileNotFoundError(report_id)
        return data

    def list_sample_set_reports(self) -> dict[str, Any]:
        reports: list[dict[str, Any]] = []
        if not self.reports_dir.is_dir():
            return {"reports": reports, "count": 0}
        for report_file in sorted(
            self.reports_dir.glob("*/report.json"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        ):
            try:
                report = json.loads(report_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(report, dict):
                continue
            reports.append(
                {
                    "report_id": str(report.get("report_id") or report_file.parent.name),
                    "schema_id": str(report.get("schema_id") or ""),
                    "created_at": str(report.get("created_at") or ""),
                    "summary": (
                        report.get("summary") if isinstance(report.get("summary"), dict) else {}
                    ),
                    "sample_count": len(report.get("samples", []))
                    if isinstance(report.get("samples"), list)
                    else 0,
                    "behavior_category_count": _safe_int(
                        report.get("summary", {}).get("behavior_category_count")
                        if isinstance(report.get("summary"), dict)
                        else 0
                    ),
                    "attack_technique_count": _safe_int(
                        report.get("summary", {}).get("attack_technique_count")
                        if isinstance(report.get("summary"), dict)
                        else 0
                    ),
                }
            )
        return {"reports": reports, "count": len(reports)}

    def create_batch_job(
        self,
        session_ids: list[str],
        workflow_id: str,
        create_report: bool = True,
    ) -> dict[str, Any]:
        job_id = str(uuid.uuid4())
        now = self._now()
        job = {
            "job_id": job_id,
            "batch_id": job_id,
            "status": "queued",
            "created_at": now,
            "updated_at": now,
            "started_at": "",
            "completed_at": "",
            "workflow_id": workflow_id,
            "session_ids": session_ids,
            "create_report": bool(create_report),
            "count": len(session_ids),
            "completed_count": 0,
            "failed_count": 0,
            "current_session_id": "",
            "report_id": "",
            "items": [
                {
                    "session_id": session_id,
                    "status": "pending",
                    "sample": {},
                    "summary": {},
                }
                for session_id in session_ids
            ],
            "error": {},
        }
        return self.save_batch_job(job)

    def save_batch_job(self, job: dict[str, Any]) -> dict[str, Any]:
        saved_job = self._sanitize_result(dict(job))
        job_id = str(saved_job.get("job_id") or saved_job.get("batch_id") or "")
        self._validate_batch_job_id(job_id)
        saved_job["job_id"] = job_id
        saved_job.setdefault("batch_id", job_id)
        saved_job["updated_at"] = self._now()
        path = self._batch_job_file(job_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(saved_job, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return saved_job

    def get_batch_job(self, job_id: str) -> dict[str, Any]:
        path = self._batch_job_file(job_id)
        if not path.is_file():
            raise FileNotFoundError(job_id)
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise FileNotFoundError(job_id)
        return data

    def list_batch_jobs(self) -> dict[str, Any]:
        jobs: list[dict[str, Any]] = []
        if not self.batch_jobs_dir.is_dir():
            return {"jobs": jobs, "count": 0}
        for job_file in sorted(
            self.batch_jobs_dir.glob("*/job.json"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        ):
            try:
                job = json.loads(job_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(job, dict):
                continue
            jobs.append(
                {
                    "job_id": str(job.get("job_id") or job_file.parent.name),
                    "batch_id": str(job.get("batch_id") or job.get("job_id") or ""),
                    "status": str(job.get("status") or ""),
                    "created_at": str(job.get("created_at") or ""),
                    "updated_at": str(job.get("updated_at") or ""),
                    "workflow_id": str(job.get("workflow_id") or ""),
                    "count": _safe_int(job.get("count")),
                    "completed_count": _safe_int(job.get("completed_count")),
                    "failed_count": _safe_int(job.get("failed_count")),
                    "report_id": str(job.get("report_id") or ""),
                }
            )
        return {"jobs": jobs, "count": len(jobs)}

    def save_ai_output(self, session_id: str, ai_output: dict[str, Any]) -> dict[str, Any]:
        ai_output["session_id"] = session_id
        ai_output.setdefault("items", [])
        path = self._ai_output_file(session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(ai_output, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return ai_output

    def append_ai_output_item(self, session_id: str, item: dict[str, Any]) -> dict[str, Any]:
        ai_output = self.get_ai_output(session_id)
        ai_output["items"].append(item)
        return self.save_ai_output(session_id, ai_output)

    def get_ai_output(self, session_id: str) -> dict[str, Any]:
        path = self._ai_output_file(session_id)
        if not path.is_file():
            return {"session_id": session_id, "items": []}
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"session_id": session_id, "items": []}

    def get_ai_output_item(self, session_id: str, raw_output_id: str) -> dict[str, Any]:
        ai_output = self.get_ai_output(session_id)
        for item in ai_output.get("items", []):
            if item.get("raw_output_id") == raw_output_id:
                return {"session_id": session_id, "item": item}
        raise KeyError(raw_output_id)

    def clear_ai_output(self, session_id: str) -> None:
        self.save_ai_output(session_id, {"session_id": session_id, "items": []})

    def get_raw_output(self, session_id: str) -> dict[str, Any]:
        path = self._raw_output_file(session_id)
        if not path.is_file():
            return {
                "session_id": session_id,
                "items": [],
            }
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _safe_filename(filename: str) -> str:
        basename = Path(filename or "sample.bin").name
        safe = _SAFE_FILENAME_RE.sub("_", basename).strip("._")
        return safe or "sample.bin"

    def _session_dir(self, session_id: str) -> Path:
        self._validate_session_id(session_id)
        return self.base_dir / session_id

    def _session_file(self, session_id: str) -> Path:
        return self._session_dir(session_id) / "session.json"

    def _raw_output_file(self, session_id: str) -> Path:
        return self._session_dir(session_id) / "raw_output" / "raw_output.json"

    def _result_file(self, session_id: str) -> Path:
        return self._session_dir(session_id) / "result" / "result.json"

    def _ai_output_file(self, session_id: str) -> Path:
        return self._session_dir(session_id) / "ai_output" / "ai_output.json"

    def _report_file(self, report_id: str) -> Path:
        self._validate_report_id(report_id)
        return self.reports_dir / report_id / "report.json"

    def _batch_job_file(self, job_id: str) -> Path:
        self._validate_batch_job_id(job_id)
        return self.batch_jobs_dir / job_id / "job.json"

    def _write_session(self, session: dict[str, Any]) -> None:
        path = self._session_file(str(session["session_id"]))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(session, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _write_raw_output(self, session_id: str, raw_output: dict[str, Any]) -> None:
        path = self._raw_output_file(session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(raw_output, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    @staticmethod
    def _raw_output_id(index: int, result_key: str) -> str:
        safe_key = _SAFE_RAW_OUTPUT_ID_RE.sub("_", result_key).strip("_") or "output"
        return f"raw-{index:03d}-{safe_key}"

    @staticmethod
    def _default_result(session_id: str) -> dict[str, Any]:
        return {
            "session_id": session_id,
            "file": {},
            "summary": {
                "overall": "",
                "risk_level": "unknown",
                "limitations": [],
            },
            "behaviors": [],
        }

    @staticmethod
    def _sanitize_result(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: SessionStore._sanitize_result(item)
                for key, item in value.items()
                if str(key).lower() not in _SENSITIVE_KEYS
            }
        if isinstance(value, list):
            return [SessionStore._sanitize_result(item) for item in value]
        return value

    @staticmethod
    def _normalize_result(session_id: str, result: dict[str, Any]) -> dict[str, Any]:
        saved_result = SessionStore._sanitize_result(dict(result))
        saved_result["session_id"] = session_id
        saved_result.setdefault("file", {})
        saved_result.setdefault(
            "summary",
            {"overall": "", "risk_level": "unknown", "limitations": []},
        )
        saved_result["behaviors"] = SessionStore._normalize_behaviors(
            saved_result.get("behaviors", [])
        )
        return saved_result

    @staticmethod
    def _normalize_behaviors(value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            return []

        behaviors: list[dict[str, Any]] = []
        for item in value:
            if not isinstance(item, dict):
                continue
            behavior = dict(item)
            behavior["behavior"] = str(behavior.get("behavior") or "")
            behavior["evidence"] = SessionStore._normalize_evidence(
                behavior.get("evidence"),
                behavior.get("raw_output_ids"),
            )
            behavior["raw_output_ids"] = [
                source["raw_output_id"]
                for source in behavior["evidence"]["sources"]
                if source.get("raw_output_id")
            ]
            behavior["evidence_missing"] = not bool(behavior["evidence"]["sources"])
            behavior["verification"] = SessionStore._normalize_verification(
                behavior.get("verification")
            )
            function_level_source = behavior.get("function_level_source")
            if function_level_source is None and behavior.get("function_source"):
                function_level_source = behavior.get("function_source")
            behavior["function_level_source"] = SessionStore._normalize_function_source(
                function_level_source
            )
            behavior.pop("function_source", None)
            behaviors.append(behavior)
        return behaviors

    @staticmethod
    def _normalize_evidence(value: Any, raw_output_ids: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            summary = str(value.get("summary") or "")
            sources = SessionStore._normalize_evidence_sources(value.get("sources"))
        else:
            summary = str(value or "")
            sources = []

        if not sources:
            sources = [
                {"source_type": "raw_output", "raw_output_id": raw_id}
                for raw_id in SessionStore._string_list(raw_output_ids)
            ]
        if not summary and not sources:
            summary = "无证据来源"
        return {"summary": summary, "sources": sources}

    @staticmethod
    def _normalize_evidence_sources(value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            return []
        sources: list[dict[str, Any]] = []
        for item in value:
            if not isinstance(item, dict):
                continue
            source = {
                "source_type": str(item.get("source_type") or "raw_output"),
                "raw_output_id": str(item.get("raw_output_id") or ""),
                "function_id": str(item.get("function_id") or ""),
                "result_key": str(item.get("result_key") or ""),
                "description": str(item.get("description") or ""),
            }
            if any(source.values()):
                sources.append(source)
        return sources

    @staticmethod
    def _normalize_verification(value: Any) -> str:
        verification = str(value or "未验证")
        return verification if verification in _VERIFICATION_VALUES else "未验证"

    @staticmethod
    def _normalize_function_source(value: Any) -> dict[str, str]:
        if isinstance(value, dict):
            return {
                "tool": str(value.get("tool") or ""),
                "function_name": str(value.get("function_name") or ""),
                "address": str(value.get("address") or ""),
                "source_raw_output_id": str(value.get("source_raw_output_id") or ""),
                "note": str(value.get("note") or ""),
            }
        text = str(value or "")
        return {
            "tool": "",
            "function_name": "",
            "address": "",
            "source_raw_output_id": "",
            "note": text or "未进行函数级分析",
        }

    @staticmethod
    def _string_list(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value] if value else []
        if isinstance(value, list):
            return [str(item) for item in value if str(item)]
        return []

    @staticmethod
    def _validate_session_id(session_id: str) -> None:
        try:
            uuid.UUID(session_id)
        except ValueError as exc:
            raise FileNotFoundError(session_id) from exc

    @staticmethod
    def _validate_report_id(report_id: str) -> None:
        try:
            uuid.UUID(report_id)
        except ValueError as exc:
            raise FileNotFoundError(report_id) from exc

    @staticmethod
    def _validate_batch_job_id(job_id: str) -> None:
        try:
            uuid.UUID(job_id)
        except ValueError as exc:
            raise FileNotFoundError(job_id) from exc


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
