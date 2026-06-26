from __future__ import annotations

import re
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

from behavior_taxonomy import dynamic_rules, event_groups

_EVENT_GROUPS = event_groups()
_BEHAVIOR_RULES: dict[str, dict[str, Any]] = dynamic_rules()
_NOISE_TEXT_MARKERS = [
    "vmware tools",
    "poweron-vm-default.bat",
    "export-dynamictelemetry.ps1",
    "export_dynamic_now.bat",
    "cleanup_uploaded_sample.bat",
    "__psscriptpolicytest_",
    "\\telemetry\\noriben\\",
    "noriben_",
    "noriben.txt",
    "noriben_timeline.csv",
    "procmonconfiguration.pmc",
    "mpcmdrun.exe",
    "taskhostw.exe",
    "sihclient.exe",
    "mscorsvw.exe",
]
_NOISE_PROCESS_NAMES = {
    "python.exe",
    "pythonw.exe",
    "procmon.exe",
    "procmon64.exe",
    "sysmon.exe",
    "sysmon64.exe",
    "vmtoolsd.exe",
    "hayabusa.exe",
    "chainsaw.exe",
    "hollows_hunter64.exe",
    "pe-sieve64.exe",
    "wermgr.exe",
    "werfault.exe",
    "mpcmdrun.exe",
    "taskhostw.exe",
    "sihclient.exe",
    "mscorsvw.exe",
}


class BehaviorMapDynamicFunction(AnalysisFunction):
    id = "behavior.map_dynamic"
    name = "Dynamic behavior mapping"
    category = "dynamic"
    result_key = "dynamic_behavior_map"
    description = (
        "Maps normalized dynamic telemetry into observed behavior categories. "
        "This function only consumes telemetry supplied by params or context and "
        "does not execute samples or connect to a VM."
    )
    cost = "low"
    candidate_only = True
    requires_human_confirmation = True
    requires_results = ["dynamic_telemetry"]
    output_schema = {
        "behaviors": "Observed behavior categories mapped from normalized telemetry.",
        "counts": "Behavior, evidence, and telemetry event counts.",
        "limitations": "Telemetry mapping only; depends on collection quality.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        telemetry, source, upstream_status, upstream_data = _dynamic_telemetry(context, params)
        if upstream_status == "skipped":
            return FunctionResult(
                function_id=self.id,
                result_key=self.result_key,
                status="skipped",
                data={
                    "source": source,
                    "skipped": True,
                    "skip_reason": str(
                        upstream_data.get("skip_reason") or "dynamic_telemetry_skipped"
                    ),
                    "behaviors": [],
                    "counts": {"behaviors": 0, "evidence": 0, "telemetry_events": 0},
                    "requires_human_confirmation": True,
                    "limitations": [
                        "Dynamic behavior mapping skipped because dynamic telemetry was skipped.",
                        "No runtime behavior was observed.",
                    ],
                },
            )
        if not telemetry:
            return self._error(
                "missing_dynamic_telemetry",
                "dynamic telemetry is required in params.telemetry or results.dynamic_telemetry",
            )
        if not isinstance(telemetry, dict):
            return self._error(
                "invalid_dynamic_telemetry",
                "dynamic telemetry must be a dict",
            )

        max_evidence = _int_param(params, "max_evidence_per_behavior", 60)
        mapper = _DynamicBehaviorMapper(telemetry, source, max_evidence, context, params)
        behaviors = mapper.map_behaviors()
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "source": source,
                "telemetry_id": str(telemetry.get("telemetry_id", "")),
                "behaviors": behaviors,
                "counts": {
                    "behaviors": len(behaviors),
                    "evidence": sum(len(item.get("evidence", [])) for item in behaviors),
                    "telemetry_events": mapper.event_count,
                    "mapped_events": mapper.mapped_event_count,
                    "excluded_events": mapper.excluded_event_count,
                },
                "attribution": mapper.attribution_summary(),
                "requires_human_confirmation": True,
                "limitations": [
                    "dynamic telemetry mapping only",
                    "depends on telemetry quality and coverage",
                    "sample attribution filters obvious VM, collection, and OS noise before behavior mapping",
                    "process-name-only matches are not treated as confirmed sample process-tree evidence",
                    "does not execute samples",
                    "does not connect to a VM",
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


class _DynamicBehaviorMapper:
    def __init__(
        self,
        telemetry: dict[str, Any],
        source: str,
        max_evidence: int,
        context: dict[str, Any],
        params: dict[str, Any],
    ) -> None:
        self.telemetry = telemetry
        self.source = source
        self.max_evidence = max(0, max_evidence)
        self.event_count = 0
        self.mapped_event_count = 0
        self.excluded_event_count = 0
        self.attributor = _TelemetryAttributor(telemetry, context, params)
        self.evidence_by_category: dict[str, list[dict[str, Any]]] = {
            key: [] for key in _BEHAVIOR_RULES
        }
        self.score_by_category: dict[str, int] = {key: 0 for key in _BEHAVIOR_RULES}

    def map_behaviors(self) -> list[dict[str, Any]]:
        for group in _EVENT_GROUPS:
            events = self.telemetry.get(group, [])
            if not isinstance(events, list):
                continue
            for event in events:
                if not isinstance(event, dict):
                    continue
                self.event_count += 1
                decision = self.attributor.classify(group, event)
                if not decision["map_event"]:
                    self.excluded_event_count += 1
                    continue
                self.mapped_event_count += 1
                attributed_event = dict(event)
                attributed_event["attribution"] = decision["attribution"]
                self._map_event(group, attributed_event)

        behaviors: list[dict[str, Any]] = []
        for category, rule in _BEHAVIOR_RULES.items():
            evidence = self.evidence_by_category.get(category, [])
            if not evidence:
                continue
            score = self.score_by_category.get(category, 0)
            behaviors.append(
                {
                    "behavior_id": category,
                    "category": category,
                    "name": str(rule["name"]),
                    "confidence": _confidence(score),
                    "score": score,
                    "evidence": evidence[: self.max_evidence],
                    "verification": "observed_dynamic_telemetry",
                }
            )
        behaviors.sort(key=lambda item: (-int(item["score"]), str(item["category"])))
        return behaviors

    def attribution_summary(self) -> dict[str, Any]:
        return self.attributor.summary(self.event_count, self.mapped_event_count)

    def _map_event(self, group: str, event: dict[str, Any]) -> None:
        event_type = str(event.get("event_type", "")).lower()
        text = _event_text(event)

        for category, rule in _BEHAVIOR_RULES.items():
            event_groups = rule.get("event_groups", [])
            event_types = rule.get("event_types", [])
            keywords = rule.get("keywords", [])
            if group not in event_groups:
                continue
            if category == "command_execution" and self.attributor.is_initial_sample_launch(event):
                continue

            matched_reasons: list[str] = []
            if event_type and event_type in event_types:
                matched_reasons.append(f"event_type:{event_type}")
            for keyword in keywords:
                if str(keyword).lower() in text:
                    matched_reasons.append(f"keyword:{keyword}")
                    break

            if (
                category == "registry_persistence"
                and group == "registry_events"
                and not any(reason.startswith("keyword:") for reason in matched_reasons)
            ):
                continue

            if not matched_reasons:
                continue
            self._add_evidence(
                category,
                _event_evidence(
                    self.source,
                    group,
                    event,
                    matched_reasons,
                ),
                weight=_weight(matched_reasons),
            )

    def _add_evidence(self, category: str, evidence: dict[str, Any], weight: int) -> None:
        if category not in self.evidence_by_category:
            return
        normalized = {
            key: value
            for key, value in evidence.items()
            if value is not None and value != ""
        }
        if normalized in self.evidence_by_category[category]:
            return
        if len(self.evidence_by_category[category]) < self.max_evidence:
            self.evidence_by_category[category].append(normalized)
        self.score_by_category[category] += weight


def _dynamic_telemetry(
    context: dict[str, Any],
    params: dict[str, Any],
) -> tuple[Any, str, str, dict[str, Any]]:
    if isinstance(params.get("telemetry"), dict):
        return params["telemetry"], "params.telemetry", "success", {}
    result = context.get("results", {}).get("dynamic_telemetry")
    if isinstance(result, dict) and result.get("status") != "error":
        data = result.get("data", {})
        if isinstance(data, dict):
            return data, "results.dynamic_telemetry", str(result.get("status") or ""), data
    return None, "", "", {}


class _TelemetryAttributor:
    def __init__(
        self,
        telemetry: dict[str, Any],
        context: dict[str, Any],
        params: dict[str, Any],
    ) -> None:
        self.telemetry = telemetry
        self.sample_indicators = _sample_indicators(telemetry, context, params)
        self.strict = bool(self.sample_indicators) and bool(params.get("attribute_to_sample", True))
        self.process_guids: set[str] = set()
        self.pids: set[str] = set()
        self.process_names: set[str] = set()
        self.counts = {
            "confirmed_sample_behavior": 0,
            "likely_sample_behavior": 0,
            "environment_noise": 0,
            "unattributed": 0,
        }
        self._build_process_tree()

    def classify(self, group: str, event: dict[str, Any]) -> dict[str, Any]:
        reason = ""
        confidence = "none"
        label = "unattributed"
        text = _event_text(event)
        own_process_mentions_sample = self._event_own_process_mentions_sample(event)
        is_noise = _is_environment_noise(event, text)

        if is_noise:
            label = "environment_noise"
            confidence = "high"
            reason = "known VM, collection, or OS background activity"
        elif self._event_source_in_sample_tree(event):
            label = "confirmed_sample_behavior"
            confidence = "high"
            reason = "event source process is in sample process tree"
        elif own_process_mentions_sample:
            label = "likely_sample_behavior"
            confidence = "medium"
            reason = "event source process or command line references sample identity"
        elif not self.strict:
            label = "unattributed"
            confidence = "low"
            reason = "no sample identity configured; preserving telemetry mapping"
        else:
            label = "unattributed"
            confidence = "low"
            reason = "event is outside sample process tree"

        self.counts[label] += 1
        map_event = label in {"confirmed_sample_behavior", "likely_sample_behavior"} or (
            label == "unattributed" and not self.strict
        )
        return {
            "map_event": map_event,
            "attribution": {
                "status": label,
                "confidence": confidence,
                "reason": reason,
                "event_group": group,
            },
        }

    def summary(self, telemetry_events: int, mapped_events: int) -> dict[str, Any]:
        return {
            "enabled": True,
            "strict": self.strict,
            "sample_indicators": sorted(self.sample_indicators)[:20],
            "sample_process_guids": sorted(self.process_guids)[:20],
            "sample_pids": sorted(self.pids)[:20],
            "sample_process_names": sorted(self.process_names)[:20],
            "counts": dict(self.counts),
            "telemetry_events": telemetry_events,
            "mapped_events": mapped_events,
            "excluded_events": max(0, telemetry_events - mapped_events),
        }

    def _build_process_tree(self) -> None:
        events = [
            event
            for event in self.telemetry.get("process_events", [])
            if isinstance(event, dict)
        ]
        for event in events:
            if self._event_is_sample_process_start(event):
                self._remember_process(event)

        changed = True
        while changed:
            changed = False
            for event in events:
                if not self._event_is_child_process_start(event):
                    continue
                if _is_environment_noise(event, _event_text(event)):
                    continue
                if self._event_parent_in_sample_tree(event):
                    before = (len(self.process_guids), len(self.pids), len(self.process_names))
                    self._remember_process(event)
                    after = (len(self.process_guids), len(self.pids), len(self.process_names))
                    changed = changed or before != after

    def _remember_process(self, event: dict[str, Any]) -> None:
        for key in ["process_guid", "ProcessGuid"]:
            value = _lower_value(event.get(key))
            if value:
                self.process_guids.add(value)
        value = _raw_field_value(event, "ProcessGuid")
        if value:
            self.process_guids.add(_lower_value(value))
        for key in ["pid", "process_id", "ProcessId"]:
            value = _id_value(event.get(key))
            if value:
                self.pids.add(value)
        value = _raw_field_value(event, "ProcessId")
        if value:
            self.pids.add(_id_value(value))
        name = _process_name(event)
        if name:
            self.process_names.add(name)

    def _event_source_in_sample_tree(self, event: dict[str, Any]) -> bool:
        for key in [
            "process_guid",
            "ProcessGuid",
            "source_process_guid",
            "SourceProcessGuid",
        ]:
            value = _lower_value(event.get(key))
            if value and value in self.process_guids:
                return True
        for label in ["ProcessGuid", "SourceProcessGuid"]:
            value = _lower_value(_raw_field_value(event, label))
            if value and value in self.process_guids:
                return True

        for key in ["parent_pid", "ParentProcessId"]:
            value = _id_value(event.get(key))
            if value and value in self.pids:
                return True
        value = _id_value(_raw_field_value(event, "ParentProcessId"))
        if value and value in self.pids:
            return True

        current_guids = {
            _lower_value(event.get(key))
            for key in ["process_guid", "ProcessGuid", "source_process_guid", "SourceProcessGuid"]
        }
        current_guids.update(
            _lower_value(_raw_field_value(event, label))
            for label in ["ProcessGuid", "SourceProcessGuid"]
        )
        current_guids.discard("")
        current_pids = [
            _id_value(event.get(key))
            for key in [
                "pid",
                "process_id",
                "ProcessId",
                "source_pid",
                "SourceProcessId",
            ]
        ]
        current_pids.extend(
            _id_value(_raw_field_value(event, label))
            for label in ["ProcessId", "SourceProcessId"]
        )
        if current_guids:
            return bool(current_guids & self.process_guids)
        for value in current_pids:
            if value and value in self.pids:
                return True
        return False

    def _event_parent_in_sample_tree(self, event: dict[str, Any]) -> bool:
        for key in ["parent_process_guid", "ParentProcessGuid"]:
            value = _lower_value(event.get(key))
            if value and value in self.process_guids:
                return True
        value = _lower_value(_raw_field_value(event, "ParentProcessGuid"))
        if value and value in self.process_guids:
            return True
        for key in ["parent_pid", "ParentProcessId"]:
            value = _id_value(event.get(key))
            if value and value in self.pids:
                return True
        value = _id_value(_raw_field_value(event, "ParentProcessId"))
        return bool(value and value in self.pids)

    def _event_is_sample_process_start(self, event: dict[str, Any]) -> bool:
        if str(event.get("event_type") or "").lower() not in {"process_create", "process_start"}:
            return False
        return self._event_own_process_mentions_sample(event)

    @staticmethod
    def _event_is_child_process_start(event: dict[str, Any]) -> bool:
        return str(event.get("event_type") or "").lower() in {"process_create", "process_start"}

    def _event_own_process_mentions_sample(self, event: dict[str, Any]) -> bool:
        text = " ".join(
            str(value or "").lower()
            for value in [
                event.get("process_name"),
                event.get("image_path"),
                event.get("command_line"),
                event.get("Image"),
                event.get("CommandLine"),
            ]
        )
        return self._event_mentions_sample(text)

    def is_initial_sample_launch(self, event: dict[str, Any]) -> bool:
        if not self._event_is_sample_process_start(event):
            return False
        return not self._event_parent_in_sample_tree(event)

    def _event_mentions_sample(self, text: str) -> bool:
        return any(indicator and indicator in text for indicator in self.sample_indicators)


def _sample_indicators(
    telemetry: dict[str, Any],
    context: dict[str, Any],
    params: dict[str, Any],
) -> set[str]:
    values: list[Any] = [
        params.get("sample_filename"),
        params.get("sample_path"),
        params.get("guest_sample_path"),
        context.get("filename"),
        context.get("sample_path"),
    ]
    sample = telemetry.get("sample")
    if isinstance(sample, dict):
        values.extend([sample.get("filename"), sample.get("path"), sample.get("sha256")])
    for result_key in ["dynamic_vm_upload", "dynamic_vm_run"]:
        result = context.get("results", {}).get(result_key)
        if not isinstance(result, dict):
            continue
        data = result.get("data")
        if isinstance(data, dict):
            values.extend(
                [
                    data.get("filename"),
                    data.get("guest_sample_path"),
                    data.get("host_sample_path"),
                ]
            )

    indicators: set[str] = set()
    for value in values:
        text = str(value or "").strip().lower()
        if not text:
            continue
        indicators.add(text)
        basename = _basename_lower(text)
        if basename:
            indicators.add(basename)
    return {item for item in indicators if len(item) >= 3}


def _is_environment_noise(event: dict[str, Any], text: str) -> bool:
    process_name = _process_name(event)
    if process_name in _NOISE_PROCESS_NAMES:
        return True
    return any(marker in text for marker in _NOISE_TEXT_MARKERS)


def _process_name(event: dict[str, Any]) -> str:
    for key in ["process_name", "source_process_name", "Image", "SourceImage", "image_path"]:
        value = _basename_lower(event.get(key))
        if value:
            return value
    return ""


def _basename_lower(value: Any) -> str:
    text = str(value or "").strip().strip('"').lower()
    if not text:
        return ""
    text = text.replace("/", "\\")
    return text.rsplit("\\", 1)[-1]


def _lower_value(value: Any) -> str:
    return str(value or "").strip().lower()


def _id_value(value: Any) -> str:
    text = str(value or "").strip()
    return text if text else ""


def _raw_field_value(event: dict[str, Any], label: str) -> str:
    raw = str(event.get("raw") or "")
    if not raw:
        return ""
    match = re.search(
        rf"\b{re.escape(label)}:\s*(.*?)(?=\s+[A-Z][A-Za-z0-9]+:|$)",
        raw,
    )
    if not match:
        return ""
    return match.group(1).strip()


def _event_text(event: dict[str, Any]) -> str:
    values: list[str] = []
    for key in [
        "event_type",
        "process_name",
        "parent_process_name",
        "command_line",
        "image_path",
        "target_process_name",
        "target_image_path",
        "api",
        "key_path",
        "value_name",
        "data",
        "path",
        "destination_host",
        "destination_ip",
        "url",
        "service_name",
        "task_name",
        "module_path",
        "Image",
        "SourceImage",
        "ProcessGuid",
        "ParentProcessGuid",
        "SourceProcessGuid",
        "raw",
    ]:
        value = event.get(key)
        if isinstance(value, list):
            values.extend(str(item) for item in value if item is not None)
        elif value is not None:
            values.append(str(value))
    return " ".join(values).lower()


def _event_evidence(
    source: str,
    group: str,
    event: dict[str, Any],
    reasons: list[str],
) -> dict[str, Any]:
    return {
        "source_result": "dynamic_telemetry",
        "source": source,
        "event_group": group,
        "event_id": str(event.get("event_id", ""))[:120],
        "event_type": str(event.get("event_type", ""))[:120],
        "process_name": str(event.get("process_name", ""))[:200],
        "image_path": str(event.get("image_path", ""))[:500],
        "pid": _safe_int(event.get("pid"), default=None),
        "process_guid": str(event.get("process_guid") or event.get("ProcessGuid") or "")[:120],
        "parent_process_name": str(event.get("parent_process_name", ""))[:200],
        "parent_process_guid": str(event.get("parent_process_guid") or event.get("ParentProcessGuid") or "")[:120],
        "target_process_name": str(event.get("target_process_name", ""))[:200],
        "target_image_path": str(event.get("target_image_path", ""))[:500],
        "command_line": str(event.get("command_line", ""))[:500],
        "path": str(event.get("path", ""))[:500],
        "key_path": str(event.get("key_path", ""))[:500],
        "value_name": str(event.get("value_name", ""))[:200],
        "data": str(event.get("data", ""))[:500],
        "destination_ip": str(event.get("destination_ip", ""))[:120],
        "destination_port": _safe_int(event.get("destination_port"), default=None),
        "destination_host": str(event.get("destination_host", ""))[:300],
        "url": str(event.get("url", ""))[:500],
        "service_name": str(event.get("service_name", ""))[:200],
        "task_name": str(event.get("task_name", ""))[:200],
        "destination": _destination(event),
        "reason": ", ".join(reasons)[:300],
        "attribution": event.get("attribution") if isinstance(event.get("attribution"), dict) else {},
    }


def _destination(event: dict[str, Any]) -> str:
    for key in ["url", "destination_host", "destination_ip"]:
        value = event.get(key)
        if value:
            return str(value)[:300]
    port = event.get("destination_port")
    if port:
        return f"port:{port}"[:300]
    return ""


def _weight(reasons: list[str]) -> int:
    event_type_hits = sum(1 for item in reasons if item.startswith("event_type:"))
    keyword_hits = sum(1 for item in reasons if item.startswith("keyword:"))
    return max(1, event_type_hits * 2 + keyword_hits)


def _confidence(score: int) -> str:
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def _int_param(params: dict[str, Any], key: str, default: int) -> int:
    try:
        return max(0, int(params.get(key, default)))
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int | None = 0) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
