from __future__ import annotations

import re
from typing import Any

from security_function_platform.core.function_base import AnalysisFunction
from security_function_platform.core.function_result import FunctionResult

from behavior_taxonomy import boundary_patterns, keyword_group_map, static_rules

_BEHAVIOR_RULES: dict[str, dict[str, Any]] = static_rules()
_BEHAVIOR_BOUNDARY_PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = (
    boundary_patterns()
)
_KEYWORD_GROUP_TO_BEHAVIOR = keyword_group_map()

_FEATURE_RESULT_KEYS = {
    "ida_function_features": "ida",
    "ghidra_function_features": "ghidra",
}


class BehaviorMapStaticFunction(AnalysisFunction):
    id = "behavior.map_static"
    name = "Static behavior mapping"
    category = "static"
    result_key = "static_behavior_map"
    description = (
        "Maps existing static analysis outputs into candidate behavior categories "
        "with evidence. This is a local synthesis step and does not confirm runtime behavior."
    )
    cost = "low"
    candidate_only = True
    requires_human_confirmation = True
    recommended_before = [
        "pe.deep_parse",
        "strings.extract",
        "strings.enhanced_extract",
        "ioc.extract",
        "packer.detect_enhanced",
        "tool.ida_function_features",
        "tool.ghidra_function_features",
    ]
    output_schema = {
        "behaviors": "Candidate behavior categories with source evidence.",
        "related_functions": "IDA/Ghidra functions associated with behavior candidates.",
        "limitations": "Static synthesis only; not observed behavior.",
    }

    def run(self, context: dict[str, Any], params: dict[str, Any]) -> FunctionResult:
        max_evidence = _int_param(params, "max_evidence_per_behavior", 50)
        max_related = _int_param(params, "max_related_functions", 50)
        mapper = _BehaviorMapper(context, max_evidence=max_evidence, max_related=max_related)
        behaviors = mapper.map_behaviors()
        return FunctionResult(
            function_id=self.id,
            result_key=self.result_key,
            data={
                "behaviors": behaviors,
                "counts": {
                    "behaviors": len(behaviors),
                    "evidence": sum(len(item.get("evidence", [])) for item in behaviors),
                    "related_functions": sum(
                        len(item.get("related_functions", [])) for item in behaviors
                    ),
                },
                "requires_human_confirmation": True,
                "limitations": [
                    "static evidence only",
                    "candidate behaviors require human confirmation",
                    "does not execute sample",
                ],
            },
        )


class _BehaviorMapper:
    def __init__(self, context: dict[str, Any], max_evidence: int, max_related: int) -> None:
        self.context = context
        self.max_evidence = max(0, max_evidence)
        self.max_related = max(0, max_related)
        self.evidence_by_category: dict[str, list[dict[str, Any]]] = {
            key: [] for key in _BEHAVIOR_RULES
        }
        self.related_by_category: dict[str, list[dict[str, Any]]] = {
            key: [] for key in _BEHAVIOR_RULES
        }
        self.score_by_category: dict[str, int] = {key: 0 for key in _BEHAVIOR_RULES}

    def map_behaviors(self) -> list[dict[str, Any]]:
        self._scan_pe_imports()
        self._scan_strings()
        self._scan_iocs()
        self._scan_function_features()
        self._scan_capa()
        self._scan_packer()

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
                    "confidence": _confidence(score, evidence),
                    "score": score,
                    "evidence": evidence[: self.max_evidence],
                    "related_functions": self.related_by_category.get(category, [])[
                        : self.max_related
                    ],
                    "verification": "candidate_static_only",
                }
            )
        behaviors.sort(key=lambda item: (-int(item["score"]), str(item["category"])))
        return behaviors

    def _scan_pe_imports(self) -> None:
        data = _result_data(self.context, "pe_deep_parse")
        imports = data.get("imports")
        if not isinstance(imports, list):
            return
        for item in imports:
            if not isinstance(item, dict):
                continue
            dll = str(item.get("dll", ""))
            functions = item.get("functions", [])
            if not isinstance(functions, list):
                continue
            for function in functions:
                value = f"{dll}.{function}"
                self._match_value(
                    value,
                    {
                        "source_result": "pe_deep_parse",
                        "field": "imports",
                        "value": value[:300],
                    },
                    weight=2,
                )

    def _scan_strings(self) -> None:
        strings = _result_data(self.context, "strings")
        enhanced = _result_data(self.context, "enhanced_strings")
        for source, field, value in [
            ("strings", "items", strings.get("items")),
            ("strings", "urls", strings.get("urls")),
            ("strings", "ips", strings.get("ips")),
            ("enhanced_strings", "ascii_items", enhanced.get("ascii_items")),
            ("enhanced_strings", "utf16le_items", enhanced.get("utf16le_items")),
            ("enhanced_strings", "urls", enhanced.get("urls")),
            ("enhanced_strings", "ips", enhanced.get("ips")),
            ("enhanced_strings", "domains", enhanced.get("domains")),
            ("enhanced_strings", "windows_paths", enhanced.get("windows_paths")),
            ("enhanced_strings", "registry_keys", enhanced.get("registry_keys")),
        ]:
            for text in _string_list(value):
                self._match_value(
                    text,
                    {
                        "source_result": source,
                        "field": field,
                        "value": text[:500],
                    },
                    weight=1,
                )
        suspicious = enhanced.get("suspicious_keywords")
        if isinstance(suspicious, dict):
            for group, values in suspicious.items():
                category = _KEYWORD_GROUP_TO_BEHAVIOR.get(str(group))
                if not category:
                    continue
                for value in _string_list(values):
                    self._add_evidence(
                        category,
                        {
                            "source_result": "enhanced_strings",
                            "field": f"suspicious_keywords.{group}",
                            "value": value[:500],
                            "reason": f"keyword_group:{group}",
                        },
                        weight=2,
                    )

    def _scan_iocs(self) -> None:
        ioc = _result_data(self.context, "ioc_extractor")
        ioc_weights = {"urls": 3, "ipv4": 1, "domains": 1}
        for field in ["urls", "ipv4", "domains"]:
            for value in _string_list(ioc.get(field)):
                self._add_evidence(
                    "network_communication",
                    {
                        "source_result": "ioc_extractor",
                        "field": field,
                        "value": value[:300],
                        "reason": "network_ioc_url" if field == "urls" else "network_ioc_candidate",
                    },
                    weight=ioc_weights[field],
                )
        for value in _string_list(ioc.get("registry_keys")):
            if not _is_concrete_persistence_evidence(value):
                continue
            self._add_evidence(
                "registry_persistence",
                {
                    "source_result": "ioc_extractor",
                    "field": "registry_keys",
                    "value": value[:500],
                    "reason": "registry_key",
                },
                weight=1,
            )

    def _scan_function_features(self) -> None:
        for result_key, tool in _FEATURE_RESULT_KEYS.items():
            data = _result_data(self.context, result_key)
            functions = data.get("functions")
            if not isinstance(functions, list):
                continue
            for function in functions:
                if not isinstance(function, dict):
                    continue
                related_hits: dict[str, list[str]] = {}
                values = _string_list(function.get("api_calls")) + _string_list(
                    function.get("strings")
                )
                for value in values:
                    matched = self._match_value(
                        value,
                        {
                            "source_result": result_key,
                            "field": "functions",
                            "function": str(function.get("name", ""))[:300],
                            "address": str(function.get("start", ""))[:64],
                            "value": value[:500],
                        },
                        weight=2,
                    )
                    for category in matched:
                        related_hits.setdefault(category, []).append(value[:200])

                for behavior in function.get("candidate_behaviors", []):
                    if not isinstance(behavior, dict):
                        continue
                    category = str(behavior.get("category", ""))
                    if category not in _BEHAVIOR_RULES:
                        continue
                    keywords = _string_list(behavior.get("keywords"))
                    self._add_evidence(
                        category,
                        {
                            "source_result": result_key,
                            "field": "functions[].candidate_behaviors",
                            "function": str(function.get("name", ""))[:300],
                            "address": str(function.get("start", ""))[:64],
                            "value": ", ".join(keywords)[:300],
                            "reason": "function_feature_candidate",
                        },
                        weight=3,
                    )
                    related_hits.setdefault(category, []).extend(keywords)

                for category, evidence in related_hits.items():
                    self._add_related_function(
                        category,
                        {
                            "tool": tool,
                            "name": str(function.get("name", ""))[:300],
                            "address": str(function.get("start", ""))[:64],
                            "size": _safe_int(function.get("size")),
                            "evidence": _unique(evidence)[:10],
                        },
                    )

    def _scan_capa(self) -> None:
        data = _result_data(self.context, "capa_analysis")
        for field in ["capabilities", "namespaces"]:
            for value in _string_list(data.get(field)):
                self._match_value(
                    value,
                    {
                        "source_result": "capa_analysis",
                        "field": field,
                        "value": value[:300],
                    },
                    weight=2,
                )

    def _scan_packer(self) -> None:
        data = _result_data(self.context, "packer_detection")
        if not data.get("likely_packed"):
            return
        category = "packer_or_obfuscation"
        confidence = str(data.get("confidence", "low"))
        weight = 4 if confidence == "high" else 3 if confidence == "medium" else 2
        self._add_evidence(
            category,
            {
                "source_result": "packer_detection",
                "field": "likely_packed",
                "value": confidence,
                "reason": "packer_or_obfuscation_heuristic",
            },
            weight=weight,
        )

    def _match_value(
        self,
        value: str,
        evidence: dict[str, Any],
        weight: int,
    ) -> list[str]:
        text = str(value).lower()
        matched: list[str] = []
        for category, rule in _BEHAVIOR_RULES.items():
            boundary_patterns = _BEHAVIOR_BOUNDARY_PATTERNS.get(category, [])
            keywords = rule.get("keywords", [])
            if not isinstance(keywords, list):
                continue
            for keyword in keywords:
                keyword_text = str(keyword).lower()
                if _has_boundary_rule(keyword_text, boundary_patterns):
                    continue
                if _requires_token_boundary(keyword_text):
                    pattern = re.compile(
                        rf"(?<![a-z0-9]){re.escape(keyword_text)}(?![a-z0-9])",
                        re.IGNORECASE,
                    )
                    if not pattern.search(str(value)):
                        continue
                    item = dict(evidence)
                    item["reason"] = f"keyword:{keyword}"
                    self._add_evidence(category, item, weight=weight)
                    matched.append(category)
                    break
                if keyword_text in text:
                    item = dict(evidence)
                    item["reason"] = f"keyword:{keyword}"
                    self._add_evidence(category, item, weight=weight)
                    matched.append(category)
                    break
            else:
                for label, pattern in boundary_patterns:
                    if pattern.search(str(value)):
                        item = dict(evidence)
                        item["reason"] = f"keyword:{label}"
                        self._add_evidence(category, item, weight=weight)
                        matched.append(category)
                        break
        return matched

    def _add_evidence(self, category: str, evidence: dict[str, Any], weight: int) -> None:
        if category not in self.evidence_by_category:
            return
        if category == "registry_persistence" and not _is_concrete_persistence_evidence(
            evidence.get("value") or evidence.get("reason") or ""
        ):
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
        if category == "anti_vm_sandbox_evasion" and "anti_analysis" in self.evidence_by_category:
            self._add_evidence("anti_analysis", evidence, weight)

    def _add_related_function(self, category: str, related: dict[str, Any]) -> None:
        if category not in self.related_by_category:
            return
        if related in self.related_by_category[category]:
            return
        if len(self.related_by_category[category]) < self.max_related:
            self.related_by_category[category].append(related)


def _result_data(context: dict[str, Any], result_key: str) -> dict[str, Any]:
    result = context.get("results", {}).get(result_key)
    if not isinstance(result, dict) or result.get("status") == "error":
        return {}
    data = result.get("data", {})
    return data if isinstance(data, dict) else {}


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item is not None]


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _confidence(score: int, evidence: list[dict[str, Any]]) -> str:
    strong = _has_strong_evidence(evidence)
    if score >= 8 and strong:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _has_strong_evidence(evidence: list[dict[str, Any]]) -> bool:
    for item in evidence:
        source = str(item.get("source_result") or "")
        field = str(item.get("field") or "")
        reason = str(item.get("reason") or "")
        if source in {"pe_deep_parse", "packer_detection", "capa_analysis"}:
            return True
        if source.endswith("_function_features"):
            return True
        if source == "enhanced_strings" and field.startswith("suspicious_keywords."):
            return True
        if source == "ioc_extractor" and (field == "urls" or reason == "network_ioc_url"):
            return True
    return False


def _is_concrete_persistence_evidence(value: Any) -> bool:
    text = str(value or "").lower()
    concrete_markers = (
        "\\currentversion\\run",
        "\\currentversion\\runonce",
        "\\windows\\currentversion\\run",
        "\\windows\\currentversion\\runonce",
        "\\winlogon\\",
        "\\services\\",
        "\\start menu\\programs\\startup\\",
        "\\startup\\",
        "schtasks",
        "\\tasks\\",
    )
    return any(marker in text for marker in concrete_markers)


def _int_param(params: dict[str, Any], key: str, default: int) -> int:
    try:
        return max(0, int(params.get(key, default)))
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _has_boundary_rule(
    keyword: str,
    patterns: list[tuple[str, re.Pattern[str]]],
) -> bool:
    return any(label == keyword for label, _pattern in patterns)


def _requires_token_boundary(keyword: str) -> bool:
    return keyword.isalnum() and len(keyword) <= 4
