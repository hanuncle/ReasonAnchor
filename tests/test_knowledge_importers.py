from __future__ import annotations

import json
from pathlib import Path

from tools.knowledge_importers.build_behavior_attack_view import build_view, write_view
from tools.knowledge_importers.check_attack_sources import check_sources, select_latest_attack_file
from tools.knowledge_importers.import_attack_sources import run_import


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_check_sources_selects_latest_semver_attack_file(tmp_path: Path) -> None:
    source_root = _write_external_sources(tmp_path / "attack")

    latest = select_latest_attack_file(source_root)
    status = check_sources(source_root)

    assert latest is not None
    assert latest.name == "enterprise-attack-19.1.json"
    assert status["ready"] is True
    attack_source = next(item for item in status["sources"] if item["name"] == "attack-stix-data")
    assert attack_source["attack_pattern_count"] == 1


def test_import_attack_sources_writes_candidate_assets(tmp_path: Path) -> None:
    source_root = _write_external_sources(tmp_path / "attack")
    module_root = _write_module_knowledge(tmp_path / "module")

    summary = run_import(source_root, module_root)

    assert summary["official_knowledge_modified"] is False
    assert summary["outputs"]["external_attack_candidates"] == 1
    assert summary["outputs"]["external_behavior_candidates"] == 1
    assert summary["outputs"]["sigma_rules"] == 1
    assert summary["outputs"]["capa_rules"] == 1

    attack = _read_json(module_root / "knowledge" / "candidates" / "external_attack_candidates.json")
    assert attack["techniques"][0]["technique_id"] == "T1055"
    assert attack["techniques"][0]["current_module_status"] == "existing"
    assert attack["techniques"][0]["related_behavior_ids"] == ["process_injection"]

    behavior = _read_json(module_root / "knowledge" / "candidates" / "external_behavior_candidates.json")
    assert behavior["behaviors"][0]["mbc_id"] == "B1055"
    assert behavior["behaviors"][0]["attack_technique_ids"] == ["T1055"]

    detection = _read_json(module_root / "knowledge" / "candidates" / "external_detection_candidates.json")
    assert {item["rule_source"] for item in detection["rules"]} == {"sigma", "capa"}


def test_behavior_attack_view_joins_official_and_candidate_context(tmp_path: Path) -> None:
    source_root = _write_external_sources(tmp_path / "attack")
    module_root = _write_module_knowledge(tmp_path / "module")
    run_import(source_root, module_root)

    output = module_root / "knowledge" / "behavior_attack_view.json"
    written = write_view(module_root, output)
    view = build_view(module_root)

    assert output.is_file()
    assert written["counts"]["behaviors"] == 1
    assert view["unmapped"] == {
        "behavior_attack_refs": [],
        "attack_behavior_refs": [],
        "rules_behavior_refs": [],
        "rules_attack_refs": [],
    }
    behavior = view["behaviors"][0]
    assert behavior["behavior_id"] == "process_injection"
    assert behavior["attack_techniques"][0]["source_status"] == "official"
    assert behavior["external_detection_candidates"]["sigma_rule_count"] == 1
    assert behavior["external_detection_candidates"]["capa_rule_count"] == 1
    assert behavior["external_mbc_candidates"]["count"] == 1


def test_malware_module_declares_external_knowledge_assets() -> None:
    manifest = _read_json(PROJECT_ROOT / "modules" / "malware_analysis" / "module.json")

    knowledge_types = {item["type"] for item in manifest["knowledge"]}
    page_ids = {item["page_id"] for item in manifest["ui"]["pages"]}

    assert {
        "behavior_attack_view",
        "external_attack_candidates",
        "external_behavior_candidates",
        "external_detection_candidates",
        "external_import_summary",
    } <= knowledge_types
    assert {
        "malware_behavior_attack_view",
        "malware_external_attack_candidates",
        "malware_external_behavior_candidates",
        "malware_external_detection_candidates",
    } <= page_ids


def _write_external_sources(root: Path) -> Path:
    attack_root = root / "attack-stix-data" / "enterprise-attack"
    attack_root.mkdir(parents=True)
    (attack_root / "enterprise-attack-9.0.json").write_text(
        json.dumps({"objects": []}),
        encoding="utf-8",
    )
    (attack_root / "enterprise-attack-19.1.json").write_text(
        json.dumps(
            {
                "objects": [
                    {
                        "type": "attack-pattern",
                        "name": "Process Injection",
                        "description": "Inject code into another process.",
                        "external_references": [
                            {
                                "source_name": "mitre-attack",
                                "external_id": "T1055",
                                "url": "https://attack.mitre.org/techniques/T1055/",
                            }
                        ],
                        "kill_chain_phases": [{"phase_name": "defense-evasion"}],
                        "x_mitre_detection": "Monitor remote thread creation.",
                        "x_mitre_data_sources": ["Process: Process Access"],
                        "x_mitre_platforms": ["Windows"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    mbc_root = root / "mbc-markdown"
    mbc_root.mkdir(parents=True)
    (mbc_root / "mbc_summary.md").write_text(
        "\n".join(
            [
                "## Malware Behaviors",
                "| ID | Behavior | Objective(s) | Related ATT&CK Technique |",
                "|----|----------|--------------|--------------------------|",
                "|B1055|**[Process Injection](https://example.test/process-injection.md)**|DEFENSE EVASION|Process Injection ([T1055](https://attack.mitre.org/techniques/T1055/))|",
                "",
                "## Malware Micro-behaviors",
            ]
        ),
        encoding="utf-8",
    )

    sigma_root = root / "sigma" / "rules" / "windows" / "create_remote_thread"
    sigma_root.mkdir(parents=True)
    (sigma_root / "create_remote_thread_test.yml").write_text(
        "\n".join(
            [
                "title: Remote Thread Injection",
                "id: sigma-test-1",
                "status: test",
                "tags:",
                "    - attack.defense-evasion",
                "    - attack.t1055",
                "logsource:",
                "    product: windows",
                "    category: create_remote_thread",
                "level: high",
            ]
        ),
        encoding="utf-8",
    )

    capa_root = root / "capa-rules" / "host-interaction" / "process" / "inject"
    capa_root.mkdir(parents=True)
    (capa_root / "inject-thread.yml").write_text(
        "\n".join(
            [
                "rule:",
                "  meta:",
                "    name: inject thread",
                "    namespace: host-interaction/process/inject",
                "    att&ck:",
                "      - Defense Evasion::Process Injection::Thread Execution Hijacking [T1055.003]",
                "  features:",
                "    - match: write process memory",
            ]
        ),
        encoding="utf-8",
    )
    return root


def _write_module_knowledge(root: Path) -> Path:
    (root / "knowledge" / "attack").mkdir(parents=True)
    (root / "knowledge" / "behavior_taxonomy.json").write_text(
        json.dumps(
            {
                "schema_version": "1",
                "categories": [
                    {
                        "id": "process_injection",
                        "name": "Process injection",
                        "attack_techniques": ["T1055"],
                        "verification_rule": "sample-attributed process injection evidence",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (root / "knowledge" / "attack" / "techniques.json").write_text(
        json.dumps(
            [
                {
                    "technique_id": "T1055",
                    "name": "Process Injection",
                    "tactic": "Defense Evasion",
                    "behavior_categories": ["process_injection"],
                    "analysis_methods": ["OpenProcess/WriteProcessMemory review"],
                    "detection_methods": ["Sysmon Event ID 8"],
                    "validation_samples": ["process_injection_fixture"],
                }
            ]
        ),
        encoding="utf-8",
    )
    (root / "knowledge" / "behavior_rules.json").write_text(
        json.dumps(
            [
                {
                    "rule_id": "defense_evasion.process_injection",
                    "behavior_id": "process_injection",
                    "name": "Process injection",
                    "attack_techniques": [{"technique_id": "T1055", "name": "Process Injection"}],
                    "event_type": ["process_access"],
                    "required_attribution": ["confirmed_sample_behavior"],
                    "status_when_matched": "verified",
                    "confidence": "medium",
                }
            ]
        ),
        encoding="utf-8",
    )
    return root


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
