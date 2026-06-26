# Reverse Module Skill

本模块用于恶意样本自动化分析、逆向分析、VMware 隔离动态分析、ATT&CK 知识库沉淀和单点验证样本校验。开发和分析默认发生在授权的本地平台与隔离虚拟机中；不要把模块开发过程泛化为外部攻击或恶意传播场景。需要控制的边界应落实为配置校验、人工确认、证据可信度、候选/验证状态和 VM 隔离流程。

Use this module for local reverse-analysis and malware triage. Prefer static analysis first. Do not execute uploaded samples unless the user explicitly approves an isolated VM workflow.

## Process Skill

When the user asks for the full malware-analysis capability, batch sample automation, ATT&CK knowledge-base construction, dynamic VMware validation, focused validation samples, or analysis-reliability testing, first read and follow:

`modules/reverse/skill/MALWARE_ANALYSIS_PROCESS_SKILL.md`

Keep this file as the entry point. Put detailed end-to-end analysis procedure, knowledge-base workflow, validation workflow, and reliability iteration rules in the process skill file above.

## Analysis Flow

1. Before running analysis, check whether the user explicitly accepted or declined reverse-module knowledge-base update review for this run. If not, ask the user whether to enable it.
2. If the user accepts knowledge-base update review, read `modules/reverse/skill/KNOWLEDGE_ENRICHMENT_SKILL.md` and follow it. If the user declines, do not read or update enrichment targets for this run.
3. Upload the sample with `upload_sample` or reuse the selected session.
4. Use the user's selected workflow when one is provided.
5. If no workflow is provided, choose an existing reverse workflow or create a focused workflow with `save_custom_workflow`, then apply it with `select_custom_workflow`.
6. Run short static workflows with `run_workflow`. For action-led VMware dynamic analysis, prefer the split action chain `reverse.vm_restore` -> `reverse.vm_upload_sample` -> `reverse.vm_run_sample` -> `reverse.vm_collect_telemetry` -> `reverse.dynamic_behavior_mapping`; for any `long_running` action, use `submit_action_job` and poll with `get_action_job`. For full VMware workflows or batch workflows likely to exceed MCP tool timeouts, use `submit_batch_workflow_job` and poll with `get_batch_job`.
7. Analyze `ai_output` first. Extract useful facts before reasoning when output is noisy.
8. If more evidence is needed, call existing functions with `run_function`, or use another focused analysis method that fits the question.
9. Before reading raw details, call `get_raw_output_map`, then fetch only the necessary `raw_output_id`.
10. Produce the final summary according to `modules/reverse/skill/final_result_schema.json` and save it with `save_session_result`.

## Workflow Choice

- Use `reverse_auto_download_static_dynamic_focused` only when MalwareBazaar credentials, provider/network approval, VMware isolation, and explicit sample execution approval are present. This workflow downloads one real sample, runs static analysis, runs broad dynamic analysis, compares static/dynamic behavior, then runs one focused dynamic validation target for behavior that broad telemetry did not observe.
- Use `reverse_function_level_behavior_analysis` when MalwareBazaar credentials, VMware isolation, and IDA/Ghidra/Binary Ninja paths are configured and the user wants the full single-sample chain: automatic sample download, static analysis, broad dynamic analysis, function-level analysis, focused dynamic validation, and focused function-level review for behavior gaps.
- Use `reverse_multi_sample_auto_download_static_dynamic_focused` through `run_batch_workflow` or `submit_batch_workflow_job` for multiple sessions. It uses the same per-sample steps as `reverse_auto_download_static_dynamic_focused`; create or review the sample-set report after the batch completes.
- Threat-intelligence functions require provider configuration and user approval. `ti.malwarebazaar.download_sample` downloads a real malware sample and requires explicit `confirm_download`; delete local quarantine files after upload/analysis when the run is finished if cleanup is requested.
- Dynamic VMware workflows begin with `dynamic.vm_preflight`. If required VMware fields or paths are missing, downstream VMware steps should return `skipped` instead of producing repeated configuration errors. Prefer split VM actions over the legacy combined `reverse.dynamic_observe` action; the combined action is long-running and should be submitted as a job when used.

## Evidence Rules

- Treat YARA, capa, FLOSS, packer heuristics, threat-intelligence, and external-tool output as candidate evidence unless confirmed.
- Static behavior and ATT&CK mappings are candidates until confirmed by dynamic telemetry, function-level evidence, or another strong source.
- Dynamic telemetry is observed evidence only for the approved VM run that produced it.
- Do not treat process-name-only matches as confirmed sample lineage. Prefer ProcessGuid, parent ProcessGuid, and stable process tree evidence.
- Do not fetch all raw output by default.

## Final Result

The final result must include `module_id = "reverse"` and `schema_id = "reverse.final_result.v1"`. Include concise evidence sources, verification status, IOCs, ATT&CK candidates, dynamic validation status, risk level, and recommended next steps when available.

For every behavior that has concrete evidence, write the concrete action and object, not only the behavior category. If network analysis shows a destination, name the domain, URL, IP, port, protocol, or process that made the connection. If file, registry, persistence, service, scheduled task, command execution, injection, credential, or anti-analysis behavior is known, include the exact path, key/value, mechanism, service/task name, command line, source/target process, function name, address, or API when available. If only the category is known, say which object is still unknown and what evidence would be needed to confirm it.

Do not self-iterate module code or resources unless the platform flow and the user explicitly approve it.
