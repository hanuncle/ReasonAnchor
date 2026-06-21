# Recon Scan Module Skill

Use `recon_scan` for authorized reconnaissance against lab targets, training ranges, internal assets, or other explicitly approved targets. This module is for recon and candidate validation only. It does not authorize exploitation, brute force, persistence, lateral movement, destructive testing, or data extraction.

## Module Purpose And Boundary

- Use this module only when the operator has provided `targets` and a matching `authorized_scope`.
- Treat every active step as gated. If the task lacks explicit authorization for active probing, stay on the safe preparation path.
- Keep findings candidate-only until they are manually verified outside this module.

## Execution Overview

Follow this execution loop:

1. Choose a workflow.
2. Review `ai_output`.
3. Run at most one AI-gated follow-up function with `run_function`.
4. Re-run `recon.attack_surface_summarize`.
5. Re-run `recon.next_step_options`.
6. Repeat until there is no higher-value low or medium risk step.
7. Generate the final report with `recon.report_generate`.
8. Save the returned `final_result` with `save_session_result`.

## When To Use Each Supporting Skill

Use `CONTROLLED_EXECUTION_SKILL.md` when:

- authorization is incomplete or needs reconfirmation
- a tool call times out at the MCP layer
- output is noisy and needs extraction before analysis
- AI is deciding whether to continue, pause, or stop

Use `SCAN_STRATEGY_SKILL.md` when:

- choosing between `recon_scope_prepare_flow` and `recon_basic_collection_flow`
- selecting the next follow-up function after a workflow run
- deciding whether to continue scanning or move to final reporting

Use `FINAL_RESULT_WRITING_SKILL.md` when:

- writing the final summary
- separating candidate findings from verified conclusions
- mapping evidence to `raw_output_id`, `function_id`, and `result_key`

## Required Inputs

- `targets`: domains, URLs, IPs, or CIDR ranges
- `authorized_scope`: exact domains, wildcard domains, URLs, IPs, or CIDRs that bound the engagement
- `exclude`: optional out-of-scope patterns
- `confirm_authorized`: required for active functions and active workflows. Use `I_CONFIRM_AUTHORIZED_ACTIVE_RECON` only after the operator confirms active probing is authorized.

Inputs can come from target sessions, workflow step params, function params, or `recon_scan.*` config fields.

## Final Save Rule

- Prefer the `final_result` returned by `recon.report_generate`.
- Save it with `save_session_result`.
- Use raw evidence only when `ai_output` is insufficient. Before raw detail, call `get_raw_output_map`, then fetch only the necessary `raw_output_id`.

## Explicit Prohibitions

- Do not scan outside `authorized_scope`.
- Do not run active steps without the exact confirmation token.
- Do not treat candidate findings as verified vulnerabilities.
- Do not print secrets, tokens, Auth-Key values, passwords, or credentials.
- Do not use this module for exploitation, brute force, destructive testing, persistence, or data extraction.
- Do not keep chaining high-risk functions when the remaining value is unclear or manual verification is the better next step.
