# Recon Scan Module Skill

这个工具用于授权靶场或明确授权目标的侦察扫描。扫描前必须先询问用户目标是否为靶场或已授权目标；只有用户确认后，才可以进行随意操作

Use this module for authorized target reconnaissance where the intended loop is:

1. Run a suitable workflow.
2. Review returned `ai_output`.
3. Let AI choose the next safest useful step.
4. Call one function with `run_function`.
5. Re-summarize with `recon.attack_surface_summarize`, refresh options with `recon.next_step_options`, and repeat.
6. Generate a final report with `recon.report_generate` and save `final_result` with `save_session_result`.

## Required Inputs

- `targets`: domains, URLs, IPs, or CIDR ranges.
- `authorized_scope`: exact domains, wildcard domains, URLs, IPs, or CIDRs that bound the engagement.
- `exclude`: optional out-of-scope patterns.
- `confirm_authorized`: required for active functions. Use `I_CONFIRM_AUTHORIZED_ACTIVE_RECON` only after the user confirms the active scan is authorized.

Inputs can come from target sessions, function params, workflow step params, or `recon_scan.*` config fields.

## Workflow Split

- `recon_scope_prepare_flow`: no-network setup. It validates target scope, normalizes targets, creates an empty attack-surface shell, produces next-step options, and generates a report draft.
- `recon_basic_collection_flow`: automated basic collection. It validates active authorization, normalizes targets, runs DNS probing, HTTP liveness probing, low-rate port scanning, summarizes the attack surface, returns next-step options, and generates a stage report.

Do not package service identification, web light discovery, or vulnerability candidate scanning into the default workflow. These are single-function AI-gated steps:

- `recon.service_identify`
- `recon.web_light_discover`
- `recon.vulnerability_candidate_scan`

After each single-function step, call:

- `recon.attack_surface_summarize`
- `recon.next_step_options`
- `recon.report_generate` when a stage or final report is needed

## Function Groups

- Scope and target prep: `recon.scope_validate`, `recon.target_normalize`.
- Basic automated collection: `recon.dns_probe`, `recon.http_probe`, `recon.port_scan`.
- AI-gated follow-up: `recon.service_identify`, `recon.web_light_discover`, `recon.vulnerability_candidate_scan`.
- AI loop and reporting: `recon.attack_surface_summarize`, `recon.next_step_options`, `recon.report_generate`.

## Safety Rules

- Do not scan targets outside `authorized_scope`.
- Do not run active steps unless `confirm_authorized` is exact.
- Keep rate limits low by default.
- Treat nuclei/template output as candidate-only until manually verified.
- If a `run_function` call times out at the MCP layer, call `get_raw_output_map` before deciding whether the function failed or should be retried; long-running tools may still finish and persist a raw output after the client timeout.
- Treat `ffuf` output as high-noise unless it is parsed from structured JSON `results`; do not treat wordlist comments or generated `FUZZ` substitutions as discovered URLs.
- Do not run brute force, exploitation, destructive testing, persistence, lateral movement, or data extraction from this module.
- Prefer `ai_output`; before raw detail, call `get_raw_output_map`, then fetch only the needed `raw_output_id`.
- When output is noisy, extract useful information first, then analyze it.

## Final Result

When complete, use `recon.report_generate` and save its `final_result` with `save_session_result`. The frontend result page reads the saved session result, and the module page exposes the workflow/function split through `scan_workflow_matrix`.
