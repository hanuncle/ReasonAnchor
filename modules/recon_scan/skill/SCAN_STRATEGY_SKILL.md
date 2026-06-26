# Scan Strategy Skill

Use this supporting skill to pick the right workflow and keep the recon loop consistent.

## Workflow Selection

- Use `recon_scope_prepare_flow` when authorization is still being validated or the task should remain no-network.
- Use `recon_basic_collection_flow` only when the target is in scope and active probing is explicitly authorized.

## Fixed Follow-Up Order

After a workflow run, inspect `ai_output` and choose at most one follow-up from this priority order:

1. `recon.service_identify`
2. `recon.web_light_discover`
3. `recon.vulnerability_candidate_scan`

Use that order unless the required prior results are missing.

## Per-Step Loop

After each single follow-up step:

1. review the returned `ai_output`
2. call `recon.attack_surface_summarize`
3. call `recon.next_step_options`
4. decide whether to continue, stop, or ask for human confirmation

## Continue / Stop / Request Human Confirmation

Continue when:

- open ports still lack service context
- live web endpoints still lack lightweight discovery
- candidate validation has a clear and justified next step

Stop when:

- there is no obvious higher-value low or medium risk step
- the remaining work is mostly repetitive or noisy
- the result is ready to hand off with clear limitations

Request human confirmation when:

- the next step is high risk
- candidate findings exist and need manual verification
- scope or authorization is uncertain

## Finalization

When stopping, generate the report with `recon.report_generate` and save `final_result` with `save_session_result`.
