# Controlled Execution Skill

This supporting skill keeps authorized reconnaissance stable, scoped, and evidence-driven. It is a control skill, not a bypass skill.

## Core Rules

- Do not enter the active path until the operator has confirmed authorization and the task carries `I_CONFIRM_AUTHORIZED_ACTIVE_RECON`.
- Prefer `ai_output` first. Use raw evidence only when the compact output is too vague for a decision.
- If a tool call appears to time out at the MCP layer, check `get_raw_output_map` before assuming the step failed. Long-running tools may still persist a usable raw output.
- Run at most one AI-gated follow-up function at a time.
- After every follow-up function, re-run `recon.attack_surface_summarize` and `recon.next_step_options` before choosing the next step.
- When output is noisy, extract the useful observations first, then analyze them.
- Do not convert candidate findings into verified vulnerabilities inside this module.

## Continue / Pause / Stop

Continue only when:

- the next step has a clear gain in attack-surface visibility or candidate validation
- the step stays within authorized scope
- the expected value is greater than the expected noise

Pause and ask for confirmation when:

- active probing authorization is unclear
- the target appears out of scope
- the next useful step is high risk
- candidate findings now require manual verification

Stop and move to final reporting when:

- no higher-value low or medium risk step remains
- only manual verification work is left
- the current evidence already supports a useful operator handoff

## Prohibited Uses

- No bypassing authorization boundaries
- No broadening target scope
- No evasion of platform or model safety controls
- No exploitation, credential attacks, persistence, or destructive testing
