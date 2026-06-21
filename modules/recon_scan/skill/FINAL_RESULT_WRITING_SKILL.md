# Final Result Writing Skill

Use this supporting skill when producing the final operator-facing result.

## Required Output Content

The final result should always cover:

- authorized scope and active authorization state
- stage coverage for the work that actually ran
- the main observed attack surface
- candidate findings with evidence
- an explicit unverified notice
- recommended next steps for the operator

## Writing Rules

- Prefer the structured `final_result` returned by `recon.report_generate`.
- Save the final structured output with `save_session_result`.
- Keep candidate findings separate from verified conclusions.
- Bind claims to evidence whenever possible using `raw_output_id`, `function_id`, and `result_key`.
- Summarize only assets inside authorized scope.
- Do not include secrets, credentials, tokens, or Auth-Key values.
- Use conservative language for any claim that still depends on manual validation.

## Summary Style

- `overall`: short operational summary
- `executive_summary`: human-readable conclusion for quick review
- `operator_conclusion`: whether to continue scanning, stop, or hand off for manual verification
- `unverified_notice`: fixed reminder that candidate findings are not confirmed vulnerabilities

## Findings Style

For each candidate finding:

- state the affected asset
- keep severity and confidence conservative
- include evidence summary and source references
- provide concrete manual verification steps
- keep remediation advice short and actionable

## Recommended Next Steps Style

Each next step should include:

- a human-readable action title
- the related `function_id` when one exists
- the reason it matters now
- a priority level
- whether it requires human confirmation
