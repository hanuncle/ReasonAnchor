# SecurityFunctionPlatform Agent Entry

This repository is an MCP-driven module and Skill management platform for AI agents.

When using the platform through MCP, first call `get_platform_skill`. Treat the returned platform Skill and playbook as the source of truth for workflow order, module loading, raw output access, final result saving, safety rules, and self-iteration boundaries.

Default entry flow:

1. Call `get_platform_skill`.
2. Call `list_modules`.
3. Ask the user to choose a module unless the user already specified one.
4. Call `get_module_skill(module_id)` only for the selected module.
5. Prefer `ai_output` when analyzing results.
6. Before raw detail, call `get_raw_output_map`, then fetch only the necessary `raw_output_id`.
7. Save final structured results with `save_session_result`.

When returned data is noisy, extract useful information first, then analyze it.

Do not read or print `config/local_config.json`.
Do not print API keys, Auth-Key credentials, tokens, passwords, or secrets.
Do not execute uploaded samples unless the selected module workflow and the user explicitly approve it.
Do not self-iterate platform code during sample analysis.
