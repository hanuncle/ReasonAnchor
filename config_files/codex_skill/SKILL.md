# SecurityFunctionPlatform Codex Skill

## Platform

SecurityFunctionPlatform is a local MCP-driven security function orchestration platform. It can create or reuse analysis sessions, list available modules, list registered functions, apply workflows, run workflows, return compact `ai_output`, expose selected raw evidence by `raw_output_id`, let Codex improve module code/resources, and save a final structured result.

Use the platform for local security analysis workflows. Do not execute uploaded samples, do not upload sample bytes to external services, and do not read or print `config/local_config.json`.

## Required Flow

1. Call `get_platform_skill`.
2. Call `get_platform_actions` when the platform-level menu or startup options are needed.
3. Call `list_modules`.
4. Ask the user to choose a module unless the user already named one.
5. Call `get_module_actions(module_id)` and `get_module_capabilities(module_id)` when the selected module menu or cached capability summary is needed.
6. Call `get_module_skill(module_id)` only for the selected module.
7. Use `get_module_detail(module_id)` when manifest details, functions, workflows, config fields, or validation status are needed.
8. Before analysis work starts, ask whether module code self-iteration is allowed for this task.
9. Upload a sample with `upload_sample` or `upload_samples`, create a target session with `create_target_session`, or reuse an existing session from `list_sessions` / `get_session`.
10. Call `list_functions` and `list_custom_workflows`.
11. Choose an existing workflow or create one with `save_custom_workflow`, then apply it with `select_custom_workflow`.
12. Run it with `run_workflow`.
    - For a short user-approved multi-session batch, use `run_batch_workflow` and review the saved sample-set report.
    - For long-running batches, VM dynamic analysis, or any workflow likely to exceed MCP tool timeouts, use `submit_batch_workflow_job`, poll with `get_batch_job`, and review the saved report when the job completes.
    - Cross-sample reports are taxonomy-driven: use `sample_facts`, `behavior_matrix`, `attack_matrix`, `validation_status`, and `knowledge_links` before writing conclusions.
13. Analyze `ai_output` first.
14. If refined output is insufficient, call `get_raw_output_map` before `get_raw_output_by_id`, then fetch only the needed `raw_output_id`.
15. Use `run_function` for one additional registered function result when needed.
16. After analysis, produce the final AI summary according to the selected module's `final_result_schema` and save it with `save_session_result`.
17. After the final summary is saved, ask whether to perform module code self-iteration if useful improvements were found.
18. Iterate only selected-module files after the user approves iteration.

When returned data is noisy, extract useful information first, then analyze it.

## Modules

Modules are user-extensible packages under `modules/<module_id>/`. A module may contain:

- `functions/`: reusable function code declared in `module.json`.
- `workflows/`: reusable workflow templates.
- `knowledge/`: module knowledge assets.
- `config_fields/`: user-configurable field declarations.
- `skill/`: module `SKILL.md`, `playbook.json`, and optional `final_result_schema.json`.
- `config_files/`: module-owned resources such as raw sorting rules and function data files.
- `module.json.ui.pages`: module page declarations rendered by platform-owned frontend components.

Use `get_module_template` to inspect the default module format. Use `create_module` to create a module in that default format.

Module contents are intentionally editable only after user approval. Platform code is not self-iterated during sample analysis. Good generated code can be integrated into the owning module, weak function code can be improved, noisy raw sorting can be rewritten, and module skill/playbook/schema guidance can be tightened. The goal is to reduce token use, improve `ai_output`, and make future runs more effective.

Put module configuration field definitions in `modules/<module_id>/config_fields/` and declare them in `module.json`. Put module resources in `modules/<module_id>/config_files/`. Put module final summary schema in `modules/<module_id>/skill/final_result_schema.json`. Do not put module-owned files in platform `config_files/`.

Declare module-specific frontend pages in `module.json.ui.pages`. Pages should reference declared module knowledge assets by `knowledge_type` and use platform-owned renderers such as `knowledge_table` or `taxonomy_browser`; modules should not ship arbitrary executable frontend code for trusted rendering.

Use `get_module_ui(module_id)` to inspect declared module pages, `get_module_knowledge(module_id, knowledge_type)` to fetch one declared knowledge asset for a page, and `upsert_module_ui_page(...)` to create or replace one module page declaration after the user approves module iteration. `upsert_module_ui_page` only updates `module.json.ui.pages`; the target `knowledge_type` must already be declared in `module.json.knowledge`.

Before writing any new file, inspect the target module directory and nearby files so the new file lands in the correct module location.

## MCP Tool Reference

| Tool | Role |
| --- | --- |
| `get_platform_skill` | Read this platform skill and the machine-readable platform playbook. |
| `get_platform_actions` | Return the platform startup menu actions. |
| `list_modules` | List available modules before choosing module context. |
| `get_module_template` | Return the default module directory and manifest format. |
| `get_module_skill` | Load only the selected module's skill, playbook, and final result schema. |
| `get_module_detail` | Inspect one module's manifest, functions, workflows, config fields, and validation. |
| `get_module_actions` | Return the selected module's generic platform-owned menu actions. |
| `get_module_capabilities` | Return the selected module's cached, structured capability summary. |
| `refresh_module_capabilities` | Force regeneration of a selected module capability summary cache. |
| `get_module_ui` | Inspect one module's frontend page declarations. |
| `get_module_knowledge` | Fetch one declared module knowledge asset by `knowledge_type`. |
| `create_module` | Create a default-format module skeleton. |
| `load_module` | Validate a module through the compatibility load endpoint. |
| `package_module` | Package a module as an `.sfpmod.zip` archive. |
| `export_module` | Export a module package. |
| `import_module_archive` | Import a trusted local module archive. |
| `list_module_knowledge` | List module knowledge assets without loading full contents. |
| `upsert_module_ui_page` | Create or replace one module frontend page declaration using a platform-owned renderer. |
| `upload_sample` | Upload one local sample and create a session. |
| `upload_samples` | Upload multiple local samples and create sessions. |
| `create_target_session` | Create a non-sample session for target-based modules such as recon or vulnerability scanning. |
| `list_sessions` | List persisted sessions before resuming work. |
| `get_session` | Fetch one persisted session by id. |
| `list_functions` | List all registered platform and module functions. |
| `list_custom_workflows` | List saved platform and module workflow templates. |
| `save_custom_workflow` | Save a new workflow template. |
| `select_custom_workflow` | Apply a workflow template to a session. |
| `run_workflow` | Run the selected workflow and return compact `ai_output`. |
| `run_batch_workflow` | Run one workflow across multiple sessions and save a cross-sample report. |
| `submit_batch_workflow_job` | Submit a long-running batch workflow job and return its job id/status. |
| `list_batch_jobs` | List persisted batch workflow jobs. |
| `get_batch_job` | Fetch one persisted batch workflow job, including progress and report id. |
| `list_sample_set_reports` | List saved cross-sample reports. |
| `get_sample_set_report` | Fetch one saved cross-sample report. |
| `get_ai_output` | Fetch refined AI-facing session output. |
| `get_ai_output_by_raw_id` | Fetch one refined output item by `raw_output_id`. |
| `get_raw_output_map` | List raw output ids before fetching raw details. |
| `get_raw_output_by_id` | Fetch one raw output item by id. |
| `run_function` | Run one registered function in the current session. |
| `get_mcp_file_access_policy` | Inspect allowed MCP file read/write scope. |
| `inspect_allowed_files` | Inspect allowed platform or module files. |
| `write_allowed_file` | Write allowed platform or module files. |
| `save_session_result` | Save the final AI summary for the current session. |

## Self-Iteration

- Ask before analysis whether module code self-iteration is allowed.
- Ask again after the final summary is saved before making any iteration edit.
- Do not self-iterate platform code during sample analysis.
- Only edit the selected module's files when the user approves.
- If `ai_output` is noisy, improve the owning module's raw sorter in `modules/<module_id>/config_files/raw_sorting/`.
- If a function is insufficient, improve or create code in `modules/<module_id>/functions/` and declare it in `module.json`.
- If a function needs static resources, put them in `modules/<module_id>/config_files/<function_id>/`.
- If a function needs user configuration, add field declarations under `modules/<module_id>/config_fields/` and declare them in `module.json`.
- If a module needs a frontend knowledge page, declare or update it with `upsert_module_ui_page` so it stays in `module.json.ui.pages` and uses platform-owned renderers.
- If module guidance is stale, update `modules/<module_id>/skill/SKILL.md`, `modules/<module_id>/skill/playbook.json`, or `modules/<module_id>/skill/final_result_schema.json`.
- Add tests when generated code becomes a reusable module function.

## Human Decision

Ask the user before steps that are risky, ambiguous, expensive, require sample execution, require dependency installation, require external network/API use, require credentials, or may change the intended module boundary.

## Safety

- Do not execute uploaded samples.
- Do not upload sample bytes to external services.
- Do not read or print `config/local_config.json`.
- Do not print API keys, Auth-Key credentials, tokens, passwords, or secrets.
- Do not treat candidate evidence as confirmed behavior.
- Do not write `observed_behaviors` automatically.
- Prefer `ai_output`; use raw output only when evidence detail is needed.
- Before raw detail, call `get_raw_output_map` and then query only the necessary `raw_output_id`.
- Do not fetch all raw outputs at once unless the user explicitly asks.
- Final results must be saved with `save_session_result`.

## Final Result Shape

Use the selected module's `final_result_schema` returned by `get_module_skill(module_id)`. Save the final AI summary with `save_session_result`; the platform stores it in `data/sessions/<session_id>/result/result.json`, and the frontend result page reads that session result.
