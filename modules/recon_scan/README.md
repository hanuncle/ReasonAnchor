# Recon Scan Module

`recon_scan` is an authorized target reconnaissance module for SecurityFunctionPlatform. It packages scope validation, target normalization, passive-style collection, low-rate active probing, AI-gated follow-up functions, raw-output sorting, and final report generation into one reusable module.

This module is designed for lab targets, training ranges, internal assets, and other explicitly authorized targets. It does not implement exploitation, brute force, persistence, lateral movement, destructive testing, or data extraction.

## Positioning

The module follows an AI-gated reconnaissance loop:

```text
user provides target
-> scope and authorization validation
-> target normalization
-> workflow executes basic collection
-> compact ai_output returns to AI
-> AI chooses one next function
-> function result returns to AI
-> AI summarizes and refreshes next-step options
-> loop repeats until enough evidence exists
-> AI generates final_result
-> frontend reads the saved session result
```

The goal is to automate stable, low-judgment collection steps while keeping higher-risk or noisier steps under AI review.

## What It Collects

- Target scope and active authorization state
- Normalized domains, hosts, URLs, IPs, and CIDR inputs
- DNS records and resolved addresses through `dnsx`
- HTTP liveness, title, status code, server, and technology hints through `httpx`
- Low-rate port candidates through `naabu`
- Service fingerprints through lightweight `nmap`
- TLS, crawl, and optional content discovery through `tlsx`, `katana`, and `ffuf`
- Candidate-only vulnerability findings through `nuclei`
- Final attack surface summary and frontend-ready report data

## Workflow Split

The module intentionally separates automated workflows from AI-gated single-function steps.

### `recon_scope_prepare_flow`

No-network preparation workflow:

1. `recon.scope_validate`
2. `recon.target_normalize`
3. `recon.attack_surface_summarize`
4. `recon.next_step_options`
5. `recon.report_generate`

Use it when the AI needs to validate scope and prepare a session without touching the network.

### `recon_basic_collection_flow`

Authorized basic collection workflow:

1. `recon.scope_validate`
2. `recon.target_normalize`
3. `recon.dns_probe`
4. `recon.http_probe`
5. `recon.port_scan`
6. `recon.attack_surface_summarize`
7. `recon.next_step_options`
8. `recon.report_generate`

Use it after the user confirms the target is authorized and active reconnaissance is allowed.

## AI-Gated Follow-Up Functions

These functions are not bundled into the default automated workflow. The AI should inspect `ai_output` first, then run at most one function at a time.

- `recon.service_identify`: runs or ingests lightweight `nmap` service fingerprint output.
- `recon.web_light_discover`: runs or ingests `tlsx`, `katana`, and optional `ffuf` output.
- `recon.vulnerability_candidate_scan`: runs or ingests conservative `nuclei` output. Findings remain candidate-only.
- `recon.attack_surface_summarize`: re-summarizes all collected evidence after each follow-up.
- `recon.next_step_options`: returns machine-readable next-step choices for the AI loop.
- `recon.report_generate`: creates the structured final result and a Markdown report draft.

## Required Authorization

Active functions require:

```text
confirm_authorized = I_CONFIRM_AUTHORIZED_ACTIVE_RECON
```

The expected target session fields are:

- `targets`
- `authorized_scope`
- `exclude`
- `module_id = recon_scan`

The module checks scope before active functions and rejects out-of-scope targets before scanning.

## Tool Dependencies

The module can run with installed local tools or ingest provided raw output through function parameters.

Recommended tools:

- `dnsx`
- `httpx`
- `naabu`
- `nmap`
- `tlsx`
- `katana`
- `ffuf`
- `nuclei`
- `SecLists` or another wordlist for optional content discovery

Tool paths are configured through the platform config center using `recon_scan.*` fields declared in:

```text
modules/recon_scan/config_fields/function_config_fields.json
```

## Output Model

The module writes three layers of evidence through the platform:

- Raw output: full function output under the session raw-output store
- AI output: compact sorted summaries produced by module raw sorters
- Final result: frontend-ready conclusion saved by `save_session_result`

The final result schema is:

```text
modules/recon_scan/skill/final_result_schema.json
```

The final report generator is:

```text
modules/recon_scan/functions/report_generate.py
```

The frontend result page reads:

```text
data/sessions/<session_id>/result/result.json
```

## Raw Sorting

Noisy external tool output is reduced by module-owned sorters:

```text
modules/recon_scan/config_files/raw_sorting/
```

Current sorter coverage includes:

- scope validation
- target normalization
- generic recon stages
- attack-surface summary
- next-step options
- final report summaries

These sorters are the preferred place to reduce token usage when a tool output is noisy.

## Frontend Mapping

The module declares one knowledge-backed page:

```text
module-page.html?module=recon_scan&page=scan_workflow_matrix
```

The page renders `knowledge/scan_workflow_matrix.json` through the platform-owned `knowledge_table` renderer. No module-owned frontend JavaScript is required.

## Module Layout

```text
modules/recon_scan/
  module.json
  functions/
  workflows/
  knowledge/
  config_fields/
  config_files/
    raw_sorting/
  skill/
    SKILL.md
    playbook.json
    final_result_schema.json
```

## Verification

Focused module tests:

```powershell
python -m py_compile modules\recon_scan\functions\scan_common.py modules\recon_scan\functions\service_identify.py modules\recon_scan\functions\vulnerability_candidate_scan.py modules\recon_scan\functions\attack_surface_summarize.py
python -m pytest tests\test_recon_scan_module.py
```

Platform compatibility check:

```text
load_module("recon_scan")
get_module_detail("recon_scan")
```

Expected result: module validation is `valid: true`.
