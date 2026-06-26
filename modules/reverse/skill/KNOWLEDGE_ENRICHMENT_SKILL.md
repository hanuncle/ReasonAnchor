# Reverse Knowledge Enrichment Skill

Use this companion skill only when the user approves knowledge-base update review for the reverse module.

## Goal

Turn repeated analysis lessons into reusable module assets without silently changing conclusions or writing unreviewed knowledge.

Candidate enrichment targets:

- `modules/reverse/knowledge/behavior_taxonomy.json`: canonical behavior category IDs, names, static keywords, dynamic telemetry rules, and ATT&CK links.
- `modules/reverse/knowledge/attack/techniques.json`: ATT&CK technique mappings, analysis methods, detection methods, false-positive notes, recommended functions, validation scenarios, and validation samples.
- `modules/reverse/config_files/validation/validation_scenarios.json`: behavior-specific validation scenarios.
- `modules/reverse/config_files/validation_samples/samples_manifest.json`: registered benign single-point validation fixtures.
- `modules/reverse/config_files/validation_samples/`: benign validation fixture files.
- `modules/reverse/config_files/raw_sorting/`: compact output sorters when repeated analysis output is too noisy.

## Before Analysis

If the user has not explicitly accepted or declined knowledge enrichment for the run, ask whether to enable knowledge-base update review.

If the user declines:

- Do not read or modify enrichment targets for that run.
- Continue normal analysis and save only the session result.

If the user accepts:

- Read this file before running analysis.
- Treat all enrichment as candidate-only until human review.
- Do not write knowledge files during sample execution or before the final session result is saved.

## After Analysis

Generate candidate knowledge updates only when the analysis reveals one of these cases:

- A behavior category is repeatedly observed but missing from `behavior_taxonomy.json`.
- Static or dynamic mapping is noisy because the taxonomy keyword or telemetry rule is too broad.
- `attack.map_static` leaves a behavior unmapped and an ATT&CK technique can be justified with evidence.
- A behavior needs focused validation but no validation scenario exists.
- A technique needs a benign single-point validation fixture.
- Raw or AI-facing output repeatedly hides the useful evidence and needs a sorter improvement.

Each candidate update must include:

- target file
- change type: add, update, split, merge, deprecate, or sorter_tune
- evidence source: session id, raw output id, function id, and short reason
- safety note
- whether a new test is required

## Write Policy

Do not automatically apply candidate updates.

Candidate updates must not modify official knowledge files directly.

When a reusable lesson should be retained, call `knowledge.update_candidate` with the proposed change, evidence references, confidence, and target. This writes a `pending_review` JSON candidate under `data/knowledge_candidates/reverse/` and sets `official_knowledge_modified=false`. A later human-reviewed apply step must update the official knowledge files.
