# Vulnerability Scan Module Skill

Use this module only for explicitly authorized targets and approved scope. This module represents active scanning capability and must not run by default.

Require human confirmation before any network scan. Extract target candidates first, confirm scope, then run only the necessary scan workflow.

After analysis, produce the final session summary according to `modules/vuln_scan/skill/final_result_schema.json` and save it with `save_session_result`. Only include explicitly authorized scope and keep unverified scan output marked as unverified.
