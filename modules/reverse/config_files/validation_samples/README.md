# Reverse Validation Samples

This directory contains benign single-point validation fixtures for the reverse module.
Each fixture is designed to exercise one behavior category and produce predictable
dynamic telemetry. Fixtures are not executed by default.

Safety rules:

- Use only in an approved isolated VM snapshot.
- Prefer `win11-tools-ready-export-ok` or a clone of it.
- Run one fixture at a time.
- Export telemetry after each run with `C:\Tools\Export-DynamicTelemetry.ps1`.
- Run the fixture cleanup mode before restoring or reusing a VM.
- Do not treat fixture telemetry as malware behavior.

Current fixture set:

- `command_execution_fixture.ps1`: launches a benign command interpreter action.
- `file_write_fixture.ps1`: writes and removes a marker file.
- `registry_run_key_fixture.ps1`: writes and removes a HKCU Run key value.
- `network_connect_fixture.ps1`: attempts a loopback TCP connection only.
- `scheduled_task_fixture.ps1`: creates, runs, and removes a current-user task.
- `process_injection_fixture.ps1`: performs query-only process access against a child process.
- `credential_access_fixture.ps1`: emits benign LSASS query wording without dumping credentials.
- `anti_analysis_fixture.ps1`: probes local analysis-related process and registry names.
- `packer_or_obfuscation_fixture.ps1`: creates static-only encoded/high-entropy-looking marker artifacts.
- `service_creation_fixture.ps1`: creates, starts, stops, and removes a temporary benign service.
