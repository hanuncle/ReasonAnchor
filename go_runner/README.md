# SFP Go Runner

`sfp-go-runner` executes `security_function_platform.runner_plan.v1` plans exported by the Python platform.

The runner is deliberately generic:

- `depends_on` builds the DAG.
- `execution.max_parallel` controls how many ready nodes may run at once.
- `resource_locks` prevents nodes that use the same resource from running together.
- `timeout_seconds` bounds a node execution.
- `stop_on_error` stops the job when a critical node fails.
- `when` can skip conditional nodes after parent results are available.

Start it with:

```powershell
go run .\cmd\sfp-go-runner -listen :8112 -api-base http://127.0.0.1:8111
```

Submit a job:

```http
POST /jobs
Content-Type: application/json

{
  "runner_plan": {
    "schema_id": "security_function_platform.runner_plan.v1",
    "...": "..."
  }
}
```

The runner calls each node through the plan's `api_contract.function_run_endpoint`, usually:

```text
/api/sessions/<session_id>/functions/run
```
