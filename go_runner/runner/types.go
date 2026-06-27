package runner

import "time"

const (
	PlanSchemaID = "security_function_platform.runner_plan.v1"

	JobQueued    = "queued"
	JobRunning   = "running"
	JobCompleted = "completed"
	JobFailed    = "failed"
	JobCanceled  = "canceled"

	NodePending  = "pending"
	NodeRunning  = "running"
	NodeSuccess  = "success"
	NodeError    = "error"
	NodeSkipped  = "skipped"
	NodeCanceled = "canceled"
	NodeTimedOut = "timed_out"
)

type RunnerPlan struct {
	SchemaID    string            `json:"schema_id"`
	Runner      string            `json:"runner"`
	ModuleID    string            `json:"module_id"`
	FlowID      string            `json:"flow_id"`
	Scope       string            `json:"scope"`
	SessionID   string            `json:"session_id"`
	Source      PlanSource        `json:"source"`
	Execution   ExecutionContract `json:"execution"`
	APIContract APIContract       `json:"api_contract"`
	Plan        PlanBody          `json:"plan"`
}

type PlanSource struct {
	Type       string   `json:"type"`
	WorkflowID string   `json:"workflow_id"`
	ActionIDs  []string `json:"action_ids"`
}

type ExecutionContract struct {
	Mode               string `json:"mode"`
	MaxParallel        int    `json:"max_parallel"`
	Scheduler          string `json:"scheduler"`
	DefaultStopOnError bool   `json:"default_stop_on_error"`
}

type APIContract struct {
	FunctionRunEndpoint            string `json:"function_run_endpoint"`
	SessionExecutionStatusEndpoint string `json:"session_execution_status_endpoint"`
	RawOutputMapEndpoint           string `json:"raw_output_map_endpoint"`
}

type PlanBody struct {
	PlanName   string     `json:"plan_name"`
	TotalNodes int        `json:"total_nodes"`
	Nodes      []PlanNode `json:"nodes"`
}

type PlanNode struct {
	NodeID                   string         `json:"node_id"`
	FunctionID               string         `json:"function_id"`
	Params                   map[string]any `json:"params,omitempty"`
	DependsOn                []string       `json:"depends_on,omitempty"`
	RequiresResults          []string       `json:"requires_results,omitempty"`
	StopOnError              bool           `json:"stop_on_error"`
	TimeoutSeconds           int            `json:"timeout_seconds,omitempty"`
	When                     map[string]any `json:"when,omitempty"`
	ResourceLocks            []string       `json:"resource_locks,omitempty"`
	ParallelSafe             bool           `json:"parallel_safe"`
	EstimatedDurationSeconds int            `json:"estimated_duration_seconds,omitempty"`
	SourceIndex              int            `json:"source_index,omitempty"`
}

type NodeOutput struct {
	Status    string         `json:"status"`
	ResultKey string         `json:"result_key,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
	Raw       map[string]any `json:"raw,omitempty"`
}

type NodeState struct {
	NodeID        string   `json:"node_id"`
	FunctionID    string   `json:"function_id"`
	Status        string   `json:"status"`
	StartedAt     string   `json:"started_at,omitempty"`
	CompletedAt   string   `json:"completed_at,omitempty"`
	DurationMS    int64    `json:"duration_ms,omitempty"`
	Error         string   `json:"error,omitempty"`
	ResultKey     string   `json:"result_key,omitempty"`
	DependsOn     []string `json:"depends_on,omitempty"`
	ResourceLocks []string `json:"resource_locks,omitempty"`
}

type JobSnapshot struct {
	JobID          string               `json:"job_id"`
	Status         string               `json:"status"`
	ModuleID       string               `json:"module_id"`
	FlowID         string               `json:"flow_id"`
	SessionID      string               `json:"session_id"`
	PlanName       string               `json:"plan_name"`
	CreatedAt      string               `json:"created_at"`
	StartedAt      string               `json:"started_at,omitempty"`
	CompletedAt    string               `json:"completed_at,omitempty"`
	MaxParallel    int                  `json:"max_parallel"`
	TotalNodes     int                  `json:"total_nodes"`
	CompletedNodes []string             `json:"completed_nodes"`
	RunningNodes   []NodeState          `json:"running_nodes"`
	FailedNode     *NodeState           `json:"failed_node,omitempty"`
	StoppedReason  string               `json:"stopped_reason,omitempty"`
	Nodes          map[string]NodeState `json:"nodes"`
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
