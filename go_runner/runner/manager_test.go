package runner

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

type fakeExecutor struct {
	sleep    time.Duration
	failNode map[string]bool
	data     map[string]map[string]any

	mu        sync.Mutex
	active    int
	maxActive int
	started   []string
	finished  []string
}

func (executor *fakeExecutor) Execute(ctx context.Context, _ RunnerPlan, node PlanNode) (NodeOutput, error) {
	executor.mu.Lock()
	executor.active++
	if executor.active > executor.maxActive {
		executor.maxActive = executor.active
	}
	executor.started = append(executor.started, node.NodeID)
	executor.mu.Unlock()

	defer func() {
		executor.mu.Lock()
		executor.active--
		executor.finished = append(executor.finished, node.NodeID)
		executor.mu.Unlock()
	}()

	select {
	case <-time.After(executor.sleep):
	case <-ctx.Done():
		return NodeOutput{Status: NodeCanceled}, ctx.Err()
	}

	if executor.failNode[node.NodeID] {
		return NodeOutput{Status: NodeError}, fmt.Errorf("node %s failed", node.NodeID)
	}
	output := NodeOutput{
		Status:    NodeSuccess,
		ResultKey: node.NodeID,
		Data:      map[string]any{},
	}
	if executor.data != nil && executor.data[node.NodeID] != nil {
		output.Data = executor.data[node.NodeID]
	}
	return output, nil
}

func TestIndependentNodesRunConcurrently(t *testing.T) {
	executor := &fakeExecutor{sleep: 80 * time.Millisecond, failNode: map[string]bool{}}
	manager := NewManager(executor)
	snapshot, err := manager.Submit(testPlan(2, []PlanNode{
		node("a"),
		node("b"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	final := waitForTerminal(t, manager, snapshot.JobID)
	if final.Status != JobCompleted {
		t.Fatalf("job status = %s, want %s", final.Status, JobCompleted)
	}
	if executor.maxActive < 2 {
		t.Fatalf("max active nodes = %d, want at least 2", executor.maxActive)
	}
}

func TestResourceLocksSerializeNodes(t *testing.T) {
	executor := &fakeExecutor{sleep: 40 * time.Millisecond, failNode: map[string]bool{}}
	manager := NewManager(executor)
	a := node("a")
	a.ResourceLocks = []string{"vm:default"}
	b := node("b")
	b.ResourceLocks = []string{"vm:default"}
	snapshot, err := manager.Submit(testPlan(2, []PlanNode{a, b}))
	if err != nil {
		t.Fatal(err)
	}
	final := waitForTerminal(t, manager, snapshot.JobID)
	if final.Status != JobCompleted {
		t.Fatalf("job status = %s, want %s", final.Status, JobCompleted)
	}
	if executor.maxActive != 1 {
		t.Fatalf("max active nodes = %d, want 1 for same resource lock", executor.maxActive)
	}
}

func TestDependenciesRunAfterParents(t *testing.T) {
	executor := &fakeExecutor{sleep: 30 * time.Millisecond, failNode: map[string]bool{}}
	manager := NewManager(executor)
	c := node("c")
	c.DependsOn = []string{"a", "b"}
	snapshot, err := manager.Submit(testPlan(3, []PlanNode{node("a"), node("b"), c}))
	if err != nil {
		t.Fatal(err)
	}
	final := waitForTerminal(t, manager, snapshot.JobID)
	if final.Status != JobCompleted {
		t.Fatalf("job status = %s, want %s", final.Status, JobCompleted)
	}
	started := executor.startedOrder()
	if indexOf(started, "c") < indexOf(started, "a") || indexOf(started, "c") < indexOf(started, "b") {
		t.Fatalf("start order = %v, dependent node c started before a or b", started)
	}
}

func TestStopOnErrorFailsJobAndSkipsDependentLaunch(t *testing.T) {
	executor := &fakeExecutor{
		sleep:    20 * time.Millisecond,
		failNode: map[string]bool{"a": true},
	}
	manager := NewManager(executor)
	a := node("a")
	a.StopOnError = true
	b := node("b")
	b.DependsOn = []string{"a"}
	snapshot, err := manager.Submit(testPlan(2, []PlanNode{a, b}))
	if err != nil {
		t.Fatal(err)
	}
	final := waitForTerminal(t, manager, snapshot.JobID)
	if final.Status != JobFailed {
		t.Fatalf("job status = %s, want %s", final.Status, JobFailed)
	}
	if final.Nodes["b"].Status != NodePending {
		t.Fatalf("dependent status = %s, want pending because parent stopped the job", final.Nodes["b"].Status)
	}
}

func TestWhenConditionSkipsNode(t *testing.T) {
	executor := &fakeExecutor{
		sleep:    10 * time.Millisecond,
		failNode: map[string]bool{},
		data: map[string]map[string]any{
			"a": {"has_network": false},
		},
	}
	manager := NewManager(executor)
	b := node("b")
	b.DependsOn = []string{"a"}
	b.When = map[string]any{
		"result_key": "a",
		"path":       "has_network",
		"equals":     true,
	}
	snapshot, err := manager.Submit(testPlan(2, []PlanNode{node("a"), b}))
	if err != nil {
		t.Fatal(err)
	}
	final := waitForTerminal(t, manager, snapshot.JobID)
	if final.Status != JobCompleted {
		t.Fatalf("job status = %s, want %s", final.Status, JobCompleted)
	}
	if final.Nodes["b"].Status != NodeSkipped {
		t.Fatalf("conditional node status = %s, want %s", final.Nodes["b"].Status, NodeSkipped)
	}
}

func TestValidatePlanRejectsUnknownDependencyAndCycle(t *testing.T) {
	_, err := validatePlan(testPlan(1, []PlanNode{
		{
			NodeID:     "a",
			FunctionID: "fn.a",
			DependsOn:  []string{"missing"},
		},
	}))
	if err == nil {
		t.Fatal("expected unknown dependency error")
	}

	a := node("a")
	a.DependsOn = []string{"b"}
	b := node("b")
	b.DependsOn = []string{"a"}
	_, err = validatePlan(testPlan(1, []PlanNode{a, b}))
	if err == nil {
		t.Fatal("expected cycle error")
	}
}

func (executor *fakeExecutor) startedOrder() []string {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return append([]string(nil), executor.started...)
}

func waitForTerminal(t *testing.T, manager *Manager, jobID string) JobSnapshot {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, ok := manager.Get(jobID)
		if !ok {
			t.Fatalf("job %s not found", jobID)
		}
		switch snapshot.Status {
		case JobCompleted, JobFailed, JobCanceled:
			return snapshot
		}
		time.Sleep(10 * time.Millisecond)
	}
	snapshot, _ := manager.Get(jobID)
	t.Fatalf("job %s did not finish before deadline, status %s", jobID, snapshot.Status)
	return JobSnapshot{}
}

func testPlan(maxParallel int, nodes []PlanNode) RunnerPlan {
	return RunnerPlan{
		SchemaID:  PlanSchemaID,
		Runner:    "go_dag_runner",
		ModuleID:  "test",
		FlowID:    "test_flow",
		SessionID: "session-1",
		Execution: ExecutionContract{
			Mode:        "async_job",
			MaxParallel: maxParallel,
			Scheduler:   "kahn_topological_ready_queue",
		},
		APIContract: APIContract{
			FunctionRunEndpoint: "/api/sessions/<session_id>/functions/run",
		},
		Plan: PlanBody{
			PlanName:   "test_plan",
			TotalNodes: len(nodes),
			Nodes:      nodes,
		},
	}
}

func node(nodeID string) PlanNode {
	return PlanNode{
		NodeID:       nodeID,
		FunctionID:   "fn." + nodeID,
		Params:       map[string]any{},
		StopOnError:  false,
		ParallelSafe: true,
	}
}

func indexOf(values []string, value string) int {
	for index, item := range values {
		if item == value {
			return index
		}
	}
	return -1
}
