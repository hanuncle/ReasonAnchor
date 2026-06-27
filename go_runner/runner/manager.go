package runner

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Manager struct {
	executor Executor
	clock    func() time.Time

	mu      sync.RWMutex
	counter atomic.Uint64
	jobs    map[string]*Job
}

type Job struct {
	id     string
	plan   RunnerPlan
	ctx    context.Context
	cancel context.CancelFunc

	mu             sync.RWMutex
	status         string
	createdAt      time.Time
	startedAt      time.Time
	completedAt    time.Time
	stoppedReason  string
	nodes          map[string]NodeState
	outputs        map[string]NodeOutput
	completedNodes []string
	failedNode     *NodeState
}

type runResult struct {
	node      PlanNode
	output    NodeOutput
	err       error
	startedAt time.Time
	endedAt   time.Time
}

func NewManager(executor Executor) *Manager {
	return &Manager{
		executor: executor,
		clock:    time.Now,
		jobs:     make(map[string]*Job),
	}
}

func (manager *Manager) Submit(plan RunnerPlan) (JobSnapshot, error) {
	if manager.executor == nil {
		return JobSnapshot{}, fmt.Errorf("runner executor is nil")
	}
	now := manager.clock()
	jobID := fmt.Sprintf("job-%d-%d", now.UnixNano(), manager.counter.Add(1))
	ctx, cancel := context.WithCancel(context.Background())
	job := &Job{
		id:        jobID,
		plan:      plan,
		ctx:       ctx,
		cancel:    cancel,
		status:    JobQueued,
		createdAt: now,
		nodes:     make(map[string]NodeState),
		outputs:   make(map[string]NodeOutput),
	}
	for _, node := range plan.Plan.Nodes {
		job.nodes[node.NodeID] = NodeState{
			NodeID:        node.NodeID,
			FunctionID:    node.FunctionID,
			Status:        NodePending,
			DependsOn:     append([]string(nil), node.DependsOn...),
			ResourceLocks: append([]string(nil), node.ResourceLocks...),
		}
	}

	manager.mu.Lock()
	manager.jobs[jobID] = job
	manager.mu.Unlock()

	go manager.run(job)
	return job.snapshot(), nil
}

func (manager *Manager) Get(jobID string) (JobSnapshot, bool) {
	job, ok := manager.job(jobID)
	if !ok {
		return JobSnapshot{}, false
	}
	return job.snapshot(), true
}

func (manager *Manager) List() []JobSnapshot {
	manager.mu.RLock()
	jobs := make([]*Job, 0, len(manager.jobs))
	for _, job := range manager.jobs {
		jobs = append(jobs, job)
	}
	manager.mu.RUnlock()
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].createdAt.After(jobs[j].createdAt)
	})
	snapshots := make([]JobSnapshot, 0, len(jobs))
	for _, job := range jobs {
		snapshots = append(snapshots, job.snapshot())
	}
	return snapshots
}

func (manager *Manager) Result(jobID string) (map[string]NodeOutput, bool) {
	job, ok := manager.job(jobID)
	if !ok {
		return nil, false
	}
	job.mu.RLock()
	defer job.mu.RUnlock()
	result := make(map[string]NodeOutput, len(job.outputs))
	for key, value := range job.outputs {
		result[key] = value
	}
	return result, true
}

func (manager *Manager) Cancel(jobID string) (JobSnapshot, bool) {
	job, ok := manager.job(jobID)
	if !ok {
		return JobSnapshot{}, false
	}
	job.cancel()
	return job.snapshot(), true
}

func (manager *Manager) job(jobID string) (*Job, bool) {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	job, ok := manager.jobs[jobID]
	return job, ok
}

func (manager *Manager) run(job *Job) {
	job.setRunning(manager.clock())
	graph, err := validatePlan(job.plan)
	if err != nil {
		job.fail(nil, err.Error(), manager.clock())
		return
	}

	maxParallel := job.plan.Execution.MaxParallel
	if maxParallel <= 0 {
		maxParallel = 1
	}

	ready := initialReady(graph)
	running := 0
	completed := 0
	heldLocks := make(map[string]bool)
	results := make(chan runResult, len(job.plan.Plan.Nodes))

	for completed < len(job.plan.Plan.Nodes) {
		launchedOrSkipped := false
		for running < maxParallel {
			index := nextReadyIndex(ready, graph.nodes, heldLocks)
			if index < 0 {
				break
			}
			nodeID := ready[index]
			ready = removeAt(ready, index)
			node := graph.nodes[nodeID]

			if !job.shouldRun(node) {
				now := manager.clock()
				job.finishSkipped(node, now)
				completed++
				ready = appendReady(ready, graph.release(nodeID)...)
				launchedOrSkipped = true
				continue
			}

			acquireLocks(heldLocks, node.ResourceLocks)
			startedAt := manager.clock()
			job.markNodeRunning(node, startedAt)
			running++
			launchedOrSkipped = true
			go manager.runNode(job, node, startedAt, results)
		}

		if completed >= len(job.plan.Plan.Nodes) {
			break
		}
		if running == 0 && !launchedOrSkipped {
			job.fail(nil, "runner deadlock: no runnable node and no running node", manager.clock())
			return
		}

		select {
		case result := <-results:
			running--
			releaseLocks(heldLocks, result.node.ResourceLocks)
			completed++
			failed := result.err != nil || isFailureStatus(result.output.Status)
			job.finishNode(result, failed)
			if failed && result.node.StopOnError {
				reason := "node failed with stop_on_error"
				if result.err != nil {
					reason = result.err.Error()
				}
				job.fail(&result.node, reason, result.endedAt)
				return
			}
			ready = appendReady(ready, graph.release(result.node.NodeID)...)
		case <-job.ctx.Done():
			now := manager.clock()
			job.cancelRunning(now)
			return
		}
	}

	job.complete(manager.clock())
}

func (manager *Manager) runNode(job *Job, node PlanNode, startedAt time.Time, results chan<- runResult) {
	ctx, cancel := WithNodeTimeout(job.ctx, node.TimeoutSeconds)
	defer cancel()
	output, err := manager.executor.Execute(ctx, job.plan, node)
	endedAt := manager.clock()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		output.Status = NodeTimedOut
		err = fmt.Errorf("node timed out after %d seconds", node.TimeoutSeconds)
	} else if errors.Is(ctx.Err(), context.Canceled) && err == nil {
		output.Status = NodeCanceled
		err = ctx.Err()
	}
	if output.Status == "" {
		output.Status = NodeSuccess
	}
	results <- runResult{
		node:      node,
		output:    output,
		err:       err,
		startedAt: startedAt,
		endedAt:   endedAt,
	}
}

func (job *Job) shouldRun(node PlanNode) bool {
	if len(node.When) == 0 {
		return true
	}
	if conditions, ok := listValue(node.When["all"]); ok {
		for _, condition := range conditions {
			if !job.evalCondition(condition) {
				return false
			}
		}
		return true
	}
	if conditions, ok := listValue(node.When["any"]); ok {
		for _, condition := range conditions {
			if job.evalCondition(condition) {
				return true
			}
		}
		return false
	}
	return job.evalCondition(node.When)
}

func (job *Job) evalCondition(condition any) bool {
	conditionMap, ok := mapValue(condition)
	if !ok {
		return false
	}
	resultKey := stringValue(conditionMap["result_key"])
	if resultKey == "" {
		resultKey = stringValue(conditionMap["node_id"])
	}
	status := stringValue(conditionMap["status"])
	path := stringValue(conditionMap["path"])

	job.mu.RLock()
	output, exists := job.outputs[resultKey]
	job.mu.RUnlock()
	if !exists {
		return false
	}
	if status != "" && !strings.EqualFold(output.Status, status) {
		return false
	}
	if path == "" {
		return true
	}
	value, exists := valueAtPath(output, path)
	if !exists {
		return false
	}
	if expected, hasExpected := conditionMap["equals"]; hasExpected {
		return valuesEqual(value, expected)
	}
	return truthy(value)
}

func (job *Job) setRunning(now time.Time) {
	job.mu.Lock()
	defer job.mu.Unlock()
	job.status = JobRunning
	job.startedAt = now
}

func (job *Job) markNodeRunning(node PlanNode, startedAt time.Time) {
	job.mu.Lock()
	defer job.mu.Unlock()
	state := job.nodes[node.NodeID]
	state.Status = NodeRunning
	state.StartedAt = formatTime(startedAt)
	state.ResourceLocks = append([]string(nil), node.ResourceLocks...)
	state.DependsOn = append([]string(nil), node.DependsOn...)
	job.nodes[node.NodeID] = state
}

func (job *Job) finishSkipped(node PlanNode, now time.Time) {
	job.mu.Lock()
	defer job.mu.Unlock()
	state := job.nodes[node.NodeID]
	state.Status = NodeSkipped
	state.CompletedAt = formatTime(now)
	job.nodes[node.NodeID] = state
	job.outputs[node.NodeID] = NodeOutput{Status: NodeSkipped}
	job.completedNodes = append(job.completedNodes, node.NodeID)
}

func (job *Job) finishNode(result runResult, failed bool) {
	job.mu.Lock()
	defer job.mu.Unlock()
	state := job.nodes[result.node.NodeID]
	state.Status = result.output.Status
	state.CompletedAt = formatTime(result.endedAt)
	state.DurationMS = result.endedAt.Sub(result.startedAt).Milliseconds()
	state.ResultKey = result.output.ResultKey
	if result.err != nil {
		state.Error = result.err.Error()
	}
	if failed && state.Status == "" {
		state.Status = NodeError
	}
	job.nodes[result.node.NodeID] = state
	job.outputs[result.node.NodeID] = result.output
	if result.output.ResultKey != "" {
		job.outputs[result.output.ResultKey] = result.output
	}
	job.completedNodes = append(job.completedNodes, result.node.NodeID)
	if failed {
		copyState := state
		job.failedNode = &copyState
	}
}

func (job *Job) fail(node *PlanNode, reason string, now time.Time) {
	job.mu.Lock()
	defer job.mu.Unlock()
	job.status = JobFailed
	job.completedAt = now
	job.stoppedReason = reason
	if node != nil && job.failedNode == nil {
		state := job.nodes[node.NodeID]
		job.failedNode = &state
	}
}

func (job *Job) complete(now time.Time) {
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.status == JobCanceled || job.status == JobFailed {
		return
	}
	job.status = JobCompleted
	job.completedAt = now
}

func (job *Job) cancelRunning(now time.Time) {
	job.mu.Lock()
	defer job.mu.Unlock()
	job.status = JobCanceled
	job.completedAt = now
	job.stoppedReason = "job canceled"
	for nodeID, state := range job.nodes {
		if state.Status == NodeRunning {
			state.Status = NodeCanceled
			state.CompletedAt = formatTime(now)
			job.nodes[nodeID] = state
		}
	}
}

func (job *Job) snapshot() JobSnapshot {
	job.mu.RLock()
	defer job.mu.RUnlock()
	nodes := make(map[string]NodeState, len(job.nodes))
	runningNodes := make([]NodeState, 0)
	for key, value := range job.nodes {
		nodes[key] = value
		if value.Status == NodeRunning {
			runningNodes = append(runningNodes, value)
		}
	}
	sort.Slice(runningNodes, func(i, j int) bool {
		return runningNodes[i].NodeID < runningNodes[j].NodeID
	})
	completedNodes := append([]string(nil), job.completedNodes...)
	return JobSnapshot{
		JobID:          job.id,
		Status:         job.status,
		ModuleID:       job.plan.ModuleID,
		FlowID:         job.plan.FlowID,
		SessionID:      job.plan.SessionID,
		PlanName:       job.plan.Plan.PlanName,
		CreatedAt:      formatTime(job.createdAt),
		StartedAt:      formatTime(job.startedAt),
		CompletedAt:    formatTime(job.completedAt),
		MaxParallel:    maxParallel(job.plan),
		TotalNodes:     len(job.plan.Plan.Nodes),
		CompletedNodes: completedNodes,
		RunningNodes:   runningNodes,
		FailedNode:     cloneNodeState(job.failedNode),
		StoppedReason:  job.stoppedReason,
		Nodes:          nodes,
	}
}

func cloneNodeState(state *NodeState) *NodeState {
	if state == nil {
		return nil
	}
	copyState := *state
	return &copyState
}

func isFailureStatus(status string) bool {
	return strings.EqualFold(status, NodeError) || strings.EqualFold(status, NodeTimedOut) || strings.EqualFold(status, "failed")
}

func maxParallel(plan RunnerPlan) int {
	if plan.Execution.MaxParallel <= 0 {
		return 1
	}
	return plan.Execution.MaxParallel
}
