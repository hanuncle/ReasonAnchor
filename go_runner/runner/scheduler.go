package runner

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
)

type planGraph struct {
	nodes      map[string]PlanNode
	dependents map[string][]string
	remaining  map[string]int
}

func validatePlan(plan RunnerPlan) (*planGraph, error) {
	if plan.SchemaID != "" && plan.SchemaID != PlanSchemaID {
		return nil, fmt.Errorf("unsupported runner plan schema: %s", plan.SchemaID)
	}
	if len(plan.Plan.Nodes) == 0 {
		return nil, fmt.Errorf("runner plan has no nodes")
	}
	graph := &planGraph{
		nodes:      make(map[string]PlanNode, len(plan.Plan.Nodes)),
		dependents: make(map[string][]string),
		remaining:  make(map[string]int),
	}
	for index, node := range plan.Plan.Nodes {
		if node.NodeID == "" {
			return nil, fmt.Errorf("node at index %d is missing node_id", index)
		}
		if node.FunctionID == "" {
			return nil, fmt.Errorf("node %s is missing function_id", node.NodeID)
		}
		if _, exists := graph.nodes[node.NodeID]; exists {
			return nil, fmt.Errorf("duplicate node_id: %s", node.NodeID)
		}
		if node.Params == nil {
			node.Params = map[string]any{}
		}
		node.SourceIndex = index
		graph.nodes[node.NodeID] = node
		graph.remaining[node.NodeID] = len(node.DependsOn)
	}
	for _, node := range graph.nodes {
		for _, dependency := range node.DependsOn {
			if _, exists := graph.nodes[dependency]; !exists {
				return nil, fmt.Errorf("node %s depends on unknown node %s", node.NodeID, dependency)
			}
			graph.dependents[dependency] = append(graph.dependents[dependency], node.NodeID)
		}
	}
	if hasCycle(graph) {
		return nil, fmt.Errorf("runner plan contains a dependency cycle")
	}
	return graph, nil
}

func hasCycle(graph *planGraph) bool {
	remaining := make(map[string]int, len(graph.remaining))
	for nodeID, count := range graph.remaining {
		remaining[nodeID] = count
	}
	ready := make([]string, 0)
	for nodeID, count := range remaining {
		if count == 0 {
			ready = append(ready, nodeID)
		}
	}
	visited := 0
	for len(ready) > 0 {
		nodeID := ready[0]
		ready = ready[1:]
		visited++
		for _, dependent := range graph.dependents[nodeID] {
			remaining[dependent]--
			if remaining[dependent] == 0 {
				ready = append(ready, dependent)
			}
		}
	}
	return visited != len(graph.nodes)
}

func initialReady(graph *planGraph) []string {
	ready := make([]string, 0)
	for nodeID, count := range graph.remaining {
		if count == 0 {
			ready = append(ready, nodeID)
		}
	}
	sortReady(ready, graph.nodes)
	return ready
}

func (graph *planGraph) release(nodeID string) []string {
	ready := make([]string, 0)
	for _, dependent := range graph.dependents[nodeID] {
		graph.remaining[dependent]--
		if graph.remaining[dependent] == 0 {
			ready = append(ready, dependent)
		}
	}
	sortReady(ready, graph.nodes)
	return ready
}

func appendReady(ready []string, additions ...string) []string {
	ready = append(ready, additions...)
	return ready
}

func sortReady(ready []string, nodes map[string]PlanNode) {
	sort.Slice(ready, func(i, j int) bool {
		left := nodes[ready[i]]
		right := nodes[ready[j]]
		if left.SourceIndex == right.SourceIndex {
			return left.NodeID < right.NodeID
		}
		return left.SourceIndex < right.SourceIndex
	})
}

func nextReadyIndex(ready []string, nodes map[string]PlanNode, heldLocks map[string]bool) int {
	for index, nodeID := range ready {
		if locksAvailable(heldLocks, nodes[nodeID].ResourceLocks) {
			return index
		}
	}
	return -1
}

func removeAt(values []string, index int) []string {
	return append(values[:index], values[index+1:]...)
}

func locksAvailable(heldLocks map[string]bool, resourceLocks []string) bool {
	for _, lock := range resourceLocks {
		if heldLocks[lock] {
			return false
		}
	}
	return true
}

func acquireLocks(heldLocks map[string]bool, resourceLocks []string) {
	for _, lock := range resourceLocks {
		heldLocks[lock] = true
	}
}

func releaseLocks(heldLocks map[string]bool, resourceLocks []string) {
	for _, lock := range resourceLocks {
		delete(heldLocks, lock)
	}
}

func listValue(value any) ([]any, bool) {
	if value == nil {
		return nil, false
	}
	if values, ok := value.([]any); ok {
		return values, true
	}
	return nil, false
}

func valueAtPath(output NodeOutput, path string) (any, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, false
	}
	if strings.HasPrefix(path, "data.") {
		return pathValue(output.Data, strings.TrimPrefix(path, "data."))
	}
	if strings.HasPrefix(path, "raw.") {
		return pathValue(output.Raw, strings.TrimPrefix(path, "raw."))
	}
	if value, ok := pathValue(output.Data, path); ok {
		return value, true
	}
	return pathValue(output.Raw, path)
}

func pathValue(root map[string]any, path string) (any, bool) {
	if root == nil {
		return nil, false
	}
	parts := strings.Split(path, ".")
	var current any = root
	for _, part := range parts {
		currentMap, ok := mapValue(current)
		if !ok {
			return nil, false
		}
		value, exists := currentMap[part]
		if !exists {
			return nil, false
		}
		current = value
	}
	return current, true
}

func valuesEqual(left any, right any) bool {
	return reflect.DeepEqual(left, right)
}

func truthy(value any) bool {
	switch typed := value.(type) {
	case nil:
		return false
	case bool:
		return typed
	case string:
		return typed != "" && !strings.EqualFold(typed, "false") && typed != "0"
	case float64:
		return typed != 0
	case float32:
		return typed != 0
	case int:
		return typed != 0
	case int64:
		return typed != 0
	case int32:
		return typed != 0
	default:
		return true
	}
}
