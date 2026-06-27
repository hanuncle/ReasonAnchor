package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Executor interface {
	Execute(ctx context.Context, plan RunnerPlan, node PlanNode) (NodeOutput, error)
}

type HTTPFunctionExecutor struct {
	APIBase string
	Client  *http.Client
}

func NewHTTPFunctionExecutor(apiBase string) *HTTPFunctionExecutor {
	if apiBase == "" {
		apiBase = "http://127.0.0.1:8111"
	}
	return &HTTPFunctionExecutor{
		APIBase: strings.TrimRight(apiBase, "/"),
		Client: &http.Client{
			Timeout: 0,
		},
	}
}

func (executor *HTTPFunctionExecutor) Execute(ctx context.Context, plan RunnerPlan, node PlanNode) (NodeOutput, error) {
	endpoint, err := executor.functionEndpoint(plan)
	if err != nil {
		return NodeOutput{Status: NodeError}, err
	}
	payload := map[string]any{
		"function_id": node.FunctionID,
		"params":      node.Params,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return NodeOutput{Status: NodeError}, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return NodeOutput{Status: NodeError}, err
	}
	request.Header.Set("Content-Type", "application/json")

	client := executor.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return NodeOutput{Status: NodeError}, err
	}
	defer response.Body.Close()

	responseBody, readErr := io.ReadAll(response.Body)
	if readErr != nil {
		return NodeOutput{Status: NodeError}, readErr
	}
	var raw map[string]any
	if len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, &raw); err != nil {
			return NodeOutput{
				Status: NodeError,
				Raw: map[string]any{
					"body": string(responseBody),
				},
			}, fmt.Errorf("decode function response: %w", err)
		}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return NodeOutput{Status: NodeError, Raw: raw}, fmt.Errorf("function endpoint returned %d", response.StatusCode)
	}

	output := NodeOutput{Status: NodeSuccess, Raw: raw}
	if result, ok := mapValue(raw["result"]); ok {
		if status := stringValue(result["status"]); status != "" {
			output.Status = status
		}
		output.ResultKey = stringValue(result["result_key"])
		if data, ok := mapValue(result["data"]); ok {
			output.Data = data
		}
	}
	if output.ResultKey == "" {
		output.ResultKey = stringValue(raw["result_key"])
	}
	if output.Status == "" {
		output.Status = NodeSuccess
	}
	return output, nil
}

func (executor *HTTPFunctionExecutor) functionEndpoint(plan RunnerPlan) (string, error) {
	endpoint := plan.APIContract.FunctionRunEndpoint
	if endpoint == "" {
		return "", fmt.Errorf("runner plan is missing api_contract.function_run_endpoint")
	}
	if strings.Contains(endpoint, "<session_id>") && plan.SessionID == "" {
		return "", fmt.Errorf("function endpoint requires session_id")
	}
	if plan.SessionID != "" {
		endpoint = strings.ReplaceAll(endpoint, "<session_id>", url.PathEscape(plan.SessionID))
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	if parsed.IsAbs() {
		return parsed.String(), nil
	}
	base, err := url.Parse(strings.TrimRight(executor.APIBase, "/"))
	if err != nil {
		return "", err
	}
	return base.ResolveReference(parsed).String(), nil
}

func WithNodeTimeout(parent context.Context, timeoutSeconds int) (context.Context, context.CancelFunc) {
	if timeoutSeconds <= 0 {
		return context.WithCancel(parent)
	}
	return context.WithTimeout(parent, time.Duration(timeoutSeconds)*time.Second)
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return ""
	}
}

func mapValue(value any) (map[string]any, bool) {
	if typed, ok := value.(map[string]any); ok {
		return typed, true
	}
	return nil, false
}
