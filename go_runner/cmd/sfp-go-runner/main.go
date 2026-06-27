package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"securityfunctionplatform/go_runner/runner"
)

type server struct {
	manager *runner.Manager
}

func main() {
	defaultAPIBase := os.Getenv("SECURITY_FUNCTION_PLATFORM_API_BASE")
	if defaultAPIBase == "" {
		defaultAPIBase = "http://127.0.0.1:8111"
	}
	listen := flag.String("listen", ":8112", "HTTP listen address")
	apiBase := flag.String("api-base", defaultAPIBase, "SecurityFunctionPlatform API base URL")
	flag.Parse()

	executor := runner.NewHTTPFunctionExecutor(*apiBase)
	app := &server{manager: runner.NewManager(executor)}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", app.handleHealth)
	mux.HandleFunc("/jobs", app.handleJobs)
	mux.HandleFunc("/jobs/", app.handleJob)

	log.Printf("sfp-go-runner listening on %s, platform api base %s", *listen, *apiBase)
	if err := http.ListenAndServe(*listen, mux); err != nil {
		log.Fatal(err)
	}
}

func (app *server) handleHealth(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"status": "ok",
		"runner": "sfp-go-runner",
	})
}

func (app *server) handleJobs(response http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet:
		writeJSON(response, http.StatusOK, map[string]any{
			"jobs": app.manager.List(),
		})
	case http.MethodPost:
		plan, err := decodeRunnerPlan(request.Body)
		if err != nil {
			writeError(response, http.StatusBadRequest, "invalid_runner_plan", err.Error())
			return
		}
		snapshot, err := app.manager.Submit(plan)
		if err != nil {
			writeError(response, http.StatusBadRequest, "submit_failed", err.Error())
			return
		}
		writeJSON(response, http.StatusAccepted, snapshot)
	default:
		writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (app *server) handleJob(response http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(request.URL.Path, "/jobs/"), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(response, http.StatusNotFound, "job_not_found", "job not found")
		return
	}
	jobID := parts[0]
	if len(parts) == 1 {
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		snapshot, ok := app.manager.Get(jobID)
		if !ok {
			writeError(response, http.StatusNotFound, "job_not_found", "job not found")
			return
		}
		writeJSON(response, http.StatusOK, snapshot)
		return
	}
	if len(parts) == 2 && parts[1] == "result" {
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		outputs, ok := app.manager.Result(jobID)
		if !ok {
			writeError(response, http.StatusNotFound, "job_not_found", "job not found")
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{
			"job_id":  jobID,
			"outputs": outputs,
		})
		return
	}
	if len(parts) == 2 && parts[1] == "cancel" {
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
			return
		}
		snapshot, ok := app.manager.Cancel(jobID)
		if !ok {
			writeError(response, http.StatusNotFound, "job_not_found", "job not found")
			return
		}
		writeJSON(response, http.StatusOK, snapshot)
		return
	}
	writeError(response, http.StatusNotFound, "job_not_found", "job not found")
}

func decodeRunnerPlan(reader io.Reader) (runner.RunnerPlan, error) {
	body, err := io.ReadAll(reader)
	if err != nil {
		return runner.RunnerPlan{}, err
	}
	var envelope struct {
		RunnerPlan *runner.RunnerPlan `json:"runner_plan"`
	}
	if err := json.Unmarshal(body, &envelope); err == nil && envelope.RunnerPlan != nil {
		return *envelope.RunnerPlan, nil
	}
	var plan runner.RunnerPlan
	if err := json.Unmarshal(body, &plan); err != nil {
		return runner.RunnerPlan{}, fmt.Errorf("decode runner plan: %w", err)
	}
	return plan, nil
}

func writeJSON(response http.ResponseWriter, statusCode int, payload any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(statusCode)
	if err := json.NewEncoder(response).Encode(payload); err != nil {
		log.Printf("write json response: %v", err)
	}
}

func writeError(response http.ResponseWriter, statusCode int, code string, message string) {
	writeJSON(response, statusCode, map[string]any{
		"status": "error",
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}
