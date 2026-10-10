package events

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNormalizeCodexToolResponse(t *testing.T) {
	tests := []struct {
		name, raw, tool, status string
		supported               bool
		content                 string
		exitCode                interface{}
	}{
		{name: "successful exit", raw: `{"exit_code":0,"output":"done"}`, tool: "Bash", status: ResultSuccess, supported: true, content: "done", exitCode: 0},
		{name: "nonzero exit", raw: `{"exitCode":7,"stderr":"no"}`, tool: "Bash", status: ResultError, supported: true, exitCode: 7},
		{name: "explicit error", raw: `{"error":{"message":"denied"}}`, tool: "Bash", status: ResultError, supported: true, content: "denied"},
		{name: "MCP error", raw: `{"content":[{"type":"text","text":"denied"}],"isError":true}`, tool: "mcp__docs__lookup", status: ResultError, supported: true, content: "denied"},
		{name: "MCP success", raw: `{"content":[{"type":"text","text":"ok"}],"isError":false}`, tool: "mcp__docs__lookup", status: ResultSuccess, supported: true, content: "ok"},
		{name: "successful array", raw: `[{"exit_code":0,"output":"one"},{"status":"completed","content":"two"}]`, tool: "Bash", status: ResultSuccess, supported: true, content: "one\ntwo"},
		{name: "array failure wins", raw: `[{"success":true},{"exit_code":1}]`, tool: "Bash", status: ResultError, supported: true},
		{name: "scalar content", raw: `"tool failed"`, tool: "Bash", status: ResultUnknown, content: "tool failed"},
		{name: "content block array", raw: `[{"type":"text","text":"done"}]`, tool: "Bash", status: ResultUnknown, content: "done"},
		{name: "null", raw: `null`, tool: "Bash", status: ResultUnknown},
		{name: "unrecognized object", raw: `{"message":"finished"}`, tool: "Bash", status: ResultUnknown},
		{name: "output text is not status", raw: `{"output":"error count: 0"}`, tool: "Bash", status: ResultUnknown, content: "error count: 0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := NormalizeCodexToolResponse(json.RawMessage(test.raw), test.tool)
			if err != nil {
				t.Fatal(err)
			}
			if result.ResultStatus != test.status || result.Supported != test.supported {
				t.Fatalf("status=%q supported=%v, want %q/%v", result.ResultStatus, result.Supported, test.status, test.supported)
			}
			if got, _ := result.Fields["content"].(string); got != test.content {
				t.Fatalf("content=%q, want %q", got, test.content)
			}
			if test.exitCode != nil && result.Fields["exit_code"] != test.exitCode {
				t.Fatalf("exit_code=%#v, want %#v", result.Fields["exit_code"], test.exitCode)
			}
		})
	}
}

func TestNormalizeCodexToolResponseInvalidJSONDoesNotEchoPayload(t *testing.T) {
	marker := "CODEX_RESPONSE_MARKER_7d029e"
	_, err := NormalizeCodexToolResponse(json.RawMessage(`{"secret":"`+marker), "Bash")
	if err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("unsafe parse error: %v", err)
	}
}
