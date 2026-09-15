package events

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// CodexHookInput is the Codex lifecycle-hook wire format. ToolInput and
// ToolResponse deliberately remain RawMessage because Codex defines them as
// arbitrary JSON values, not objects.
type CodexHookInput struct {
	SessionID          string          `json:"session_id"`
	TranscriptPath     string          `json:"transcript_path"`
	CWD                string          `json:"cwd"`
	HookEventName      string          `json:"hook_event_name"`
	Model              string          `json:"model"`
	PermissionMode     string          `json:"permission_mode"`
	TurnID             string          `json:"turn_id"`
	ToolName           string          `json:"tool_name"`
	ToolUseID          string          `json:"tool_use_id"`
	ToolInput          json.RawMessage `json:"tool_input"`
	ToolResponse       json.RawMessage `json:"tool_response"`
	Prompt             string          `json:"prompt"`
	Source             string          `json:"source"`
	Reason             string          `json:"reason"`
	PermissionDecision string          `json:"permission_decision"`
	PermissionStatus   string          `json:"permission_status"`
}

// ParseCodexHookInput validates the top-level JSON object and preserves the
// native JSON shape of tool_input/tool_response for agent-specific handling.
func ParseCodexHookInput(data []byte) (*CodexHookInput, error) {
	var raw CodexHookInput
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse Codex hook input: %w", err)
	}
	if len(data) == 0 || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil, fmt.Errorf("parse Codex hook input: expected JSON object")
	}
	if raw.PermissionStatus == "" {
		switch raw.PermissionDecision {
		case "allow", "allowed":
			raw.PermissionStatus = "allowed"
		case "deny", "denied", "reject", "rejected":
			raw.PermissionStatus = "denied"
		}
	}
	return &raw, nil
}

// JSONObject converts an arbitrary JSON value to an object when possible.
// Non-object values are valid Codex payloads and return (nil, false).
func JSONObject(raw json.RawMessage) (map[string]interface{}, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false
	}
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

// MapCodexToolToAction maps Codex's canonical hook tool names.
func MapCodexToolToAction(toolName string) string {
	if toolName == "apply_patch" || toolName == "Edit" || toolName == "Write" {
		return ActionFileWrite
	}
	return MapToolToAction(toolName)
}
