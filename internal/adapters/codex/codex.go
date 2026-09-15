// Package codex implements the versioned adapter contract for Codex hooks.
package codex

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/secuardenai/secuarden-cli/internal/adapter"
)

type Adapter struct{}

var _ adapter.Adapter = Adapter{}

type input struct {
	SessionID        string          `json:"session_id"`
	PermissionMode   string          `json:"permission_mode"`
	Reason           string          `json:"reason"`
	PermissionStatus string          `json:"permission_status"`
	ToolName         string          `json:"tool_name"`
	ToolUseID        string          `json:"tool_use_id"`
	ToolInput        json.RawMessage `json:"tool_input"`
	HookEventName    string          `json:"hook_event_name"`
}

func (Adapter) Descriptor() adapter.Descriptor {
	return adapter.Descriptor{APIVersion: adapter.APIVersion, ID: "codex", Version: "1.0.0", AgentFamily: "codex"}
}

func (Adapter) Capabilities() adapter.Capabilities {
	return adapter.Capabilities{Hooks: []adapter.HookCapability{
		{Hook: "PreToolUse", Actions: []string{"file_write", "command_exec", "mcp_tool_use"}, Enforcement: adapter.EnforcementSynchronous, Decisions: []adapter.DecisionKind{adapter.DecisionAllow, adapter.DecisionDeny, adapter.DecisionRequireApproval}},
		{Hook: "PermissionRequest", Actions: []string{"file_write", "command_exec", "mcp_tool_use"}, Enforcement: adapter.EnforcementSynchronous, Decisions: []adapter.DecisionKind{adapter.DecisionAllow, adapter.DecisionDeny, adapter.DecisionRequireApproval}},
		{Hook: "PostToolUse", Actions: []string{"file_write", "command_exec", "mcp_tool_use"}, Enforcement: adapter.EnforcementObserveOnly},
		{Hook: "UserPromptSubmit", Actions: []string{"developer_intent"}, Enforcement: adapter.EnforcementObserveOnly},
		{Hook: "SessionStart", Actions: []string{"session_start"}, Enforcement: adapter.EnforcementObserveOnly},
		{Hook: "SessionEnd", Actions: []string{"session_end"}, Enforcement: adapter.EnforcementObserveOnly},
	}}
}

func (a Adapter) Validate(raw adapter.RawEvent) error {
	if _, ok := a.Capabilities().ForHook(raw.Hook); !ok {
		return fmt.Errorf("%w: %s", adapter.ErrUnsupportedHook, raw.Hook)
	}
	var v input
	if err := json.Unmarshal(raw.Payload, &v); err != nil {
		return fmt.Errorf("%w: %v", adapter.ErrInvalidInput, err)
	}
	if v.SessionID == "" {
		return fmt.Errorf("%w: missing session_id", adapter.ErrInvalidInput)
	}
	if raw.Hook == "PreToolUse" || raw.Hook == "PermissionRequest" || raw.Hook == "PostToolUse" {
		if v.ToolName == "" || v.ToolUseID == "" {
			return fmt.Errorf("%w: missing tool_name or tool_use_id", adapter.ErrInvalidInput)
		}
	}
	return nil
}

func (a Adapter) Normalize(raw adapter.RawEvent) (adapter.ActionProposal, error) {
	if err := a.Validate(raw); err != nil {
		return adapter.ActionProposal{}, err
	}
	var v input
	_ = json.Unmarshal(raw.Payload, &v)
	action := "unknown"
	switch {
	case raw.Hook == "UserPromptSubmit":
		action = "developer_intent"
	case raw.Hook == "SessionStart":
		action = "session_start"
	case raw.Hook == "SessionEnd":
		action = "session_end"
	case v.ToolName == "Bash":
		action = "command_exec"
	case v.ToolName == "apply_patch" || v.ToolName == "Edit" || v.ToolName == "Write":
		action = "file_write"
	case strings.HasPrefix(v.ToolName, "mcp__"):
		action = "mcp_tool_use"
	}
	attributes := map[string]interface{}{}
	if v.PermissionMode != "" {
		attributes["permission_mode"] = v.PermissionMode
	}
	if v.Reason != "" {
		attributes["reason"] = v.Reason
	}
	if v.PermissionStatus != "" {
		attributes["permission_status"] = v.PermissionStatus
	}
	return adapter.ActionProposal{SessionID: v.SessionID, InvocationID: v.ToolUseID, Hook: raw.Hook, ActionType: action, ToolName: v.ToolName, Attributes: attributes}, nil
}

func (a Adapter) RenderDecision(proposal adapter.ActionProposal, decision adapter.PolicyDecision) (adapter.AgentResponse, error) {
	if err := decision.Validate(); err != nil {
		return adapter.AgentResponse{}, err
	}
	capability, ok := a.Capabilities().ForHook(proposal.Hook)
	if !ok || !capability.SupportsDecision(decision.Kind) {
		return adapter.AgentResponse{}, fmt.Errorf("%w: %s", adapter.ErrUnsupportedDecision, decision.Kind)
	}
	if decision.Kind == adapter.DecisionRequireApproval {
		return adapter.AgentResponse{ExitCode: 0}, nil
	}
	behavior := "allow"
	if decision.Kind == adapter.DecisionDeny {
		behavior = "deny"
	}
	if proposal.Hook == "PermissionRequest" {
		body := map[string]interface{}{"hookSpecificOutput": map[string]interface{}{"hookEventName": proposal.Hook, "decision": map[string]interface{}{"behavior": behavior}}}
		if decision.Reason != "" {
			body["hookSpecificOutput"].(map[string]interface{})["decision"].(map[string]interface{})["message"] = decision.Reason
		}
		payload, _ := json.Marshal(body)
		return adapter.AgentResponse{Payload: payload, ExitCode: 0}, nil
	}
	body := map[string]interface{}{"hookSpecificOutput": map[string]interface{}{"hookEventName": proposal.Hook, "permissionDecision": behavior}}
	if decision.Reason != "" {
		body["hookSpecificOutput"].(map[string]interface{})["permissionDecisionReason"] = decision.Reason
	}
	payload, _ := json.Marshal(body)
	return adapter.AgentResponse{Payload: payload, ExitCode: 0}, nil
}
