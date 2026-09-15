package events

import "encoding/json"

const SchemaURL = "https://schema.secuarden.ai/stage1/2.0/event.schema.json"
const SchemaVersion = "2.0.0"

// Event is a governance event captured from an AI coding agent session.
// It matches the JSON schema at schema/stage1/v2/event.schema.json.
type Event struct {
	Schema        string `json:"$schema"`
	SchemaVersion string `json:"schema_version"`

	ID           string `json:"id"`
	SessionID    string `json:"session_id"`
	Sequence     int    `json:"sequence"`
	Timestamp    string `json:"timestamp"`
	CapturedAt   string `json:"captured_at"`
	InvocationID string `json:"invocation_id,omitempty"`

	Source        string `json:"source"`
	SourceVersion string `json:"source_version,omitempty"`

	AgentName    string `json:"agent_name"`
	AgentVersion string `json:"agent_version,omitempty"`
	Provider     string `json:"provider,omitempty"`

	HookPhase  string `json:"hook_phase"`
	ActionType string `json:"action_type"`
	ToolName   string `json:"tool_name,omitempty"`

	ResultStatus     string       `json:"result_status,omitempty"`
	Outcome          string       `json:"outcome"`
	PermissionStatus string       `json:"permission_status"`
	ExecutionStatus  string       `json:"execution_status"`
	PrivacyMode      string       `json:"privacy_mode"`
	Completeness     Completeness `json:"completeness"`

	IsSensitive    bool     `json:"is_sensitive"`
	RedactedFields []string `json:"redacted_fields"`

	FilePath    string `json:"file_path,omitempty"`
	ContentHash string `json:"content_hash,omitempty"`
	DiffStats   string `json:"diff_stats,omitempty"`

	Command              string `json:"command,omitempty"`
	ExitCode             *int   `json:"exit_code,omitempty"`
	CommandOutputPreview string `json:"command_output_preview,omitempty"`

	MCPServer string `json:"mcp_server,omitempty"`
	MCPTool   string `json:"mcp_tool,omitempty"`

	DurationMS *int64 `json:"duration_ms,omitempty"`

	WorkingDirectory string `json:"working_directory,omitempty"`
	GitRepoURL       string `json:"git_repo_url,omitempty"`
	GitBranch        string `json:"git_branch,omitempty"`

	DeveloperName  string `json:"developer_name,omitempty"`
	DeveloperEmail string `json:"developer_email,omitempty"`
	OSUser         string `json:"os_user,omitempty"`
	MachineID      string `json:"machine_id,omitempty"`

	IntentSummary     string `json:"intent_summary,omitempty"`
	RawEventHash      string `json:"raw_event_hash,omitempty"`
	PreviousEventHash string `json:"previous_event_hash,omitempty"`
	EventHash         string `json:"event_hash,omitempty"`
	Model             string `json:"model,omitempty"`
}

type Completeness struct {
	State   string   `json:"state"`
	Reasons []string `json:"reasons"`
}

// HookPhase constants
const (
	HookPhasePre          = "pre"
	HookPhasePost         = "post"
	HookPhaseSessionStart = "session_start"
	HookPhaseSessionEnd   = "session_end"
	HookPhaseIntent       = "intent"
)

// ActionType constants
const (
	ActionFileRead        = "file_read"
	ActionFileWrite       = "file_write"
	ActionFileDelete      = "file_delete"
	ActionCommandExec     = "command_exec"
	ActionNetworkReq      = "network_request"
	ActionMCPToolUse      = "mcp_tool_use"
	ActionSubagentSpawn   = "subagent_spawn"
	ActionPlan            = "plan"
	ActionSessionStart    = "session_start"
	ActionSessionEnd      = "session_end"
	ActionDeveloperIntent = "developer_intent"
	ActionNotification    = "notification"
	ActionUnknown         = "unknown"
)

// ResultStatus constants
const (
	ResultSuccess  = "success"
	ResultError    = "error"
	ResultBlocked  = "blocked"
	ResultRejected = "rejected"
	ResultUnknown  = "unknown"
)

// RawHookInput is the raw JSON received from Claude Code hooks on stdin.
type RawHookInput struct {
	SessionID        string `json:"session_id"`
	Type             string `json:"type"`
	CWD              string `json:"cwd"`
	ToolUseID        string `json:"tool_use_id"`
	Model            string `json:"model"`
	PermissionMode   string `json:"permission_mode"`
	HookEventName    string `json:"hook_event_name"`
	Reason           string `json:"reason"`
	PermissionStatus string `json:"permission_status"`
	AgentVersion     string `json:"agent_version"`
	Timestamp        string `json:"timestamp"`
	Prompt           string `json:"prompt"`

	// PreToolUse / PostToolUse
	ToolName  string                 `json:"tool_name"`
	ToolInput map[string]interface{} `json:"tool_input"`
	// ToolInputRaw preserves the agent-native JSON value. ToolInput is retained
	// for the Claude-compatible object-shaped extraction helpers.
	ToolInputRaw json.RawMessage `json:"-"`

	// PostToolUse — populated by ParseHookInput after normalizing the raw value.
	// Claude Code may send tool_response as an object OR an array of content blocks.
	ToolResponse map[string]interface{} `json:"-"`
	// ToolResponseRaw preserves arbitrary JSON values such as Codex arrays or
	// scalar tool results.
	ToolResponseRaw json.RawMessage `json:"-"`
}
