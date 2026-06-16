package events

const SchemaURL = "https://schema.secuarden.ai/v1/event.schema.json"
const SchemaVersion = "1.0.0"

// Event is a governance event captured from an AI coding agent session.
// It matches the JSON schema at schema/secuarden-event.schema.json.
type Event struct {
	Schema        string `json:"$schema"`
	SchemaVersion string `json:"schema_version"`

	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Sequence  int    `json:"sequence"`
	Timestamp string `json:"timestamp"`

	Source        string `json:"source"`
	SourceVersion string `json:"source_version,omitempty"`

	AgentName    string `json:"agent_name"`
	AgentVersion string `json:"agent_version,omitempty"`

	HookPhase  string `json:"hook_phase"`
	ActionType string `json:"action_type"`
	ToolName   string `json:"tool_name,omitempty"`

	ResultStatus string `json:"result_status,omitempty"`

	IsSensitive    bool     `json:"is_sensitive"`
	RedactedFields []string `json:"redacted_fields,omitempty"`

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

	IntentSummary string `json:"intent_summary,omitempty"`
	RawEventHash  string `json:"raw_event_hash,omitempty"`
	Model         string `json:"model,omitempty"`
}

// HookPhase constants
const (
	HookPhasePre          = "pre"
	HookPhasePost         = "post"
	HookPhaseSessionStart = "session_start"
	HookPhaseSessionEnd   = "session_end"
)

// ActionType constants
const (
	ActionFileRead      = "file_read"
	ActionFileWrite     = "file_write"
	ActionFileDelete    = "file_delete"
	ActionCommandExec   = "command_exec"
	ActionNetworkReq    = "network_request"
	ActionMCPToolUse    = "mcp_tool_use"
	ActionSubagentSpawn = "subagent_spawn"
	ActionPlan          = "plan"
	ActionSessionStart  = "session_start"
	ActionSessionEnd    = "session_end"
	ActionNotification  = "notification"
	ActionUnknown       = "unknown"
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
	SessionID string `json:"session_id"`
	Type      string `json:"type"`
	CWD       string `json:"cwd"`

	// PreToolUse / PostToolUse
	ToolName  string                 `json:"tool_name"`
	ToolInput map[string]interface{} `json:"tool_input"`

	// PostToolUse — populated by ParseHookInput after normalizing the raw value.
	// Claude Code may send tool_response as an object OR an array of content blocks.
	ToolResponse map[string]interface{} `json:"-"`
}
