package events

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ParseHookInput parses raw JSON bytes from a Claude Code hook into a RawHookInput.
// tool_response is normalized: Claude Code may send it as an object or as an array
// of content blocks (e.g. from multi-part tool results). Both shapes are accepted.
func ParseHookInput(data []byte) (*RawHookInput, error) {
	var shadow struct {
		SessionID    string                 `json:"session_id"`
		Type         string                 `json:"type"`
		CWD          string                 `json:"cwd"`
		ToolName     string                 `json:"tool_name"`
		ToolInput    map[string]interface{} `json:"tool_input"`
		ToolResponse json.RawMessage        `json:"tool_response"`
	}
	if err := json.Unmarshal(data, &shadow); err != nil {
		return nil, fmt.Errorf("parse hook input: %w", err)
	}

	raw := &RawHookInput{
		SessionID: shadow.SessionID,
		Type:      shadow.Type,
		CWD:       shadow.CWD,
		ToolName:  shadow.ToolName,
		ToolInput: shadow.ToolInput,
	}

	if len(shadow.ToolResponse) > 0 {
		var asMap map[string]interface{}
		if err := json.Unmarshal(shadow.ToolResponse, &asMap); err == nil {
			raw.ToolResponse = asMap
		} else {
			// Array of content blocks — flatten text into a single map
			var blocks []map[string]interface{}
			if json.Unmarshal(shadow.ToolResponse, &blocks) == nil {
				raw.ToolResponse = normalizeContentBlocks(blocks)
			}
		}
	}

	return raw, nil
}

// normalizeContentBlocks converts a content-block array into a simple map with
// a "content" key holding the concatenated text of all text-type blocks.
func normalizeContentBlocks(blocks []map[string]interface{}) map[string]interface{} {
	var parts []string
	for _, b := range blocks {
		if t, ok := b["text"].(string); ok {
			parts = append(parts, t)
		}
	}
	return map[string]interface{}{
		"content": strings.Join(parts, "\n"),
	}
}

// ExtractFilePath extracts a file path from tool_input, supporting multiple field names.
func ExtractFilePath(toolInput map[string]interface{}) string {
	for _, key := range []string{"file_path", "path", "old_path"} {
		if v, ok := toolInput[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// ExtractCommand extracts the shell command from a Bash tool_input.
func ExtractCommand(toolInput map[string]interface{}) string {
	if v, ok := toolInput["command"]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// ExtractExitCode extracts the exit code from a PostToolUse tool_response.
func ExtractExitCode(toolResponse map[string]interface{}) *int {
	if toolResponse == nil {
		return nil
	}
	// Claude Code may nest it differently; try common shapes
	for _, key := range []string{"exit_code", "exitCode"} {
		if v, ok := toolResponse[key]; ok {
			switch n := v.(type) {
			case float64:
				code := int(n)
				return &code
			case int:
				return &n
			}
		}
	}
	return nil
}

// ExtractOutputPreview extracts and truncates command output from tool_response.
func ExtractOutputPreview(toolResponse map[string]interface{}) string {
	if toolResponse == nil {
		return ""
	}
	for _, key := range []string{"output", "stdout", "content"} {
		if v, ok := toolResponse[key]; ok {
			if s, ok := v.(string); ok {
				if len(s) > 500 {
					return s[:500]
				}
				return s
			}
		}
	}
	return ""
}

// ExtractResultStatus maps tool_response outcome to a ResultStatus constant.
func ExtractResultStatus(toolResponse map[string]interface{}) string {
	if toolResponse == nil {
		return ""
	}
	if v, ok := toolResponse["error"]; ok && v != nil {
		return ResultError
	}
	if ec := ExtractExitCode(toolResponse); ec != nil && *ec != 0 {
		return ResultError
	}
	return ResultSuccess
}

// ExtractDiffStats computes a "+N/-M" diff summary from Edit tool_input.
// Returns empty string if old/new strings aren't present.
func ExtractDiffStats(toolInput map[string]interface{}) string {
	oldStr, _ := toolInput["old_string"].(string)
	newStr, _ := toolInput["new_string"].(string)
	if oldStr == "" && newStr == "" {
		return ""
	}
	added := countLines(newStr)
	removed := countLines(oldStr)
	if added == 0 && removed == 0 {
		return ""
	}
	return fmt.Sprintf("+%d/-%d", added, removed)
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	n := 1
	for _, c := range s {
		if c == '\n' {
			n++
		}
	}
	return n
}

// ExtractModel extracts the LLM model from session start data.
func ExtractModel(raw *RawHookInput) string {
	return ""
}
