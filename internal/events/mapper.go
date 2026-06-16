package events

import "strings"

// MapToolToAction maps a Claude Code tool name to a normalized ActionType.
func MapToolToAction(toolName string) string {
	switch {
	case toolName == "Read" || toolName == "Grep" || toolName == "Glob":
		return ActionFileRead
	case toolName == "Write":
		return ActionFileWrite
	case toolName == "Edit" || toolName == "MultiEdit":
		return ActionFileWrite
	case toolName == "Bash":
		return ActionCommandExec
	case toolName == "WebFetch":
		return ActionNetworkReq
	case toolName == "Task":
		return ActionSubagentSpawn
	case toolName == "Plan":
		return ActionPlan
	case strings.HasPrefix(toolName, "mcp__"):
		return ActionMCPToolUse
	default:
		return ActionUnknown
	}
}

// ParseMCPTool splits "mcp__server__tool" into (server, tool).
// e.g. "mcp__memory__create_entities" → ("memory", "create_entities")
func ParseMCPTool(toolName string) (server, tool string) {
	parts := strings.SplitN(toolName, "__", 3)
	if len(parts) == 3 {
		return parts[1], parts[2]
	}
	return "", toolName
}
